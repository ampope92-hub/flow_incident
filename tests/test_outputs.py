"""Grades the case report. test.sh rebuilt the agent's Zig three times and ran it against the
shipped archive, a held-back one and a small one reached by host name, capturing stdout to
/opt/run. Nothing here recomputes the report; every value is compared with the golden the rule
book in solution/generate_archive.py wrote, an oracle cross-checked by two independent
implementations of SPEC.md: that Python rule book and the Zig reference, whose report on each
archive was written at generation time to golden_ref."""
import ipaddress
import json
import os
import re
import struct

import pytest

RUN = "/opt/run"
TRUTH = "/opt/truth"
SETS = ["sample", "hidden", "edge"]
HDR = struct.Struct(">HHIIIIBBH")
REC = struct.Struct(">IIIHHIIIIHHBBBBHHBBH")
IP_RE = re.compile(r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$")


def read_bytes(path):
    """Opens without following a symlink, so a link planted at the path is refused."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fh:
        return fh.read()


def raw(name):
    return read_bytes(os.path.join(RUN, f"report_{name}.json")).decode("utf-8")


def report(name):
    text = raw(name)
    text = text.removesuffix("\n")
    assert "\n" not in text, f"the {name} report is not exactly one line"
    return json.loads(text)


def golden(name):
    return json.loads(read_bytes(os.path.join(TRUTH, "golden", name + ".json")))


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


# ── the archive as the service holds it, for the coverage checks ───────────────────────────

def archive(name):
    """[(exporter, received_ms, bytes)] in arrival order, and the case fields."""
    blob = read_bytes(os.path.join(TRUTH, name, "archive.bin"))
    items = []
    p = 0
    while p < len(blob):
        n = blob[p]
        ex = blob[p + 1:p + 1 + n].decode()
        p += 1 + n
        rx, ln = struct.unpack_from(">QH", blob, p)
        p += 10
        items.append((ex, rx, blob[p:p + ln]))
        p += ln
    line = read_bytes(os.path.join(TRUTH, name, "case.txt")).decode().split()
    case = dict(kv.split("=", 1) for kv in line[1:])
    case["exporters"] = case["exporters"].split(",")
    case["from"] = int(case["from"])
    case["to"] = int(case["to"])
    return items, case


def distinct(items):
    first = {}
    for ex, rx, data in sorted(items, key=lambda it: it[1]):
        first.setdefault((ex, data), rx)
    return first


def header(data):
    h = HDR.unpack_from(data)
    return {"count": h[1], "uptime": h[2], "clock": h[3] * 1000 + h[4] // 1_000_000, "seq": h[5],
                "mode": h[8] >> 14, "n": h[8] & 0x3FFF}


def records(data):
    h = header(data)
    for i in range(h["count"]):
        f = REC.unpack_from(data, HDR.size + i * REC.size)
        yield {"src": f[0], "dst": f[1], "bytes": f[6], "first": f[7], "last": f[8], "sport": f[9], "dport": f[10], "proto": f[13]}


def offsets(dist):
    """Each exporter's clock error as the spec states it: arrival minus header on the earliest
    copy, a whole number of seconds, the same everywhere."""
    vals = {}
    for (ex, data), rx in dist.items():
        vals.setdefault(ex, []).append(round((header(data)["clock"] - rx) / 1000))
    out = {}
    for ex, lst in vals.items():
        assert len(set(lst)) == 1, f"{ex}: the arrival lag does not round to one offset: {sorted(set(lst))[:5]}"
        out[ex] = lst[0]
    return out


# ── the report ─────────────────────────────────────────────────────────────────────────────

def test_golden_agrees_with_the_zig_reference():
    """Fixture consistency: for every graded archive the rule book's golden and the Zig
    reference's report are the same file."""
    for name in SETS:
        a = read_bytes(os.path.join(TRUTH, "golden", name + ".json"))
        assert a == read_bytes(os.path.join(TRUTH, "golden_ref", name + ".json")), f"{name}: the two goldens differ"


def test_every_build_succeeded():
    """All three rebuilds of the collected sources produced a regular binary."""
    status = read_bytes(os.path.join(RUN, "build_check.txt")).decode().strip()
    assert status == "ok", "a rebuild of /app/flowkit/src failed or produced no binary"


@pytest.mark.parametrize("name", SETS)
def test_report_is_one_json_object(name):
    """Each run printed exactly one line: a JSON object with the three members of the spec."""
    rep = report(name)
    assert isinstance(rep, dict)
    assert set(rep) == {"outbound", "lateral", "lost"}, f"unexpected members: {sorted(rep)}"


@pytest.mark.parametrize("name", SETS)
def test_report_shape(name):
    """Each table has the members, integer types and order SPEC.md gives."""
    rep = report(name)
    _, case = archive(name)
    hosts = []
    for row in rep["outbound"]:
        assert set(row) == {"host", "bytes", "connections"}, row
        assert isinstance(row["host"], str) and IP_RE.match(row["host"]), row
        assert is_int(row["bytes"]) and is_int(row["connections"]) and row["connections"] >= 1, row
        hosts.append(int(ipaddress.IPv4Address(row["host"])))
    assert hosts == sorted(hosts), "outbound is not in ascending address order"
    assert len(hosts) == len(set(hosts)), "a host is listed twice in outbound"
    assert isinstance(rep["lateral"], list)
    order = []
    for row in rep["lateral"]:
        assert set(row) == {"host", "first_ms", "bytes", "connections"}, row
        assert isinstance(row["host"], str) and IP_RE.match(row["host"]), row
        assert is_int(row["first_ms"]) and is_int(row["bytes"]) and is_int(row["connections"]), row
        order.append((row["first_ms"], int(ipaddress.IPv4Address(row["host"]))))
    assert order == sorted(order), "lateral is not in ascending order of first_ms then address"
    assert len({h for _, h in order}) == len(order), "a host is listed twice in lateral"
    assert set(rep["lost"]) == set(case["exporters"]), f"lost names {sorted(rep['lost'])}, the case names {case['exporters']}"
    assert all(is_int(v) and v >= 0 for v in rep["lost"].values()), rep["lost"]


def _outbound(name):
    got = {r["host"]: r for r in report(name)["outbound"]}
    want = {r["host"]: r for r in golden(name)["outbound"]}
    wrong = sorted(h for h in set(got) | set(want) if got.get(h) != want.get(h))
    assert not wrong, (f"{name}: {len(wrong)} of {len(want)} outbound rows differ from the rule book, first: "
                       + "; ".join(f"{h}: {got.get(h)} (expected {want.get(h)})" for h in wrong[:3]))


def _lateral(name):
    got = report(name)["lateral"]
    want = golden(name)["lateral"]
    assert got == want, f"{name}: lateral differs from the rule book: {got} (expected {want})"


def _lost(name):
    got = report(name)["lost"]
    want = golden(name)["lost"]
    assert got == want, f"{name}: lost is {got}, the rule book gives {want}"


def test_sample_outbound():
    """On the shipped archive every outbound row equals the rule book's."""
    _outbound("sample")


def test_sample_lateral():
    """On the shipped archive every lateral row, first contact time included, equals the rule book's."""
    _lateral("sample")


def test_sample_lost():
    """On the shipped archive both lost counts equal the rule book's."""
    _lost("sample")


def test_hidden_outbound():
    """On the held-back archive every outbound row equals the rule book's."""
    _outbound("hidden")


def test_hidden_lateral():
    """On the held-back archive every lateral row equals the rule book's."""
    _lateral("hidden")


def test_hidden_lost():
    """On the held-back archive both lost counts equal the rule book's."""
    _lost("hidden")


def test_edge_outbound():
    """On the small archive every outbound row equals the rule book's."""
    _outbound("edge")


def test_edge_lateral():
    """On the small archive the suspect's only inside connections lie outside the window, one of
    them where the core's raw clock would put it inside, so lateral is the empty array."""
    _lateral("edge")


def test_edge_lost():
    """On the small archive both lost counts equal the rule book's; only the uptime marks the core's boot."""
    _lost("edge")


# ── the protocol ───────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", SETS)
def test_each_run_read_the_whole_archive_it_was_given(name):
    """The run's archive logged the case being asked for and every page being fetched, each
    FETCH after the first presenting a token that archive had already handed out (its tokens
    are random, so none can be made up)."""
    log = read_bytes(os.path.join(RUN, f"archive_{name}.log")).decode("utf-8", "replace")
    assert " CASE" in log, "the run never asked for the case"
    pages, total, handed = set(), None, {"-"}
    for m in re.finditer(r" FETCH (\w+)(?: (\d+) of (\d+))? .*?token=(\S+) next=(\S+)", log):
        assert m.group(1) == "page" and m.group(4) in handed, f"FETCH {m.group(4)!r} is not a token this archive handed out"
        handed.add(m.group(5))
        pages.add(int(m.group(2)))
        total = int(m.group(3))
    assert total, "the run never fetched a page"
    missing = sorted(set(range(1, total + 1)) - pages)
    assert not missing, f"pages never fetched: {missing[:10]} of {total}"


def test_a_graded_run_was_told_where_its_archive_is_by_name():
    """ARCHIVE_HOST carries a host name as readily as an address, and the edge run was given
    one; its archive listened on the address the name resolves to and logged the run's case
    request, so the tool resolved the name rather than parsing four numbers."""
    host = read_bytes(os.path.join(RUN, "named_host.txt")).decode().strip()
    assert host and not IP_RE.match(host), f"the named run was given {host!r}, a dotted quad"
    log = read_bytes(os.path.join(RUN, "archive_edge.log")).decode("utf-8", "replace")
    assert "127.0.0.4:" in log.splitlines()[0], "the edge archive did not listen on the named address"
    assert " CASE" in log, "the named run never reached its archive"


# ── coverage: counted from the archives rather than assumed ────────────────────────────────

def _cases(name):
    items, case = archive(name)
    dist = distinct(items)
    edge_name, core_name = case["exporters"]
    modes = {ex: {header(d)["mode"] for (e, d) in dist if e == ex} for ex in case["exporters"]}
    ns = {header(d)["n"] for (e, d) in dist if e == edge_name}
    dup = sum(1 for k in dist if sum(1 for it in items if (it[0], it[2]) == k) > 1)
    wrapped = sum(1 for (e, d) in dist for r in records(d) if r["first"] > header(d)["uptime"])
    core = sorted((header(d)["clock"], header(d)["seq"], header(d)["count"], d) for (e, d) in dist if e == core_name)
    restarts = sum(1 for i in range(1, len(core)) if core[i][1] < core[i - 1][1])
    boots = len({(h["clock"] - h["uptime"]) % 2**32 // 1000 for h in (header(d) for *_, d in core)})
    seqs = {}
    for _, seq, _, d in core:
        seqs.setdefault(seq, []).append(d)
    collisions = sum(1 for v in seqs.values() if len(v) > 1)
    longest_core_gap = max((core[i][0] - core[i - 1][0] for i in range(1, len(core))), default=0)
    off = offsets(dist)
    # the core's records on the true clock, per 5-tuple
    by = {}
    starts = {"from": 0, "to": 0}
    for e, d in dist:
        if e != core_name:
            continue
        h = header(d)
        base = h["clock"] - off[e] * 1000
        for r in records(d):
            s = base - ((h["uptime"] - r["first"]) & 0xFFFFFFFF)
            t = base - ((h["uptime"] - r["last"]) & 0xFFFFFFFF)
            by.setdefault((r["src"], r["dst"], r["sport"], r["dport"], r["proto"]), []).append((s, t))
            if s == case["from"]:
                starts["from"] += 1
            if s == case["to"]:
                starts["to"] += 1
    exact_five = 0
    for lst in by.values():
        lst.sort()
        for i in range(1, len(lst)):
            if lst[i][0] - max(t for _, t in lst[:i]) == 300_000:
                exact_five += 1
    return {"modes": modes, "ns": ns, "dup": dup, "wrapped": wrapped, "restarts": restarts, "collisions": collisions, "boots": boots,
                "longest_core_gap": longest_core_gap, "starts": starts, "exact_five": exact_five, "off": off, "case": case}


def test_sample_carries_every_case():
    """The shipped archive carries each case the spec's rules turn on: the edge router sampling
    and the core not, a whole-second clock error on the core and none on the edge, re-sent
    datagrams, a power cycle whose restarted sequence collides with the earlier boot's,
    records whose uptime counter wrapped, a stretch only the edge router saw, records of one
    5-tuple exactly five minutes apart, and a connection starting exactly at each window edge."""
    c = _cases("sample")
    assert c["modes"][c["case"]["exporters"][0]] == {1} and c["modes"][c["case"]["exporters"][1]] == {0}
    assert c["ns"] == {4}
    assert c["off"][c["case"]["exporters"][0]] == 0 and c["off"][c["case"]["exporters"][1]] == 667
    assert c["dup"] >= 20 and c["restarts"] == 1 and c["boots"] == 2 and c["collisions"] >= 10
    assert c["wrapped"] >= 3 and c["longest_core_gap"] >= 300_000
    assert c["exact_five"] >= 1 and c["starts"]["from"] >= 1 and c["starts"]["to"] >= 1
    assert golden("sample")["lateral"] and all(v > 0 for v in golden("sample")["lost"].values())


def test_hidden_carries_every_case():
    """The held-back archive carries the same cases with other constants: one packet in 260,
    a core clock behind true time, other names, network and window, and two lateral hosts
    first contacted in the same millisecond, the higher address exported first."""
    c = _cases("hidden")
    assert c["modes"][c["case"]["exporters"][0]] == {1} and c["modes"][c["case"]["exporters"][1]] == {0}
    assert c["ns"] == {260}
    assert c["off"][c["case"]["exporters"][0]] == 0 and c["off"][c["case"]["exporters"][1]] == -1420
    assert c["dup"] >= 20 and c["restarts"] == 1 and c["boots"] == 2 and c["collisions"] >= 10
    assert c["wrapped"] >= 3 and c["longest_core_gap"] >= 300_000
    assert c["exact_five"] >= 1 and c["starts"]["from"] >= 1 and c["starts"]["to"] >= 1
    lat = golden("hidden")["lateral"]
    assert len({r["first_ms"] for r in lat}) < len(lat) and all(v > 0 for v in golden("hidden")["lost"].values())


def test_edge_carries_its_cases():
    """The small archive samples one packet in one, has no re-sent datagrams, a core clock five
    minutes ahead, a power cycle whose restarted sequence never falls below the old boot's, a
    wrapped counter on the edge router, which lost nothing, and the window-edge and five-minute cases."""
    c = _cases("edge")
    assert c["modes"][c["case"]["exporters"][0]] == {1} and c["modes"][c["case"]["exporters"][1]] == {0}
    assert c["ns"] == {1}
    assert c["off"][c["case"]["exporters"][0]] == 0 and c["off"][c["case"]["exporters"][1]] == 301
    assert c["dup"] == 0 and c["restarts"] == 0 and c["boots"] == 2 and c["collisions"] == 0
    assert c["wrapped"] >= 3
    assert c["exact_five"] >= 1 and c["starts"]["from"] >= 1 and c["starts"]["to"] >= 1
    lost = golden("edge")["lost"]
    assert lost[c["case"]["exporters"][0]] == 0 and lost[c["case"]["exporters"][1]] > 0
