#!/usr/bin/env python3
"""Builds the three flow archives the task ships and the report each one must produce.

    generate_archive.py --write ROOT        write the environment copy, the verifier sets
                                            and the goldens
    generate_archive.py --set NAME --seed S print the report for a fresh draw (calibrate.py)

The site has two routers that export flow records to one collector. Both see every
connection between the inside network and the internet; only the core sees traffic that stays
inside. The edge router samples one packet in N and says so in its header; the core counts
every packet but keeps its own clock, a whole number of seconds away from true time. The core
was power cycled once during the archive, the collector lost some datagrams from each router,
and the collector itself restarted once and re-sent part of its spool, so some datagrams are
in the archive twice with a later arrival time.

The report (the golden) is computed by `rulebook()` from the archive bytes alone, by the rules
SPEC.md states, never from the generator's own bookkeeping. calibrate.py drives `rulebook()`
with one reading changed at a time to measure how far each misreading lands from it.
"""
import argparse
import ipaddress
import itertools
import json
import os
import random
import struct
from collections import defaultdict

HDR = struct.Struct(">HHIIIIBBH")      # version, count, uptime, secs, nsecs, seq, etype, eid, sampling
REC = struct.Struct(">IIIHHIIIIHHBBBBHHBBH")
ACTIVE_MS = 60_000
INACTIVE_MS = 15_000
REUSE_MS = 300_000
PER_DGRAM = 30
FLUSH_MS = 1_000

SETS = {
    "sample": {
        "seed": 20260503, "inside": "10.20.0.0/16", "suspect": "10.20.3.17", "server_net": "10.20.1.",
        "ws_nets": ["10.20.2.", "10.20.3.", "10.20.4.", "10.20.5.", "10.20.7."],
        "exporters": ("border", "core"), "start": 1746277200000, "hours": 2.0, "lead_min": 10,
        "n_pkt": 4, "offset_s": 667, "ws_count": 34, "internet_per_ws": (14, 40), "inside_per_ws": (3, 10),
        "exfil_ips": ["203.0.113.24", "203.0.113.61"], "exfil_ports": [443, 8443],
        "border_uptime_ms": 4_294_967_296 - 3_200_000, "core_uptime_ms": 11_232_000, "border_seq0": 1_203_455, "core_seq0": 640,
        "reboot_at": 0.42, "reboot_down_s": 390, "core_loss": (0.71, 130), "border_loss": (0.19, 200),
        "replay_back_min": 12, "replay_after_s": 300,
    },
    "hidden": {
        "seed": 20260611, "inside": "172.22.0.0/16", "suspect": "172.22.40.9", "server_net": "172.22.8.",
        "ws_nets": ["172.22.40.", "172.22.41.", "172.22.42.", "172.22.44.", "172.22.45.", "172.22.46."],
        "exporters": ("edge-fw", "dist-1"), "start": 1749650400000, "hours": 3.0, "lead_min": 15,
        "n_pkt": 8, "offset_s": -1420, "ws_count": 130, "internet_per_ws": (12, 36), "inside_per_ws": (2, 9),
        "exfil_ips": ["198.51.100.77", "198.51.100.140", "203.0.113.9"], "exfil_ports": [443, 8443, 4444],
        "border_uptime_ms": 4_294_967_296 - 6_400_000, "core_uptime_ms": 18_144_000, "border_seq0": 44_910_002, "core_seq0": 905,
        "reboot_at": 0.57, "reboot_down_s": 610, "core_loss": (0.23, 170), "border_loss": (0.80, 240),
        "replay_back_min": 14, "replay_after_s": 240, "first_tie": True,
    },
    "edge": {
        "seed": 20260705, "inside": "192.168.50.0/24", "suspect": "192.168.50.77", "server_net": "192.168.50.",
        "ws_nets": ["192.168.50."], "server_last": (2, 3, 4), "ws_last": range(60, 120),
        "exporters": ("gw", "sw"), "start": 1751713200000, "hours": 0.4, "lead_min": 8,
        "n_pkt": 1, "offset_s": 301, "ws_count": 9, "internet_per_ws": (4, 12), "inside_per_ws": (1, 3),
        "exfil_ips": ["203.0.113.200"], "exfil_ports": [443],
        "border_uptime_ms": 4_294_967_296 - 720_000, "core_uptime_ms": 1_500_000, "border_seq0": 77_310, "core_seq0": 20,
        "reboot_at": -0.25, "reboot_down_s": 45, "boot_loss_s": 200, "core_loss": (0.55, 40), "border_loss": None,
        "replay_back_min": 0, "replay_after_s": 0, "no_lateral": True,
    },
}

PUBLIC_POOL = ["23.45.%d.%d", "52.19.%d.%d", "104.18.%d.%d", "142.250.%d.%d", "151.101.%d.%d",
               "185.199.%d.%d", "35.190.%d.%d", "64.233.%d.%d", "13.107.%d.%d", "40.99.%d.%d"]
RESOLVERS = ["9.9.9.9", "1.1.1.1"]


def ip_int(s):
    return int(ipaddress.IPv4Address(s))


class Conn:
    """One connection: a forward 5-tuple (client side) and the packets in both directions."""
    __slots__ = ("dport", "dst", "kind", "pkts", "proto", "sport", "src", "tag")

    def __init__(self, src, dst, sport, dport, proto, kind, tag=""):
        self.src, self.dst, self.sport, self.dport, self.proto = src, dst, sport, dport, proto
        self.pkts = []          # (t_ms, fwd?, bytes, flags)
        self.kind = kind        # internet | lateral | inside | dns
        self.tag = tag

    def first(self):
        return self.pkts[0][0]

    def last(self):
        return self.pkts[-1][0]

    def last_fwd(self):
        return max(t for t, fwd, _, _ in self.pkts if fwd)


# ── traffic ────────────────────────────────────────────────────────────────────────────────

def tcp_train(rng, t0, dur_ms, up_bytes, down_bytes, min_gap=250, max_gap=1800):
    """Packets of a TCP connection: handshake, then data both ways at a steady pace, then FIN.
    Gaps between consecutive packets stay under max_gap, so the core never expires it early."""
    pk = [(t0, True, 60, 0x02), (t0 + rng.randint(5, 40), False, 60, 0x12), (t0 + rng.randint(45, 80), True, 52, 0x10)]
    t = t0 + 90
    end = t0 + dur_ms
    n_up = max(1, up_bytes // 1400)
    n_down = max(1, down_bytes // 1400)
    n = n_up + n_down
    gap = max(min_gap, min(max_gap, (end - t) // max(1, n)))
    ups, downs = n_up, n_down
    up_left, down_left = up_bytes, down_bytes
    while (ups or downs) and t < end:
        if ups and (not downs or rng.random() < ups / (ups + downs)):
            b = min(1460, up_left) if ups > 1 else up_left
            up_left -= b
            ups -= 1
            pk.append((t, True, 52 + b, 0x18))
        else:
            b = min(1460, down_left) if downs > 1 else down_left
            down_left -= b
            downs -= 1
            pk.append((t, False, 52 + b, 0x18))
        t += rng.randint(min_gap, gap)
    while t < end - 200:
        # keep-alive style traffic so the connection stays open the full duration
        pk.append((t, rng.random() < 0.5, 52 + rng.randint(0, 900), 0x18))
        t += rng.randint(min_gap, max_gap)
    pk.append((max(t, end - 100), True, 52, 0x11))
    pk.append((max(t, end - 100) + rng.randint(3, 30), False, 52, 0x11))
    pk.sort(key=lambda p: p[0])
    return pk


def gen_traffic(rng, cfg):
    inside = ipaddress.IPv4Network(cfg["inside"])
    suspect = cfg["suspect"]
    t_from = cfg["start"]
    t_to = t_from + int(cfg["hours"] * 3600_000)
    lead = cfg["lead_min"] * 60_000
    span_lo, span_hi = t_from - lead, t_to + lead

    if "ws_last" in cfg:
        servers = [cfg["server_net"] + str(x) for x in cfg["server_last"]]
        ws_pool = [cfg["server_net"] + str(x) for x in cfg["ws_last"]]
    else:
        servers = [cfg["server_net"] + str(x) for x in (5, 6, 7, 10, 20, 30)]
        ws_pool = [n + str(x) for n in cfg["ws_nets"] for x in range(1, 251)]
    ws_pool = [w for w in ws_pool if w != suspect]
    workstations = rng.sample(ws_pool, cfg["ws_count"])
    public = [p % (rng.randint(1, 254), rng.randint(1, 254)) for p in PUBLIC_POOL for _ in range(6)]
    public = [p for p in public if not ipaddress.IPv4Address(p) in inside]

    conns = []

    def fresh_port(src):
        return rng.randint(20000, 60999)

    def add_tcp(src, dst, dport, t0, dur, up, down, kind, tag="", sport=None):
        c = Conn(src, dst, sport or fresh_port(src), dport, 6, kind, tag)
        c.pkts = tcp_train(rng, t0, dur, up, down)
        conns.append(c)
        return c

    def add_dns(src, t0, kind="dns"):
        c = Conn(src, rng.choice(RESOLVERS), fresh_port(src), 53, 17, kind)
        c.pkts = [(t0, True, rng.randint(60, 90), 0), (t0 + rng.randint(8, 60), False, rng.randint(90, 400), 0)]
        conns.append(c)
        return c

    # ordinary browsing from every workstation, with a DNS lookup before most connections
    for ws in workstations + [suspect]:
        n_net = rng.randint(*cfg["internet_per_ws"])
        for _ in range(n_net):
            t0 = rng.randint(span_lo, span_hi)
            if rng.random() < 0.6:
                add_dns(ws, t0 - rng.randint(100, 900))
            dst = rng.choice(public)
            long = rng.random() < 0.12
            dur = rng.randint(70_000, 320_000) if long else rng.randint(400, 28_000)
            add_tcp(ws, dst, rng.choice([443, 443, 443, 80]), t0, dur,
                    rng.randint(300, 9_000), rng.randint(2_000, 900_000) if long else rng.randint(1_000, 120_000), "internet")
        if ws != suspect:
            for _ in range(rng.randint(*cfg["inside_per_ws"])):
                t0 = rng.randint(span_lo, span_hi)
                add_tcp(ws, rng.choice(servers), rng.choice([445, 445, 3389, 22, 8080]), t0,
                        rng.randint(1_000, 90_000), rng.randint(500, 40_000), rng.randint(500, 200_000), "inside")

    # the suspect: lateral movement to the servers, then exfiltration in bursts
    if not cfg.get("no_lateral"):
        for _ in range(rng.randint(14, 22)):
            t0 = rng.randint(span_lo, span_hi)
            add_tcp(suspect, rng.choice(servers), rng.choice([445, 3389, 22, 5985]), t0,
                    rng.randint(3_000, 150_000), rng.randint(2_000, 900_000), rng.randint(500, 60_000), "lateral")
    else:
        # the only inside connections of the suspect sit outside the window, one of them where the
        # core's raw clock would put it inside
        add_tcp(suspect, servers[0], 445, t_from - 100_000, 20_000, 30_000, 4_000, "lateral", "outside_raw_inside")
        add_tcp(suspect, servers[1], 3389, t_to + 40_000, 20_000, 30_000, 4_000, "lateral", "outside_after")
    for _ in range(rng.randint(10, 18)):
        t0 = rng.randint(span_lo, span_hi)
        add_tcp(suspect, rng.choice(cfg["exfil_ips"]), rng.choice(cfg["exfil_ports"]), t0,
                rng.randint(15_000, 260_000), rng.randint(200_000, 6_000_000), rng.randint(300, 3_000), "internet", "exfil")

    # ── planted cases ───────────────────────────────────────────────────────────────────
    off = cfg["offset_s"] * 1000
    # window edges on the true clock: a start exactly at from is in, exactly at to is out
    add_tcp(suspect, cfg["exfil_ips"][0], cfg["exfil_ports"][0], t_from, 9_000, 40_000, 800, "internet", "edge_from")
    add_tcp(suspect, cfg["exfil_ips"][0], cfg["exfil_ports"][0], t_to, 9_000, 40_000, 800, "internet", "edge_to")
    if not cfg.get("no_lateral"):
        add_tcp(suspect, servers[2], 445, t_from - 1, 6_000, 20_000, 500, "lateral", "edge_from_minus")
        add_tcp(suspect, servers[3], 445, t_to - 1, 6_000, 20_000, 500, "lateral", "edge_to_minus")
        # on the core's raw clock these lateral connections are on the other side of a window edge
        if off > 0:
            add_tcp(suspect, servers[4], 3389, t_from - off // 2, 8_000, 20_000, 500, "lateral", "raw_in_true_out")
            add_tcp(suspect, servers[5], 3389, t_to - off // 2, 8_000, 20_000, 500, "lateral", "raw_out_true_in")
        else:
            add_tcp(suspect, servers[4], 3389, t_to + off // 2, 8_000, 20_000, 500, "lateral", "raw_in_true_out")
            add_tcp(suspect, servers[5], 3389, t_from - off // 2, 8_000, 20_000, 500, "lateral", "raw_out_true_in")
        if cfg.get("first_tie"):  # .10 and .5 first contacted in one millisecond, .10 exported first
            for k, dur in ((3, 2_000), (0, 9_000)):
                add_tcp(suspect, servers[k], 445, t_from + 20_000, dur, 20_000, 500, "lateral", "first_tie")
    # a source port used twice, five minutes and more apart, and once exactly five minutes apart
    p = fresh_port(suspect)
    t0 = t_from + int(0.3 * (t_to - t_from))
    a = add_tcp(suspect, cfg["exfil_ips"][-1], cfg["exfil_ports"][0], t0, 12_000, 60_000, 900, "internet", "reuse_a", sport=p)
    add_tcp(suspect, cfg["exfil_ips"][-1], cfg["exfil_ports"][0], a.last() + 330_000, 12_000, 60_000, 900, "internet", "reuse_b", sport=p)
    p2 = fresh_port(suspect)
    t0 = t_from + int(0.15 * (t_to - t_from))
    b = add_tcp(suspect, cfg["exfil_ips"][0], cfg["exfil_ports"][0], t0, 10_000, 50_000, 900, "internet", "reuse_exact_a", sport=p2)
    add_tcp(suspect, cfg["exfil_ips"][0], cfg["exfil_ports"][0], b.last_fwd() + REUSE_MS, 10_000, 50_000, 900, "internet", "reuse_exact_b", sport=p2)
    # a slow connection the edge router's sampling breaks on its own inactive timeout: two
    # bursts 14 s apart (the core keeps it whole); placed where only the edge router saw it
    if cfg["reboot_at"] is not None:
        r_at = t_from + int(cfg["reboot_at"] * (t_to - t_from))
        for k in range(3):
            t0 = r_at + 40_000 + k * 90_000
            c = Conn(suspect, cfg["exfil_ips"][0], fresh_port(suspect), cfg["exfil_ports"][-1], 6, "internet", "sampled_split")
            pk = tcp_train(rng, t0, 12_000, 30_000, 600)
            pk = [q for q in pk if q[3] != 0x11]
            t1 = pk[-1][0] + 14_000
            pk2 = tcp_train(rng, t1, 12_000, 30_000, 600)
            pk2 = [q for q in pk2 if q[3] != 0x02 and q[3] != 0x12]
            c.pkts = sorted(pk + pk2, key=lambda q: q[0])
            conns.append(c)

    # police the port-reuse guarantee: a 5-tuple is not reused within five minutes of its
    # last packet. Deliberate reuses are planted above; any accidental one is re-ported.
    by5 = defaultdict(list)
    for c in conns:
        by5[(c.src, c.dst, c.sport, c.dport, c.proto)].append(c)
    for lst in by5.values():
        lst.sort(key=lambda c: c.first())
        for i in range(1, len(lst)):
            if lst[i].tag.startswith("reuse"):
                continue
            if lst[i].first() - lst[i - 1].last() < REUSE_MS:
                lst[i].sport = fresh_port(lst[i].src)
    conns.sort(key=lambda c: (c.first(), c.src, c.sport))
    return conns, {"t_from": t_from, "t_to": t_to, "servers": servers, "workstations": workstations}


# ── exporters ──────────────────────────────────────────────────────────────────────────────

class Exporter:
    def __init__(self, name, boot_ms, offset_ms, seq0, sampling_n, engine_id):
        self.name = name
        self.boot = boot_ms
        self.offset = offset_ms
        self.seq = seq0
        self.n = sampling_n       # 0 = every packet counted
        self.engine_id = engine_id
        self.records = []         # (expire_ms, rec dict)


def cache_records(packets, boot_ms):
    """Runs one 5-tuple's packets through a flow cache: a record ends after 60 s of traffic
    or 15 s without a packet. Returns records as dicts with uptime-relative First/Last."""
    out = []
    cur = None
    for t, b, flags in packets:
        if cur is not None and (t - cur["first"] >= ACTIVE_MS or t - cur["last"] >= INACTIVE_MS):
            cur["expire"] = cur["last"] + INACTIVE_MS if t - cur["last"] >= INACTIVE_MS else t
            out.append(cur)
            cur = None
        if cur is None:
            cur = {"first": t, "last": t, "pkts": 0, "bytes": 0, "flags": 0}
        cur["last"] = t
        cur["pkts"] += 1
        cur["bytes"] += b
        cur["flags"] |= flags
    if cur is not None:
        cur["expire"] = cur["last"] + INACTIVE_MS
        out.append(cur)
    return out


def export(exp, conns, sees, rng, down=None):
    """Exports every connection `sees` says this router carried. `down` is the interval the
    router was off; packets in it are never seen and the cache is empty at the reboot."""
    flows = defaultdict(list)     # 5-tuple -> [(t, bytes, flags)]
    counter = 0
    allpk = []
    for c in conns:
        if not sees(c):
            continue
        for t, fwd, b, fl in c.pkts:
            if down and down[0] <= t < down[1]:
                continue
            key = (c.src, c.dst, c.sport, c.dport, c.proto) if fwd else (c.dst, c.src, c.dport, c.sport, c.proto)
            allpk.append((t, key, b, fl))
    allpk.sort(key=lambda p: (p[0], p[1]))
    for t, key, b, fl in allpk:
        counter += 1
        if exp.n and counter % exp.n:
            continue
        flows[key].append((t, b, fl))
    recs = []
    for key, pk in flows.items():
        for r in cache_records(pk, None):
            r["key"] = key
            recs.append(r)
    recs.sort(key=lambda r: (r["expire"], r["key"]))
    return recs


def build_datagrams(exp, recs, boot_ms, seq_start, rng, cuts=()):
    """Packs expired records into datagrams: flushed at 30 records or one second after the
    first record was buffered, and always before a record whose expiry crosses one of `cuts`
    (so the spans the collector lost hold whole datagrams). Returns
    [(flush_true_ms, received_ms, bytes, first_expiry_ms)]."""
    out = []
    buf = []
    buf_t0 = None
    seq = seq_start

    def flush(at):
        nonlocal buf, buf_t0, seq
        if not buf:
            return
        uptime = at - boot_ms
        clock = at + exp.offset
        hdr = HDR.pack(5, len(buf), uptime & 0xFFFFFFFF, clock // 1000, (clock % 1000) * 1_000_000,
                       seq & 0xFFFFFFFF, 0, exp.engine_id, ((1 << 14) | exp.n) if exp.n else 0)
        body = b""
        for r in buf:
            src, dst, sport, dport, proto = r["key"]
            body += REC.pack(ip_int(src), ip_int(dst), 0, 1, 2, r["pkts"], r["bytes"],
                             (r["first"] - boot_ms) & 0xFFFFFFFF, (r["last"] - boot_ms) & 0xFFFFFFFF,
                             sport, dport, 0, r["flags"] if proto == 6 else 0, proto, 0, 0, 0, 0, 0, 0)
        seq += len(buf)
        out.append((at, at + rng.randint(3, 40), hdr + body, buf_t0))
        buf = []
        buf_t0 = None

    for r in recs:
        if buf and any(buf_t0 < c <= r["expire"] for c in cuts):
            flush(min(buf_t0 + FLUSH_MS, r["expire"]))
        if buf and r["expire"] - buf_t0 >= FLUSH_MS:
            flush(buf_t0 + FLUSH_MS)
        if not buf:
            buf_t0 = r["expire"]
        buf.append(r)
        if len(buf) == PER_DGRAM:
            flush(r["expire"])
    if buf:
        flush(buf_t0 + FLUSH_MS)
    return out


def simulate(cfg, seed):
    rng = random.Random(seed)
    conns, meta = gen_traffic(rng, cfg)
    t_from, t_to = meta["t_from"], meta["t_to"]
    inside = ipaddress.IPv4Network(cfg["inside"])
    bname, cname = cfg["exporters"]
    off_ms = cfg["offset_s"] * 1000
    border = Exporter(bname, t_from - cfg["border_uptime_ms"], 0, cfg["border_seq0"], cfg["n_pkt"], 1)
    core = Exporter(cname, t_from - cfg["core_uptime_ms"], off_ms, cfg["core_seq0"], 0, 2)

    def crosses(c):
        return (ipaddress.IPv4Address(c.src) in inside) != (ipaddress.IPv4Address(c.dst) in inside)

    down = None
    if cfg["reboot_at"] is not None:
        r_at = t_from + int(cfg["reboot_at"] * (t_to - t_from))
        down = (r_at, r_at + cfg["reboot_down_s"] * 1000)
        # no connection may have a record the core lost at the power cycle or straddle the
        # boot: nothing with a packet in the 25 s before it and nothing across its end
        keep = []
        for c in conns:
            f, l = c.first(), c.last()
            if l >= down[0] - 25_000 and f < down[0] + 2_000:
                continue
            if f < down[1] + 2_000 <= l or (f < down[1] - 2_000 and l >= down[1] - 2_000):
                continue
            keep.append(c)
        conns = keep

    def span(frac, secs):
        a = t_from + int(frac * (t_to - t_from))
        return (a, a + secs * 1000)

    lost_core = [span(*cfg["core_loss"])] + ([(down[1], down[1] + cfg["boot_loss_s"] * 1000)] if cfg.get("boot_loss_s") else [])
    lost_border = [span(*cfg["border_loss"])] if cfg["border_loss"] else []
    cuts_c = tuple(x for sp in lost_core for x in sp)
    cuts_b = tuple(x for sp in lost_border for x in sp)

    def pack_core(conns):
        if down:
            r1 = export(core, conns, lambda c: c.last() < down[0], rng)
            r2 = export(core, conns, lambda c: c.first() >= down[1], rng)
            return [d + (0,) for d in build_datagrams(core, r1, core.boot, core.seq, rng, cuts_c)] + \
                [d + (1,) for d in build_datagrams(core, r2, down[1] - 30_000, 0, rng, cuts_c)]
        return [d + (0,) for d in build_datagrams(core, export(core, conns, lambda c: True, rng), core.boot, core.seq, rng, cuts_c)]

    def in_span(dg, sps):
        return any(sp[0] <= dg[3] < sp[1] for sp in sps)

    # datagrams the collector never received: a span of the core's and a span of the border's.
    # A connection with a record in a dropped core datagram and another in a kept one would be
    # neither whole nor absent on the core, so those connections are removed. Membership of
    # the span is by the first record's expiry and the packer flushes at the span's edges, so
    # removing connections does not move any other record across the edge.
    for _ in range(4):
        c_dg = pack_core(conns)
        in_drop, in_keep = set(), set()
        for dg in c_dg:
            for key in record_keys(dg[2]):
                (in_drop if in_span(dg, lost_core) else in_keep).add(key)
        partial = in_drop & in_keep
        if not partial:
            break
        conns = [c for c in conns if (c.src, c.dst, c.sport, c.dport, c.proto) not in partial
                 and (c.dst, c.src, c.dport, c.sport, c.proto) not in partial]
    else:
        raise SystemExit("could not settle the dropped span")
    border_recs = export(border, conns, crosses, rng)
    b_dg = [d + (0,) for d in build_datagrams(border, border_recs, border.boot, border.seq, rng, cuts_b)]
    dropped_core = {i for i, dg in enumerate(c_dg) if in_span(dg, lost_core)}
    dropped_border = {i for i, dg in enumerate(b_dg) if in_span(dg, lost_border)}

    items = []   # (received_ms, exporter, bytes, note)
    for i, (at, rx, data, *_) in enumerate(b_dg):
        if i not in dropped_border:
            items.append((rx, bname, data, "orig"))
    for i, (at, rx, data, *_) in enumerate(c_dg):
        if i not in dropped_core:
            items.append((rx, cname, data, "orig"))
    items.sort(key=lambda it: (it[0], it[1]))

    # the collector restarted a few minutes after the window and re-sent what it had received
    # in the minutes before, so the copies cover the datagrams around the window's end
    if cfg["replay_back_min"]:
        s_at = t_to + cfg["replay_after_s"] * 1000
        replay = [it for it in items if s_at - cfg["replay_back_min"] * 60_000 <= it[0] < s_at]
        t = s_at + 3_000
        for rx, name, data, _ in replay:
            items.append((t, name, data, "replay"))
            t += rng.randint(1, 4)
        items.sort(key=lambda it: (it[0], it[1]))

    truth = {"conns": conns, "down": down, "lost_core": lost_core, "dropped_core": len(dropped_core),
                 "dropped_border": len(dropped_border), "c_dg": c_dg, "b_dg": b_dg,
                 "lost_core_flows": planted_lost(c_dg, dropped_core), "lost_border_flows": planted_lost(b_dg, dropped_border)}
    case = {"inside": cfg["inside"], "suspect": cfg["suspect"], "frm": t_from, "to": t_to, "exporters": list(cfg["exporters"])}
    return items, case, truth


def planted_lost(dgs, dropped):
    """Records in the dropped datagrams that lie between two kept ones of the same boot; a
    boot's datagrams are in sequence order, and those before its first kept one are not lost."""
    kept = defaultdict(list)
    for i, d in enumerate(dgs):
        if i not in dropped:
            kept[d[4]].append(i)
    return sum(HDR.unpack_from(dgs[i][2])[1] for i in dropped if kept[dgs[i][4]] and kept[dgs[i][4]][0] < i < kept[dgs[i][4]][-1])


def record_keys(data):
    n = HDR.unpack_from(data)[1]
    keys = set()
    for i in range(n):
        f = REC.unpack_from(data, HDR.size + i * REC.size)
        keys.add((str(ipaddress.IPv4Address(f[0])), str(ipaddress.IPv4Address(f[1])), f[9], f[10], f[13]))
    return keys


# ── the rule book ──────────────────────────────────────────────────────────────────────────

def rulebook(items, case, mis=None, want_conns=False):
    """The report SPEC.md's rules produce from the archive. `mis` is a set of misreadings for
    calibrate.py; the empty set is the golden."""
    mis = mis or set()
    inside = ipaddress.IPv4Network(case["inside"])
    suspect = case["suspect"]
    frm, to = case["frm"], case["to"]

    # 1. one copy of each datagram
    seen = {}
    if "no_dedup" in mis:
        distinct = [(rx, name, data) for rx, name, data, _ in items]
    else:
        for rx, name, data, _ in sorted(items, key=lambda it: it[0]):
            key = (name, HDR.unpack_from(data)[5]) if "seq_dedup" in mis else (name, data)
            if "keep_last" in mis or key not in seen:
                seen[key] = (rx, name, data)
        distinct = list(seen.values())

    # 2. each exporter's clock offset from arrival minus header, whole seconds
    per = defaultdict(list)
    for rx, name, data in distinct:
        per[name].append((rx, data))
    offset = {}
    for name, lst in per.items():
        if "raw_clock" in mis:
            offset[name] = 0
            continue
        vals = []
        for rx, data in lst:
            h = HDR.unpack_from(data)
            clock = h[3] * 1000 + h[4] // 1_000_000
            vals.append(round((clock - rx) / 1000))
        vals.sort()
        offset[name] = vals[len(vals) // 2]

    # 3. lost flows per exporter, boots separated
    lost = {}
    for name, lst in per.items():
        hs = []
        for rx, data in lst:
            h = HDR.unpack_from(data)
            hs.append((h[3] * 1000 + h[4] // 1_000_000, h[2], h[5], h[1]))
        hs.sort()
        boots = [[]]
        for i, h in enumerate(hs):
            # clock less uptime is the boot instant (the counter is 32-bit), one value per boot;
            # the sequence never wraps (no router exported 2^32 flows), so a fall is a boot too
            moved = abs((h[0] - h[1] - hs[i - 1][0] + hs[i - 1][1] + 2**31) % 2**32 - 2**31) > 1000 or h[2] < hs[i - 1][2]
            if "seq_decrease_only" in mis:
                moved = h[2] < hs[i - 1][2]
            if i and moved and "no_boot_split" not in mis:
                boots.append([])
            boots[-1].append(h)
        total = 0
        for b in boots:
            if "lost_from_zero" in mis:
                total += b[0][2]
            for i in range(1, len(b)):
                gap = b[i][2] - (b[i - 1][2] + b[i - 1][3])
                total += gap
        lost[name] = total

    # 4. records on the true clock
    recs = []
    for rx, name, data in distinct:
        h = HDR.unpack_from(data)
        clock = h[3] * 1000 + (0 if "secs_only" in mis else h[4] // 1_000_000)
        base = rx if "receipt_time" in mis else clock - offset[name] * 1000
        if "per_datagram_offset" in mis:
            base = clock - round((clock - rx) / 1000) * 1000
        n = (h[8] & 0x3FFF) if (h[8] >> 14) == 1 else 0
        for i in range(h[1]):
            f = REC.unpack_from(data, HDR.size + i * REC.size)
            if "no_wrap" in mis:
                start = base - (h[2] - f[7])
                end = base - (h[2] - f[8])
            else:
                start = base - ((h[2] - f[7]) & 0xFFFFFFFF)
                end = base - ((h[2] - f[8]) & 0xFFFFFFFF)
            if "last_as_start" in mis:
                start = end
            key = (f[0], f[1], f[9], f[10], f[13])
            recs.append((key, start, end, f[6], f[5], n, name))

    # 5. connections: one 5-tuple, records under five minutes apart
    by = defaultdict(list)
    for r in recs:
        by[r[0]].append(r)
    conns = []
    thr = REUSE_MS
    if "chain_15s" in mis:
        thr = INACTIVE_MS
    if "chain_60s" in mis:
        thr = ACTIVE_MS
    for key, lst in by.items():
        lst.sort(key=lambda r: (r[1], r[2], r[6]))
        cur = None
        for r in lst:
            if cur is not None:
                gap = r[1] - cur["end"]
                new = gap >= thr if "chain_le" not in mis else gap > thr
                if "tuple_only" in mis:
                    new = False
                if new:
                    conns.append(cur)
                    cur = None
            if cur is None:
                cur = {"key": key, "start": r[1], "end": r[2], "recs": []}
            cur["end"] = max(cur["end"], r[2])
            cur["start"] = min(cur["start"], r[1])
            cur["recs"].append(r)
        conns.append(cur)

    def conn_bytes(c):
        exact = [r for r in c["recs"] if r[5] == 0]
        sampled = [r for r in c["recs"] if r[5] > 0]
        if "sum_all" in mis:
            return sum(r[3] * (r[5] or 1) for r in c["recs"])
        if "prefer_sampled" in mis and sampled:
            return sum(r[3] * r[5] for r in sampled)
        if "core_only" in mis:
            return sum(r[3] for r in exact)
        if exact:
            return sum(r[3] for r in exact)
        if "no_scale" in mis:
            return sum(r[3] for r in sampled)
        return sum(r[3] * r[5] for r in sampled)

    def in_window(c):
        if "core_only" in mis and not any(r[5] == 0 for r in c["recs"]):
            return False
        if "window_any" in mis:
            return c["end"] >= frm and c["start"] < to
        if "window_end_inclusive" in mis:
            return frm <= c["start"] <= to
        return frm <= c["start"] < to

    outbound = defaultdict(lambda: [0, 0])
    lateral = {}
    for c in conns:
        src, dst = c["key"][0], c["key"][1]
        s_in = ipaddress.IPv4Address(src) in inside
        d_in = ipaddress.IPv4Address(dst) in inside
        if not in_window(c):
            continue
        if s_in and not d_in:
            o = outbound[src]
            o[0] += conn_bytes(c)
            o[1] += 1
        elif s_in and d_in and src == ip_int(suspect):
            l = lateral.setdefault(dst, {"first": c["start"], "bytes": 0, "connections": 0})
            l["first"] = min(l["first"], c["start"])
            l["bytes"] += conn_bytes(c)
            l["connections"] += 1
    rep = {
        "outbound": [{"host": str(ipaddress.IPv4Address(h)), "bytes": v[0], "connections": v[1]}
                     for h, v in sorted(outbound.items())],
        "lateral": [{"host": str(ipaddress.IPv4Address(h)), "first_ms": v["first"], "bytes": v["bytes"],
                     "connections": v["connections"]}
                    for h, v in sorted(lateral.items(), key=lambda kv: (kv[1]["first"], kv[0]))],
        "lost": {name: lost[name] for name in sorted(lost)},
    }
    return (rep, conns) if want_conns else rep


# ── coverage: what each set must carry, counted from the archive ──────────────────────────

def coverage(items, case, truth, cfg):
    """Counts the planted cases from the archive and the generator's bookkeeping, for the
    verifier's coverage checks and for the seed search."""
    rep = rulebook(items, case)
    tags = defaultdict(int)
    for c in truth["conns"]:
        if c.tag:
            tags[c.tag] += 1
    distinct = {}
    for rx, name, data, note in items:
        distinct.setdefault((name, data), []).append(note)
    dup = sum(1 for v in distinct.values() if len(v) > 1)
    # post-reboot core datagrams whose sequence collides with a pre-reboot one
    cname = cfg["exporters"][1]
    seqs = defaultdict(list)
    for (name, data), notes in distinct.items():
        if name == cname:
            h = HDR.unpack_from(data)
            seqs[h[5]].append(h[2])
    collide = sum(1 for v in seqs.values() if len(v) > 1)
    # boot boundaries on the core where the restarted sequence neither falls nor carries straight on
    hs = sorted((h[3] * 1000 + h[4] // 1_000_000, h[2], h[5], h[1]) for (name, data) in distinct if name == cname
                for h in [HDR.unpack_from(data)])
    rise = sum(1 for a, b in itertools.pairwise(hs) if abs((b[0] - b[1] - a[0] + a[1] + 2**31) % 2**32 - 2**31) > 1000
               and b[2] > a[2] + a[3])
    replayed_post = 0
    if truth["down"]:
        for (name, data), notes in distinct.items():
            h = HDR.unpack_from(data)
            if name == cname and len(notes) > 1 and h[2] < 3_600_000:
                replayed_post += 1
    # connections only the sampled router saw, inside the window, and how many of those have
    # two or more of its records fifteen seconds or more apart
    border_only = 0
    split = 0
    short_both = 0
    for c in rulebook_conns(items, case):
        if not (case["frm"] <= c["start"] < case["to"]):
            continue
        exs = {r[6] for r in c["recs"]}
        if exs == {cfg["exporters"][0]}:
            border_only += 1
            rs = sorted(c["recs"], key=lambda r: r[1])
            if any(rs[i][1] - rs[i - 1][2] >= INACTIVE_MS for i in range(1, len(rs))):
                split += 1
        if len(exs) == 2 and c["end"] - c["start"] < abs(cfg["offset_s"]) * 1000:
            short_both += 1
    wrapped = 0
    for (name, data), notes in distinct.items():
        h = HDR.unpack_from(data)
        for i in range(h[1]):
            f = REC.unpack_from(data, HDR.size + i * REC.size)
            if f[7] > h[2]:
                wrapped += 1
    return {
        "wrapped_records": wrapped,
        "tags": dict(tags), "duplicate_datagrams": dup, "seq_collisions": collide, "boot_seq_rise": rise, "replayed_post_reboot": replayed_post,
        "border_only_in_window": border_only, "sampled_split": split, "short_seen_by_both": short_both,
        "lost": rep["lost"], "lost_planted": {cfg["exporters"][0]: truth["lost_border_flows"], cfg["exporters"][1]: truth["lost_core_flows"]},
        "outbound_hosts": len(rep["outbound"]), "lateral_hosts": len(rep["lateral"]),
        "lateral_first_ties": sum(a["first_ms"] == b["first_ms"] for a, b in itertools.pairwise(rep["lateral"])),
        "datagrams": len(items), "distinct": len(distinct), "connections": len(truth["conns"]),
    }


def rulebook_conns(items, case):
    """The connections the rule book forms, for coverage counting."""
    return rulebook(items, case, want_conns=True)[1]


REQUIRED = {
    "duplicate_datagrams": lambda v, cfg: v >= (20 if cfg["replay_back_min"] else 0),
    "seq_collisions": lambda v, cfg: v >= (10 if cfg["reboot_at"] is not None and "boot_loss_s" not in cfg else 0),
    "boot_seq_rise": lambda v, cfg: v >= 1 if "boot_loss_s" in cfg else v == 0,
    "border_only_in_window": lambda v, cfg: v >= (6 if cfg["reboot_at"] is not None and cfg["n_pkt"] > 1 else 2),
    "sampled_split": lambda v, cfg: v >= (1 if cfg["reboot_at"] is not None and cfg["n_pkt"] > 1 else 0),
    "short_seen_by_both": lambda v, cfg: v >= 20,
    "wrapped_records": lambda v, cfg: v >= 3,
    "lateral_hosts": lambda v, cfg: (v >= 4) if not cfg.get("no_lateral") else v == 0,
    "lateral_first_ties": lambda v, cfg: v >= (1 if cfg.get("first_tie") else 0),
}


def satisfies(cov, cfg):
    for k, f in REQUIRED.items():
        if not f(cov[k], cfg):
            return False
    if cov["lost"] != cov["lost_planted"]:
        return False
    if cfg["border_loss"] and cov["lost"][cfg["exporters"][0]] <= 0:
        return False
    return cov["lost"][cfg["exporters"][1]] > 0


def build(name, seed=None):
    """One set from one seed: the first sub-seed whose draw carries every planted case."""
    cfg = SETS[name]
    base = cfg["seed"] if seed is None else seed
    for k in range(40):
        items, case, truth = simulate(cfg, base * 100 + k)
        cov = coverage(items, case, truth, cfg)
        if satisfies(cov, cfg):
            cov["sub_seed"] = k
            return items, case, truth, cov
    raise SystemExit(f"{name}: no sub-seed of {base} carries every case")


# ── files ──────────────────────────────────────────────────────────────────────────────────

def archive_bytes(items):
    out = bytearray()
    for rx, name, data, _ in items:
        nb = name.encode()
        out += struct.pack(">B", len(nb)) + nb + struct.pack(">QH", rx, len(data)) + data
    return bytes(out)


def case_line(case):
    return (f"CASE inside={case['inside']} suspect={case['suspect']} from={case['frm']} to={case['to']} "
            f"exporters={','.join(case['exporters'])}\n")


def write_set(root, name, items, case, rep):
    d = os.path.join(root, "tests", "data", name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "archive.bin"), "wb") as fh:
        fh.write(archive_bytes(items))
    with open(os.path.join(d, "case.txt"), "w") as fh:
        fh.write(case_line(case))
    os.makedirs(os.path.join(root, "tests", "golden"), exist_ok=True)
    with open(os.path.join(root, "tests", "golden", name + ".json"), "w") as fh:
        json.dump(rep, fh, separators=(",", ":"), sort_keys=True)
        fh.write("\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", metavar="ROOT")
    ap.add_argument("--set", choices=sorted(SETS))
    ap.add_argument("--seed", type=int)
    ap.add_argument("--coverage", action="store_true")
    args = ap.parse_args()
    if args.write:
        for name in ("sample", "hidden", "edge"):
            items, case, truth, cov = build(name)
            rep = rulebook(items, case)
            write_set(args.write, name, items, case, rep)
            if name == "sample":
                d = os.path.join(args.write, "environment", "archive", "sample")
                os.makedirs(d, exist_ok=True)
                with open(os.path.join(d, "archive.bin"), "wb") as fh:
                    fh.write(archive_bytes(items))
                with open(os.path.join(d, "case.txt"), "w") as fh:
                    fh.write(case_line(case))
            print(f"{name}: {len(items)} datagrams, {cov['distinct']} distinct, {len(truth['conns'])} connections, "
                  f"{len(rep['outbound'])} outbound hosts, {len(rep['lateral'])} lateral, lost {rep['lost']}, sub-seed {cov['sub_seed']}")
        return
    name = args.set or "sample"
    items, case, truth, cov = build(name, args.seed)
    if args.coverage:
        print(json.dumps(cov, indent=1, sort_keys=True))
    else:
        print(json.dumps(rulebook(items, case), sort_keys=True))


if __name__ == "__main__":
    main()
