#!/usr/bin/env python3
"""Measures how far each misreading of the archive lands from the rule book's report.

    calibrate.py [--seeds 8] [--sets sample,hidden,edge]

For every set the shipped draw and N fresh seeds are built with generate_archive.py, the rule
book produces the report, and then each misreading below is switched on alone (the
`keep_last_copy` one is two readings that only bite together) and the number of report fields
it gets wrong is counted: an outbound row, a lateral row or a lost count that differs from or
is missing from the rule book's. The grade is exact equality on all three sets at once, so a
route is separated when its minimum over every seed of the sets that carry its case is at
least one.
"""
import argparse
import json
import sys
from multiprocessing import Pool

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import generate_archive as g

ROUTES = {
    "raw_clock": ({"raw_clock"}, "every record on the exporter's own clock, no correction"),
    "receipt_time": ({"receipt_time"}, "record times taken from the collector's arrival stamp instead of the header"),
    "keep_last_copy": ({"keep_last", "per_datagram_offset"}, "duplicates resolved by the later copy, the clock read per datagram"),
    "seq_dedup": ({"seq_dedup"}, "duplicates keyed on exporter and flow sequence"),
    "no_dedup": ({"no_dedup"}, "re-sent datagrams counted again"),
    "sum_all": ({"sum_all"}, "both exporters' counts added for a connection they both saw"),
    "prefer_sampled": ({"prefer_sampled"}, "the sampled exporter's scaled count taken where it saw the connection"),
    "no_scale": ({"no_scale"}, "sampled counts not multiplied by the sampling interval"),
    "core_only": ({"core_only"}, "the sampled exporter ignored altogether"),
    "chain_15s": ({"chain_15s"}, "records of a 5-tuple 15 s or more apart taken as another connection"),
    "chain_60s": ({"chain_60s"}, "records of a 5-tuple 60 s or more apart taken as another connection"),
    "chain_le": ({"chain_le"}, "records exactly five minutes apart merged"),
    "tuple_only": ({"tuple_only"}, "every record of a 5-tuple merged whatever the gap"),
    "window_any": ({"window_any"}, "a connection counted when any of it overlaps the window"),
    "window_end_inclusive": ({"window_end_inclusive"}, "a connection starting exactly at the window's end counted"),
    "no_boot_split": ({"no_boot_split"}, "lost flows counted across the power cycle as one sequence"),
    "lost_from_zero": ({"lost_from_zero"}, "flows before the first archived datagram counted as lost"),
    "secs_only": ({"secs_only"}, "the header's nanoseconds ignored"),
    "last_as_start": ({"last_as_start"}, "a record's Last taken as its start"),
    "no_wrap": ({"no_wrap"}, "the 32-bit uptime counter subtracted without wrapping"),
}


def diff(a, b):
    n = 0
    ra = {r["host"]: r for r in a["outbound"]}
    rb = {r["host"]: r for r in b["outbound"]}
    n += sum(1 for h in set(ra) | set(rb) if ra.get(h) != rb.get(h))
    la = {r["host"]: r for r in a["lateral"]}
    lb = {r["host"]: r for r in b["lateral"]}
    n += sum(1 for h in set(la) | set(lb) if la.get(h) != lb.get(h))
    n += sum(1 for k in set(a["lost"]) | set(b["lost"]) if a["lost"].get(k) != b["lost"].get(k))
    return n


def one(job):
    name, seed = job
    items, case, _truth, _cov = g.build(name, seed)
    gold = g.rulebook(items, case)
    out = {}
    for route, (mis, _) in ROUTES.items():
        out[route] = diff(gold, g.rulebook(items, case, mis))
    out["_lateral_rows"] = len(gold["lateral"])
    out["_outbound_rows"] = len(gold["outbound"])
    return name, seed, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=8)
    ap.add_argument("--sets", default="sample,hidden,edge")
    ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args()
    sets = args.sets.split(",")
    jobs = []
    for name in sets:
        jobs.append((name, None))
        for k in range(args.seeds):
            jobs.append((name, 7_000 + 13 * k + len(name)))
    with Pool(args.jobs) as pool:
        results = pool.map(one, jobs)
    table = {}
    for name, seed, out in results:
        table.setdefault(name, []).append((seed, out))
    print(f"{'route':22s} " + " ".join(f"{n:>8s}" for n in sets) + "   worst seed (min over seeds per set)")
    for route, (_, why) in ROUTES.items():
        shipped = [table[n][0][1][route] for n in sets]
        mins = [min(o[route] for _, o in table[n]) for n in sets]
        print(f"{route:22s} " + " ".join(f"{v:8d}" for v in shipped) + "   " + " ".join(f"{v:8d}" for v in mins) + f"   {why}")
    print()
    for n in sets:
        print(f"{n}: lateral rows on the shipped draw {table[n][0][1]['_lateral_rows']}, outbound rows {table[n][0][1]['_outbound_rows']}; "
              f"seeds {[s for s, _ in table[n][1:]]}")
    print(json.dumps({n: {r: [o[r] for _, o in table[n]] for r in ROUTES} for n in sets}))


if __name__ == "__main__":
    main()
