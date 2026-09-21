#!/usr/bin/env python3
"""Word-count summariser (reference implementation)."""

import argparse
import json
from pathlib import Path


def summarize(data_dir):
    entries = []
    for path in sorted(Path(data_dir).glob("*.txt"), key=lambda p: p.name):
        entries.append({"name": path.name, "words": len(path.read_text().split())})
    return {"files": entries, "total_words": sum(e["words"] for e in entries)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    report = summarize(args.data)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
