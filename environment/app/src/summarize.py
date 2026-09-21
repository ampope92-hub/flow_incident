#!/usr/bin/env python3
"""Word-count summariser.

Usage: summarize.py --data <dir> --out <file>

NOTE (skeleton): this is the deliberately broken program the agent must fix.
Replace it with whatever your task ships. Three defects are planted here; see
solution/src/summarize.py for the corrected version.
"""

import argparse
import json
from pathlib import Path


def summarize(data_dir):
    entries = []
    for path in Path(data_dir).glob("*.txt"):
        entries.append({"name": path.name, "words": len(path.read_text().split())})
    # Defect 1: results are left in filesystem order instead of sorted by name.
    # Defect 2: total counts files rather than words.
    return {"files": entries, "total_words": len(entries)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    report = summarize(args.data)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    # Defect 3: no trailing newline.
    out.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
