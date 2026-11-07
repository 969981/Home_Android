#!/usr/bin/env python3
"""Summarize actual Unity export failures from the detailed objects CSV."""
from __future__ import annotations
import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from home import ROOT, dump, write_rows

FIELDS=["source_path","source_bytes","path_id","type","name","output_path",
        "output_sha256","status","error","tool_version"]

def run(version,report):
    source=report/"unity_objects.csv"
    if not source.exists():
        raise SystemExit("Need unity_objects.csv from unity_export.py first")
    with source.open("r",encoding="utf-8-sig",newline="") as f:
        rows=[r for r in csv.DictReader(f) if r["status"] in
              {"parse_failed","export_failed","skipped_too_large","unresolved_texture_stream"}]
    write_rows(report/"unity_failures.csv",rows,FIELDS)
    summary={"version":version,"total_failures_or_skips":len(rows),
             "by_status":dict(Counter(r["status"] for r in rows)),
             "by_type":dict(Counter(r["type"] for r in rows)),
             "examples":[{"source_path":r["source_path"],"path_id":r["path_id"],
                          "type":r["type"],"name":r["name"],"error":r["error"][:250]}
                         for r in rows[:30]]}
    dump(report/"unity_failures_summary.json",summary)
    return summary

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--version",default="4.1.0")
    p.add_argument("--report")
    a=p.parse_args()
    report=Path(a.report) if a.report else ROOT/"reports"/a.version
    print(json.dumps(run(a.version,report),ensure_ascii=False,indent=2))
