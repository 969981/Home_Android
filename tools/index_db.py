#!/usr/bin/env python3
"""Build a source-linked SQLite inventory from audit and Unity export reports."""
from __future__ import annotations
import argparse
import csv
import json
import sqlite3
from pathlib import Path
from home import ROOT, dump

def import_csv(con, table, csvpath, columns):
    if not csvpath.exists():
        return 0
    with csvpath.open("r", encoding="utf-8-sig", newline="") as f:
        reader=csv.DictReader(f)
        rows=[tuple(row.get(c,"") for c in columns) for row in reader]
    placeholders=", ".join(["?"]*len(columns))
    con.executemany(f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders})", rows)
    return len(rows)

def build(version, report, target):
    report.mkdir(parents=True, exist_ok=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.unlink()  # deterministic regeneration from CSV inputs
    con=sqlite3.connect(target)
    try:
        con.executescript("""
            PRAGMA journal_mode=DELETE;
            CREATE TABLE apk_files (
                path TEXT PRIMARY KEY, size INTEGER, compressed_size INTEGER,
                crc32 TEXT, kind TEXT, magic_hex TEXT
            );
            CREATE INDEX apk_files_kind ON apk_files(kind);
            CREATE TABLE unity_objects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_path TEXT NOT NULL, source_bytes INTEGER, path_id TEXT, type TEXT,
                name TEXT, output_path TEXT, output_sha256 TEXT, status TEXT,
                error TEXT, tool_version TEXT
            );
            CREATE INDEX unity_objects_source ON unity_objects(source_path, path_id);
            CREATE INDEX unity_objects_type ON unity_objects(type, status);
        """)
        n1=import_csv(con,"apk_files",report/"apk_entries.csv",
                      ["path","size","compressed_size","crc32","kind","magic_hex"])
        n2=import_csv(con,"unity_objects",report/"unity_objects.csv",
                      ["source_path","source_bytes","path_id","type","name","output_path",
                       "output_sha256","status","error","tool_version"])
        con.commit()
        sanity=con.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        con.close()
    info=dict(version=version,apk_files=n1,unity_objects=n2,
              integrity_check=sanity,database=str(target),status="ok" if sanity=="ok" else "failed")
    dump(report/"index_summary.json",info)
    if sanity!="ok":
        raise RuntimeError("SQLite integrity check failed")
    return info

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--version",default="4.1.0")
    p.add_argument("--report")
    p.add_argument("--out")
    a=p.parse_args()
    report=Path(a.report) if a.report else ROOT/"reports"/a.version
    target=Path(a.out) if a.out else report/"resources.sqlite"
    print(json.dumps(build(a.version,report,target),ensure_ascii=False,indent=2))
