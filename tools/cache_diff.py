#!/usr/bin/env python3
"""Compare filesystem cache inventory to APK entries without collecting account data.

Use only a sanitized app asset/cache directory supplied explicitly by the user.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
from pathlib import Path
from home import ROOT, dump

def run(version:str,report:Path,cache:Path|None)->dict:
    apk=report/"apk_entries.csv"
    if not apk.exists(): raise SystemExit("Audit APK first")
    with apk.open("r",newline="",encoding="utf-8-sig") as f:
        apk_paths={r["path"]:int(r["size"]) for r in csv.DictReader(f)}
    if cache is None or not cache.is_dir():
        data={"version":version,"status":"no_runtime_cache_input",
              "apk_file_count":len(apk_paths),"cache_files":None,
              "scope":"Only local APK is available; no online CDN or device cache claimed.",
              "help":"Pass --cache to a sanitized local directory that contains no accounts, tokens or personal data."}
        dump(report/"runtime_cache_diff.json",data)
        return data
    cache_files=[p for p in sorted(cache.rglob("*")) if p.is_file() and not p.is_symlink()]
    if len(cache_files)>100000: raise ValueError("Refusing to scan >100000 cache files")
    entries=[]
    for p in cache_files:
        rel=p.relative_to(cache).as_posix()
        if any(t in rel.lower() for t in ("token","account","auth","session","cookie","credential")):
            continue
        size=p.stat().st_size
        entries.append({"path":rel,"size":size,"apk_same_path":rel in apk_paths,
                        "apk_same_size":bool(rel in apk_paths and apk_paths[rel]==size)})
    data={"version":version,"status":"cache_inventory_compared",
          "apk_file_count":len(apk_paths),"cache_files_count":len(entries),
          "same_relative_paths":sum(x["apk_same_path"] for x in entries),
          "same_path_and_size":sum(x["apk_same_size"] for x in entries),
          "cache_only":sum(not x["apk_same_path"] for x in entries),
          "scope":"Path and size comparison only; no binary files or private credentials copied",
          "examples":entries[:30]}
    dump(report/"runtime_cache_diff.json",data)
    return data

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--version",default="4.1.0")
    p.add_argument("--cache")
    p.add_argument("--report")
    a=p.parse_args()
    report=Path(a.report) if a.report else ROOT/"reports"/a.version
    print(json.dumps(run(a.version,report,Path(a.cache) if a.cache else None),ensure_ascii=False,indent=2))
