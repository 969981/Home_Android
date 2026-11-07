#!/usr/bin/env python3
"""Losslessly export media already present as directly readable APK members."""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import shutil
from collections import Counter
from pathlib import Path

from home import ROOT, dump, hash_file, safe_relative, write_rows

KINDS={"image_png":"images","image_jpeg":"images","audio_candidate":"audio",
       "audio_ogg":"audio","text_or_data_candidate":"text"}
FIELDS=["source_path","kind","size","output_path","output_sha256","status","error"]

def run(version: str, raw_root: Path, reports: Path, output: Path):
    source=reports/"apk_entries.csv"
    if not source.exists():
        raise SystemExit("audit first: "+str(source))
    with source.open("r",encoding="utf-8-sig",newline="") as f:
        selected=[r for r in csv.DictReader(f) if r["kind"] in KINDS]
    rows=[]
    counter=Counter()
    for item in selected:
        rel=safe_relative(item["path"])
        src=raw_root/rel
        dest=output/"apk_raw"/KINDS[item["kind"]]/rel
        rec={"source_path":item["path"],"kind":item["kind"],
             "size":int(item["size"]),"output_path":"","output_sha256":"",
             "status":"","error":""}
        try:
            dest.parent.mkdir(parents=True,exist_ok=True)
            if not dest.exists() or dest.stat().st_size != src.stat().st_size or hash_file(dest) != hash_file(src):
                shutil.copyfile(src,dest)
            if src.stat().st_size != dest.stat().st_size or hash_file(src)!=hash_file(dest):
                raise ValueError("Bytes differ after copy")
            rec["output_path"]=dest.relative_to(ROOT).as_posix() if dest.is_relative_to(ROOT) else str(dest)
            rec["output_sha256"]=hash_file(dest)
            rec["status"]="verified_copy"
            counter[item["kind"]]+=1
        except Exception as exc:
            rec["status"]="failed"
            rec["error"]=str(exc)[:250]
            counter["failed"]+=1
        rows.append(rec)
    write_rows(reports/"raw_assets.csv",rows,FIELDS)
    info={"version":version,"selected":len(selected),"verified":sum(r["status"]=="verified_copy" for r in rows),
          "by_kind":dict(counter),"status":"ok" if not counter["failed"] else "partial",
          "note":"No format conversion; all exported files are byte-identical copies of APK ZIP members."}
    dump(reports/"raw_assets_summary.json",info)
    return info

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--version",default="4.1.0")
    p.add_argument("--input")
    p.add_argument("--report")
    p.add_argument("--out")
    a=p.parse_args()
    root=Path(a.input) if a.input else ROOT/"Unpack"/a.version/"apk/raw"
    reports=Path(a.report) if a.report else ROOT/"reports"/a.version
    output=Path(a.out) if a.out else ROOT/"resources"/a.version
    print(json.dumps(run(a.version,root,reports,output),ensure_ascii=False,indent=2))
