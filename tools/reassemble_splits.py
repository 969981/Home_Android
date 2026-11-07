#!/usr/bin/env python3
"""Reconstruct Unity *.assets.splitN streams in numeric order, never editing APK raw."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

from home import ROOT, dump

SPLIT = re.compile(r"^(.*)\.split(\d+)$", re.IGNORECASE)

def run(version: str, inp: Path, out: Path, report: Path) -> dict:
    groups: dict[str, list[tuple[int,Path]]] = defaultdict(list)
    for file in inp.rglob("*"):
        if not file.is_file() or file.is_symlink():
            continue
        rel = file.relative_to(inp).as_posix()
        match = SPLIT.fullmatch(rel)
        if match:
            groups[match.group(1)].append((int(match.group(2)),file))
    records=[]
    for name, chunks in sorted(groups.items()):
        chunks.sort(key=lambda pair: pair[0])
        indices=[x[0] for x in chunks]
        row={"source_prefix":name,"parts":len(chunks),"bytes":0,"sha256":"",
             "status":"","output_path":"","error":""}
        if indices != list(range(len(chunks))):
            row["status"]="incomplete"
            row["error"]="Expected contiguous parts 0..N; got "+str(indices)
            records.append(row)
            continue
        dest=out / name
        dest.parent.mkdir(parents=True,exist_ok=True)
        tmp=dest.with_name(dest.name+".partial")
        h=hashlib.sha256()
        total=0
        try:
            with tmp.open("wb") as output:
                for _,source in chunks:
                    with source.open("rb") as f:
                        for buf in iter(lambda:f.read(1024*1024),b""):
                            output.write(buf)
                            h.update(buf)
                            total+=len(buf)
            tmp.replace(dest)
            row.update(bytes=total,sha256=h.hexdigest(),status="reassembled",
                       output_path=dest.relative_to(ROOT).as_posix() if dest.is_relative_to(ROOT) else str(dest))
        except Exception as exc:
            tmp.unlink(missing_ok=True)
            row.update(status="failed",error=str(exc))
        records.append(row)
    summary={"version":version,"groups":len(groups),"split_files":sum(len(c) for c in groups.values()),
             "reassembled":sum(r["status"]=="reassembled" for r in records),
             "failed":sum(r["status"]!="reassembled" for r in records),
             "outputs":records,
             "note":"Output is a derived file. Raw APK extracted split chunks are unchanged."}
    dump(report/"reassembly_summary.json",summary)
    return summary

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--version",default="4.1.0")
    p.add_argument("--input")
    p.add_argument("--out")
    p.add_argument("--report")
    a=p.parse_args()
    input=Path(a.input) if a.input else ROOT/"Unpack"/a.version/"apk/raw"
    out=Path(a.out) if a.out else ROOT/"Unpack"/a.version/"unity/reassembled"
    report=Path(a.report) if a.report else ROOT/"reports"/a.version
    print(json.dumps(run(a.version,input,out,report),ensure_ascii=False,indent=2))
