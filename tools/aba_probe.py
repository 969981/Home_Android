#!/usr/bin/env python3
"""Evidence-only inspection of uncommon Android .aba resource containers."""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from home import ROOT, dump, write_rows

COLUMNS=["path","bytes","sha256","head64_hex","tail16_hex",
         "sample_entropy_bits_per_byte","unityfs_offset","ogg_offset","fsb5_offset",
         "riff_offset","png_offset"]
MAGICS={"unityfs":b"UnityFS","ogg":b"OggS","fsb5":b"FSB5",
        "riff":b"RIFF","png":bytes.fromhex("89504e470d0a1a0a")}

def entropy(data: bytes)->float:
    if not data:
        return 0.0
    hist=Counter(data)
    return round(-sum((n/len(data))*math.log2(n/len(data)) for n in hist.values()),5)

def inspect(path:Path,base:Path)->dict:
    # All known examples are under 2 MiB. Keep a hard cap to avoid opening
    # arbitrary user-supplied archives or decompression bombs as full bytes.
    if path.stat().st_size>64*1024*1024:
        raise ValueError("ABA exceeds 64 MiB inspection cap: "+str(path))
    data=path.read_bytes()
    row={"path":path.relative_to(base).as_posix(),"bytes":len(data),
         "sha256":hashlib.sha256(data).hexdigest(),
         "head64_hex":data[:64].hex(),"tail16_hex":data[-16:].hex(),
         "sample_entropy_bits_per_byte":entropy(data[:min(len(data),1024*1024)])}
    for label,signature in MAGICS.items():
        row[label+"_offset"]=data.find(signature)
    return row

def run(version:str,root:Path,report:Path)->dict:
    paths=sorted(p for p in root.rglob("*.aba") if p.is_file() and not p.is_symlink())
    rows=[inspect(p,root) for p in paths]
    write_rows(report/"aba_headers.csv",rows,COLUMNS)
    first=bytes.fromhex(rows[0]["head64_hex"]) if rows else b""
    others=[bytes.fromhex(row["head64_hex"]) for row in rows]
    common=0
    if others:
        for i in range(min(map(len,others))):
            if all(b[i]==first[i] for b in others): common+=1
            else: break
    result={"version":version,"files":len(rows),"total_bytes":sum(r["bytes"] for r in rows),
            "common_prefix_bytes":common,"shared_header_hex":first[:common].hex(),
            "embedded_known_signature_files":{
                name:sum(r[name+"_offset"]>=0 for r in rows) for name in MAGICS},
            "avg_sample_entropy":round(sum(r["sample_entropy_bits_per_byte"] for r in rows)/len(rows),5) if rows else None,
            "status":"header_inspected_not_decompressed",
            "warning":"Shared header or entropy alone does not prove encryption or compression."}
    dump(report/"aba_summary.json",result)
    return result

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--version",default="4.1.0")
    parser.add_argument("--input")
    parser.add_argument("--report")
    a=parser.parse_args()
    root=Path(a.input) if a.input else ROOT/"Unpack"/a.version/"apk/raw"
    report=Path(a.report) if a.report else ROOT/"reports"/a.version
    print(json.dumps(run(a.version,root,report),ensure_ascii=False,indent=2))
