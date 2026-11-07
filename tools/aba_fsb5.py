#!/usr/bin/env python3
"""Validated FSB5 carving from four .aba candidates, without decoding the ABA wrapper."""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path
from home import ROOT, dump, hash_file, write_rows

FIELDS=["aba_path","fsb_offset","fsb_version","sample_count","codec",
        "header_bytes","sample_headers_bytes","names_bytes","sample_data_bytes",
        "fsb_bytes","remaining_wrapper_bytes","output_path","sha256","status","error"]

def inspect_embedded(blob: bytes, pos: int):
    if pos<0 or pos+64>len(blob) or blob[pos:pos+4]!=b"FSB5":
        raise ValueError("No complete FSB5 header at offset")
    version,samples,sh,names,data,codec=struct.unpack_from("<6I",blob,pos+4)
    if version not in (0,1):
        raise ValueError("Unsupported FSB version "+str(version))
    if not (0<samples<=50000):
        raise ValueError("Unreasonable sample count")
    base=60 if version==1 else 64
    total=base+sh+names+data
    if sh<8 or sh>len(blob) or names>len(blob) or data==0:
        raise ValueError("Invalid FSB5 sample/name/data header sizes")
    if total>len(blob)-pos:
        raise ValueError("Truncated embedded FSB5; total exceeds wrapper tail")
    return {"fsb_version":version,"sample_count":samples,"codec":codec,
            "header_bytes":base,"sample_headers_bytes":sh,"names_bytes":names,
            "sample_data_bytes":data,"fsb_bytes":total,
            "remaining_wrapper_bytes":len(blob)-pos-total}

def run(version:str,root:Path,report:Path,out:Path|None=None):
    rows=[]
    for file in sorted(root.rglob("*.aba")):
        if not file.is_file() or file.is_symlink(): continue
        blob=file.read_bytes()
        pos=blob.find(b"FSB5")
        row={"aba_path":file.relative_to(root).as_posix(),"fsb_offset":pos,
             "output_path":"","sha256":"","status":"","error":""}
        if pos<0:
            row.update(status="no_fsb5_signature")
        else:
            try:
                header=inspect_embedded(blob,pos)
                row.update(header)
                row["status"]="validated_embedded_header"
                if out:
                    dest=out/"audio"/"aba_embedded"/(file.stem+".fsb")
                    dest.parent.mkdir(parents=True,exist_ok=True)
                    dest.write_bytes(blob[pos:pos+header["fsb_bytes"]])
                    if dest.stat().st_size!=header["fsb_bytes"]:
                        raise IOError("Carved FSB size mismatch")
                    row["output_path"]=dest.relative_to(ROOT).as_posix() if dest.is_relative_to(ROOT) else str(dest)
                    row["sha256"]=hash_file(dest)
                    row["status"]="fsb5_carved"
            except Exception as e:
                row.update(status="not_validated",error=str(e)[:250])
        rows.append(row)
    write_rows(report/"aba_fsb5_records.csv",rows,FIELDS)
    result={"version":version,"aba_files":len(rows),"fsb_magic_found":sum(r["fsb_offset"]>=0 for r in rows),
            "validated_fsb_headers":sum(r["status"] in ("validated_embedded_header","fsb5_carved") for r in rows),
            "fsb_carved":sum(r["status"]=="fsb5_carved" for r in rows),
            "failed_validation":sum(r["status"]=="not_validated" for r in rows),
            "scope":"Embedded FSB5 container only, not decrypted .aba wrapper or decoded audio samples"}
    dump(report/"aba_fsb5_summary.json",result)
    return result

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--version",default="4.1.0")
    p.add_argument("--input")
    p.add_argument("--report")
    p.add_argument("--out")
    a=p.parse_args()
    root=Path(a.input) if a.input else ROOT/"Unpack"/a.version/"apk/raw"
    report=Path(a.report) if a.report else ROOT/"reports"/a.version
    out=Path(a.out) if a.out else None
    print(json.dumps(run(a.version,root,report,out),ensure_ascii=False,indent=2))
