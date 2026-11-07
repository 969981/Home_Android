#!/usr/bin/env python3
"""Inspect IL2CPP metadata section pairs and exported ELF function symbols.

Symbol metadata is NOT reconstructed managed method body code.
"""
from __future__ import annotations
import argparse
import csv
import json
import re
import struct
import subprocess
from pathlib import Path
from home import ROOT, dump, write_rows, hash_file
SECTION_FIELDS=["index","offset","byte_count","end","within_file"]
SYMBOL_FIELDS=["address","size","kind","name"]

def run(version:str,root:Path,report:Path)->dict:
    meta=root/"assets/bin/Data/Managed/Metadata/global-metadata.dat"
    binary=root/"lib/arm64-v8a/libil2cpp.so"
    if not meta.is_file() or not binary.is_file():
        result={"version":version,"status":"il2cpp_pair_missing"}
        dump(report/"il2cpp_sections_summary.json",result)
        return result
    with meta.open("rb") as f: header=f.read(512)
    if len(header)<16:
        raise ValueError("IL2CPP header unexpectedly short")
    magic,ver=struct.unpack_from("<II",header)
    if magic!=0xFAB11BAF:
        raise ValueError("Invalid metadata magic")
    first_offset=struct.unpack_from("<I",header,8)[0]
    # The first segment offset provides a candidate header extent. Validate it:
    if first_offset<16 or first_offset>512 or first_offset%8:
        raise ValueError("IL2CPP first section offset out of expected bounds: "+str(first_offset))
    rows=[]
    file_size=meta.stat().st_size
    for idx,off in enumerate(range(8,first_offset,8)):
        offset,byte_count=struct.unpack_from("<II",header,off)
        rows.append({"index":idx,"offset":offset,"byte_count":byte_count,
                     "end":offset+byte_count,
                     "within_file":int(0<=offset<=file_size and offset+byte_count<=file_size)})
    write_rows(report/"il2cpp_sections.csv",rows,SECTION_FIELDS)
    symbols=[]
    sym_error=""
    try:
        p=subprocess.run(["readelf","--dyn-syms","--wide",str(binary)],
                         capture_output=True,text=True,timeout=45)
        if p.returncode:
            sym_error=p.stderr[-400:]
        else:
            # readelf output columns: Num: Value Size Type Bind Vis Ndx Name
            for line in p.stdout.splitlines():
                m=re.match(r"\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+FUNC\s+\w+\s+\w+\s+\S+\s+(\S+)",line)
                if m:
                    symbols.append({"address":"0x"+m.group(1),"size":int(m.group(2)),
                                    "kind":"dynamic_FUNC","name":m.group(3)})
    except (subprocess.TimeoutExpired,FileNotFoundError) as e:
        sym_error=str(e)
    write_rows(report/"il2cpp_dynamic_symbols.csv",symbols,SYMBOL_FIELDS)
    result={"version":version,"metadata_version":ver,"metadata_bytes":file_size,
            "metadata_sha256":hash_file(meta),"libil2cpp_sha256":hash_file(binary),
            "metadata_section_pairs":len(rows),
            "pairs_within_file":sum(int(r["within_file"]) for r in rows),
            "dynamic_function_symbols":len(symbols),"symbol_error":sym_error,
            "status":"headers_and_exports_inspected",
            "limitation":"Static metadata ranges/dynsym only; registration pointers and IL2CPP method addresses not yet recovered."}
    dump(report/"il2cpp_sections_summary.json",result)
    return result

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--version",default="4.1.0")
    p.add_argument("--input")
    p.add_argument("--report")
    a=p.parse_args()
    root=Path(a.input) if a.input else ROOT/"Unpack"/a.version/"apk/raw"
    report=Path(a.report) if a.report else ROOT/"reports"/a.version
    print(json.dumps(run(a.version,root,report),ensure_ascii=False,indent=2))
