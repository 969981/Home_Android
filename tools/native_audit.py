#!/usr/bin/env python3
"""Record real DEX/ELF/IL2CPP metadata headers, without claiming decompilation."""
from __future__ import annotations
import argparse
import json
import re
import struct
import subprocess
from pathlib import Path
from home import ROOT, dump, hash_file

DEX_FIELDS={"string_ids":56,"type_ids":64,"proto_ids":72,"field_ids":80,
            "method_ids":88,"class_defs":96}
EM={3:"x86",40:"ARM",62:"x86-64",183:"AArch64"}
def examine_dex(file: Path):
    with file.open("rb") as f:
        header=f.read(112)
    result={"path":str(file),"bytes":file.stat().st_size,"sha256":hash_file(file),
            "magic_hex":header[:8].hex(),"valid":False}
    if len(header)<112 or not header.startswith(b"dex"+bytes([10])):
        return result
    result["valid"]=True
    result["version"]=header[4:7].decode("ascii",errors="replace")
    result["header_file_size"]=struct.unpack_from("<I",header,32)[0]
    result["header_size"]=struct.unpack_from("<I",header,36)[0]
    for name,off in DEX_FIELDS.items():
        result[name]=struct.unpack_from("<I",header,off)[0]
    result["size_matches"]=result["header_file_size"]==file.stat().st_size
    return result

def examine_elf(file: Path):
    with file.open("rb") as f:
        h=f.read(64)
    result={"path":str(file),"bytes":file.stat().st_size,"sha256":hash_file(file),
            "magic_hex":h[:8].hex(),"valid":False}
    if len(h)<20 or h[:4]!=bytes.fromhex("7f454c46"):
        return result
    endian="<" if h[5]==1 else ">"
    machine=struct.unpack_from(endian+"H",h,18)[0]
    result.update(valid=True,bits=64 if h[4]==2 else 32,
                  machine=machine,architecture=EM.get(machine,f"unknown_{machine}"),
                  endian="little" if endian=="<" else "big")
    try:
        output=subprocess.run(["readelf","-n",str(file)],capture_output=True,text=True,timeout=20)
        m=re.search(r"Build ID:\s*([a-fA-F0-9]+)",output.stdout)
        if m:
            result["build_id"]=m.group(1)
    except (FileNotFoundError,subprocess.TimeoutExpired):
        result["build_id_status"]="readelf_not_available"
    return result

def examine_metadata(file: Path):
    with file.open("rb") as f:
        h=f.read(32)
    result={"path":str(file),"bytes":file.stat().st_size,"sha256":hash_file(file),
            "header_hex":h.hex(),"sanity_valid":False}
    if len(h)>=8:
        magic,version=struct.unpack_from("<II",h)
        result.update(magic=f"0x{magic:08x}",version=version,
                      sanity_valid=(magic==0xFAB11BAF))
    return result

def run(version,root,reports):
    dex=[examine_dex(p) for p in sorted(root.rglob("*.dex")) if p.is_file()]
    native=[examine_elf(p) for p in sorted(root.rglob("*.so")) if p.is_file()]
    meta=[examine_metadata(p) for p in sorted(root.rglob("global-metadata.dat")) if p.is_file()]
    def portable(records):
        for row in records:
            row["path"]=Path(row["path"]).relative_to(root).as_posix()
        return records
    report={"version":version,"dex":portable(dex),"elf":portable(native),
            "il2cpp_metadata":portable(meta),
            "dex_count":len(dex),"elf_count":len(native),
            "il2cpp_pair_present":any(p["path"].endswith("/libil2cpp.so") for p in native) and bool(meta),
            "scope":"Header and BuildID audit only; JADX/Cpp2IL/Ghidra decompilation not performed"}
    dump(reports/"native_summary.json",report)
    return report

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--version",default="4.1.0")
    p.add_argument("--input")
    p.add_argument("--report")
    a=p.parse_args()
    root=Path(a.input) if a.input else ROOT/"Unpack"/a.version/"apk/raw"
    report=Path(a.report) if a.report else ROOT/"reports"/a.version
    result=run(a.version,root,report)
    print(json.dumps({"version":a.version,"dex_count":result["dex_count"],"elf_count":result["elf_count"],
                      "il2cpp_pair_present":result["il2cpp_pair_present"]},indent=2))
