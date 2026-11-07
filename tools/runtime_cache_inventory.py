#!/usr/bin/env python3
"""Inventory an explicitly supplied, sanitized asset-cache folder.

No network access, no app authentication, no attempt to bypass Android sandbox.
Only recognized standalone resource binary types can be copied.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import re
import shutil
from collections import Counter
from pathlib import Path
from home import dump, write_rows

FIELDS=["resource_id","name_hint","relative_source","size","sha256","kind",
        "status","stored_relative","reason"]
DENY_PARTS={"shared_prefs","databases","accounts","account","auth","token","tokens",
            "session","sessions","cookie","cookies","credential","credentials",
            "user","userdata","private","personal","keystore","login","logs",
            "crash","analytics","http","headers","oauth"}
MAGICS={
    "unity_bundle":(b"UnityFS",b"UnityWeb",b"UnityRaw"),
    "image_png":(bytes.fromhex("89504e470d0a1a0a"),),
    "image_jpeg":(bytes.fromhex("ffd8ff"),),
    "ktx2_texture":(bytes.fromhex("ab4b5458203230bb0d0a1a0a"),),
    "ktx_texture":(bytes.fromhex("ab4b5458203131bb0d0a1a0a"),),
    "audio_ogg":(b"OggS",),
    "audio_fsb5":(b"FSB5",),
    "audio_riff":(b"RIFF",),
    "model_glb":(b"glTF",),
}
EXTENSIONS={
    "unity_bundle":".bundle","unity_serialized_candidate":".assets",
    "image_png":".png","image_jpeg":".jpg",
    "ktx2_texture":".ktx2","ktx_texture":".ktx",
    "audio_ogg":".ogg","audio_fsb5":".fsb",
    "audio_riff":".riff","model_glb":".glb",
}

def detect(header:bytes)->str:
    for kind,signatures in MAGICS.items():
        if any(header.startswith(s) for s in signatures):
            return kind
    # SerializedFile type-tree and Unity 22+ extended header. Avoid recognizing
    # arbitrary all-zero files solely on extension.
    if (len(header)>=20 and header[:8]==bytes(8)
            and 16<=int.from_bytes(header[8:12],"big")<=31
            and header[12:20]==bytes(8)):
        return "unity_serialized_candidate"
    return "unrecognized"

def permitted_path(rel:Path)->bool:
    parts=[re.sub(r"[^a-z0-9]+","",p.lower()) for p in rel.parts]
    return not any(p in DENY_PARTS or p.startswith(("token","session","credential","account","oauth"))
                   for p in parts)

def sha256_file(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for buf in iter(lambda:f.read(1024*1024),b""):
            h.update(buf)
    return h.hexdigest()

def run(version:str,source:Path|None,report:Path,output:Path|None=None,
        max_mib:int=95,limit:int=100000)->dict:
    report.mkdir(parents=True,exist_ok=True)
    if source is None or not source.is_dir():
        summary={"version":version,"status":"runtime_cache_not_supplied",
                 "eligible_files":0,"copied_files":0,"note":"No device cache was provided. APK-only assets cannot prove full Pokemon species coverage."}
        dump(report/"runtime_inventory_summary.json",summary)
        write_rows(report/"runtime_inventory.csv",[],FIELDS)
        return summary
    source=source.resolve()
    if output and (output.resolve()==source or source in output.resolve().parents):
        raise ValueError("Output must be outside the source cache directory")
    rows=[]
    counts=Counter()
    paths=sorted(p for p in source.rglob("*") if p.is_file() and not p.is_symlink())
    if len(paths)>limit:
        raise ValueError(f"Too many files {len(paths)}; use a smaller sanitized source")
    for p in paths:
        rel=p.relative_to(source)
        if not permitted_path(rel):
            counts["excluded_sensitive_path"]+=1
            continue
        size=p.stat().st_size
        if size<16 or size>max_mib*1024*1024:
            counts["excluded_size"]+=1
            continue
        with p.open("rb") as f:
            magic=f.read(64)
        kind=detect(magic)
        if kind=="unrecognized":
            counts["unrecognized"]+=1
            continue
        digest=sha256_file(p)
        resource_id=digest[:20]
        # Name is used only as a weak semantic hint. Always keep the SHA
        # as identity, never trust user filenames as output paths.
        name_hint=p.name[:100]
        row={"resource_id":resource_id,"name_hint":name_hint,
             "relative_source":rel.as_posix(),"size":size,"sha256":digest,
             "kind":kind,"status":"identified_only","stored_relative":"","reason":""}
        if output:
            dest_rel=Path(kind)/(resource_id+EXTENSIONS[kind])
            dest=output/dest_rel
            dest.parent.mkdir(parents=True,exist_ok=True)
            if not dest.exists() or sha256_file(dest)!=digest:
                temporary=dest.with_suffix(dest.suffix+".partial")
                try:
                    shutil.copyfile(p,temporary)
                    if sha256_file(temporary)!=digest:
                        raise ValueError("SHA-256 copy verification failed")
                    temporary.replace(dest)
                finally:
                    temporary.unlink(missing_ok=True)
            row["stored_relative"]=dest_rel.as_posix()
            row["status"]="copied_and_verified"
            counts["copied_files"]+=1
        counts["eligible_files"]+=1
        counts["kind_"+kind]+=1
        rows.append(row)
    write_rows(report/"runtime_inventory.csv",rows,FIELDS)
    summary={"version":version,"status":"cache_scanned" if not output else "assets_copied",
             "eligible_files":counts["eligible_files"],"copied_files":counts["copied_files"],
             "by_type":dict(sorted((k[5:],v) for k,v in counts.items() if k.startswith("kind_"))),
             "excluded_sensitive_path":counts["excluded_sensitive_path"],
             "unrecognized":counts["unrecognized"],"excluded_size":counts["excluded_size"],
             "source_absolute_path_saved":False,
             "security":"Only files with known asset magic, no account/token paths or cache metadata; no Android sandbox bypass",
             "note":"Cache names/hashes alone cannot establish Pokemon species or that remote resources have all been downloaded."}
    dump(report/"runtime_inventory_summary.json",summary)
    return summary

if __name__=="__main__":
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--version",default="4.1.0")
    ap.add_argument("--cache-dir",type=Path,help="Previously exported, sanitized, authorized asset cache")
    ap.add_argument("--out",type=Path,help="Optional private resource output directory")
    ap.add_argument("--report",type=Path,help="Output CSV/JSON directory")
    ap.add_argument("--max-mib",type=int,default=95)
    args=ap.parse_args()
    from home import ROOT
    report=args.report or ROOT/"reports"/args.version
    print(json.dumps(run(args.version,args.cache_dir,report,args.out,args.max_mib),indent=2,ensure_ascii=False))
