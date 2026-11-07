#!/usr/bin/env python3
"""Read-only discovery and selective copy of an Android app's accessible asset files.

This tool DOES NOT attempt to enter app-private /data/user/0 directories,
elevate privileges, extract credentials or access any network service.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from runtime_cache_inventory import DENY_PARTS, EXTENSIONS, detect, permitted_path, sha256_file

PACKAGE="jp.pokemon.pokemonhome"
REMOTE_ROOT="/sdcard/Android/data/"+PACKAGE+"/files"
ALLOWED_EXT={".bundle",".unity3d",".assetbundle",".assets",".png",
             ".jpg",".jpeg",".ktx",".ktx2",".ogg",".fsb",".glb"}
MAX_SIZE=95*1024*1024

def safe_remote_path(remote:str)->Path|None:
    remote=remote.strip()
    if not remote.startswith(REMOTE_ROOT+"/"):
        return None
    relative=remote[len(REMOTE_ROOT)+1:]
    path=Path(relative)
    if (not relative or relative.startswith("/") or ".." in path.parts
            or not permitted_path(path)):
        return None
    basename=path.name.lower()
    if basename=="__data" or path.suffix.lower() in ALLOWED_EXT:
        return path
    return None

def adb(args:list[str],timeout:int=35)->subprocess.CompletedProcess:
    return subprocess.run(["adb",*args],capture_output=True,text=True,
                          encoding="utf-8",errors="replace",timeout=timeout)

def run(out:Path,pull:bool,limit:int=200,serial:str|None=None):
    pre=["-s",serial] if serial else []
    check=adb(pre+["shell","pm","path",PACKAGE])
    if check.returncode:
        raise SystemExit("App package not visible to adb: "+check.stderr[-250:])
    listing=adb(pre+["shell","find",REMOTE_ROOT,"-type","f"],timeout=60)
    if listing.returncode:
        return {"status":"external_files_unavailable","package_detected":True,
                "reason":"Android may restrict /sdcard/Android/data; no private sandbox bypass attempted",
                "stderr":listing.stderr[-300:],"selected_paths":0}
    candidates=[]
    for line in listing.stdout.splitlines():
        rel=safe_remote_path(line)
        if rel is not None:
            candidates.append((line,rel))
    candidates=sorted(set(candidates),key=lambda t:t[0])
    result={"status":"listed_only" if not pull else "copied",
            "package_detected":True,"selected_paths":len(candidates),
            "copied_valid_assets":0,"skipped_non_asset":0,"skipped_oversize":0,
            "limit":limit,
            "note":"Only accessible external app files; Unity's app-private temporaryCachePath is not included."}
    if not pull:return result
    out.mkdir(parents=True,exist_ok=True)
    # Never preserve raw remote data paths or account identifiers in filenames.
    for remote,relative in candidates[:limit]:
        with tempfile.TemporaryDirectory(prefix="home-cache-") as temp:
            tmp=Path(temp)/"candidate"
            p=adb(pre+["pull",remote,str(tmp)],timeout=120)
            if p.returncode or not tmp.is_file():
                result["skipped_non_asset"]+=1
                continue
            size=tmp.stat().st_size
            if size<16 or size>MAX_SIZE:
                result["skipped_oversize"]+=1
                continue
            with tmp.open("rb") as f:
                kind=detect(f.read(64))
            if kind=="unrecognized":
                result["skipped_non_asset"]+=1
                continue
            digest=sha256_file(tmp)
            # Stable content addressing + shortened harmless basename hint.
            hint=re.sub(r"[^a-z0-9_-]+","_",relative.stem.lower())[:40].strip("_")
            name=digest[:20]+("_"+hint if hint and hint!="data" else "")+EXTENSIONS[kind]
            dest=out/name
            if not dest.is_file() or sha256_file(dest)!=digest:
                shutil.copyfile(tmp,dest)
                if sha256_file(dest)!=digest:
                    dest.unlink(missing_ok=True)
                    raise ValueError("SHA-256 mismatch after cache copy")
            result["copied_valid_assets"]+=1
    return result

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out",type=Path,default=Path("home41_cache_export"))
    p.add_argument("--device",help="ADB serial when multiple devices connected")
    p.add_argument("--limit",type=int,default=200)
    p.add_argument("--pull",action="store_true",help="Opt in to pulling recognized resource files")
    a=p.parse_args()
    if a.limit<1 or a.limit>10000:
        p.error("--limit must be 1..10000")
    try:
        result=run(a.out,a.pull,a.limit,a.device)
    except FileNotFoundError:
        raise SystemExit("adb was not found; install Android SDK Platform-Tools and add adb to PATH")
    except subprocess.TimeoutExpired as e:
        raise SystemExit("ADB command timed out; no additional permissions requested")
    print(json.dumps(result,indent=2,ensure_ascii=False))
