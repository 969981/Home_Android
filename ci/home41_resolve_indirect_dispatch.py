#!/usr/bin/env python3
"""Offline map observed HOME 4.1.0 BLR X8 in-module RVAs to IL2CppDumper names.

Inputs:
* A locally obtained ORIGINAL 4.1.0 IL2CppDumper script.json.
* The REDACTED output of ci/home41_arm64_auth_timeline.py.

The script does not read account contents, contact any server, launch Android,
use Frida, register guests, or copy the original timeline into its output.

Index association rules:
* Exact Address == RVA: method ENTRY identity candidate from the dump.
* Between two method addresses: names are proximity hints ONLY. They are not
  verified owning functions and are NEVER automatically treated as owners.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

MAX_METHOD_INDEX_BYTES = 250_000_000
MAX_LOCAL_REPORT_BYTES = 5_000_000
MAX_RVAS = 16
MAX_NAMES_PER_ADDRESS = 6
MAX_NAME_CHARS = 280
SAFE_RVA = re.compile(r"^0x[0-9A-Fa-f]{1,8}$")


def parse_script_index(raw: object) -> tuple[list[int], dict[int,list[str]]]:
    entries = raw.get("ScriptMethod") if isinstance(raw,dict) else None
    if not isinstance(entries,list):
        raise ValueError("missing_ScriptMethod")
    mapping=defaultdict(list)
    for rec in entries:
        if not isinstance(rec,dict):
            continue
        name, addr=rec.get("Name"),rec.get("Address")
        if (not isinstance(name,str) or not (0<len(name)<=MAX_NAME_CHARS)
                or any(ord(c)<32 or ord(c)>=127 for c in name)):
            continue
        try:
            value=int(addr,0) if isinstance(addr,str) else int(addr)
        except (ValueError,TypeError):
            continue
        if not 0 < value < 0x40000000:
            continue
        found=mapping[value]
        if name not in found and len(found)<MAX_NAMES_PER_ADDRESS:
            found.append(name)
    return sorted(mapping), dict(mapping)


def extract_observed_rvas(report: object) -> list[int]:
    if not isinstance(report,dict):
        return []
    chain=report.get("guest_chain_diagnosis")
    entries=(chain.get("indirect_dispatch_module_relative_target_rvas")
             if isinstance(chain,dict) else None)
    if not isinstance(entries,list):
        return []
    normalized=[]
    for item in entries[:MAX_RVAS]:
        if not isinstance(item,str) or not SAFE_RVA.fullmatch(item):
            continue
        candidate=int(item,16)
        if not 0 <= candidate < 0x40000000:
            continue
        if candidate not in normalized:
            normalized.append(candidate)
    return normalized


def resolve_index(
    addresses: list[int],
    methods: dict[int,list[str]],
    rvas: list[int],
) -> dict:
    results=[]
    for rva in rvas[:MAX_RVAS]:
        if type(rva) is not int or not 0<=rva<0x40000000:
            continue
        idx=bisect.bisect_left(addresses,rva)
        exact=idx<len(addresses) and addresses[idx]==rva
        preceding=addresses[idx-1] if idx>0 else None
        following=addresses[idx] if idx<len(addresses) else None
        # Never infer a function's extent from the next method Address.
        results.append({
            "observed_dispatch_target_rva":f"0x{rva:X}",
            "exact_method_entry_in_index":exact,
            "exact_method_names":methods.get(rva,[]) if exact else [],
            "nearest_preceding_method_entry":(
                {"rva":f"0x{preceding:X}",
                 "names":methods[preceding],
                 "byte_distance":rva-preceding}
                if not exact and preceding is not None else None),
            "next_indexed_method_entry":(
                {"rva":f"0x{following:X}", "names":methods[following]}
                if not exact and following is not None else None),
            "non_exact_function_ownership_verified":False,
            "runtime_target_execution_verified_by_index_alone":False,
        })
    return {
        "status":"offline_original_method_index_cross_reference",
        "observed_indirect_dispatch_targets":len(results),
        "resolved_code_targets":results,
        "source_method_index_hash_verified_against_original":False,
        "same_registration_transaction_verified":False,
        "server_guest_registration_verified":False,
        "real_six_digit_home_id_verified":False,
        "raw_account_data_exported":False,
    }


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--script",type=Path,required=True,
                   help="Original HOME 4.1.0 IL2CppDumper script.json")
    p.add_argument("--timeline",type=Path,required=True,
                   help="Redacted private HOME timeline JSON (not raw Frida logs)")
    p.add_argument("--output",type=Path,required=True,
                   help="Local output containing only code names and normalized RVAs")
    args=p.parse_args()
    if not args.script.is_file() or args.script.stat().st_size>MAX_METHOD_INDEX_BYTES:
        raise SystemExit("original_method_index_missing_or_too_large")
    if not args.timeline.is_file() or args.timeline.stat().st_size>MAX_LOCAL_REPORT_BYTES:
        raise SystemExit("redacted_timeline_missing_or_too_large")
    report=json.loads(args.timeline.read_text(encoding="utf8"))
    targets=extract_observed_rvas(report)
    if targets:
        addresses,methods=parse_script_index(
            json.loads(args.script.read_text(encoding="utf-8-sig")))
        result=resolve_index(addresses,methods,targets)
        result["indexed_method_entry_addresses"]=len(addresses)
        result["index_file_sha256"]=hashlib.sha256(
            args.script.read_bytes()).hexdigest()
    else:
        result=resolve_index([],{},[])
        result["status"]="no_verified_in_module_dispatch_rvas_in_redacted_report"
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(
        json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True)+"\n",
        encoding="utf8")
    print(json.dumps({
        "status":result["status"],
        "observed_indirect_dispatch_targets":
            result["observed_indirect_dispatch_targets"],
        "raw_account_data_exported":False,
    },sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
