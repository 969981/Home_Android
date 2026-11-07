#!/usr/bin/env python3
"""Find resource-loading method name candidates in private IL2CppDumper script.json."""
from __future__ import annotations
import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from home import dump, write_rows

TOKENS=(
  "assetbundle","assetcache","caching.","cachedassetbundle","unitywebrequestasset",
  "addressable","loadasset","downloadasset","modelviewer","pokemonmodel",
  "monster","species","formid","characterasset","pokemodel","texture2d",
)
COLUMNS=["source","method_name","method_address","matched_terms","confidence"]
def run(path:Path|None,report:Path,max_results=5000):
    report.mkdir(parents=True,exist_ok=True)
    if path is None or not path.is_file():
        result={"status":"il2cpp_script_not_supplied","method_rows_scanned":0,"hits":0}
        dump(report/"il2cpp_loader_hints_summary.json",result)
        write_rows(report/"il2cpp_loader_hints.csv",[],COLUMNS)
        return result
    data=json.loads(path.read_text(encoding="utf-8-sig"))
    methods=data.get("ScriptMethod",[]) if isinstance(data,dict) else []
    found=[]
    for method in methods:
        if not isinstance(method,dict):continue
        name=str(method.get("Name",""))
        sig=str(method.get("Signature",""))
        combined=(name+" "+sig).lower()
        hits=[t for t in TOKENS if t in combined]
        if not hits:continue
        found.append({"source":"script.json","method_name":name[:300],
                      "method_address":str(method.get("Address",""))[:100],
                      "matched_terms":";".join(hits),"confidence":"name_based_candidate"})
        if len(found)>=max_results:break
    write_rows(report/"il2cpp_loader_hints.csv",found,COLUMNS)
    result={"status":"name_candidates_only","method_rows_scanned":len(methods),
            "hits":len(found),"max_results":max_results,"truncated":len(found)>=max_results,
            "limitation":"String matching in generated names, not call-graph or runtime cache attribution"}
    dump(report/"il2cpp_loader_hints_summary.json",result)
    return result

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--script",type=Path)
    p.add_argument("--report",type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(run(a.script,a.report),ensure_ascii=False,indent=2))
