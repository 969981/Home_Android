#!/usr/bin/env python3
"""Inventory Unity material, animation and controller pointer relationships.

This is an evidence table of serialized PPtr links, not rigged 3D export.
"""
from __future__ import annotations
import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from home import ROOT, dump, write_rows

TARGET_TYPES={"Material","AnimationClip","AnimatorController","Animator","SpriteAtlas",
              "SkinnedMeshRenderer","MeshRenderer","MeshFilter","AudioClip","PlayableDirector"}
FIELDS=["source_container","owner_path_id","owner_type","owner_name","property_path",
        "target_file_id","target_path_id","resolved_same_file_type","status"]
ERRFIELDS=["source_container","owner_path_id","owner_type","error"]

def gather(node,location="$",depth=0,max_depth=10):
    if depth>max_depth:
        return
    if isinstance(node,dict):
        # A Unity PPtr is not a global path ID; m_FileID=0 means same SerializedFile.
        if "m_FileID" in node and "m_PathID" in node:
            try:
                fid=int(node["m_FileID"]); pid=int(node["m_PathID"])
                if pid != 0:
                    yield (location,fid,pid)
            except (ValueError,TypeError):
                pass
            return
        for key,value in list(node.items())[:512]:
            if isinstance(value,(dict,list)):
                yield from gather(value,location+"."+str(key),depth+1,max_depth)
    elif isinstance(node,list):
        for i,value in enumerate(node[:1024]):
            if isinstance(value,(dict,list)):
                yield from gather(value,location+"["+str(i)+"]",depth+1,max_depth)

def as_data(obj):
    if hasattr(obj,"parse_as_dict"):
        return obj.parse_as_dict()
    if hasattr(obj,"read_typetree"):
        return obj.read_typetree()
    raise NotImplementedError("UnityPy object has no dictionary parser")

def run(version:str,root:Path,report:Path):
    try:
        import UnityPy
    except ImportError as e:
        raise SystemExit("Install UnityPy first") from e
    import csv
    with (report/"resource_candidates.csv").open("r",encoding="utf-8-sig",newline="") as f:
        sources=[{"path":r["path"],"source":root/r["path"]}
                 for r in csv.DictReader(f)
                 if r["kind"] in ("unity_bundle","unity_serialized_candidate")]
    reassembled=ROOT/"Unpack"/version/"unity"/"reassembled"
    if reassembled.is_dir():
        sources.extend({"path":"@reassembled/"+p.relative_to(reassembled).as_posix(),"source":p}
                       for p in sorted(reassembled.rglob("*")) if p.is_file())
    out=[]
    errors=[]
    counts=Counter()
    for src in sources:
        try:
            env=UnityPy.load(str(src["source"]))
        except Exception as e:
            errors.append({"source_container":src["path"],"owner_path_id":"",
                           "owner_type":"Container","error":str(e)[:300]})
            continue
        types={str(o.path_id):getattr(o.type,"name","Unknown") for o in env.objects}
        for obj in env.objects:
            typ=getattr(obj.type,"name","Unknown")
            if typ not in TARGET_TYPES: continue
            counts["selected_objects"]+=1
            pid=str(obj.path_id)
            try:
                data=as_data(obj)
                if not isinstance(data,dict):
                    raise TypeError("parse_as_dict produced "+type(data).__name__)
                name=str(data.get("m_Name",""))[:256]
                refs=list(gather(data))
                counts["parsed_selected_objects"]+=1
                if not refs:
                    counts["selected_without_refs"]+=1
                for prop,fileid,pathid in refs[:5000]:
                    resolved=types.get(str(pathid),"") if fileid==0 else ""
                    out.append({"source_container":src["path"],"owner_path_id":pid,
                                "owner_type":typ,"owner_name":name,"property_path":prop,
                                "target_file_id":fileid,"target_path_id":pathid,
                                "resolved_same_file_type":resolved,
                                "status":"same_file_resolved" if resolved else
                                         "external_file" if fileid else "same_file_missing"})
                    counts["links_total"]+=1
                    counts["same_file_resolved" if resolved else
                           "external_file" if fileid else "same_file_missing"]+=1
                if len(refs)>5000: counts["links_truncated"]+=len(refs)-5000
            except Exception as e:
                counts["selected_parse_failed"]+=1
                errors.append({"source_container":src["path"],"owner_path_id":pid,
                               "owner_type":typ,"error":str(e)[:300]})
    write_rows(report/"unity_references.csv",out,FIELDS)
    write_rows(report/"unity_relation_errors.csv",errors,ERRFIELDS)
    summary={"version":version,"containers":len(sources),"tool_version":str(getattr(UnityPy,"__version__","unknown")),
             "by_status":dict(sorted(counts.items())),"error_records":len(errors),
             "scope":"Unity material/animation serialized PPtr refs only; external links require dependency resolution"}
    dump(report/"unity_references_summary.json",summary)
    return summary

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--version",default="4.1.0")
    p.add_argument("--input")
    p.add_argument("--report")
    a=p.parse_args()
    root=Path(a.input) if a.input else ROOT/"Unpack"/a.version/"apk/raw"
    report=Path(a.report) if a.report else ROOT/"reports"/a.version
    print(json.dumps(run(a.version,root,report),ensure_ascii=False,indent=2))
