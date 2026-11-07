#!/usr/bin/env python3
"""Extract evidence-based Pokémon species/form hints from sanitized Unity caches.

Does not infer species from arbitrary numbers, UI sprite names or mesh shapes.
"""
from __future__ import annotations
import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path
from home import dump, write_rows

FIELDS=["resource_id","cache_kind","object_path_id","object_type","object_name",
        "species_id","form_id","evidence","status","export_path","error"]
PATTERNS=[
    re.compile(r"(?<![a-z0-9])(?:pm|pkm|pokemon|poke)[_\-]?(\d{3,4})(?:[_\-]?(?:f|form)(\d{1,3}))?(?!\d)",re.I),
    re.compile(r"(?<![a-z0-9])(?:species)[_\-]?(\d{3,4})(?:[_\-]?(?:f|form)(\d{1,3}))?(?!\d)",re.I),
]
KINDS={"unity_bundle","unity_serialized_candidate"}
TYPES={"Mesh","Texture2D","Sprite","AnimationClip","Material",
       "SkinnedMeshRenderer","GameObject","Animator","TextAsset"}
IMAGE_TYPES={"Texture2D","Sprite"}

def species_from_name(name:str):
    if not name: return None
    for pat in PATTERNS:
        m=pat.search(name)
        if m:
            species=int(m.group(1))
            if 1<=species<=2048:
                return (species,int(m.group(2)) if m.group(2) is not None else None)
    return None

def run(version:str,assets:Path,report:Path,output:Path|None=None,max_objects:int=500000):
    report.mkdir(parents=True,exist_ok=True)
    inventory=report/"runtime_inventory.csv"
    if not inventory.exists():
        raise SystemExit("Run runtime_cache_inventory.py first")
    with inventory.open("r",newline="",encoding="utf-8-sig") as f:
        candidates=[r for r in csv.DictReader(f)
                    if r.get("kind") in KINDS and r.get("stored_relative")]
    if not candidates:
        summary={"version":version,"status":"no_cached_unity_assets",
                 "containers":0,"objects":0,"species_candidates":0,
                 "note":"No runtime-cache Unity bundles supplied. APK UI meshes are not Pokemon models."}
        dump(report/"pokemon_cache_summary.json",summary)
        write_rows(report/"pokemon_asset_candidates.csv",[],FIELDS)
        return summary
    try:
        import UnityPy
    except ImportError as e:
        raise SystemExit("Install tools/requirements-unity.txt") from e
    rows=[]; stats=Counter()
    for info in candidates:
        p=assets/info["stored_relative"]
        if not p.is_file():
            stats["missing_asset_file"]+=1
            continue
        try:
            env=UnityPy.load(str(p))
            objects=env.objects
            stats["containers_parsed"]+=1
        except Exception as exc:
            stats["container_parse_failed"]+=1
            rows.append(dict(resource_id=info["resource_id"],cache_kind=info["kind"],
                             object_path_id="",object_type="Container",object_name="",
                             species_id="",form_id="",evidence="",status="parse_failed",
                             export_path="",error=str(exc)[:280]))
            continue
        for obj in objects:
            stats["objects_total"]+=1
            if stats["objects_total"]>max_objects:
                raise ValueError("Object limit hit; run in batches")
            typ=getattr(obj.type,"name","Unknown")
            if typ not in TYPES: continue
            # Object names can be present as typetree fields, but they are not
            # reliable proof of species unless the prefix explicitly encodes it.
            try:
                data=obj.read_typetree()
                name=data.get("m_Name","") if isinstance(data,dict) else ""
            except Exception:
                name=""
            match=species_from_name(str(name))
            source_match=species_from_name(info.get("name_hint",""))
            found=match or source_match
            if not found:
                stats["selected_without_species_id"]+=1
                continue
            species,form=found
            evidence="object_name_pattern" if match else "cache_name_pattern"
            rec=dict(resource_id=info["resource_id"],cache_kind=info["kind"],
                     object_path_id=str(obj.path_id),object_type=typ,object_name=str(name)[:256],
                     species_id=species,form_id="" if form is None else form,
                     evidence=evidence,status="identified",export_path="",error="")
            stats["species_candidate_objects"]+=1
            if output and typ in IMAGE_TYPES|{"Mesh"}:
                try:
                    data=obj.parse_as_object()
                    stem=f"pm{species:04d}_f{form or 0:02d}_{info['resource_id']}_{obj.path_id}"
                    if typ in IMAGE_TYPES:
                        dest=output/"pokemon"/"images"/(stem+".png")
                        dest.parent.mkdir(parents=True,exist_ok=True)
                        data.image.save(dest,format="PNG")
                        from PIL import Image
                        with Image.open(dest) as im: im.verify()
                    else:
                        dest=output/"pokemon"/"models"/(stem+".obj")
                        dest.parent.mkdir(parents=True,exist_ok=True)
                        mesh=data.export()
                        if not re.search(r"(?m)^v ",mesh):
                            raise ValueError("Mesh OBJ had no vertices")
                        dest.write_text(mesh,encoding="utf-8")
                    rec["status"]="exported"
                    rec["export_path"]=str(dest)
                    stats["exported"]+=1
                except Exception as e:
                    rec["status"]="export_failed"
                    rec["error"]=str(e)[:250]
                    stats["export_failed"]+=1
            rows.append(rec)
    write_rows(report/"pokemon_asset_candidates.csv",rows,FIELDS)
    species=sorted(set(int(r["species_id"]) for r in rows if r.get("species_id") not in ("",None)))
    summary={"version":version,"status":"scanned",
             "cache_unity_containers":len(candidates),"containers_parsed":stats["containers_parsed"],
             "container_parse_failed":stats["container_parse_failed"],
             "objects_scanned":stats["objects_total"],"species_candidates":len(species),
             "candidate_objects":stats["species_candidate_objects"],
             "exported_assets":stats["exported"],"export_failed":stats["export_failed"],
             "species_ids":species,
             "limitation":"Name-pattern candidate, not a verified in-game species/form ID mapping; needs screenshot/runtime cross-check."}
    dump(report/"pokemon_cache_summary.json",summary)
    return summary

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--version",default="4.1.0")
    p.add_argument("--assets",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    print(json.dumps(run(a.version,a.assets,a.report,a.out),ensure_ascii=False,indent=2))
