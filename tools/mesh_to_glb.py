#!/usr/bin/env python3
"""Convert previously exported mesh OBJ geometry to GLB and validate actual binary."""
from __future__ import annotations
import argparse
import json
from collections import Counter
from pathlib import Path

from home import ROOT, dump, hash_file, write_rows

FIELDS=["obj_path","glb_path","glb_sha256","vertices","triangles","status","error"]

def run(version: str, resources: Path, reports: Path):
    try:
        import trimesh
    except ImportError as e:
        raise SystemExit("pip install trimesh numpy first") from e
    model_root=resources/"models"
    files=sorted(model_root.glob("*.obj"))
    rows=[]
    counts=Counter()
    for src in files:
        rec={"obj_path":str(src.relative_to(ROOT)) if src.is_relative_to(ROOT) else str(src),
             "glb_path":"","glb_sha256":"","vertices":0,"triangles":0,
             "status":"","error":""}
        try:
            scene=trimesh.load(str(src),file_type="obj",force="scene",process=False)
            geometries=list(scene.geometry.values())
            if not geometries:
                raise ValueError("OBJ contains no geometry")
            vertices=sum(len(g.vertices) for g in geometries)
            triangles=sum(len(g.faces) for g in geometries)
            if vertices==0 or triangles==0:
                raise ValueError("No vertices or triangles; refuse empty GLB")
            payload=scene.export(file_type="glb")
            if payload[:4]!=b"glTF":
                raise ValueError("GLB magic mismatch")
            dest=model_root/"glb"/(src.stem+".glb")
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(payload)
            rec.update(glb_path=dest.relative_to(ROOT).as_posix() if dest.is_relative_to(ROOT) else str(dest),
                       glb_sha256=hash_file(dest),vertices=vertices,triangles=triangles,status="geometry_validated")
            counts["success"]+=1
        except Exception as exc:
            rec.update(status="failed",error=str(exc)[:400])
            counts["failed"]+=1
        rows.append(rec)
    write_rows(reports/"glb_objects.csv",rows,FIELDS)
    summary={"version":version,"obj_candidates":len(files),
             "glb_converted":counts["success"],"glb_failed":counts["failed"],
             "scope":"Geometry-only GLB; no armature, materials, or animation validation"}
    dump(reports/"glb_summary.json",summary)
    return summary

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--version",default="4.1.0")
    p.add_argument("--resources")
    p.add_argument("--report")
    a=p.parse_args()
    resources=Path(a.resources) if a.resources else ROOT/"resources"/a.version
    reports=Path(a.report) if a.report else ROOT/"reports"/a.version
    print(json.dumps(run(a.version,resources,reports),ensure_ascii=False,indent=2))
