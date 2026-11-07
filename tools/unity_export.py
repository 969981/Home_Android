#!/usr/bin/env python3
"""Read local Unity candidates, record objects and export images/text/OBJ where supported.

Never treats missing remote assets or unsupported objects as successful extraction.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from home import ROOT, dump, hash_file, write_rows

HEADERS = ["source_path", "source_bytes", "path_id", "type", "name",
           "output_path", "output_sha256", "status", "error", "tool_version"]
SUPPORTED = {"Texture2D", "Sprite", "TextAsset", "Mesh"}
INVENTORY_ONLY = {"Material", "AnimationClip", "Animator", "Animation",
                  "SkinnedMeshRenderer", "MeshRenderer", "AudioClip",
                  "GameObject", "MonoBehaviour", "Shader"}

def clean_name(s: str) -> str:
    result = re.sub(r"[^\w.\-]+", "_", s, flags=re.UNICODE).strip("._")
    return (result or "unnamed")[:56]

def decode_text(script):
    if isinstance(script, str):
        return script.encode("utf-8", "surrogateescape")
    return bytes(script)

def load_candidates(path: Path) -> list[dict]:
    if not path.exists():
        raise SystemExit("Run home.py scan first: missing " + str(path))
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return [r for r in csv.DictReader(f) if r["kind"] in
                {"unity_bundle", "unity_serialized_candidate"}]

def export(version: str, root: Path, report: Path, output: Path, max_size_mib: int):
    try:
        import UnityPy
    except ImportError as e:
        dump(report / "unity_summary.json", {"version":version,"status":"dependency_missing","error":str(e)})
        raise SystemExit("Install tools/requirements-unity.txt first") from e
    tool_version = "UnityPy " + str(getattr(UnityPy, "__version__", "unknown"))
    items = load_candidates(report / "resource_candidates.csv")
    stats = Counter()
    rows = []
    size_limit = max_size_mib * 1024 * 1024
    apk_sha = ""
    p = report / "summary.json"
    if p.exists():
        apk_sha = json.loads(p.read_text(encoding="utf-8")).get("apk_sha256", "")
    for record in items:
        relative = record["path"]
        src = root / relative
        size = int(record["size"])
        if size > size_limit:
            stats["skipped_too_large"] += 1
            rows.append(dict(source_path=relative, source_bytes=size, path_id="",
                             type="Container", name="", output_path="", output_sha256="",
                             status="skipped_too_large",error=f"limit={max_size_mib} MiB",
                             tool_version=tool_version))
            continue
        try:
            env = UnityPy.load(str(src))
            objects = list(env.objects)
            stats["containers_parsed"] += 1
        except Exception as exc:
            stats["containers_failed"] += 1
            rows.append(dict(source_path=relative,source_bytes=size,path_id="",
                             type="Container",name="",output_path="",output_sha256="",
                             status="parse_failed",error=str(exc)[:400],tool_version=tool_version))
            continue
        for obj in objects:
            obj_type = getattr(getattr(obj, "type", None), "name", "Unknown")
            stats["objects_total"] += 1
            stats["object_" + obj_type] += 1
            if obj_type not in SUPPORTED | INVENTORY_ONLY:
                continue
            path_id = str(getattr(obj, "path_id", ""))
            row = dict(source_path=relative,source_bytes=size,path_id=path_id,
                       type=obj_type,name="",output_path="",output_sha256="",
                       status="identified",error="",tool_version=tool_version)
            # Unique combination of container and path ID, not only an asset name.
            source_key = hashlib.sha256(relative.encode("utf-8")).hexdigest()[:12]
            output_stem = source_key + "_" + (path_id or "noid")
            try:
                if obj_type in SUPPORTED:
                    data = obj.parse_as_object()
                    name = str(getattr(data, "m_Name", "")) or obj_type
                    row["name"] = name[:256]
                    output_stem += "_" + clean_name(name)
                    if obj_type in ("Texture2D", "Sprite"):
                        export_path = output / ("images" if obj_type == "Texture2D" else "sprites") / (output_stem + ".png")
                        export_path.parent.mkdir(parents=True, exist_ok=True)
                        im = data.image
                        im.save(export_path, format="PNG")
                        # A valid image must open again, not merely exist.
                        from PIL import Image
                        with Image.open(export_path) as test:
                            test.verify()
                    elif obj_type == "TextAsset":
                        blob = decode_text(data.m_Script)
                        try:
                            blob.decode("utf-8")
                            suffix = ".txt"
                        except UnicodeDecodeError:
                            suffix = ".bin"
                        export_path = output / "text" / (output_stem + suffix)
                        export_path.parent.mkdir(parents=True, exist_ok=True)
                        export_path.write_bytes(blob)
                    else:
                        # Geometry only: Wavefront OBJ does NOT prove materials/rig/animation.
                        geom = data.export()
                        if not geom.strip() or not re.search(r"(?m)^v ", geom):
                            raise ValueError("Mesh exporter returned no OBJ vertices")
                        export_path = output / "models" / (output_stem + ".obj")
                        export_path.parent.mkdir(parents=True, exist_ok=True)
                        export_path.write_text(geom, encoding="utf-8", newline="")
                    row["output_path"] = export_path.relative_to(ROOT).as_posix() if export_path.is_relative_to(ROOT) else str(export_path)
                    row["output_sha256"] = hash_file(export_path)
                    row["status"] = "exported_verified"
                    stats["exported_" + obj_type] += 1
                else:
                    # Inventories models, materials, audio/animation references;
                    # nothing here is a playable or validated 3D export.
                    row["status"] = "identified_only"
                    stats["identified_only"] += 1
            except Exception as exc:
                row["status"] = "export_failed"
                row["error"] = str(exc)[:400]
                stats["object_export_failed"] += 1
            rows.append(row)
    report.mkdir(parents=True, exist_ok=True)
    write_rows(report / "unity_objects.csv", rows, HEADERS)
    summary = dict(version=version, apk_sha256=apk_sha, tool=tool_version,
                   candidate_containers=len(items), **dict(sorted(stats.items())),
                   status="completed_with_failures" if stats["containers_failed"] or stats["object_export_failed"]
                   else "completed", scope="Local APK Unity candidates only",
                   note="Mesh OBJ is geometry only; rigging, materials, motion and GLB are not validated.")
    dump(report / "unity_summary.json", summary)
    return summary

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--version", default="4.1.0")
    p.add_argument("--input")
    p.add_argument("--out")
    p.add_argument("--report")
    p.add_argument("--max-size-mib", type=int, default=256)
    a=p.parse_args()
    root=Path(a.input) if a.input else ROOT/"Unpack"/a.version/"apk/raw"
    report=Path(a.report) if a.report else ROOT/"reports"/a.version
    out=Path(a.out) if a.out else ROOT/"resources"/a.version
    print(json.dumps(export(a.version,root,report,out,a.max_size_mib),ensure_ascii=False,indent=2))

if __name__=="__main__":
    main()
