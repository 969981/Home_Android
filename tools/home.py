#!/usr/bin/env python3
"""Auditable, non-destructive APK inventory / safe extraction / resource discovery."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import stat
import tempfile
import zipfile
import zlib
from collections import Counter
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ["path", "size", "compressed_size", "crc32", "kind", "magic_hex"]

def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def dump(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def write_rows(path: Path, rows: list[dict], headers=FIELDS):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

def locate_apk(version: str, path: str | None) -> Path:
    if path:
        p = Path(path).resolve()
    else:
        matches = sorted((ROOT / "ROMS" / version).glob("*.apk"))
        if len(matches) != 1:
            raise SystemExit("Expected exactly one APK in ROMS/" + version + "; pass --apk")
        p = matches[0]
    if not p.is_file():
        raise SystemExit("No APK: " + str(p))
    return p

def safe_relative(filename: str) -> Path:
    # Never allow ZIP extraction to escape the chosen directory.
    name = filename.replace("\\", "/")
    p = PurePosixPath(name)
    if (not name or p.is_absolute() or ".." in p.parts or
            any(":" in part for part in p.parts) or "\x00" in name):
        raise ValueError("Unsafe archive path: " + repr(filename))
    return Path(*p.parts)

def kind(path: str, magic: bytes) -> str:
    name = path.lower().replace("\\", "/")
    base = name.rsplit("/", 1)[-1]
    # Unity 2020+ serialized format 22 frequently has GUID-only filenames,
    # without a .assets extension. The header is big-endian and its first
    # 8 bytes (legacy sizes) can be zero for the 64-bit extended header.
    if name.startswith("assets/bin/data/") and re.search(r"\.split\d+$", name):
        return "unity_split_chunk"
    if name.startswith("assets/ab/") and name.endswith(".aba"):
        return "aba_container_candidate"
    if (name.startswith("assets/bin/data/") and len(magic) >= 20
            and magic[:8] == bytes(8)
            and 22 <= int.from_bytes(magic[8:12], "big") <= 31
            and magic[12:20] == bytes(8)):
        return "unity_serialized_candidate"
    if magic.startswith((b"UnityFS", b"UnityWeb", b"UnityRaw")):
        return "unity_bundle"
    if magic.startswith(b"\x7fELF"):
        return "native_elf"
    if magic.startswith(b"dex\n"):
        return "android_dex"
    if magic.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image_png"
    if magic.startswith(b"\xff\xd8\xff"):
        return "image_jpeg"
    if magic.startswith(b"OggS"):
        return "audio_ogg"
    if magic.startswith((b"RIFF", b"FSB5", b"fLaC")):
        return "audio_candidate"
    if base == "global-metadata.dat":
        return "il2cpp_metadata_candidate"
    if name.endswith((".assets", ".bundle", ".unity3d", ".assetbundle")):
        return "unity_serialized_candidate"
    if "assets/bin/data/" in name and (re.fullmatch(r"sharedassets\d+", base) or
                                     re.fullmatch(r"level\d+", base) or
                                     base in {"globalgamemanagers", "maindata", "resources.assets"}):
        return "unity_serialized_candidate"
    if name.endswith((".resS".lower(), ".resource")):
        return "unity_external_resource"
    if name.endswith((".xml", ".arsc")):
        return "android_resource_candidate"
    if name.endswith((".json", ".txt", ".csv", ".bytes")):
        return "text_or_data_candidate"
    if name.endswith((".ktx", ".ktx2", ".astc", ".pvr", ".basis", ".dds")):
        return "texture_candidate"
    if base.endswith((".so", ".dex")):
        return "native_or_dex_candidate"
    return "unknown"

def audit(version: str, apk: Path, out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    counts = Counter()
    rows: list[dict] = []
    bad_paths: list[str] = []
    with zipfile.ZipFile(apk) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            try:
                safe_relative(info.filename)
            except ValueError:
                bad_paths.append(info.filename)
                continue
            with z.open(info) as f:
                magic = f.read(24)
            k = kind(info.filename, magic)
            counts[k] += 1
            rows.append(dict(path=info.filename, size=info.file_size,
                             compressed_size=info.compress_size, crc32=f"{info.CRC:08x}",
                             kind=k, magic_hex=magic.hex()))
        failed_crc = z.testzip()
    write_rows(out / "apk_entries.csv", rows)
    manifest = dict(version=version, apk_name=apk.name, apk_sha256=hash_file(apk),
                    apk_bytes=apk.stat().st_size, zip_entries=len(rows),
                    zip_total_uncompressed_bytes=sum(int(r["size"]) for r in rows),
                    by_kind=dict(sorted(counts.items())), unsafe_paths=bad_paths,
                    first_crc_error=failed_crc,
                    status="ok" if not bad_paths and not failed_crc else "invalid",
                    scope="APK ZIP audit; does not imply Unity asset decoding")
    dump(out / "summary.json", manifest)
    (out / "apk.sha256").write_text(manifest["apk_sha256"] + "  " + apk.name + "\n", encoding="utf-8")
    if bad_paths or failed_crc:
        raise RuntimeError("APK failed safety / CRC verification; see summary.json")
    return manifest

def extract(apk: Path, dest: Path) -> dict:
    dest.mkdir(parents=True, exist_ok=True)
    completed = skipped = 0
    with zipfile.ZipFile(apk) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            rel = safe_relative(info.filename)
            if stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError("Refusing symbolic link: " + info.filename)
            path = dest / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink():
                raise ValueError("Refusing symlink destination: " + str(path))
            if path.exists() and path.stat().st_size == info.file_size:
                c = 0
                with path.open("rb") as f:
                    for b in iter(lambda: f.read(1024 * 1024), b""):
                        c = zlib.crc32(b, c)
                if (c & 0xffffffff) == info.CRC:
                    skipped += 1
                    continue
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".tmp-", delete=False) as tmp:
                temporary = Path(tmp.name)
                try:
                    with z.open(info) as src:
                        while True:
                            b = src.read(1024 * 1024)
                            if not b:
                                break
                            tmp.write(b)
                except BaseException:
                    temporary.unlink(missing_ok=True)
                    raise
            os.replace(temporary, path)
            completed += 1
    return {"extracted_new_or_replaced": completed, "skipped_verified_crc": skipped, "directory": str(dest)}

def scan(version: str, root: Path, out: Path) -> dict:
    if not root.is_dir():
        raise SystemExit("Extract APK first; missing " + str(root))
    rows = []
    counts = Counter()
    libs = set()
    has_metadata = False
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root).as_posix()
        with path.open("rb") as f:
            magic = f.read(24)
        k = kind(rel, magic)
        rows.append(dict(path=rel, size=path.stat().st_size, compressed_size="",
                         crc32="", kind=k, magic_hex=magic.hex()))
        counts[k] += 1
        if rel.endswith(".so"):
            libs.add(path.name)
        if path.name == "global-metadata.dat":
            has_metadata = True
    rows.sort(key=lambda r: r["path"])
    write_rows(out / "resource_candidates.csv", rows)
    unity_possible = ("libunity.so" in libs or any(r["kind"].startswith("unity_") for r in rows))
    il2cpp_possible = "libil2cpp.so" in libs and has_metadata
    summary = dict(version=version, scanned_files=len(rows), by_kind=dict(sorted(counts.items())),
                   unity_runtime_present="libunity.so" in libs,
                   unity_candidates=sum(n for k, n in counts.items() if k.startswith("unity_")),
                   il2cpp_binary_present="libil2cpp.so" in libs,
                   il2cpp_metadata_present=has_metadata,
                   il2cpp_ready_for_analysis=il2cpp_possible,
                   unity_possible=unity_possible,
                   native_libraries=sorted(libs),
                   largest_files=sorted([{"path":r["path"],"bytes":r["size"]} for r in rows],
                                        key=lambda x: x["bytes"], reverse=True)[:20])
    dump(out / "scan_summary.json", summary)
    return summary

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", choices=("audit", "extract", "scan"))
    ap.add_argument("--version", default="4.1.0")
    ap.add_argument("--apk")
    ap.add_argument("--input", help="Extracted APK root for scan")
    ap.add_argument("--out", help="Output directory")
    args = ap.parse_args()
    if args.command == "scan":
        root = Path(args.input) if args.input else ROOT / "Unpack" / args.version / "apk/raw"
        out = Path(args.out) if args.out else ROOT / "reports" / args.version
        result = scan(args.version, root, out)
    else:
        apk = locate_apk(args.version, args.apk)
        if args.command == "audit":
            out = Path(args.out) if args.out else ROOT / "reports" / args.version
            result = audit(args.version, apk, out)
        else:
            out = Path(args.out) if args.out else ROOT / "Unpack" / args.version / "apk/raw"
            result = extract(apk, out)
    print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
