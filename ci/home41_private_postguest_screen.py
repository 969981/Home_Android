#!/usr/bin/env python3
"""Capture one CURRENT original HOME screen on the user's local Android only.

A screenshot may contain account identifiers or Pokémon data. This helper
never uploads, prints the screenshot or captures while running in CI. It
does not tap UI, initiate registration, set IDs, read HTTP, or restart HOME.
Private output is restricted to an ignored local directory inside the repo.
"""
from __future__ import annotations
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

PACKAGE = "jp.pokemon.pokemonhome"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
ROOT = Path(__file__).resolve().parent.parent
PRIVATE_DIR = ROOT / "local-home41-private"


def adb(*args: str, serial: str | None = None, binary: bool = False):
    cmd=["adb"]+ (["-s",serial] if serial else [])+list(args)
    try:
        return subprocess.run(cmd, capture_output=True, timeout=20,
                              text=not binary, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def eligibility(serial: str | None, *, env: dict | None = None) -> str:
    environ = os.environ if env is None else env
    if environ.get("GITHUB_ACTIONS","").lower()=="true" or not sys.stdout.isatty():
        return "requires_local_interactive_terminal"
    p=adb("shell","pidof",PACKAGE,serial=serial)
    if p is None or p.returncode!=0 or not re.fullmatch(
            r"\s*\d+(?:\s+\d+)*\s*",p.stdout or ""):
        return "home_process_not_running"
    focus=adb("shell","dumpsys","window",serial=serial)
    if focus is None or focus.returncode!=0:
        return "window_focus_unavailable"
    detail=focus.stdout or ""
    # The package must be mentioned in a real focus/resume line, not
    # merely somewhere in the general window-manager dump.
    lines=[x for x in detail.splitlines() if
           any(y in x for y in ("mCurrentFocus","mFocusedApp",
                                "mTopFocusedDisplayId","mResumedActivity"))]
    if not any(PACKAGE in x for x in lines):
        return "home_not_verified_foreground"
    return "original_home_foreground_verified"


def capture(label: str, serial: str | None, *, env: dict | None = None):
    if not re.fullmatch(r"[a-z0-9_-]{1,32}",label):
        return {"status":"invalid_label"}
    status=eligibility(serial,env=env)
    if status!="original_home_foreground_verified":
        return {"status":status}
    output=PRIVATE_DIR/(label+".png")
    if output.exists():
        return {"status":"image_exists_not_overwritten"}
    screen=adb("exec-out","screencap","-p",serial=serial,binary=True)
    if screen is None or screen.returncode!=0 or not isinstance(
            screen.stdout,bytes):
        return {"status":"screencap_failed"}
    png=screen.stdout
    if not png.startswith(PNG_MAGIC) or not 1000<len(png)<20000000:
        return {"status":"invalid_png"}
    PRIVATE_DIR.mkdir(mode=0o700,parents=True,exist_ok=True)
    # O_EXCL avoids accidental replacement of a previous private evidence image.
    # chmod is not a confidentiality guarantee on Windows; user's PC must be secure.
    try:
        fd=os.open(output,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,"wb") as f:
            f.write(png)
    except FileExistsError:
        return {"status":"image_exists_not_overwritten"}
    return {
        "status":"private_local_image_saved",
        "page_classification_verified":False,
        "registered_account_verified":False,
        "contains_potential_account_data":True,
        "safe_for_public_upload":False,
        "relative_private_path":str(output.relative_to(ROOT)).replace("\\","/"),
    }


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--label",required=True,
        help="Local-only label: e.g. after_guest, avatar, starter")
    ap.add_argument("--serial",help="ADB serial for a personally controlled device")
    ap.add_argument("--i-understand-this-is-private",action="store_true")
    args=ap.parse_args()
    if not args.i_understand_this_is_private:
        print(json.dumps({"status":"private_capture_optin_required"}))
        return 2
    result=capture(args.label,args.serial)
    print(json.dumps(result,ensure_ascii=False,sort_keys=True))
    return 0 if result["status"]=="private_local_image_saved" else 3

if __name__ == "__main__":
    raise SystemExit(main())
