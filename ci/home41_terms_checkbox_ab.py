#!/usr/bin/env python3
"""One optional A/B of ONLY the first checkbox on original HOME Terms screen.

Never clicks Next, never accepts/commits Terms, never registers an account.
Requires original ARM64 FirstBoot Phase=3 TERM_OF_SERVICE and verified
ConfirmationTermOfService event. UI screenshot is masked for evidence.
"""
from __future__ import annotations

import argparse
import io
import json
import time
from pathlib import Path

import home41_terms_probe as terms
from home41_terms_visual_capture import eligible_for_terms_capture

PNG_MAGIC = terms.PNG_MAGIC


def rgb_near(a: tuple[int, int, int], b: tuple[int, int, int],
             tolerance: int = 22) -> bool:
    return all(abs(x - y) <= tolerance for x, y in zip(a, b))


def terms_ui_signature(pixels: bytes, require_two_unchecked: bool) -> tuple[int, int] | None:
    if not pixels.startswith(PNG_MAGIC):
        return None
    try:
        from PIL import Image
        with Image.open(io.BytesIO(pixels)) as src:
            image = src.convert("RGB")
        w, h = image.size
        if not (900 <= w <= 2200 and 1700 <= h <= 4000 and 1.9 < h/w < 2.5):
            return None
        p = lambda x, y: image.getpixel((int(w*x), int(h*y)))
        # Exact real UI corroborated by original phase 3 screenshot Actions #42462814367.
        background = (
            ((.5,.14),(38,179,151),18),       # official teal header
            ((.5,.2),(207,247,166),22),       # green HOME background
            ((.8,.30),(240,246,237),22),      # white Terms page button
            ((.8,.38),(240,246,237),22),      # white Privacy page button
            ((.65,.64),(255,173,4),18),       # orange Next button
        )
        if not all(rgb_near(p(x,y),expected,tol) for (x,y),expected,tol in background):
            return None
        if require_two_unchecked:
            if not (rgb_near(p(.135,.46),(247,251,247),22)
                    and rgb_near(p(.135,.514),(247,251,247),22)):
                return None
        return (int(w*.135), int(h*.46))
    except (OSError, ValueError, ImportError):
        return None


def roi_change_counts(before: bytes, after: bytes) -> tuple[int,int] | None:
    try:
        from PIL import Image, ImageChops
        with Image.open(io.BytesIO(before)) as a, Image.open(io.BytesIO(after)) as b:
            x, y = a.convert("RGB"), b.convert("RGB")
        if x.size != y.size or x.width < 900:
            return None
        w, h = x.size
        rects = (
            (.105,.444,.165,.480),  # first checkbox
            (.105,.496,.165,.534),  # second checkbox
        )
        result=[]
        for x0,y0,x1,y1 in rects:
            rect=(int(w*x0),int(h*y0),int(w*x1),int(h*y1))
            diff=ImageChops.difference(x.crop(rect),y.crop(rect)).convert("L")
            result.append(sum(v>35 for v in diff.getdata()))
        return tuple(result)
    except (OSError, ValueError, ImportError):
        return None


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report",type=Path,required=True)
    parser.add_argument("--fingerprint",type=Path,required=True)
    parser.add_argument("--output-dir",type=Path,required=True)
    parser.add_argument("--authorize-first-checkbox-ab",action="store_true",
                        help="One local Terms checkbox ONLY; NEVER Terms Next")
    args=parser.parse_args()
    status={
        "status":"guard_rejected",
        "first_checkbox_tapped":False,
        "first_checkbox_visual_change_verified":False,
        "second_checkbox_untouched":True,
        "terms_next_tapped":False,
        "terms_accepted":False,
        "registration_attempted":False,
        "utid_saved":False,
        "masked_screenshots_only":True,
    }
    out=args.output_dir
    def write_status():
        out.mkdir(parents=True,exist_ok=True)
        (out/"checkbox_ab_status.json").write_text(
            json.dumps(status,indent=2,sort_keys=True)+"\n",encoding="utf8")
        print(json.dumps(status,sort_keys=True))
    try:
        report=json.loads(args.report.read_text(encoding="utf8"))
        fp=json.loads(args.fingerprint.read_text(encoding="utf8"))
        if not args.authorize_first_checkbox_ab:
            status["status"]="explicit_one_checkbox_optin_missing"
            write_status()
            return 2
        if not eligible_for_terms_capture(report,fp):
            status["status"]="original_terms_phase_preflight_missing"
            write_status()
            return 3
        if not terms.home_is_foreground(
                str(terms.adb(None,"shell","dumpsys","window"))):
            status["status"]="home_not_foreground"
            write_status()
            return 3
        before=terms.adb(None,"exec-out","screencap","-p",binary=True)
        location=terms_ui_signature(before,require_two_unchecked=True)
        if location is None:
            status["status"]="not_exact_verified_unchecked_terms_ui"
            write_status()
            return 3
        if not terms.save_masked_consent_screen(out/"before_masked.png",before):
            status["status"]="cannot_mask_before_image"
            write_status()
            return 3
        # Re-read current focus and visual signature to deny stale screen.
        if not terms.home_is_foreground(
                str(terms.adb(None,"shell","dumpsys","window"))):
            status["status"]="focus_changed_no_tap"
            write_status()
            return 3
        recent=terms.adb(None,"exec-out","screencap","-p",binary=True)
        if terms_ui_signature(recent,True) != location:
            status["status"]="visual_preflight_changed_no_tap"
            write_status()
            return 3
        terms.adb(None,"shell","input","tap",str(location[0]),str(location[1]))
        status["first_checkbox_tapped"]=True
        time.sleep(2.5)
        after=terms.adb(None,"exec-out","screencap","-p",binary=True)
        if not terms.save_masked_consent_screen(out/"after_masked.png",after):
            status["status"]="cannot_mask_after_image"
            write_status()
            return 3
        if terms_ui_signature(after,False) is None:
            status["status"]="unexpected_screen_after_first_checkbox"
            write_status()
            return 3
        changed=roi_change_counts(recent,after)
        if changed is None:
            status["status"]="checkbox_diff_unavailable"
        elif changed[0] >= 90 and changed[1] <= 80:
            status["first_checkbox_visual_change_verified"]=True
            status["status"]="first_original_checkbox_visual_ab_confirmed"
        else:
            status["status"]="checkbox_tapped_but_visual_result_unverified"
        write_status()
        return 0 if status["first_checkbox_visual_change_verified"] else 3
    except Exception as exc:
        status["status"]="safe_ab_probe_exception"
        status["error_type"]=type(exc).__name__
        write_status()
        return 3


if __name__=="__main__":
    raise SystemExit(main())
