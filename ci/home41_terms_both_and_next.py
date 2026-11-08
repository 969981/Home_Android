#!/usr/bin/env python3
"""One-shot original HOME Terms consent: both real checkboxes, ONE Next, stop.

User-authorized. Guards exact signed HOME 4.1.0 ARM64 Phase=3 Terms,
original ConfirmationTermOfService, original pixel signature and two visual
checkbox transitions. No Nintendo Account binding or registration action.
The post-Next unknown screen is observed in RAM but never saved or uploaded.
"""
from __future__ import annotations

import argparse
import io
import json
import time
from pathlib import Path

import home41_terms_probe as terms
from home41_terms_checkbox_ab import terms_ui_signature, rgb_near
from home41_terms_visual_capture import eligible_for_terms_capture


def checkbox_status(frame: bytes, checkbox: str) -> str:
    try:
        from PIL import Image
        with Image.open(io.BytesIO(frame)) as raw:
            img=raw.convert("RGB")
        if img.width < 900:
            return "unknown"
        y = .450 if checkbox == "terms" else .504 if checkbox == "privacy" else None
        if y is None:
            return "unknown"
        pixel=img.getpixel((int(img.width*.135),int(img.height*y)))
        if rgb_near(pixel,(247,251,247),20):
            return "unchecked"
        if rgb_near(pixel,(101,203,195),23):
            return "checked"
        return "unknown"
    except (OSError,ValueError,ImportError):
        return "unknown"


def substantial_page_transition(previous: bytes, current: bytes) -> bool:
    try:
        from PIL import Image, ImageChops
        with Image.open(io.BytesIO(previous)) as a, Image.open(io.BytesIO(current)) as b:
            first=a.convert("RGB")
            last=b.convert("RGB")
        if first.size!=last.size or first.width<900:
            return False
        w,h=first.size
        # A transition of the page body, NOT just the two checkboxes.
        rect=(int(w*.18),int(h*.20),int(w*.83),int(h*.77))
        difference=ImageChops.difference(first.crop(rect),last.crop(rect)).convert("L")
        return sum(value>35 for value in difference.getdata()) > 5000
    except (OSError,ValueError,ImportError):
        return False


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report",type=Path,required=True)
    p.add_argument("--fingerprint",type=Path,required=True)
    p.add_argument("--output-dir",type=Path,required=True)
    p.add_argument("--authorize-original-terms-once",action="store_true")
    args=p.parse_args()
    state={
        "status":"guard_rejected",
        "first_checkbox_checked_verified":False,
        "privacy_checkbox_checked_verified":False,
        "terms_next_tapped":False,
        "post_terms_page_changed":False,
        "account_registration_clicked_by_script":False,
        "nintendo_account_linking_clicked_by_script":False,
        "utid_saved":False,
        "unverified_post_next_screen_saved":False,
    }
    out=args.output_dir
    def record():
        out.mkdir(parents=True,exist_ok=True)
        (out/"terms_once_status.json").write_text(
            json.dumps(state,indent=2,sort_keys=True)+"\n",encoding="utf8")
        print(json.dumps(state,sort_keys=True))
    try:
        report=json.loads(args.report.read_text(encoding="utf8"))
        fp=json.loads(args.fingerprint.read_text(encoding="utf8"))
        if not args.authorize_original_terms_once:
            state["status"]="one_time_user_authorization_not_armed"
            record()
            return 2
        if not eligible_for_terms_capture(report,fp):
            state["status"]="original_phase3_terms_preflight_failed"
            record()
            return 3
        def snap():
            if not terms.home_is_foreground(str(
                    terms.adb(None,"shell","dumpsys","window"))):
                raise RuntimeError("home_not_foreground")
            return terms.adb(None,"exec-out","screencap","-p",binary=True)
        before=snap()
        first_point=terms_ui_signature(before,True)
        if first_point is None or (
                checkbox_status(before,"terms")!="unchecked" or
                checkbox_status(before,"privacy")!="unchecked"):
            state["status"]="original_unchecked_terms_ui_not_verified"
            record()
            return 3
        if not terms.save_masked_consent_screen(out/"before_masked.png",before):
            state["status"]="failed_to_mask_original_ui"
            record()
            return 3
        # One terms checkbox; independently verify its settled checkmark.
        fresh=snap()
        if terms_ui_signature(fresh,True)!=first_point:
            state["status"]="before_terms_checkbox_stale"
            record()
            return 3
        terms.adb(None,"shell","input","tap",str(first_point[0]),str(first_point[1]))
        time.sleep(2.5)
        after_first=snap()
        if not (terms_ui_signature(after_first,False)
                and checkbox_status(after_first,"terms")=="checked"
                and checkbox_status(after_first,"privacy")=="unchecked"):
            state["status"]="first_checkbox_not_proven_checked"
            record()
            return 3
        state["first_checkbox_checked_verified"]=True

        # Second independent privacy checkbox, same verified original UI.
        w,h=1080,2340
        from PIL import Image
        with Image.open(io.BytesIO(after_first)) as temp:
            w,h=temp.size
        if terms_ui_signature(snap(),False) is None:
            state["status"]="before_privacy_checkbox_stale"
            record()
            return 3
        terms.adb(None,"shell","input","tap",str(int(w*.135)),str(int(h*.514)))
        time.sleep(2.5)
        both=snap()
        if not (terms_ui_signature(both,False)
                and checkbox_status(both,"terms")=="checked"
                and checkbox_status(both,"privacy")=="checked"):
            state["status"]="both_checkbox_selected_not_verified"
            record()
            return 3
        state["privacy_checkbox_checked_verified"]=True
        if not terms.save_masked_consent_screen(out/"both_checked_masked.png",both):
            state["status"]="cannot_mask_both_checked_screen"
            record()
            return 3

        # Explicitly user-authorized official Terms Next, exactly once.
        ready=snap()
        if not (terms_ui_signature(ready,False)
                and checkbox_status(ready,"terms")=="checked"
                and checkbox_status(ready,"privacy")=="checked"):
            state["status"]="terms_next_page_preflight_stale"
            record()
            return 3
        terms.adb(None,"shell","input","tap",str(int(w*.5)),str(int(h*.64)))
        state["terms_next_tapped"]=True
        time.sleep(7)
        # Evaluate whether UI changed in RAM. No screenshot of the unknown
        # next page is retained; no other UI action is attempted.
        try:
            next_page=snap()
            state["post_terms_page_changed"]=(
                terms_ui_signature(next_page,False) is None
                and substantial_page_transition(ready,next_page))
            state["status"]=("terms_next_clicked_new_page_seen"
                             if state["post_terms_page_changed"]
                             else "terms_next_clicked_but_transition_unverified")
        except Exception as ex:
            state["status"]="terms_next_clicked_foreground_unavailable"
            state["error_type"]=type(ex).__name__
        record()
        return 0 if state["post_terms_page_changed"] else 3
    except Exception as exc:
        state["status"]="one_shot_terms_experiment_stopped"
        state["error_type"]=type(exc).__name__
        record()
        return 3


if __name__=="__main__":
    raise SystemExit(main())
