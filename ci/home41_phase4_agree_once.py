#!/usr/bin/env python3
"""ONE user-authorized tap of original HOME Phase 4 RIGHT 同意.

Explicit opt-in for optional app usage/performance data collection. Only the
original verified 1080x2340 Chinese Phase4 screen is eligible. No blind taps,
extra dialogs, Nintendo Account linking, account registration, tokens or UTID.
The original page's exact pixel signature is shared with the already tested
Phase4 "不同意" gate, but the target is the independent RIGHT button.
"""
from __future__ import annotations

import argparse
import io
import json
import time
from pathlib import Path

import home41_terms_probe as terms
from home41_phase4_decline_once import phase4_decline_point
from home41_phase4_masked_capture import (
    combine_age_and_phase_reports, phase4_capture_allowed)
from home41_terms_checkbox_ab import rgb_near
from home41_terms_both_and_next import substantial_page_transition


def verified_phase4_agree_point(pixels: bytes) -> tuple[int, int] | None:
    """Only original visual signature with DISTINCT right-side Agree target."""
    left = phase4_decline_point(pixels)
    if left != (270, 2199):
        return None
    try:
        from PIL import Image
        with Image.open(io.BytesIO(pixels)) as original:
            image = original.convert("RGB")
        if image.size != (1080, 2340):
            return None
        # Two valid buttons still visible, and no darkened modal overlay.
        get = lambda x,y: image.getpixel((int(1080*x),int(2340*y)))
        if not (rgb_near(get(.25,.925),(247,251,247),12)
                and rgb_near(get(.75,.925),(247,251,247),12)
                and rgb_near(get(.5,.14),(38,179,151),16)):
            return None
        return (810, 2199)  # center of official RIGHT「同意」only
    except (OSError, ValueError, ImportError):
        return None


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--age-report",type=Path,required=True)
    p.add_argument("--phase-report",type=Path,required=True)
    p.add_argument("--output-dir",type=Path,required=True)
    p.add_argument("--authorize-optional-collection-agree-once",action="store_true")
    args=p.parse_args()
    state={
        "status":"unverified_no_action",
        "optional_data_collection_agree_tapped":False,
        "post_agree_screen_changed":False,
        "disagree_button_tapped":False,
        "secondary_popup_clicked":False,
        "account_registration_attempted":False,
        "nintendo_account_linking_attempted":False,
        "raw_screen_saved":False,
        "utid_saved":False,
    }
    out=args.output_dir
    def record():
        out.mkdir(parents=True,exist_ok=True)
        (out/"phase4_agree_status.json").write_text(
            json.dumps(state,indent=2,sort_keys=True)+"\n",encoding="utf8")
        print(json.dumps(state,sort_keys=True))
    try:
        if not args.authorize_optional_collection_agree_once:
            state["status"]="explicit_optional_collection_authorization_missing"
            record()
            return 2
        age=json.loads(args.age_report.read_text(encoding="utf8"))
        phase=json.loads(args.phase_report.read_text(encoding="utf8"))
        if not phase4_capture_allowed(
                combine_age_and_phase_reports(age,phase)):
            state["status"]="original_native_phase4_guard_failed"
            record()
            return 3

        def screenshot() -> bytes:
            focus=str(terms.adb(None,"shell","dumpsys","window"))
            if not terms.home_is_foreground(focus):
                raise RuntimeError("home_not_foreground")
            return terms.adb(None,"exec-out","screencap","-p",binary=True)

        before=screenshot()
        target=verified_phase4_agree_point(before)
        if target is None:
            state["status"]="unexpected_original_phase4_ui_no_action"
            record()
            return 3
        if not terms.save_masked_consent_screen(
                out/"phase4_agree_before_masked.png",before):
            state["status"]="mask_failure_no_action"
            record()
            return 3
        fresh=screenshot()
        if verified_phase4_agree_point(fresh)!=target:
            state["status"]="screen_changed_before_agree_no_action"
            record()
            return 3

        # Exactly one click on RIGHT 「同意」, authorized by user.
        terms.adb(None,"shell","input","tap",str(target[0]),str(target[1]))
        state["optional_data_collection_agree_tapped"]=True
        time.sleep(6)
        try:
            after=screenshot()
            state["post_agree_screen_changed"]=(
                verified_phase4_agree_point(after) is None
                and substantial_page_transition(fresh,after))
        except Exception as exc:
            state["post_click_observation_error_type"]=type(exc).__name__
        state["status"]=(
            "original_phase4_optional_collection_agree_tapped_new_screen"
            if state["post_agree_screen_changed"]
            else "original_phase4_agree_tapped_transition_unverified")
        record()
        return 0 if state["post_agree_screen_changed"] else 3
    except Exception as exc:
        state["status"]="phase4_optional_agree_stopped"
        state["error_type"]=type(exc).__name__
        record()
        return 3


if __name__=="__main__":
    raise SystemExit(main())
