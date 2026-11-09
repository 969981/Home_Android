#!/usr/bin/env python3
"""One guarded opt-out of optional HOME 4.1.0 app-usage data collection.

The verified Chinese official Phase 4 page states that declining collection
does not prevent Pokémon HOME use. This tool never clicks "同意", never binds
Nintendo Account, never registers an account, and never saves the unknown
post-decline page. It will tap "不同意" ONCE only after strict native and
original visual evidence checks.
"""
from __future__ import annotations

import argparse
import io
import json
import time
from pathlib import Path

from home41_phase4_masked_capture import (
    combine_age_and_phase_reports,phase4_capture_allowed)
import home41_terms_probe as terms
from home41_terms_checkbox_ab import rgb_near
from home41_terms_both_and_next import substantial_page_transition


def phase4_decline_point(pixels: bytes) -> tuple[int,int] | None:
    """Fixed 1080x2340 original HOME Phase 4; fail-closed on other layouts."""
    if not pixels.startswith(terms.PNG_MAGIC):
        return None
    try:
        from PIL import Image
        with Image.open(io.BytesIO(pixels)) as src:
            image=src.convert("RGB")
        w,h=image.size
        if (w,h)!=(1080,2340):
            return None
        p=lambda x,y:image.getpixel((int(w*x),int(h*y)))
        # Exact first-party Phase 4 Chinese page screenshot #42538845441.
        samples=(
            (.50,.14,(38,179,151),16),    # real teal section header
            (.50,.16,(38,179,151),16),
            (.50,.20,(207,247,166),22),   # light green details background
            (.50,.68,(158,239,203),24),
            (.25,.925,(247,251,247),12),  # LEFT white "不同意" button
            (.75,.925,(247,251,247),12),  # RIGHT white "同意" button
            (.25,.955,(247,251,247),12),
            (.75,.955,(247,251,247),12),
            (.50,.930,(163,245,220),25),  # colored gap between buttons
        )
        if not all(rgb_near(p(x,y),rgb,tol) for x,y,rgb,tol in samples):
            return None
        # Both button captions need visible grey label strokes. No OCR nor
        # arbitrary language text leaves this process.
        for x0,x1,min_dark,max_dark in (
            (.20,.34,1000,2300),(.67,.83,850,1900),
        ):
            pixels_roi=image.crop((
                int(w*x0),int(h*.93),int(w*x1),int(h*.956)))
            dark=sum(v<210 for v in pixels_roi.convert("L").getdata())
            if not min_dark<=dark<=max_dark:
                return None
        return (int(w*.25),int(h*.94))
    except (OSError,ValueError,ImportError):
        return None


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--age-report",type=Path,required=True)
    p.add_argument("--phase-report",type=Path,required=True)
    p.add_argument("--output-dir",type=Path,required=True)
    p.add_argument("--decline-optional-collection-once",action="store_true")
    args=p.parse_args()
    state={
        "status":"preflight_rejected",
        "decline_button_tapped":False,
        "post_decline_screen_changed":False,
        "agree_button_tapped":False,
        "account_registration_attempted":False,
        "nintendo_account_linking_attempted":False,
        "unknown_post_click_image_saved":False,
        "utid_saved":False,
    }
    out=args.output_dir
    def record():
        out.mkdir(parents=True,exist_ok=True)
        (out/"phase4_decline_status.json").write_text(
            json.dumps(state,indent=2,sort_keys=True)+"\n",encoding="utf8")
        print(json.dumps(state,sort_keys=True))
    try:
        if not args.decline_optional_collection_once:
            state["status"]="one_shot_optout_not_authorized"
            record()
            return 2
        age=json.loads(args.age_report.read_text(encoding="utf8"))
        phase=json.loads(args.phase_report.read_text(encoding="utf8"))
        if not phase4_capture_allowed(combine_age_and_phase_reports(age,phase)):
            state["status"]="native_phase4_guard_failed"
            record()
            return 3
        def live_screen() -> bytes:
            focus=str(terms.adb(None,"shell","dumpsys","window"))
            if not terms.home_is_foreground(focus):
                raise RuntimeError("home_focus_lost")
            return terms.adb(None,"exec-out","screencap","-p",binary=True)
        before=live_screen()
        target=phase4_decline_point(before)
        if target is None:
            state["status"]="unknown_phase4_visual_no_click"
            record()
            return 3
        if not terms.save_masked_consent_screen(out/"phase4_before_masked.png",before):
            state["status"]="masked_evidence_unavailable_no_click"
            record()
            return 3
        fresh=live_screen()
        if phase4_decline_point(fresh)!=target:
            state["status"]="visual_changed_no_click"
            record()
            return 3
        # Exactly one official LEFT "不同意"; never tap RIGHT "同意".
        terms.adb(None,"shell","input","tap",str(target[0]),str(target[1]))
        state["decline_button_tapped"]=True
        time.sleep(6)
        try:
            after=live_screen()
            state["post_decline_screen_changed"]=(
                phase4_decline_point(after) is None
                and substantial_page_transition(fresh,after))
        except Exception as ex:
            state["post_click_observation_error_type"]=type(ex).__name__
        state["status"]=(
            "original_phase4_decline_tapped_new_screen"
            if state["post_decline_screen_changed"]
            else "original_phase4_decline_tapped_transition_unverified")
        record()
        return 0 if state["post_decline_screen_changed"] else 3
    except Exception as exc:
        state["status"]="phase4_decline_stopped"
        state["error_type"]=type(exc).__name__
        record()
        return 3


if __name__=="__main__":
    raise SystemExit(main())
