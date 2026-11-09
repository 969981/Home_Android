#!/usr/bin/env python3
"""Confirm the official "不同意" Phase 4 popup by tapping its orange Next ONCE.

The original HOME Chinese popup explicitly states that the app remains usable
without optional usage/diagnostic data collection. No opt-in is selected.
Requires native ARM64 Phase4, previously proven opt-out click, and the exact
second-screen modal visual signature. The next unknown screen is NOT saved.
"""
from __future__ import annotations
import argparse
import io
import json
import time
from pathlib import Path

import home41_terms_probe as terms
from home41_phase4_post_decline_capture import capture_gate
from home41_terms_checkbox_ab import rgb_near
from home41_terms_both_and_next import substantial_page_transition


def official_decline_modal_next_point(pixels: bytes) -> tuple[int,int] | None:
    if not pixels.startswith(terms.PNG_MAGIC):
        return None
    try:
        from PIL import Image
        with Image.open(io.BytesIO(pixels)) as src:
            im=src.convert("RGB")
        w,h=im.size
        if (w,h)!=(1080,2340):
            return None
        p=lambda x,y: im.getpixel((int(w*x),int(h*y)))
        required=(
            (.5,.14,(23,107,91),17),       # darkened original HOME header
            (.5,.38,(247,251,247),12),     # white confirmation modal
            (.5,.50,(243,251,247),15),
            (.5,.70,(95,145,124),28),      # original darkened backdrop
            (.22,.60,(247,251,247),14),    # LEFT gray "返回" button
            (.28,.59,(247,251,247),14),
            (.70,.59,(255,173,4),14),      # RIGHT orange "下一步"
            (.70,.60,(255,173,4),14),
            (.70,.61,(255,173,4),14),
            (.70,.62,(255,173,4),14),
        )
        if not all(rgb_near(p(x,y),c,tol) for x,y,c,tol in required):
            return None
        # Orange button must occupy a substantial rounded rectangle.
        # This distinguishes it from a tiny tooltip or unrelated icon.
        region=im.crop((int(w*.58),int(h*.585),int(w*.85),int(h*.625)))
        orange=sum(
            v[0]>230 and 140<v[1]<205 and v[2]<50
            for v in region.getdata()
        )
        if orange<8500:
            return None
        return (int(w*.70),int(h*.605))
    except (OSError,ValueError,ImportError):
        return None


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--age-report",type=Path,required=True)
    p.add_argument("--phase-report",type=Path,required=True)
    p.add_argument("--output-dir",type=Path,required=True)
    p.add_argument("--confirm-previous-optout-once",action="store_true")
    args=p.parse_args()
    state={
        "status":"gate_rejected",
        "original_optout_modal_next_tapped":False,
        "post_modal_screen_changed":False,
        "opt_in_clicked":False,
        "nintendo_link_clicked":False,
        "account_registration_clicked":False,
        "utid_saved":False,
    }
    out=args.output_dir
    def record():
        out.mkdir(parents=True,exist_ok=True)
        (out/"phase4_modal_status.json").write_text(
            json.dumps(state,indent=2,sort_keys=True)+"\n",encoding="utf8")
        print(json.dumps(state,sort_keys=True))
    try:
        if not args.confirm_previous_optout_once:
            state["status"]="one_shot_optout_modal_confirmation_not_authorized"
            record()
            return 2
        age=json.loads(args.age_report.read_text(encoding="utf8"))
        phase=json.loads(args.phase_report.read_text(encoding="utf8"))
        if not capture_gate(age,phase):
            state["status"]="original_native_phase4_after_decline_unverified"
            record()
            return 3
        def frame() -> bytes:
            focus=str(terms.adb(None,"shell","dumpsys","window"))
            if not terms.home_is_foreground(focus):
                raise RuntimeError("home_not_foreground")
            return terms.adb(None,"exec-out","screencap","-p",binary=True)
        before=frame()
        target=official_decline_modal_next_point(before)
        if target is None:
            state["status"]="unknown_original_optout_modal_no_click"
            record()
            return 3
        if not terms.save_masked_consent_screen(out/"modal_before_masked.png",before):
            state["status"]="cannot_mask_original_modal_no_click"
            record()
            return 3
        fresh=frame()
        if official_decline_modal_next_point(fresh)!=target:
            state["status"]="modal_changed_before_click"
            record()
            return 3
        terms.adb(None,"shell","input","tap",str(target[0]),str(target[1]))
        state["original_optout_modal_next_tapped"]=True
        time.sleep(6)
        try:
            after=frame()
            state["post_modal_screen_changed"]=(
                official_decline_modal_next_point(after) is None
                and substantial_page_transition(fresh,after))
        except Exception as exc:
            state["post_click_observation_error_type"]=type(exc).__name__
        state["status"]=(
            "original_optout_modal_next_tapped_new_screen"
            if state["post_modal_screen_changed"]
            else "original_optout_modal_next_tapped_transition_unverified"
        )
        record()
        return 0 if state["post_modal_screen_changed"] else 3
    except Exception as exc:
        state["status"]="original_optout_modal_confirmation_stopped"
        state["error_type"]=type(exc).__name__
        record()
        return 3


if __name__=="__main__":
    raise SystemExit(main())
