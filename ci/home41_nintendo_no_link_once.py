#!/usr/bin/env python3
"""ONE explicit user-authorized original HOME "不关联" choice.

The user accepted the official irreversible warning that this HOME account
cannot link a Nintendo Account later. This is ONLY a fresh disposable AVD
experiment, not a persistent account creation workflow. Strictly verify:
  - native ARM64 original GoToPhase(7) request after official Phase4 Agree;
  - real Chinese Nintendo Account page including orange top "关联",
    grey-white lower "不关联", and bordered warning region;
  - unchanged HOME foreground and two matching fresh screenshots.
Click the LOWER "不关联" only once, then stop. No further confirmation,
nickname, avatar, starter, Nintendo login or account registration clicks.
"""
from __future__ import annotations

import argparse
import io
import json
import time
from pathlib import Path

from home41_post_phase4_agree_screen import capture_allowed
from home41_terms_checkbox_ab import rgb_near
from home41_terms_both_and_next import substantial_page_transition
import home41_terms_probe as terms


def verified_no_link_point(pixels: bytes) -> tuple[int, int] | None:
    """Reference: original 1080x2340 Chinese HOME view, Actions #42542835109."""
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
        # Robust first-party samples from the original proven screenshot.
        samples=(
            (.5,.15,(38,179,151),16),      # header: 关联Nintendo Account
            (.5,.18,(200,242,160),23),     # header background
            (.5,.28,(18,166,168),13),      # official Switch feature panel
            (.5,.50,(18,166,168),13),
            (.04,.70,(235,94,65),16),      # red irreversible warning border
            (.96,.70,(235,94,65),16),
            (.5,.86,(248,170,4),14),       # UPPER "关联" orange
            (.5,.88,(248,170,4),14),
            (.2,.94,(240,246,236),14),     # LOWER "不关联" gray-white
            (.8,.94,(240,246,236),14),
            (.2,.955,(240,246,236),14),
            (.8,.955,(240,246,236),14),
        )
        if not all(rgb_near(p(x,y),value,tol)
                   for x,y,value,tol in samples):
            return None
        # At least some gray Chinese label strokes must actually be inside
        # the LOWER button. This is not OCR and saves no raw text.
        roi=image.crop((
            int(w*.38),int(h*.947),int(w*.62),int(h*.958)))
        dark=sum(v<175 for v in roi.convert("L").getdata())
        if not 400<=dark<=1800:
            return None
        # Hard-coded center of the LOWER gray-white "不关联" button.
        return (540,2235)
    except (ValueError,OSError,ImportError):
        return None


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--age-report",type=Path,required=True)
    p.add_argument("--phase-report",type=Path,required=True)
    p.add_argument("--output-dir",type=Path,required=True)
    p.add_argument("--authorize-irreversible-no-link-once",
                   action="store_true")
    args=p.parse_args()
    state={
        "status":"preflight_refused",
        "user_confirmed_irreversible_no_link":bool(
            args.authorize_irreversible_no_link_once),
        "original_no_link_button_tapped":False,
        "post_click_screen_changed":False,
        "nintendo_link_button_tapped":False,
        "further_confirmation_tapped":False,
        "registration_button_tapped":False,
        "starter_selected":False,
        "utid_saved":False,
        "unknown_post_click_image_saved":False,
    }
    out=args.output_dir
    def write():
        out.mkdir(parents=True,exist_ok=True)
        (out/"no_link_once_status.json").write_text(
            json.dumps(state,indent=2,sort_keys=True)+"\n",encoding="utf8")
        print(json.dumps(state,sort_keys=True))
    try:
        if not args.authorize_irreversible_no_link_once:
            state["status"]="explicit_irreversible_confirmation_not_provided"
            write()
            return 2
        age=json.loads(args.age_report.read_text(encoding="utf8"))
        phase=json.loads(args.phase_report.read_text(encoding="utf8"))
        if not capture_allowed(age,phase):
            state["status"]="native_phase7_request_preflight_failed"
            write()
            return 3
        def screenshot() -> bytes:
            focus=str(terms.adb(None,"shell","dumpsys","window"))
            if not terms.home_is_foreground(focus):
                raise RuntimeError("original_home_not_foreground")
            return terms.adb(None,"exec-out","screencap","-p",binary=True)
        before=screenshot()
        target=verified_no_link_point(before)
        if target is None:
            state["status"]="unknown_original_nintendo_choice_page_no_action"
            write()
            return 3
        if not terms.save_masked_consent_screen(
                out/"no_link_before_masked.png",before):
            state["status"]="masking_failed_no_action"
            write()
            return 3
        fresh=screenshot()
        if verified_no_link_point(fresh)!=target:
            state["status"]="original_choice_page_changed_before_click"
            write()
            return 3
        # Only user-authorized irreversible LOWER "不关联" ONCE.
        terms.adb(None,"shell","input","tap",str(target[0]),str(target[1]))
        state["original_no_link_button_tapped"]=True
        time.sleep(6)
        try:
            after=screenshot()
            state["post_click_screen_changed"]=(
                verified_no_link_point(after) is None
                and substantial_page_transition(fresh,after))
        except Exception as exc:
            state["post_click_observation_error_type"]=type(exc).__name__
        state["status"]=(
            "original_no_link_tapped_new_screen"
            if state["post_click_screen_changed"]
            else "original_no_link_tapped_transition_not_verified")
        write()
        return 0 if state["post_click_screen_changed"] else 3
    except Exception as exc:
        state["status"]="original_no_link_experiment_stopped"
        state["error_type"]=type(exc).__name__
        write()
        return 3


if __name__=="__main__":
    raise SystemExit(main())
