#!/usr/bin/env python3
"""One original HOME 4.1.0 final guest confirmation: RIGHT orange button.

User already authorized a single guest signup and permanent Nintendo no-link.
This action MAY initiate actual server registration on a DISPOSABLE GitHub AVD;
the resulting guest session is not retained for user access.

Strict eligibility: original FirstBoot native GoToPhase(23), first guest
confirmation clicked, native First callback >=1, native Second callback 0,
registration request/response 0, first_basic false, and the EXACT original
Chinese modal screenshot. Click only the right "以游客身份开始使用" once.
Do not export token, raw UTID, backend responses or post-signup images.
"""
from __future__ import annotations

import argparse
import io
import json
import time
from pathlib import Path

import home41_terms_probe as terms
from home41_guest_after_first_visual import eligible_after_first
from home41_terms_checkbox_ab import rgb_near
from home41_terms_both_and_next import substantial_page_transition


def final_guest_start_point(png: bytes) -> tuple[int, int] | None:
    """Original #42550641554, 1080x2340 Chinese modal, fail closed."""
    if not png.startswith(terms.PNG_MAGIC):
        return None
    try:
        from PIL import Image
        with Image.open(io.BytesIO(png)) as original:
            image = original.convert("RGB")
        w, h = image.size
        if (w, h) != (1080, 2340):
            return None
        pixel = lambda x,y: image.getpixel((int(w*x),int(h*y)))
        # Darkened HOME FirstBoot behind an original pure-white dialog.
        landmarks = (
            (.50,.15,(11,53,44),20),       # dark teal original header
            (.50,.17,(11,53,44),20),
            (.50,.30,(247,250,246),14),    # modal white
            (.50,.36,(247,251,247),14),
            (.50,.46,(241,164,146),20),    # original orange-red text
            (.50,.60,(243,251,247),16),
            (.50,.63,(243,251,247),16),
            (.50,.675,(247,251,247),14),
            (.25,.695,(247,251,247),14),   # LEFT white "关闭"
            (.25,.72,(247,251,247),14),
            (.62,.695,(255,173,4),14),     # RIGHT orange start as guest
            (.76,.718,(255,173,4),14),
            (.76,.725,(255,173,4),14),
            (.85,.72,(255,173,4),14),
            (.93,.70,(247,251,247),14),   # outside orange
            (.50,.80,(73,74,72),24),      # dark overlay below modal
        )
        if not all(rgb_near(pixel(x,y),color,tolerance)
                   for x,y,color,tolerance in landmarks):
            return None
        # Ensure both actual large buttons, including their different caption
        # colors, not an unrelated small notification with similar colors.
        right = image.crop((
            int(w*.55),int(h*.69),int(w*.90),int(h*.735)))
        left = image.crop((
            int(w*.10),int(h*.69),int(w*.40),int(h*.735)))
        orange = sum(
            r>245 and 151<=g<=194 and b<60
            for r,g,b in right.getdata())
        bright_caption = sum(
            r>245 and g>239 and b>205
            for r,g,b in right.getdata())
        gray_caption = sum(
            max(p)<190 for p in left.getdata())
        if not (18000<=orange<=35000 and
                4500<=bright_caption<=17500 and
                400<=gray_caption<=5000):
            return None
        # Right orange: safely below its text and fully inside button.
        return (int(w*.76),int(h*.72))
    except (OSError, ValueError, ImportError):
        return None


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--age-report",type=Path,required=True)
    parser.add_argument("--phase-report",type=Path,required=True)
    parser.add_argument("--output-dir",type=Path,required=True)
    parser.add_argument("--authorize-original-final-guest-once",
                        action="store_true")
    args=parser.parse_args()
    status={
        "status":"not_authorized_no_action",
        "final_guest_button_tapped":False,
        "post_click_screen_changed":False,
        "close_button_tapped":False,
        "nintendo_link_tapped":False,
        "other_ui_tapped":False,
        "raw_postclick_screenshot_saved":False,
        "utid_saved":False,
        "token_saved":False,
    }
    out=args.output_dir
    def record():
        out.mkdir(parents=True,exist_ok=True)
        (out/"guest_final_once_status.json").write_text(
            json.dumps(status,ensure_ascii=False,sort_keys=True,indent=2)+"\n",
            encoding="utf-8")
        print(json.dumps(status,sort_keys=True))
    try:
        if not args.authorize_original_final_guest_once:
            record()
            return 2
        age=json.loads(args.age_report.read_text(encoding="utf-8"))
        phase=json.loads(args.phase_report.read_text(encoding="utf-8"))
        if not eligible_after_first(age,phase):
            status["status"]="native_first_guest_registration_gate_failed"
            record()
            return 3
        visual=phase.get("after_first_visual")
        if not (isinstance(visual,dict)
                and visual.get("native_pre_registration_confirmed") is True
                and visual.get("masked_image_saved") is True
                and visual.get("buttons_detail_saved") is True
                and visual.get("ui_clicked") is False):
            status["status"]="original_second_guest_modal_visual_not_verified"
            record()
            return 3
        def live_frame() -> bytes:
            if not terms.home_is_foreground(
                    str(terms.adb(None,"shell","dumpsys","window"))):
                raise RuntimeError("home_not_foreground")
            return terms.adb(None,"exec-out","screencap","-p",binary=True)
        before=live_frame()
        target=final_guest_start_point(before)
        if target is None:
            status["status"]="unknown_second_guest_modal_no_click"
            record()
            return 3
        if not terms.save_masked_consent_screen(
                out/"before_final_guest_masked.png",before):
            status["status"]="original_second_modal_mask_failed_no_click"
            record()
            return 3
        fresh=live_frame()
        if final_guest_start_point(fresh)!=target:
            status["status"]="second_guest_modal_changed_before_click"
            record()
            return 3
        # The only UI action in this module. Never retry after this point.
        terms.adb(None,"shell","input","tap",str(target[0]),str(target[1]))
        status["final_guest_button_tapped"]=True
        time.sleep(9)
        # Post-click pixels may be personally identifying; compare in RAM
        # to determine visual transition, and DO NOT save or log the image.
        try:
            after=live_frame()
            status["post_click_screen_changed"]=(
                final_guest_start_point(after) is None
                and substantial_page_transition(fresh,after))
        except Exception as exc:
            status["post_click_observation_error_type"]=type(exc).__name__
        status["status"]=(
            "original_guest_final_start_tapped_new_screen"
            if status["post_click_screen_changed"]
            else "original_guest_final_start_tapped_transition_unverified")
        record()
        return 0 if status["post_click_screen_changed"] else 3
    except Exception as exc:
        status["status"]="original_guest_final_start_experiment_stopped"
        status["error_type"]=type(exc).__name__
        record()
        return 3


if __name__=="__main__":
    raise SystemExit(main())
