#!/usr/bin/env python3
"""One explicit user-authorized official HOME 4.1.0 guest-start confirmation.

Clicks only the original right orange "是" on the verified page titled
"使用游客账号开始". This MAY initiate real guest registration on this disposable
GitHub-hosted emulator: the session cannot be recovered after the job ends.
Never submits any other UI, Nintendo Account login, API replay, request edits,
account deletion or repeated signup. Does not save a post-registration image,
UTID, tokens, private session, or any server response body.

The caller must retain the read-only Frida agent to observe registration/basic
method COUNT and presence, not their contents.
"""
from __future__ import annotations

import argparse
import io
import json
import time
from pathlib import Path

import home41_terms_probe as terms
from home41_guest_confirmation_visual import guest_visual_allowed
from home41_terms_checkbox_ab import rgb_near
from home41_terms_both_and_next import substantial_page_transition


def verified_original_guest_yes_point(png: bytes) -> tuple[int, int] | None:
    if not png.startswith(terms.PNG_MAGIC):
        return None
    try:
        from PIL import Image
        with Image.open(io.BytesIO(png)) as raw:
            img = raw.convert("RGB")
        w, h = img.size
        if (w, h) != (1080, 2340):
            return None
        p = lambda x, y: img.getpixel((int(w*x), int(h*y)))
        # HOME 4.1.0 Chinese guest confirmation screen; real 2-run
        # corroboration from Actions #42547016591 and #42547739283.
        samples = (
            (.50,.15,(38,179,151),16),   # "使用游客账号开始" teal header
            (.50,.17,(38,179,151),16),
            (.50,.22,(255,255,244),18),
            (.04,.205,(235,94,65),17),   # original irreversible red warning
            (.96,.25,(235,94,65),17),
            (.50,.28,(196,245,166),24),
            (.50,.70,(248,250,245),15), # disabled feature list panel
            (.50,.745,(248,250,245),15),
            (.25,.975,(247,251,247),17),# LEFT "否" button
            (.75,.975,(255,173,4),17),  # RIGHT "是" button
            (.75,.985,(255,243,218),35),
        )
        if not all(rgb_near(p(x,y),v,tol) for x,y,v,tol in samples):
            return None
        # Reject other screens with the same colored buttons. The original
        # left "否" has gray text, right "是" has white text.
        left = img.crop((int(w*.22),int(h*.978),
                         int(w*.32),int(h*.989))).convert("L")
        right = img.crop((int(w*.70),int(h*.978),
                          int(w*.80),int(h*.989))).convert("L")
        left_dark = sum(v<205 for v in left.getdata())
        right_light = sum(v>240 for v in right.getdata())
        if not (120 <= left_dark <= 1200 and
                75 <= right_light <= 1000):
            return None
        return (810, 2280)
    except (OSError, ValueError, ImportError):
        return None


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--age-report",type=Path,required=True)
    p.add_argument("--phase-report",type=Path,required=True)
    p.add_argument("--output-dir",type=Path,required=True)
    p.add_argument("--user-authorized-original-guest-yes-once",
                   action="store_true")
    args=p.parse_args()
    status = {
        "status": "not_armed_no_action",
        "guest_yes_tapped": False,
        "post_click_screen_changed": False,
        "guest_no_tapped": False,
        "nintendo_link_tapped": False,
        "additional_signup_ui_tapped": False,
        "raw_post_click_image_saved": False,
        "token_saved": False,
        "utid_saved": False,
    }
    def record():
        args.output_dir.mkdir(parents=True,exist_ok=True)
        (args.output_dir/"guest_yes_once_status.json").write_text(
            json.dumps(status,ensure_ascii=False,indent=2,sort_keys=True)+"\n",
            encoding="utf-8")
        print(json.dumps(status,sort_keys=True))
    try:
        if not args.user_authorized_original_guest_yes_once:
            record()
            return 2
        age=json.loads(args.age_report.read_text(encoding="utf-8"))
        phase=json.loads(args.phase_report.read_text(encoding="utf-8"))
        if not guest_visual_allowed(age,phase):
            status["status"]="original_guest_native_gate_failed"
            record()
            return 3
        visual=phase.get("guest_confirmation_visual",{})
        if (not isinstance(visual,dict)
                or visual.get("gest_request_proven") is not True
                or visual.get("masked_image_saved") is not True
                or visual.get("buttons_detail_saved") is not True
                or visual.get("next_screen_clicked") is not False):
            status["status"]="original_guest_yes_visual_prerequisite_not_met"
            record()
            return 3
        def screenshot() -> bytes:
            focus=str(terms.adb(None,"shell","dumpsys","window"))
            if not terms.home_is_foreground(focus):
                raise RuntimeError("home_not_foreground")
            return terms.adb(None,"exec-out","screencap","-p",binary=True)
        before=screenshot()
        target=verified_original_guest_yes_point(before)
        if target is None:
            status["status"]="unknown_guest_yes_page_no_tap"
            record()
            return 3
        if not terms.save_masked_consent_screen(
                args.output_dir/"guest_before_masked.png",before):
            status["status"]="cannot_mask_pre_guest_screen"
            record()
            return 3
        fresh=screenshot()
        if verified_original_guest_yes_point(fresh)!=target:
            status["status"]="guest_yes_page_changed_no_tap"
            record()
            return 3
        # Exactly one original official RIGHT orange "是".
        terms.adb(None,"shell","input","tap",str(target[0]),str(target[1]))
        status["guest_yes_tapped"]=True
        time.sleep(8)
        try:
            after=screenshot()
            status["post_click_screen_changed"]=(
                verified_original_guest_yes_point(after) is None
                and substantial_page_transition(fresh,after))
        except Exception as exc:
            status["post_click_observation_error_type"]=type(exc).__name__
        status["status"]=(
            "guest_yes_tapped_new_screen"
            if status["post_click_screen_changed"]
            else "guest_yes_tapped_transition_not_verified")
        # Never save, upload, or include the post-click screenshot: from here
        # forward the server may have created actual guest account data.
        record()
        return 0 if status["post_click_screen_changed"] else 3
    except Exception as exc:
        status["status"]="guest_yes_one_shot_stopped"
        status["error_type"]=type(exc).__name__
        record()
        return 3


if __name__=="__main__":
    raise SystemExit(main())
