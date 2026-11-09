#!/usr/bin/env python3
"""Read-only masked screen AFTER original Phase 4 "不同意" once.

Capture ONLY when the same native Frida agent reports Phase 4 after decline,
with a prior verified click and changed Unity screen. Never interact again
and never capture any registered-account session or sensitive API payloads.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import home41_terms_probe as terms


def capture_gate(age: object, phase: object) -> bool:
    if not isinstance(age,dict) or not isinstance(phase,dict):
        return False
    if not all(age.get(key) is True for key in (
        "process_at_end","birthday_native_preflight_passed",
        "birthday_next_tapped","post_next_screen_changed",
    )):
        return False
    if (age.get("registration_status")!="not_attempted" or
            age.get("first_basic_utid_status")!="not_observed"):
        return False
    if phase.get("status")!="phase_4_advertisement_sdk_confirmed":
        return False
    before=phase.get("native_phase")
    click=phase.get("phase4_decline_probe")
    after=phase.get("post_phase4_native")
    if not all(isinstance(x,dict) for x in (before,click,after)):
        return False
    return all((
        before.get("native_arm64") is True,
        before.get("hooks_ready") is True,
        type(before.get("current_phase_index")) is int,
        before.get("current_phase_index")==4,
        before.get("current_phase_name")=="ADVERTISEMENT_SDK",
        click.get("decline_button_tapped") is True,
        click.get("post_decline_screen_changed") is True,
        click.get("agree_button_tapped") is False,
        click.get("account_registration_attempted") is False,
        after.get("native_arm64") is True,
        after.get("hooks_ready") is True,
        type(after.get("current_phase_index")) is int,
        after.get("current_phase_index")==4,
        after.get("current_phase_name")=="ADVERTISEMENT_SDK",
        type(after.get("last_requested_phase_index")) is int,
        after.get("last_requested_phase_index")==4,
        after.get("account_registration_attempted") is False,
        after.get("nintendo_account_linking_attempted") is False,
        after.get("utid_saved") is False,
    ))


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--age-report",type=Path,required=True)
    p.add_argument("--phase-report",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--status",type=Path,required=True)
    args=p.parse_args()
    state={
        "status":"post_decline_visual_gate_rejected",
        "post_decline_original_phase4_confirmed":False,
        "masked_screenshot_saved":False,
        "screen_clicked":False,
        "account_registration_attempted":False,
        "nintendo_account_linking_attempted":False,
        "raw_screenshot_saved":False,
    }
    try:
        age=json.loads(args.age_report.read_text(encoding="utf8"))
        phase=json.loads(args.phase_report.read_text(encoding="utf8"))
    except (ValueError,OSError):
        age,phase={},{}
    allowed=capture_gate(age,phase)
    state["post_decline_original_phase4_confirmed"]=allowed
    if allowed:
        try:
            focus=str(terms.adb(None,"shell","dumpsys","window"))
            if not terms.home_is_foreground(focus):
                state["status"]="home_not_foreground_no_capture"
            else:
                pixels=terms.adb(None,"exec-out","screencap","-p",binary=True)
                if terms.save_masked_consent_screen(args.output,pixels):
                    state["masked_screenshot_saved"]=True
                    state["status"]="verified_original_phase4_post_decline_masked_screen"
                else:
                    state["status"]="invalid_image_no_capture"
        except Exception as exc:
            state["status"]="adb_screen_capture_unavailable"
            state["error_type"]=type(exc).__name__
    args.status.parent.mkdir(parents=True,exist_ok=True)
    args.status.write_text(json.dumps(state,indent=2,sort_keys=True)+"\n",
                           encoding="utf8")
    print(json.dumps(state,sort_keys=True))
    return 0 if state["masked_screenshot_saved"] else 3


if __name__=="__main__":
    raise SystemExit(main())
