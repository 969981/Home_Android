#!/usr/bin/env python3
"""Read-only original HOME screen after first official guest Yes confirmation.

Requires that the same retained ARM64 observer confirms First guest method
has executed, Second has not, registration serializer/response are both zero,
and first_basic has NOT been seen. Thus only a pre-registration UI is
eligible. No taps, API calls, tokens, UTID or post-registration screen logs.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import home41_terms_probe as terms
from home41_guest_confirmation_visual import guest_visual_allowed
from home41_guest_confirmation_visual import save_guest_buttons_detail


def eligible_after_first(age: object, report: object) -> bool:
    if not guest_visual_allowed(age, report):
        return False
    if not isinstance(report, dict):
        return False
    click = report.get("guest_start_probe")
    native = report.get("post_guest_start_native")
    if not isinstance(click, dict) or not isinstance(native, dict):
        return False
    numeric = (
        "registration_serializer_entries",
        "registration_response_handler_entries",
        "first_basic_utid_event_count",
        "guest_confirmation_method_entries",
        "guest_first_method_entries",
        "guest_second_method_entries",
    )
    if any(type(native.get(k)) is not int for k in numeric):
        return False
    return all((
        click.get("status") == "guest_yes_tapped_new_screen",
        click.get("guest_yes_tapped") is True,
        click.get("post_click_screen_changed") is True,
        click.get("nintendo_link_tapped") is False,
        click.get("additional_signup_ui_tapped") is False,
        click.get("token_saved") is False,
        native.get("native_arm64") is True,
        native.get("hooks_ready") is True,
        native.get("registration_serializer_entries") == 0,
        native.get("registration_response_handler_entries") == 0,
        native.get("first_basic_seen") is False,
        native.get("first_basic_utid_event_count") == 0,
        native.get("guest_confirmation_method_entries") >= 1,
        native.get("guest_first_method_entries") >= 1,
        native.get("guest_second_method_entries") == 0,
        native.get("raw_utid_saved") is False,
        native.get("token_saved") is False,
        native.get("account_persisted_verified") is False,
        native.get("registration_completed_verified") is False,
    ))


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--age-report",type=Path,required=True)
    p.add_argument("--phase-report",type=Path,required=True)
    p.add_argument("--image-out",type=Path,required=True)
    p.add_argument("--buttons-out",type=Path,required=True)
    p.add_argument("--status-out",type=Path,required=True)
    args=p.parse_args()
    status={
        "status":"post_first_guest_capture_rejected",
        "native_pre_registration_confirmed":False,
        "masked_image_saved":False,
        "buttons_detail_saved":False,
        "ui_clicked":False,
        "registration_attempted":False,
        "utid_saved":False,
        "token_saved":False,
        "raw_screenshot_saved":False,
    }
    try:
        age=json.loads(args.age_report.read_text(encoding="utf8"))
        report=json.loads(args.phase_report.read_text(encoding="utf8"))
    except (OSError,ValueError):
        age,report={},{}
    allowed=eligible_after_first(age,report)
    status["native_pre_registration_confirmed"]=allowed
    if allowed:
        try:
            if not terms.home_is_foreground(
                    str(terms.adb(None,"shell","dumpsys","window"))):
                status["status"]="home_focus_lost_no_capture"
            else:
                png=terms.adb(None,"exec-out","screencap","-p",binary=True)
                if terms.save_masked_consent_screen(args.image_out,png):
                    status["masked_image_saved"]=True
                    status["buttons_detail_saved"]=save_guest_buttons_detail(
                        args.buttons_out,png)
                    status["status"]="post_first_guest_screen_masked_only"
                else:
                    status["status"]="invalid_image_no_capture"
        except Exception as exc:
            status["status"]="adb_capture_failed"
            status["error_type"]=type(exc).__name__
    args.status_out.parent.mkdir(parents=True,exist_ok=True)
    args.status_out.write_text(
        json.dumps(status,sort_keys=True,indent=2)+"\n",encoding="utf8")
    print(json.dumps(status,sort_keys=True))
    return 0 if status["masked_image_saved"] else 3


if __name__=="__main__":
    raise SystemExit(main())
