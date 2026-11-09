#!/usr/bin/env python3
"""Read-only screenshot of the original HOME guest confirmation stage.

Requires proof of a *new* native GoToPhase(23)=GEST_CONFIRMATION request
immediately after a user-approved one-shot "不关联" click. The requested
phase is NOT presumed to be the currently rendered one.

The screenshot is system-bar-masked. This script DOES NOT click the guest
confirmation screen or perform account initialization, login, Nintendo Account
linkage, session export, UTID extraction or API calls.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import home41_terms_probe as terms
from home41_post_phase4_agree_screen import capture_allowed as prior_gate


def guest_visual_allowed(age: object, phase: object) -> bool:
    if not prior_gate(age, phase):
        return False
    if not isinstance(phase, dict):
        return False
    screenshot = phase.get("phase7_screen_capture")
    choice = phase.get("nintendo_no_link_probe")
    native = phase.get("post_no_link_native")
    prior = phase.get("post_phase4_agree_native")
    if not all(isinstance(item, dict)
               for item in (screenshot, choice, native, prior)):
        return False
    prev = native.get("go_to_phase_entries_before")
    after = native.get("go_to_phase_entries_after")
    if not (type(prev) is int and type(after) is int
            and 0 <= prev < after <= 100000
            and prev == prior.get("go_to_phase_entries_after")):
        return False
    registration = native.get("registration_serializer_entries")
    basic = native.get("first_basic_seen")
    # For new post-2026-11-09 reports these are mandatory live hook readings,
    # not constant statements of what the test was intended to do.
    if type(registration) is not int or registration != 0 or basic is not False:
        return False
    return all((
        screenshot.get("phase7_requested") is True,
        screenshot.get("masked_image_saved") is True,
        choice.get("status") == "original_no_link_tapped_new_screen",
        choice.get("original_no_link_button_tapped") is True,
        choice.get("post_click_screen_changed") is True,
        choice.get("nintendo_link_button_tapped") is False,
        choice.get("further_confirmation_tapped") is False,
        choice.get("registration_button_tapped") is False,
        native.get("status") == "original_phase_requested_after_no_link",
        native.get("native_arm64") is True,
        native.get("hooks_ready") is True,
        type(native.get("last_requested_phase_index")) is int,
        native.get("last_requested_phase_index") == 23,
        native.get("last_requested_phase_name") == "GEST_CONFIRMATION",
        native.get("nintendo_link_button_tapped") is False,
        native.get("registration_button_tapped") is False,
        native.get("utid_saved") is False,
    ))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--age-report", required=True, type=Path)
    parser.add_argument("--phase-report", required=True, type=Path)
    parser.add_argument("--image-out", required=True, type=Path)
    parser.add_argument("--status-out", required=True, type=Path)
    args = parser.parse_args()

    status = {
        "status": "guest_confirmation_capture_gate_refused",
        "original_gest_confirmation_request_proven": False,
        "guest_confirmation_screen_identified": False,
        "masked_screenshot_saved": False,
        "next_screen_clicked": False,
        "nintendo_account_linked": False,
        "guest_registration_attempted": False,
        "utid_observed": False,
        "raw_screen_saved": False,
    }
    try:
        age = json.loads(args.age_report.read_text(encoding="utf-8"))
        phase = json.loads(args.phase_report.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        age, phase = {}, {}
    allowed = guest_visual_allowed(age, phase)
    status["original_gest_confirmation_request_proven"] = allowed
    if allowed:
        try:
            focus = str(terms.adb(None, "shell", "dumpsys", "window"))
            if not terms.home_is_foreground(focus):
                status["status"] = "home_not_foreground_no_capture"
            else:
                png = terms.adb(None, "exec-out", "screencap", "-p", binary=True)
                if terms.save_masked_consent_screen(args.image_out, png):
                    status["status"] = "masked_screen_after_guest_request_saved"
                    status["masked_screenshot_saved"] = True
                else:
                    status["status"] = "invalid_image_not_saved"
        except Exception as exc:
            status["status"] = "adb_capture_exception"
            status["error_type"] = type(exc).__name__
    args.status_out.parent.mkdir(parents=True, exist_ok=True)
    args.status_out.write_text(
        json.dumps(status, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    print(json.dumps(status, ensure_ascii=False, sort_keys=True))
    return 0 if status["masked_screenshot_saved"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
