#!/usr/bin/env python3
"""Capture only a masked visual of the verified original HOME Phase 4 screen.

Read-only, no clicks, no registration, no consent changes, no raw screenshot.
The gate requires the same native ARM64 evidence that proved the Phase 3->4
transition in the original signed HOME 4.1.0 APK.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import home41_terms_probe as terms


def combine_age_and_phase_reports(age_report: object, phase_report: object) -> dict:
    """Explicitly combine the TWO separate original CI evidence outputs.

    The phase probe is written only AFTER diag.run saves the age report.
    Never assume the earlier age report contains post_terms_phase_probe.
    Reject malformed/forged nested probe data and copy no user payloads.
    """
    age = age_report if isinstance(age_report, dict) else {}
    phase = phase_report if isinstance(phase_report, dict) else {}
    return {
        "process_at_end": age.get("process_at_end"),
        "registration_status": age.get("registration_status"),
        "account_registration": age.get("account_registration"),
        "birthday_native_preflight_passed":
            age.get("birthday_native_preflight_passed"),
        "birthday_next_tapped": age.get("birthday_next_tapped"),
        "post_next_screen_changed": age.get("post_next_screen_changed"),
        "post_terms_phase_probe": phase,
    }


def phase4_capture_allowed(report: object) -> bool:
    if not isinstance(report,dict):
        return False
    if report.get("process_at_end") is not True:
        return False
    if not all(report.get(key) is True for key in (
        "birthday_native_preflight_passed", "birthday_next_tapped",
        "post_next_screen_changed",
    )):
        return False
    if report.get("registration_status") not in (None,"not_attempted"):
        return False
    if report.get("account_registration") not in (None,"not_attempted"):
        return False
    probe=report.get("post_terms_phase_probe")
    if not isinstance(probe,dict):
        return False
    if probe.get("status")!="phase_4_advertisement_sdk_confirmed":
        return False
    if probe.get("terms_ui",{}).get("terms_next_tapped") is not True:
        return False
    if probe.get("terms_ui",{}).get("post_terms_page_changed") is not True:
        return False
    phase=probe.get("native_phase")
    if not isinstance(phase,dict):
        return False
    return all((
        phase.get("native_arm64") is True,
        phase.get("hooks_ready") is True,
        phase.get("firstboot_controller_seen") is True,
        phase.get("phase_mapping_verified") is True,
        phase.get("current_phase_index")==4,
        phase.get("current_phase_name")=="ADVERTISEMENT_SDK",
        phase.get("last_requested_phase_index")==4,
        phase.get("last_requested_phase_name")=="ADVERTISEMENT_SDK",
        phase.get("go_to_phase_hook_attached") is True,
        phase.get("advertisement_sdk_hook_attached") is True,
        type(phase.get("advertisement_sdk_method_entries")) is int,
        phase.get("advertisement_sdk_method_entries")>0,
        type(phase.get("go_to_phase_entries")) is int,
        phase.get("go_to_phase_entries")>0,
        phase.get("account_registration_attempted") is False,
        phase.get("nintendo_account_linking_attempted") is False,
        phase.get("utid_saved") is False,
        phase.get("http_body_saved") is False,
        phase.get("raw_screen_saved") is False,
    ))


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report",type=Path,required=True,
                   help="Saved age report, home41_emulator_report.json")
    p.add_argument("--phase-report",type=Path,required=True,
                   help="Separate home41_post_terms_phase_report.json")
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--status",type=Path,required=True)
    args=p.parse_args()
    state={
        "status":"phase4_capture_gate_rejected",
        "phase4_advertisement_sdk_confirmed":False,
        "masked_screenshot_saved":False,
        "raw_screenshot_saved":False,
        "ui_clicked":False,
        "registration_attempted":False,
        "nintendo_account_linking_attempted":False,
        "utid_saved":False,
    }
    try:
        age=json.loads(args.report.read_text(encoding="utf8"))
        phase=json.loads(args.phase_report.read_text(encoding="utf8"))
        report=combine_age_and_phase_reports(age,phase)
    except (OSError,ValueError):
        report={}
    allowed=phase4_capture_allowed(report)
    state["phase4_advertisement_sdk_confirmed"]=allowed
    if allowed:
        try:
            focus=str(terms.adb(None,"shell","dumpsys","window"))
            if not terms.home_is_foreground(focus):
                state["status"]="home_not_foreground_no_capture"
            else:
                pixels=terms.adb(None,"exec-out","screencap","-p",binary=True)
                if terms.save_masked_consent_screen(args.output,pixels):
                    state["masked_screenshot_saved"]=True
                    state["status"]="verified_phase4_masked_visual_saved"
                else:
                    state["status"]="invalid_image_no_capture"
        except Exception as exc:
            state["status"]="phase4_capture_unavailable"
            state["error_type"]=type(exc).__name__
    args.status.parent.mkdir(parents=True,exist_ok=True)
    args.status.write_text(json.dumps(state,indent=2,sort_keys=True)+"\n",encoding="utf8")
    print(json.dumps(state,sort_keys=True))
    return 0 if allowed else 3


if __name__=="__main__":
    raise SystemExit(main())
