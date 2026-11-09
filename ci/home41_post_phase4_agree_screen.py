#!/usr/bin/env python3
"""Read-only original HOME next rendered screen after user-authorized Phase4 Agree.

Capture gate proves original ARM64 GoToPhase requested 7=NA_LINK_CONTINUE
after one real right-hand Phase4 Agree. It does NOT claim Phase7's UI is
fully initialized: the old FirstBoot controller may already be destroyed.
No registration, Nintendo linking or UTID; only a system-bar-masked image.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import home41_terms_probe as terms


def capture_allowed(age: object, report: object) -> bool:
    if not isinstance(age,dict) or not isinstance(report,dict):
        return False
    if not all(age.get(k) is True for k in (
        "process_at_end","birthday_native_preflight_passed",
        "birthday_next_tapped","post_next_screen_changed"
    )):
        return False
    if age.get("registration_status")!="not_attempted":
        return False
    if age.get("first_basic_utid_status")!="not_observed":
        return False
    if report.get("status")!="phase_4_advertisement_sdk_confirmed":
        return False
    agree=report.get("phase4_agree_probe")
    after=report.get("post_phase4_agree_native")
    original=report.get("native_phase")
    if not all(isinstance(x,dict) for x in (agree,after,original)):
        return False
    before_go=after.get("go_to_phase_entries_before")
    after_go=after.get("go_to_phase_entries_after")
    return all((
        original.get("native_arm64") is True,
        original.get("hooks_ready") is True,
        original.get("current_phase_index")==4,
        original.get("current_phase_name")=="ADVERTISEMENT_SDK",
        agree.get("optional_data_collection_agree_tapped") is True,
        agree.get("post_agree_screen_changed") is True,
        agree.get("disagree_button_tapped") is False,
        agree.get("account_registration_attempted") is False,
        agree.get("nintendo_account_linking_attempted") is False,
        agree.get("utid_saved") is False,
        after.get("status") in (
            "native_phase_request_advanced_current_unreadable",
            "native_phase_current_confirmed",
        ),
        after.get("native_arm64") is True,
        after.get("hooks_ready") is True,
        type(after.get("last_requested_phase_index")) is int,
        after.get("last_requested_phase_index")==7,
        after.get("last_requested_phase_name")=="NA_LINK_CONTINUE",
        type(before_go) is int,
        type(after_go) is int,
        0<=before_go<after_go<=100000,
        after.get("account_registration_attempted") is False,
        after.get("nintendo_account_linking_attempted") is False,
        after.get("utid_saved") is False,
    ))


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--age-report",type=Path,required=True)
    p.add_argument("--phase-report",type=Path,required=True)
    p.add_argument("--image-out",type=Path,required=True)
    p.add_argument("--status-out",type=Path,required=True)
    args=p.parse_args()
    state={
        "status":"phase7_request_read_only_capture_rejected",
        "original_phase7_request_confirmed":False,
        "masked_image_saved":False,
        "new_screen_interacted":False,
        "current_phase7_ui_verified":False,
        "nintendo_account_linked":False,
        "account_registration_attempted":False,
        "raw_screen_saved":False,
        "utid_saved":False,
    }
    try:
        age=json.loads(args.age_report.read_text(encoding="utf8"))
        phase=json.loads(args.phase_report.read_text(encoding="utf8"))
    except (OSError,ValueError):
        age,phase={},{}
    verified=capture_allowed(age,phase)
    state["original_phase7_request_confirmed"]=verified
    if verified:
        try:
            focus=str(terms.adb(None,"shell","dumpsys","window"))
            if not terms.home_is_foreground(focus):
                state["status"]="home_not_foreground_no_capture"
            else:
                img=terms.adb(None,"exec-out","screencap","-p",binary=True)
                if terms.save_masked_consent_screen(args.image_out,img):
                    state["masked_image_saved"]=True
                    state["status"]="masked_post_agree_phase7_requested_screen_saved"
                else:
                    state["status"]="invalid_screen_no_capture"
        except Exception as exc:
            state["status"]="adb_screen_unavailable"
            state["error_type"]=type(exc).__name__
    args.status_out.parent.mkdir(parents=True,exist_ok=True)
    args.status_out.write_text(
        json.dumps(state,indent=2,sort_keys=True)+"\n",encoding="utf8")
    print(json.dumps(state,sort_keys=True))
    return 0 if state["masked_image_saved"] else 3


if __name__=="__main__":
    raise SystemExit(main())
