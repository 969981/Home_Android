#!/usr/bin/env python3
"""Read-only structural observation after a verified single HOME age-page Next.

Run inside a disposable Android AVD, immediately after the original age page
has been advanced once. No screenshot or raw accessibility text is saved.
Never click Terms, register an account or read API/authentication payloads.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import home41_terms_probe as terms


def fingerprint(age_report: dict, foreground_text: str, xml: str) -> dict:
    """The only persistable output contains allowlisted categories."""
    preflight = (
        isinstance(age_report, dict)
        and age_report.get("birthday_native_preflight_passed") is True
        and age_report.get("birthday_next_tapped") is True
        and age_report.get("post_next_screen_changed") is True
        and age_report.get("registration_status") == "not_attempted"
        and age_report.get("terms_accepted") is False
        and age_report.get("account_delete_attempted") is False
        and age_report.get("first_basic_utid_status") == "not_observed"
    )
    result = {
        "status": "preflight_failed",
        "age_next_native_verified": bool(preflight),
        "home_foreground": False,
        "terms_marker": False,
        "privacy_marker": False,
        "unique_terms_next_button": False,
        "unique_final_agree_button": False,
        "button_location_saved": False,
        "raw_text_or_xml_saved": False,
        "screenshot_saved": False,
        "terms_click_attempted": False,
        "account_registration_attempted": False,
        "basic_utid_saved": False,
        "native_terms_setup_event_seen": False,
        "native_clause_creation_event_seen": False,
        "native_checkbox_change_event_seen": False,
        "native_terms_dialog_open_event_seen": False,
        "native_terms_dialog_ok_event_seen": False,
        "native_terms_page_visible_verified": False,
        "native_firstboot_controller_seen": False,
        "native_firstboot_phase_index": None,
        "native_firstboot_phase_mapping_verified": False,
        "native_firstboot_confirmation_terms_entered": False,
    }
    if not preflight:
        return result
    # This is a source-backed native-call hint, NOT proof that the legal UI
    # has been rendered. Candidates can be called during initialization.
    snap = age_report.get("stage_monitor")
    realm = snap.get("arm64_emulated_realm") if isinstance(snap, dict) else None
    native = realm.get("snapshot") if isinstance(realm, dict) else None
    counts = native.get("counts") if isinstance(native, dict) else None
    if (isinstance(counts, dict) and native.get("native_arm64") is True
            and native.get("hooks_ready") is True):
        state = native.get("firstboot_ui")
        if isinstance(state, dict):
            result["native_firstboot_controller_seen"] = (
                state.get("original_controller_seen") is True)
            value = state.get("original_phase_enum_index")
            result["native_firstboot_phase_index"] = (
                value if type(value) is int and 0 <= value <= 128 else None)
        targets = {
            "native_firstboot_confirmation_terms_entered":
                "firstboot_confirmation_terms_entered",
            "native_terms_setup_event_seen":
                "firstboot_terms_confirmation_setup_entered",
            "native_clause_creation_event_seen":
                "firstboot_clause_agree_part_entered",
            "native_checkbox_change_event_seen":
                "firstboot_agreement_checkbox_changed",
            "native_terms_dialog_open_event_seen":
                "terms_confirm_dialog_open_entered",
            "native_terms_dialog_ok_event_seen":
                "terms_confirm_dialog_ok_clicked",
        }
        for output, name in targets.items():
            value = counts.get(name)
            result[output] = type(value) is int and 0 < value <= 100000
    result["home_foreground"] = terms.home_is_foreground(foreground_text)
    if not result["home_foreground"]:
        result["status"] = "home_not_foreground"
        return result
    nxt = terms.classify_accessibility(xml, "terms_next")
    agree = terms.classify_accessibility(xml, "final_agree")
    result["terms_marker"] = nxt.get("terms_marker") is True
    result["privacy_marker"] = nxt.get("privacy_marker") is True
    result["unique_terms_next_button"] = nxt.get("eligible") is True
    result["unique_final_agree_button"] = agree.get("eligible") is True
    result["status"] = (
        "preconsent_terms_accessibility_verified"
        if result["terms_marker"] and result["privacy_marker"] else
        "post_age_screen_not_accessible_as_terms"
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    result: dict
    try:
        age_report = json.loads(args.report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        age_report = {}
    # No UI inspection at all until age-page state is validated.
    initial = fingerprint(age_report, "", "")
    if not initial["age_next_native_verified"]:
        result = initial
    else:
        try:
            focus = str(terms.adb(None, "shell", "dumpsys", "window"))
            if not terms.home_is_foreground(focus):
                result = fingerprint(age_report, focus, "")
            else:
                ui = terms.dump_accessibility(None)
                result = fingerprint(age_report, focus, ui)
        except Exception as ex:
            result = fingerprint(age_report, "", "")
            result["status"] = "readonly_accessibility_probe_unavailable"
            result["error_type"] = type(ex).__name__
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["age_next_native_verified"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
