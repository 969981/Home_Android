#!/usr/bin/env python3
"""Opt-in masked screenshot of a VERIFIED original pre-consent HOME Terms page.

This is an evidence-only tool. It never clicks or accepts any agreement,
creates accounts, reads HOME transport data, or captures a registered session.
The source is an original 4.1.0 AVD with native FirstBoot Phase=3 verified.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import home41_terms_probe as terms


def eligible_for_terms_capture(report: object, fingerprint: object) -> bool:
    if not isinstance(report, dict) or not isinstance(fingerprint, dict):
        return False
    if not all((
        report.get("process_at_end") is True,
        report.get("birthday_native_preflight_passed") is True,
        report.get("birthday_next_tapped") is True,
        report.get("post_next_screen_changed") is True,
        report.get("registration_status") == "not_attempted",
        report.get("terms_accepted") is False,
        report.get("account_delete_attempted") is False,
        report.get("first_basic_utid_status") == "not_observed",
        fingerprint.get("age_next_native_verified") is True,
        fingerprint.get("home_foreground") is True,
        fingerprint.get("native_firstboot_controller_seen") is True,
        fingerprint.get("native_firstboot_phase_index") == 3,
        fingerprint.get("native_firstboot_confirmation_terms_entered") is True,
        fingerprint.get("terms_click_attempted") is False,
        fingerprint.get("account_registration_attempted") is False,
        fingerprint.get("basic_utid_saved") is False,
    )):
        return False
    stage = report.get("stage_monitor")
    realm = stage.get("arm64_emulated_realm") if isinstance(stage, dict) else None
    snapshot = realm.get("snapshot") if isinstance(realm, dict) else None
    counts = snapshot.get("counts") if isinstance(snapshot, dict) else None
    original = snapshot.get("firstboot_ui") if isinstance(snapshot, dict) else None
    return bool(
        isinstance(counts, dict)
        and isinstance(original, dict)
        and snapshot.get("native_arm64") is True
        and snapshot.get("hooks_ready") is True
        and type(original.get("original_phase_enum_index")) is int
        and original["original_phase_enum_index"] == 3
        and original.get("original_controller_seen") is True
        and type(counts.get("firstboot_confirmation_terms_entered")) is int
        and counts["firstboot_confirmation_terms_entered"] > 0
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--fingerprint", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--status", required=True, type=Path)
    args = parser.parse_args()
    state = {
        "status": "preconsent_capture_gate_rejected",
        "original_phase_is_terms_3": False,
        "masked_screenshot_saved": False,
        "terms_click_attempted": False,
        "registration_attempted": False,
        "raw_xml_saved": False,
        "utid_saved": False,
    }
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        fingerprint = json.loads(args.fingerprint.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        report, fingerprint = {}, {}
    allowed = eligible_for_terms_capture(report, fingerprint)
    state["original_phase_is_terms_3"] = allowed
    if allowed:
        try:
            focus = str(terms.adb(None, "shell", "dumpsys", "window"))
            if not terms.home_is_foreground(focus):
                state["status"] = "home_lost_foreground_no_capture"
            else:
                pixels = terms.adb(None, "exec-out", "screencap", "-p", binary=True)
                if terms.save_masked_consent_screen(args.output, pixels):
                    state["masked_screenshot_saved"] = True
                    state["status"] = "original_terms_page_masked_visual_evidence_saved"
                else:
                    state["status"] = "invalid_screen_no_capture"
        except Exception as exc:
            state["status"] = "adb_capture_unavailable"
            state["error_type"] = type(exc).__name__
    args.status.parent.mkdir(parents=True, exist_ok=True)
    args.status.write_text(json.dumps(state, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps(state, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
