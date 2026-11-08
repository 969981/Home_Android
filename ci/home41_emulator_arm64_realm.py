#!/usr/bin/env python3
"""A real disposable Android x86_64 + NativeBridge Frida emulated-realm trial.

Try Frida 17.26.1 device.attach(pid, realm='emulated') after successfully
attaching in the normal x64 realm, then run the existing ARM64 IL2CPP read-only
auth timeline IN THE EMULATED REALM only if the host supports it.

Default mode never registers, submits a birth date, accepts Terms, links a
Nintendo Account, deletes an account, or saves tokens. A separately opted-in,
LOCAL interactive single-account assistant prepares the verified 1999/4/5 UI,
then leaves every official registration/consent action to the person at the
device while ARM64 Frida observes the first basic.utid privately.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import home41_emulator_diagnostics as diag
from home41_emulator_stage_frida import StageMonitor
from home41_arm64_auth_timeline import sanitize_timeline_event


_ALLOWED_AGENT_EVENTS = frozenset({
    "arm64_auth_observer_ready",
    "arm64_auth_observer_partial",
    "native_preflight_failed",
    "hook_attach_failed",
    "registration_request_serializer_entered",
    "registration_lng_cntry_packed_write_seen",
    "registration_request_formatter_entered",
    "registration_response_formatter_entered",
    "registration_response_handler_entered",
    "token_request_serializer_entered",
    "token_response_handler_entered",
    "login_request_serializer_entered",
    "login_response_handler_entered",
    "common_response_handler_entered",
    "first_basic_utid_observed",
    "firstboot_birthdata_setdata_entered",
    "firstboot_birthdata_year_change_entered",
    "firstboot_birthdata_month_change_entered",
    "firstboot_birthdata_day_change_entered",
    "firstboot_year_scroll_open_entered",
    "firstboot_year_item_selection_entered",
    "firstboot_clause_agree_part_entered",
    "firstboot_terms_confirmation_setup_entered",
    "firstboot_agreement_checkbox_changed",
    "terms_confirm_dialog_open_entered",
    "terms_confirm_dialog_ok_clicked",
    "optional_hook_attach_failed",
    "year_native_item_select_armed",
    "year_native_item_select_returned",
    "year_native_item_select_failed",
    "month_native_item_select_armed",
    "month_4_native_item_select_returned",
    "month_4_native_item_select_failed",
    "day_native_item_select_armed",
    "day_5_native_item_select_returned",
    "day_5_native_item_select_failed",
    "year_1999_local_setter_armed",
    "year_1999_local_setter_returned",
    "year_1999_local_setter_failed",
    "month_4_local_setter_armed",
    "month_4_local_setter_returned",
    "month_4_local_setter_failed",
    "day_5_local_setter_armed",
    "day_5_local_setter_returned",
    "day_5_local_setter_failed",
})


def sanitize_option_status(raw: object, *, expected_count: int) -> dict:
    """Only report fixed menu size / target index / selection status."""
    obj=raw if isinstance(raw,dict) else {}
    count=obj.get("option_count")
    index=obj.get("target_index")
    return {
        "dropdown_present":obj.get("dropdown_present") is True,
        "option_list_present":obj.get("option_list_present") is True,
        "option_count":count if type(count) is int and
                       0<=count<=32 else None,
        "target_index":index if type(index) is int and
                       0<=index<expected_count else None,
        "target_found_uniquely":obj.get("target_found_uniquely") is True,
        "value_index_equals_target":obj.get(
            "value_index_equals_target") is True,
        "target_option_text_verified":obj.get(
            "target_option_text_verified") is True,
    }


def sanitize_birth_ui(raw: object) -> dict:
    """Whitelist only derived, non-secret birthdate UI probe categories."""
    fields = (
        "controller_seen", "year_dropdown_present",
        "year_option_list_present", "inputed_year_in_supported_range",
        "inputed_year_equals_1999", "inputed_month_in_range",
        "inputed_month_equals_4", "inputed_day_in_range",
        "inputed_day_equals_5", "exact_birthdate_selected",
    )
    src=raw if isinstance(raw,dict) else {}
    n=src.get("year_option_count")
    return {
        **{key:src.get(key) is True for key in fields},
        "year_setter_opted_in":src.get("year_setter_opted_in") is True,
        "year_setter_attempted":src.get("year_setter_attempted") is True,
        "year_setter_returned":src.get("year_setter_returned") is True,
        "year_setter_failure":src.get("year_setter_failure") is True,
        "year_scroll_open_input_index": (
            src.get("year_scroll_open_input_index")
            if type(src.get("year_scroll_open_input_index")) is int
            and -1<=src["year_scroll_open_input_index"]<=126 else None),
        "year_scroll_open_input_equals_1999": (
            src.get("year_scroll_open_input_equals_1999") is True),
        "year_item_selection_count": (
            src.get("year_item_selection_count")
            if type(src.get("year_item_selection_count")) is int
            and 0<=src["year_item_selection_count"]<=100 else None),
        "year_item_selected_index": (
            src.get("year_item_selected_index")
            if type(src.get("year_item_selected_index")) is int
            and 0<=src["year_item_selected_index"]<=126 else None),
        "year_option_count": n if type(n) is int and 0<=n<=500 else None,
        "year_1999_index": (
            src.get("year_1999_index")
            if type(src.get("year_1999_index")) is int
            and 0<=src["year_1999_index"]<=300 else None
        ),
        "first_option_is_2026": src.get("first_option_is_2026") is True,
        "month_setter_attempted": src.get("month_setter_attempted") is True,
        "month_setter_returned": src.get("month_setter_returned") is True,
        "month_setter_failure": src.get("month_setter_failure") is True,
        "day_setter_attempted": src.get("day_setter_attempted") is True,
        "day_setter_returned": src.get("day_setter_returned") is True,
        "day_setter_failure": src.get("day_setter_failure") is True,
        "year_dropdown_value_index": (
            src.get("year_dropdown_value_index")
            if type(src.get("year_dropdown_value_index")) is int
            and -1 <= src["year_dropdown_value_index"] <= 126 else None
        ),
        "year_dropdown_is_selected": (
            src.get("year_dropdown_is_selected")
            if type(src.get("year_dropdown_is_selected")) is bool else None),
        "month_dropdown_is_selected": (
            src.get("month_dropdown_is_selected")
            if type(src.get("month_dropdown_is_selected")) is bool else None),
        "day_dropdown_is_selected": (
            src.get("day_dropdown_is_selected")
            if type(src.get("day_dropdown_is_selected")) is bool else None),
        "native_year_item_select_attempted": (
            src.get("native_year_item_select_attempted") is True),
        "native_year_item_select_returned": (
            src.get("native_year_item_select_returned") is True),
        "native_year_item_select_confirmed": (
            src.get("native_year_item_select_confirmed") is True),
        "native_year_item_select_failure": (
            src.get("native_year_item_select_failure") is True),
        "native_month_item_select_attempted": (
            src.get("native_month_item_select_attempted") is True),
        "native_month_item_select_returned": (
            src.get("native_month_item_select_returned") is True),
        "native_month_item_select_confirmed": (
            src.get("native_month_item_select_confirmed") is True),
        "native_month_item_select_failure": (
            src.get("native_month_item_select_failure") is True),
        "native_day_item_select_attempted": (
            src.get("native_day_item_select_attempted") is True),
        "native_day_item_select_returned": (
            src.get("native_day_item_select_returned") is True),
        "native_day_item_select_confirmed": (
            src.get("native_day_item_select_confirmed") is True),
        "native_day_item_select_failure": (
            src.get("native_day_item_select_failure") is True),
        "year_dropdown_value_equals_1999_option": (
            src.get("year_dropdown_value_equals_1999_option") is True),
        "month_dropdown":sanitize_option_status(
            src.get("month_dropdown"),expected_count=12),
        "day_dropdown":sanitize_option_status(
            src.get("day_dropdown"),expected_count=31),
        # Never export raw birth date, pointer, list elements or account data.
        "raw_birthdate_logged": False,
    }


def sanitized_arm64_snapshot(raw: object) -> dict:
    if not isinstance(raw, dict):
        return {"status": "invalid_snapshot"}
    counts = raw.get("counts")
    if not isinstance(counts, dict):
        counts = {}
    cleaned_counts = {
        k: v for k, v in counts.items()
        if k in _ALLOWED_AGENT_EVENTS and type(v) is int and 0 <= v <= 100000
    }
    return {
        "status": "snapshot_received",
        "native_arm64": raw.get("native_arm64") is True,
        "native_module_ready": raw.get("native_module_ready") is True,
        "hooks_ready": raw.get("hooks_ready") is True,
        "first_basic_seen": raw.get("first_basic_seen") is True,
        "observed_common_basic_caller":
            raw.get("observed_common_basic_caller") is True,
        "serialized_lng_cntry_seen":
            raw.get("serialized_lng_cntry_seen") is True,
        "counts": cleaned_counts,
        "birthdate_ui": sanitize_birth_ui(raw.get("birthdate_ui")),
        "utid_raw_or_candidate_logged": False,
        "backend_endpoint_identified": False,
        "registered_account": False,
    }


class ARM64RealmStageMonitor(StageMonitor):
    def __init__(self, server: Path, network_script: Path, arm64_script: Path,
                 select_year_1999: bool=False,
                 select_month_day: bool=False,
                 probe_native_year_select: bool=False,
                 probe_native_full_date_select: bool=False):
        super().__init__(server, network_script)
        self.select_year_1999 = select_year_1999
        self.select_month_day = select_month_day
        self.probe_native_year_select = probe_native_year_select
        self.probe_native_full_date_select = probe_native_full_date_select
        self.native_month_select_arm_result = "not_attempted"
        self.native_day_select_arm_result = "not_attempted"
        self.native_year_select_arm_result = "not_attempted"
        self.local_month_arm_result = "not_attempted"
        self.local_day_arm_result = "not_attempted"
        self.local_year_set_arm_result = "not_attempted"
        self.arm64_script_path = arm64_script
        self.arm64_session = None
        self.arm64_agent = None
        self.arm64_realm_status = "not_attempted"
        self.arm64_error_type = None
        self.arm64_events = []
        self.arm64_script_error = False

    def _on_arm64_message(self, message, _data):
        if isinstance(message, dict) and message.get("type") == "error":
            self.arm64_script_error = True
            return
        event = sanitize_timeline_event(message)
        if event and event.get("event") in _ALLOWED_AGENT_EVENTS:
            if len(self.arm64_events) < 100:
                self.arm64_events.append(event)

    def start(self) -> dict:
        base = super().start()
        if self.setup != "frida_attached_to_home_x86_64" or self.device is None:
            self.arm64_realm_status = "native_realm_not_ready"
            return base
        if not self.arm64_script_path.is_file():
            self.arm64_realm_status = "arm64_observer_missing"
            return base
        try:
            # This is the critical experiment! Frida must explicitly accept
            # the guest/emulated realm and create an ARM64 agent. No x64 Agent
            # is ever allowed to attach a native ARM64 RVA.
            pid_result = diag.adb("shell", "pidof", diag.PACKAGE, timeout=12)
            if not pid_result or pid_result.returncode != 0:
                self.arm64_realm_status = "home_pid_missing"
                return base
            pid = int(pid_result.stdout.strip().split()[0])
            self.arm64_session = self.device.attach(pid, realm="emulated")
            self.arm64_agent = self.arm64_session.create_script(
                self.arm64_script_path.read_text(encoding="utf-8"))
            self.arm64_agent.on("message", self._on_arm64_message)
            self.arm64_agent.load()
            self.arm64_realm_status = "emulated_realm_attached"
        except Exception as err:
            self.arm64_realm_status = "emulated_realm_not_attached"
            # Do not log raw Frida error messages; they may contain paths.
            self.arm64_error_type = type(err).__name__
        return base

    def arm_local_year_1999(self) -> bool:
        if not self.select_year_1999 or not self.arm64_agent or \
                self.arm64_realm_status != "emulated_realm_attached":
            self.local_year_set_arm_result = "not_eligible"
            return False
        try:
            allowed = self.arm64_agent.exports_sync.armlocalyear1999()
            self.local_year_set_arm_result = (
                "verified_options_arm_succeeded" if allowed
                else "native_options_not_verified")
            return allowed is True
        except Exception as err:
            self.local_year_set_arm_result = "frida_rpc_error_" + type(err).__name__
            return False

    def arm_native_year_item_select(self) -> bool:
        if (not self.probe_native_year_select or not self.arm64_agent or
                self.arm64_realm_status != "emulated_realm_attached"):
            self.native_year_select_arm_result = "not_eligible"
            return False
        try:
            allowed = self.arm64_agent.exports_sync.armnativeyearitemselect()
            self.native_year_select_arm_result = (
                "guarded_native_onselect_armed" if allowed
                else "native_onselect_preflight_rejected")
            return allowed is True
        except Exception as err:
            self.native_year_select_arm_result = (
                "frida_rpc_error_" + type(err).__name__)
            return False

    def arm_native_month_item_select(self) -> bool:
        if (not self.probe_native_full_date_select or not self.arm64_agent or
                self.arm64_realm_status != "emulated_realm_attached"):
            self.native_month_select_arm_result = "not_eligible"
            return False
        try:
            ok=self.arm64_agent.exports_sync.armnativemonthitemselect()
            self.native_month_select_arm_result = (
                "guarded_native_month_onselect_armed" if ok
                else "native_month_onselect_preflight_rejected")
            return ok is True
        except Exception as err:
            self.native_month_select_arm_result="frida_rpc_error_"+type(err).__name__
            return False

    def arm_native_day_item_select(self) -> bool:
        if (not self.probe_native_full_date_select or not self.arm64_agent or
                self.arm64_realm_status != "emulated_realm_attached"):
            self.native_day_select_arm_result = "not_eligible"
            return False
        try:
            ok=self.arm64_agent.exports_sync.armnativedayitemselect()
            self.native_day_select_arm_result = (
                "guarded_native_day_onselect_armed" if ok
                else "native_day_onselect_preflight_rejected")
            return ok is True
        except Exception as err:
            self.native_day_select_arm_result="frida_rpc_error_"+type(err).__name__
            return False

    def verify_full_visible_birthdate_native(self) -> bool:
        """Only a yes/no check. No ID, DOB raw strings or tokens exported."""
        if (self.arm64_realm_status != "emulated_realm_attached" or
                not self.arm64_agent):
            return False
        try:
            snapshot=sanitized_arm64_snapshot(
                self.arm64_agent.exports_sync.snapshot())
            ui=snapshot.get("birthdate_ui",{})
            return bool(
                snapshot.get("native_arm64") is True and
                snapshot.get("hooks_ready") is True and
                ui.get("exact_birthdate_selected") is True and
                ui.get("inputed_year_equals_1999") is True and
                ui.get("inputed_month_equals_4") is True and
                ui.get("inputed_day_equals_5") is True and
                ui.get("year_dropdown_is_selected") is True and
                ui.get("month_dropdown_is_selected") is True and
                ui.get("day_dropdown_is_selected") is True and
                ui.get("native_year_item_select_confirmed") is True and
                ui.get("native_month_item_select_confirmed") is True and
                ui.get("native_day_item_select_confirmed") is True)
        except Exception:
            return False

    def arm_local_month_4(self) -> bool:
        if (not self.select_month_day or not self.arm64_agent or
                self.arm64_realm_status != "emulated_realm_attached"):
            self.local_month_arm_result = "not_eligible"
            return False
        try:
            ok = self.arm64_agent.exports_sync.armlocalmonth4()
            self.local_month_arm_result = (
                "verified_month_option_arm_succeeded" if ok
                else "native_month_options_not_verified")
            return ok is True
        except Exception as err:
            self.local_month_arm_result = "frida_rpc_error_" + type(err).__name__
            return False

    def arm_local_day_5(self) -> bool:
        if (not self.select_month_day or not self.arm64_agent or
                self.arm64_realm_status != "emulated_realm_attached"):
            self.local_day_arm_result = "not_eligible"
            return False
        try:
            ok = self.arm64_agent.exports_sync.armlocalday5()
            self.local_day_arm_result = (
                "verified_day_option_arm_succeeded" if ok
                else "native_day_options_not_verified")
            return ok is True
        except Exception as err:
            self.local_day_arm_result = "frida_rpc_error_" + type(err).__name__
            return False

    def finish(self) -> dict:
        evidence = {
            "status": self.arm64_realm_status,
            "error_type": self.arm64_error_type,
            "agent_script_error": self.arm64_script_error,
            "events": list(self.arm64_events),
            "local_year_set_arm_result": self.local_year_set_arm_result,
            "native_year_select_arm_result": self.native_year_select_arm_result,
            "native_month_select_arm_result": self.native_month_select_arm_result,
            "native_day_select_arm_result": self.native_day_select_arm_result,
            "local_month_arm_result": self.local_month_arm_result,
            "local_day_arm_result": self.local_day_arm_result,
            "raw_utid_saved": False,
            "http_response_body_saved": False,
            "arm64_rvas_used_in_native_x64_realm": False,
        }
        if self.arm64_agent:
            try:
                evidence["snapshot"] = sanitized_arm64_snapshot(
                    self.arm64_agent.exports_sync.snapshot())
            except Exception as err:
                evidence["snapshot_error_type"] = type(err).__name__
        if self.arm64_session:
            try:
                self.arm64_session.detach()
            except Exception:
                evidence["detach_status"] = "failed"
        result = super().finish()
        result["arm64_emulated_realm"] = evidence
        return result


def confirmed_local_date_for_assisted_signup(report: object) -> bool:
    """Require native, visual, and privacy gates before manual registration.

    True proves only the local HOME birthdate UI, never account creation.
    """
    if not isinstance(report, dict):
        return False
    if report.get("process_at_end") is not True:
        return False
    if report.get("birthday_submitted") is not False:
        return False
    # Assisted flow explicitly advances the age page exactly once. The guard
    # in diag.run had already established original native dropdown selections.
    # After navigation the birthdate controller may be destroyed, so require
    # the recorded native preflight rather than dereferencing stale UI memory.
    if not all(report.get(k) is True for k in (
        "birthday_native_preflight_passed",
        "birthday_next_tapped",
        "post_next_screen_changed",
    )):
        return False
    if report.get("registration_status") != "not_attempted":
        return False
    if report.get("terms_accepted") is not False:
        return False
    if report.get("account_delete_attempted") is not False:
        return False
    probe = report.get("local_month_day_probe")
    if not isinstance(probe, dict) or not all(
        probe.get(k) is True for k in (
            "year_caption_roi_changed",
            "month_caption_roi_changed",
            "day_caption_roi_changed",
            "native_year_item_select_armed",
            "native_month_item_select_armed",
            "native_day_item_select_armed",
        )
    ):
        return False
    stage = report.get("stage_monitor")
    if not isinstance(stage, dict):
        return False
    realm = stage.get("arm64_emulated_realm")
    if not isinstance(realm, dict) or realm.get("status") != "emulated_realm_attached":
        return False
    snapshot = realm.get("snapshot")
    if not isinstance(snapshot, dict):
        return False
    if snapshot.get("native_arm64") is not True or snapshot.get("hooks_ready") is not True:
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--network-script", type=Path,
        default=Path(__file__).with_name("home41_emulator_network_meta.js"))
    parser.add_argument("--arm64-script", type=Path,
        default=Path(__file__).with_name("home41_arm64_auth_timeline.js"))
    parser.add_argument("--settle-seconds", type=int, default=16)
    parser.add_argument("--select-local-year-1999", action="store_true",
                        help="OPT IN: one original Unity dropdown setter call; no date submission")
    parser.add_argument("--select-local-month-day", action="store_true",
                        help="OPT IN: original Unity month/day setters after verified 1999; no form submission")
    parser.add_argument("--assisted-single-signup", action="store_true",
                        help="LOCAL TTY only: prepare verified 1999/4/5 then observe ONE manually completed original signup; never click Terms")
    parser.add_argument("--registration-timeout", type=int, default=1200,
                        help="Local Frida first-basic observer wait, 1..3600 seconds")
    parser.add_argument("--advance-birthday-once", action="store_true",
                        help="Opt in: after native/UI full-date verification, tap only age form Next once; no Terms consent")
    parser.add_argument("--probe-native-full-date-select", action="store_true",
                        help="Opt in: original OnSelectItem for 1999, April, May 5, never submit")
    parser.add_argument("--probe-native-year-select", action="store_true",
                        help="Opt in: call original OnSelectItem(27) on Unity thread after fully verified internal date")
    parser.add_argument("--probe-year-touch-scroll", action="store_true",
                        help="Up to four bounded touch drags only within the opened original year menu")
    parser.add_argument("--probe-birthday-year", action="store_true",
                        help="Only open year picker after exact known birthdate UI; never submit")
    parser.add_argument("--probe-year-dpad", action="store_true",
                        help="On verified open year list send one non-selecting DPAD_DOWN key")
    args = parser.parse_args()
    if args.assisted_single_signup:
        if os.environ.get("GITHUB_ACTIONS", "").lower() == "true" or not sys.stdout.isatty():
            print('{"status":"assisted_signup_requires_private_interactive_local_terminal"}')
            return 2
        if not all((
                args.probe_birthday_year,
                args.select_local_year_1999,
                args.select_local_month_day,
                args.probe_native_full_date_select,
            )):
            print('{"status":"assisted_signup_requires_verified_native_full_date"}')
            return 2
        if not 1 <= args.registration_timeout <= 3600:
            print('{"status":"registration_timeout_out_of_range"}')
            return 2
        print("[LOCAL ONLY] Prepare one HOME 4.1.0 setup in this persistent emulator.")
        print("[LOCAL ONLY] No account deletion, reset, scripted Terms acceptance or repeated signup.")
    observer = ARM64RealmStageMonitor(
        args.server, args.network_script, args.arm64_script,
        select_year_1999=args.select_local_year_1999,
        select_month_day=args.select_local_month_day,
        probe_native_year_select=(
            args.probe_native_year_select or args.probe_native_full_date_select),
        probe_native_full_date_select=args.probe_native_full_date_select)
    report = diag.run(
        args.apk, args.output, settle=max(3,min(60,args.settle_seconds)),
        observer=observer, select_china_mainland=True,
        probe_birthday_year=args.probe_birthday_year,
        probe_year_dpad=args.probe_year_dpad,
        select_local_year_1999=args.select_local_year_1999,
        select_local_month_day=args.select_local_month_day,
        probe_year_touch_scroll=args.probe_year_touch_scroll,
        probe_native_year_select=(
            args.probe_native_year_select or args.probe_native_full_date_select),
        probe_native_full_date_select=args.probe_native_full_date_select,
        # User-authorized assisted signup always advances the already
        # verified official age page once. This does NOT click a ToS button.
        advance_birthday_once=(args.advance_birthday_once or args.assisted_single_signup))
    if args.assisted_single_signup:
        if not confirmed_local_date_for_assisted_signup(report):
            print('{"status":"verified_visible_1999_04_05_not_met_no_signup_continued"}')
            return 3
        print("[LOCAL ONLY] Birthday 1999/4/5 verified BEFORE one original age-page NEXT.")
        print("[LOCAL ONLY] Age-page NEXT clicked; post-next screen changed.")
        print("[LOCAL ONLY] Reattaching the read-only ARM64 first-basic observer.")
        print("[LOCAL ONLY] Do not operate the new screen until arm64_auth_observer_ready appears.")
        print("[LOCAL ONLY] Then use the ORIGINAL HOME app screens yourself:")
        print("  1. The age-form NEXT has already been clicked exactly once.")
        print("  2. User authorized HOME Terms of Use and Privacy Notice consent.")
        print("     On the VERIFIED official terms UI, use Next, then I agree.")
        print("     No blind tap, and no Nintendo Account binding authorization.")
        print("  3. If offered Nintendo Account linkage, choose the official unlinked route.")
        print("  4. Choose the first valid avatar and Charmander (species #0004).")
        print("  5. Complete only one guest setup; do not clear app storage or create again.")
        print("[LOCAL ONLY] The server basic.utid and six-digit candidate are printed ONLY here.")
        print("[LOCAL ONLY] Six-digit candidate is NOT yet proven to equal the starter OT ID.")
        import home41_arm64_auth_timeline as auth
        return auth.run(
            args.apk, args.arm64_script, serial=None,
            timeout=args.registration_timeout, output=None,
            show_local_values=True, realm="emulated", remote_frida=True
        )
    obs = report.get("stage_monitor", {})
    arm = obs.get("arm64_emulated_realm", {})
    snapshot = arm.get("snapshot", {})
    # Fixed fields only; never raw args, RPC localvalues, IDs or endpoints.
    print(json.dumps({
        "result": report.get("result"),
        "app_running": report.get("process_at_end"),
        "language_clicked": report.get("language_clicked"),
        "country_confirmation_clicked": report.get("country_confirmation_clicked"),
        "birthday_year_dropdown_tapped": report.get("birthday_year_dropdown_tapped"),
        "birthday_year_picker_screenshot_saved":
            report.get("birthday_year_picker_screenshot_saved"),
        "birthday_submitted": report.get("birthday_submitted"),
        "birthday_next_tapped": report.get("birthday_next_tapped"),
        "post_next_screen_changed": report.get("post_next_screen_changed"),
        "post_next_screen_raw_saved": False,
        "year_keyboard_probe_sent": report.get("year_keyboard_probe_sent"),
        "year_popup_verifiable_after_keyboard":
            report.get("year_popup_verifiable_after_keyboard"),
        "year_keyboard_image_changed": report.get("year_keyboard_image_changed"),
        "local_year_setter_armed": obs.get("arm64_emulated_realm", {}).get(
            "local_year_set_arm_result"),
        "local_month_setter_armed": arm.get("local_month_arm_result"),
        "local_day_setter_armed": arm.get("local_day_arm_result"),
        "native_year_select_arm_result": arm.get("native_year_select_arm_result"),
        "native_month_select_arm_result": arm.get("native_month_select_arm_result"),
        "native_day_select_arm_result": arm.get("native_day_select_arm_result"),
        "local_month_day_probe": report.get("local_month_day_probe"),
        "frida_x64_status": obs.get("status"),
        "arm64_emulated_status": arm.get("status"),
        "arm64_emulated_error_type": arm.get("error_type"),
        "arm64_snapshot_status": snapshot.get("status"),
        "native_arm64_agent": snapshot.get("native_arm64"),
        "native_arm64_module": snapshot.get("native_module_ready"),
        "arm64_il2cpp_hooks_ready": snapshot.get("hooks_ready"),
        "birthdate_ui": snapshot.get("birthdate_ui"),
        "first_basic_utid_observed": snapshot.get("first_basic_seen"),
        "account_registration": "not_attempted",
    }, sort_keys=True))
    # Only success if the emulated ARM64 agent actually installed IL2CPP hooks.
    return (0 if report.get("process_at_end") is True
            and arm.get("status") == "emulated_realm_attached"
            and snapshot.get("native_arm64") is True
            and snapshot.get("hooks_ready") is True
            else 3)


if __name__ == "__main__":
    raise SystemExit(main())
