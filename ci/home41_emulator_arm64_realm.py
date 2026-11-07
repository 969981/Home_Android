#!/usr/bin/env python3
"""A real disposable Android x86_64 + NativeBridge Frida emulated-realm trial.

Try Frida 17.26.1 device.attach(pid, realm='emulated') after successfully
attaching in the normal x64 realm, then run the existing ARM64 IL2CPP read-only
auth timeline IN THE EMULATED REALM only if the host supports it.

No registration, birth date, Terms, Nintendo link, account deletion, network
replay, HTTP payloads or tokens. All published evidence is allowlisted.
"""
from __future__ import annotations

import argparse
import json
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
                 select_month_day: bool=False):
        super().__init__(server, network_script)
        self.select_year_1999 = select_year_1999
        self.select_month_day = select_month_day
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
    parser.add_argument("--probe-birthday-year", action="store_true",
                        help="Only open year picker after exact known birthdate UI; never submit")
    parser.add_argument("--probe-year-dpad", action="store_true",
                        help="On verified open year list send one non-selecting DPAD_DOWN key")
    args = parser.parse_args()
    observer = ARM64RealmStageMonitor(
        args.server, args.network_script, args.arm64_script,
        select_year_1999=args.select_local_year_1999,
        select_month_day=args.select_local_month_day)
    report = diag.run(
        args.apk, args.output, settle=max(3,min(60,args.settle_seconds)),
        observer=observer, select_china_mainland=True,
        probe_birthday_year=args.probe_birthday_year,
        probe_year_dpad=args.probe_year_dpad,
        select_local_year_1999=args.select_local_year_1999,
        select_local_month_day=args.select_local_month_day)
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
        "birthday_submitted": False,
        "year_keyboard_probe_sent": report.get("year_keyboard_probe_sent"),
        "year_popup_verifiable_after_keyboard":
            report.get("year_popup_verifiable_after_keyboard"),
        "year_keyboard_image_changed": report.get("year_keyboard_image_changed"),
        "local_year_setter_armed": obs.get("arm64_emulated_realm", {}).get(
            "local_year_set_arm_result"),
        "local_month_setter_armed": arm.get("local_month_arm_result"),
        "local_day_setter_armed": arm.get("local_day_arm_result"),
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
