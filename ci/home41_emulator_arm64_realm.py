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
import subprocess
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
    "firstboot_controller_start_entered",
    "firstboot_contents_first_entered",
    "firstboot_confirmation_terms_entered",
    "firstboot_confirmation_advertisement_sdk_entered",
    "firstboot_go_to_phase_entered",
    "firstboot_confirmation_gest_account_entered",
    "firstboot_confirm_gest_first_entered",
    "firstboot_confirm_gest_second_entered",
    "guest_second_direct_callee_unclassified_entered",
    "guest_second_decision_thunk_entered",
    "guest_second_denial_thunk_entered",
    "post_guest_candidate_1098_entered",
    "post_guest_candidate_16f4_entered",
    "auth_manager_register_user_entered",
    "firstboot_decision_gest_account_entered",
    "firstboot_denial_gest_account_entered",
    "firstboot_guest_start_callback_b84_6_entered",
    "firstboot_start_callback_b84_9_entered",
    "firstboot_start_callback_b84_10_entered",
    "firstboot_start_callback_b84_13_entered",
    "firstboot_select_trainer_icon_entered",
    "firstboot_input_name_entered",
    "firstboot_login_entered",
    "firstboot_confirm_mt_detail_entered",
    "firstboot_play_prologue_entered",
    "firstboot_play_prologue2_entered",
    "firstboot_add_icon_selector_entered",
    "firstboot_add_prologue_panel_entered",
    "firstboot_setup_mt_account_setting_entered",
    "firstboot_icon_selector_set_data_entered",
    "firstboot_icon_selector_create_images_entered",
    "firstboot_icon_selector_on_tap_icon_entered",
    "firstboot_prologue_panel_set_pokemon_view_entered",
    "firstboot_prologue_panel_cast_pokemon_select_entered",
    "firstboot_prologue_pokemon_panel_open_entered",
    "firstboot_prologue_pokemon_panel_on_tap_pokemon_entered",
    "firstboot_prologue_pokemon_panel_selected_icon_entered",
    "firstboot_prologue_panel_on_tap_yes_entered",
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


# Verified original IL2CppDumper dump.cs:
# public enum FirstBootBodyController.Phase // TypeDefIndex: 1949.
FIRSTBOOT_PHASE_NAMES = (
    "NONE", "LANGUAGE", "MD_DOWNLOAD", "TERM_OF_SERVICE",
    "ADVERTISEMENT_SDK", "WARNING", "APPLE_ID_LINK",
    "NA_LINK_CONTINUE", "NA_LINK_BEGIN", "NA_LINK_PROCEDURE",
    "NA_LINK_PROCEDURE_WAIT", "NA_LIMK_SUCCESS", "NA_LINK_FAILD",
    "NA_NOT_LINK", "MT_LOGIN", "MT_SELECT_ICON", "MT_INPUT_NAME",
    "MT_INPUT_BIRTH", "MT_SELECT_COUNTRY", "MT_CONFIRMATION",
    "MT_MOVING", "PROLOGUE", "PROLOGUE2",
    "GEST_CONFIRMATION", "ALL_END", "ATT",
)


def sanitize_firstboot_ui(raw: object) -> dict:
    """Read-only native Phase enum with values from ORIGINAL 4.1.0 dump.cs."""
    source = raw if isinstance(raw, dict) else {}
    raw_index = source.get("original_phase_enum_index")
    index = raw_index if type(raw_index) is int and 0 <= raw_index <= 128 else None
    mapped = index is not None and index < len(FIRSTBOOT_PHASE_NAMES)
    requested_raw = source.get("last_requested_phase_enum_index")
    requested = (requested_raw if type(requested_raw) is int
                 and 0 <= requested_raw <= 128 else None)
    requested_mapped = (requested is not None
                        and requested < len(FIRSTBOOT_PHASE_NAMES))
    return {
        "original_controller_seen": source.get("original_controller_seen") is True,
        "original_phase_enum_index": index,
        "original_phase_name": FIRSTBOOT_PHASE_NAMES[index] if mapped else None,
        "original_phase_mapping_verified": bool(mapped),
        "last_requested_phase_enum_index": requested,
        "last_requested_phase_name": (
            FIRSTBOOT_PHASE_NAMES[requested] if requested_mapped else None),
        "go_to_phase_hook_attached": source.get("go_to_phase_hook_attached") is True,
        "advertisement_sdk_hook_attached": (
            source.get("advertisement_sdk_hook_attached") is True),
    }


_GUEST_FINAL_CALL_EVENTS = {
    "second_direct": "guest_second_direct_callee_unclassified_entered",
    "decision_thunk": "guest_second_decision_thunk_entered",
    "denial_thunk": "guest_second_denial_thunk_entered",
    "post_1098": "post_guest_candidate_1098_entered",
    "post_16f4": "post_guest_candidate_16f4_entered",
    "register_manager": "auth_manager_register_user_entered",
}


_POST_GUEST_UI_EVENTS = {
    "decision_gest": "firstboot_decision_gest_account_entered",
    "denial_gest": "firstboot_denial_gest_account_entered",
    "guest_start_b84_6": "firstboot_guest_start_callback_b84_6_entered",
    "start_b84_9": "firstboot_start_callback_b84_9_entered",
    "start_b84_10": "firstboot_start_callback_b84_10_entered",
    "start_b84_13": "firstboot_start_callback_b84_13_entered",
    "select_trainer_icon": "firstboot_select_trainer_icon_entered",
    "input_name": "firstboot_input_name_entered",
    "firstboot_login": "firstboot_login_entered",
    "confirm_mt_detail": "firstboot_confirm_mt_detail_entered",
    "play_prologue": "firstboot_play_prologue_entered",
    "play_prologue2": "firstboot_play_prologue2_entered",
    "add_icon_selector": "firstboot_add_icon_selector_entered",
    "add_prologue_panel": "firstboot_add_prologue_panel_entered",
    "setup_mt_account": "firstboot_setup_mt_account_setting_entered",
    "icon_selector_set_data": "firstboot_icon_selector_set_data_entered",
    "icon_selector_create_images": "firstboot_icon_selector_create_images_entered",
    "icon_selector_on_tap": "firstboot_icon_selector_on_tap_icon_entered",
    "prologue_set_pokemon_view": "firstboot_prologue_panel_set_pokemon_view_entered",
    "prologue_cast_pokemon_select": "firstboot_prologue_panel_cast_pokemon_select_entered",
    "prologue_pokemon_panel_open": "firstboot_prologue_pokemon_panel_open_entered",
    "prologue_pokemon_tap": "firstboot_prologue_pokemon_panel_on_tap_pokemon_entered",
    "prologue_pokemon_selected_icon": "firstboot_prologue_pokemon_panel_selected_icon_entered",
    "prologue_on_tap_yes": "firstboot_prologue_panel_on_tap_yes_entered",
}


def post_guest_ui_count_deltas(after: object, before: object,
                               hook_coverage: object) -> dict:
    """Fail-closed count deltas for original UI function entry hooks.

    If a hook was not attached, or a count was missing/decreasing,
    the resulting value is None, *not* proof of zero execution.
    """
    a = after if isinstance(after,dict) else {}
    b = before if isinstance(before,dict) else {}
    h = hook_coverage if isinstance(hook_coverage,dict) else {}
    out = {}
    for label,event in _POST_GUEST_UI_EVENTS.items():
        cur, old = a.get(event), b.get(event)
        if (h.get(label) is not True or type(cur) is not int or
                type(old) is not int or old < 0 or cur < old or
                cur > 100000):
            out[label] = None
        else:
            out[label] = cur - old
    return out


def guest_callback_count_deltas(after: object, before: object,
                                hook_coverage: object) -> dict:
    """Categorical post-click deltas; missing hooks/counters stay unknown."""
    a = after if isinstance(after, dict) else {}
    b = before if isinstance(before, dict) else {}
    h = hook_coverage if isinstance(hook_coverage, dict) else {}
    result = {}
    for label, event in _GUEST_FINAL_CALL_EVENTS.items():
        x, y = a.get(event), b.get(event)
        if (h.get(label) is not True or type(x) is not int or
                type(y) is not int or x < y or x > 100000 or y < 0):
            result[label] = None
        else:
            result[label] = x - y
    return result


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
        "guest_callback_hook_coverage": {
            k: (raw.get("guest_callback_hook_coverage") or {}).get(k) is True
            if isinstance(raw.get("guest_callback_hook_coverage"), dict)
            else False
            for k in ("second_direct", "decision_thunk", "denial_thunk",
                      "post_1098", "post_16f4", "register_manager")
        },
        "post_guest_ui_hook_coverage": {
            k: (raw.get("post_guest_ui_hook_coverage") or {}).get(k)
               if isinstance(raw.get("post_guest_ui_hook_coverage"),dict)
               and type((raw.get("post_guest_ui_hook_coverage") or {}).get(k))
               is bool else None
            for k in _POST_GUEST_UI_EVENTS
        },
        "birthdate_ui": sanitize_birth_ui(raw.get("birthdate_ui")),
        "firstboot_ui": sanitize_firstboot_ui(raw.get("firstboot_ui")),
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
        self.keep_arm64_attached = False

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
        if self.arm64_session and not self.keep_arm64_attached:
            try:
                self.arm64_session.detach()
            except Exception:
                evidence["detach_status"] = "failed"
        if self.keep_arm64_attached:
            self.keep_forward_open = True
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



def run_terms_next_phase_probe(args: argparse.Namespace, report: dict,
                               observer: ARM64RealmStageMonitor) -> dict:
    """Repeat the user-authorized Terms UI once while the native phase agent stays attached."""
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / "home41_emulator_report.json"
    fingerprint_path = out / "home41_post_age_terms_fingerprint.json"
    terms_dir = out / "home41_terms_phase3"
    result = {
        "status": "phase_probe_preflight_rejected",
        "account_registration_attempted": False,
        "nintendo_account_linking_attempted": False,
        "utid_saved": False,
        "http_body_saved": False,
        "raw_screen_saved": False,
    }

    def finish_observer() -> None:
        if observer.arm64_session:
            try:
                observer.arm64_session.detach()
            except Exception:
                result["observer_detach_status"] = "failed"
        observer.keep_arm64_attached = False
        observer.keep_forward_open = False
        if observer.device:
            try:
                diag.adb("forward", "--remove", "tcp:27042", timeout=15)
            except Exception:
                result["port_forward_cleanup_status"] = "failed"

    try:
        if not confirmed_local_date_for_assisted_signup(report):
            result["status"] = "verified_1999_04_05_age_flow_not_met"
            return result
        if not report_path.is_file():
            result["status"] = "age_report_missing"
            return result
        if observer.arm64_agent is None or observer.arm64_session is None:
            result["status"] = "native_arm64_observer_not_retained"
            return result

        # Before any Terms interaction, independently re-read the live phase
        # while the ARM64 observer is still attached to the same process.
        pre_snapshot = sanitized_arm64_snapshot(
            observer.arm64_agent.exports_sync.snapshot())
        pre_ui = pre_snapshot.get("firstboot_ui", {})
        pre_counts = pre_snapshot.get("counts", {})
        if not (
            pre_snapshot.get("native_arm64") is True
            and pre_snapshot.get("hooks_ready") is True
            and pre_ui.get("original_controller_seen") is True
            and pre_ui.get("original_phase_enum_index") == 3
            and pre_ui.get("original_phase_name") == "TERM_OF_SERVICE"
            and pre_ui.get("original_phase_mapping_verified") is True
            and type(pre_counts.get("firstboot_confirmation_terms_entered")) is int
            and pre_counts["firstboot_confirmation_terms_entered"] > 0
        ):
            result["status"] = "live_phase3_terms_preflight_not_verified"
            result["pre_terms_phase"] = pre_ui
            return result

        focus_result = diag.adb("shell", "dumpsys", "window", timeout=12)
        focus_text = focus_result.stdout if focus_result and focus_result.returncode == 0 else ""
        from home41_post_age_terms_fingerprint import fingerprint as build_fingerprint
        from home41_terms_visual_capture import eligible_for_terms_capture
        fp = build_fingerprint(report, focus_text, "")
        if not eligible_for_terms_capture(report, fp):
            result["status"] = "native_terms_fingerprint_gate_rejected"
            result["pre_terms_phase"] = pre_ui
            return result
        fingerprint_path.write_text(
            json.dumps(fp, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        # This is the previously user-authorized original Terms+Privacy UI
        # flow, replayed only on a fresh disposable AVD so the observer can
        # remain attached through the one official Next transition.
        terms_dir.mkdir(parents=True, exist_ok=True)
        command = [
            sys.executable,
            str(Path(__file__).with_name("home41_terms_both_and_next.py")),
            "--authorize-original-terms-once",
            "--report", str(report_path),
            "--fingerprint", str(fingerprint_path),
            "--output-dir", str(terms_dir),
        ]
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, timeout=240, check=False)
            result["terms_helper_exit_code"] = (
                completed.returncode if type(completed.returncode) is int else None)
        except subprocess.TimeoutExpired:
            result["status"] = "terms_helper_timeout"
            return result

        terms_status_path = terms_dir / "terms_once_status.json"
        if terms_status_path.is_file():
            terms_status = json.loads(terms_status_path.read_text(encoding="utf-8"))
        else:
            terms_status = {}
        result["terms_ui"] = {
            "status": terms_status.get("status"),
            "first_checkbox_checked_verified":
                terms_status.get("first_checkbox_checked_verified") is True,
            "privacy_checkbox_checked_verified":
                terms_status.get("privacy_checkbox_checked_verified") is True,
            "terms_next_tapped": terms_status.get("terms_next_tapped") is True,
            "post_terms_page_changed":
                terms_status.get("post_terms_page_changed") is True,
        }

        # Read only enum/counter fields from the SAME ARM64 agent that saw
        # Phase 3 before the click. Never persist screenshots or auth data.
        time.sleep(2)
        post_snapshot = sanitized_arm64_snapshot(
            observer.arm64_agent.exports_sync.snapshot())
        from home41_post_terms_phase import classify_post_terms_phase
        phase = classify_post_terms_phase(post_snapshot, terms_status)
        result["native_phase"] = phase
        result["status"] = phase["status"]
        result["pre_terms_phase"] = {
            "current_phase_index": pre_ui.get("original_phase_enum_index"),
            "current_phase_name": pre_ui.get("original_phase_name"),
        }
        result["observer_stayed_attached_through_terms"] = True
        if getattr(args, "probe_phase4_agree_once", False):
            # Separate user-authorized route, starting a NEW disposable AVD.
            # Do NOT run the previous "不同意" flow on this session.
            result["phase4_agree_probe"] = {
                "status": "original_phase4_agree_preflight_rejected",
                "optional_data_collection_agree_tapped": False,
                "post_agree_screen_changed": False,
            }
            if phase.get("status") != "phase_4_advertisement_sdk_confirmed":
                return result
            phase_path = out / "home41_phase4_preagree_native.json"
            phase_path.write_text(
                json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8")
            agree_dir = out / "home41_phase4_agree"
            command = [
                sys.executable,
                str(Path(__file__).with_name("home41_phase4_agree_once.py")),
                "--authorize-optional-collection-agree-once",
                "--age-report", str(report_path),
                "--phase-report", str(phase_path),
                "--output-dir", str(agree_dir),
            ]
            try:
                completed = subprocess.run(
                    command, capture_output=True, text=True,
                    timeout=100, check=False)
                result["phase4_agree_helper_exit_code"] = completed.returncode
                status_path = agree_dir / "phase4_agree_status.json"
                if status_path.is_file():
                    info = json.loads(status_path.read_text(encoding="utf-8"))
                    result["phase4_agree_probe"] = {
                        "status": info.get("status"),
                        "optional_data_collection_agree_tapped":
                            info.get("optional_data_collection_agree_tapped") is True,
                        "post_agree_screen_changed":
                            info.get("post_agree_screen_changed") is True,
                        "disagree_button_tapped": False,
                        "account_registration_attempted": False,
                        "nintendo_account_linking_attempted": False,
                        "utid_saved": False,
                    }
            except subprocess.TimeoutExpired:
                result["phase4_agree_probe"]["status"] = "agree_helper_timeout"
            if result["phase4_agree_probe"]["optional_data_collection_agree_tapped"]:
                time.sleep(2)
                current = sanitized_arm64_snapshot(
                    observer.arm64_agent.exports_sync.snapshot())
                ui = current.get("firstboot_ui", {})
                counts = current.get("counts", {})
                phase_index = ui.get("original_phase_enum_index")
                requested = ui.get("last_requested_phase_enum_index")
                before_go = phase.get("go_to_phase_entries")
                after_go = counts.get("firstboot_go_to_phase_entered")
                from home41_post_terms_phase import PHASES
                requested_advanced = bool(
                    current.get("native_arm64") is True
                    and current.get("hooks_ready") is True
                    and type(requested) is int
                    and 5 <= requested < len(PHASES)
                    and ui.get("last_requested_phase_name") == PHASES[requested]
                    and type(before_go) is int
                    and type(after_go) is int
                    and after_go > before_go
                )
                current_confirmed = bool(
                    requested_advanced
                    and type(phase_index) is int
                    and phase_index == requested
                    and ui.get("original_phase_mapping_verified") is True
                    and ui.get("original_phase_name") == PHASES[phase_index]
                )
                # The controller can be destroyed during a transition,
                # making current_phase null even though GoToPhase advanced.
                # Preserve that evidence boundary instead of claiming
                # arrival at the requested phase.
                result["post_phase4_agree_native"] = {
                    "status": (
                        "phase_5_warning_confirmed"
                        if current_confirmed and phase_index == 5
                        else "native_phase_current_confirmed"
                        if current_confirmed
                        else "native_phase_request_advanced_current_unreadable"
                        if requested_advanced
                        else "native_phase_after_agree_not_confirmed"),
                    "native_arm64": current.get("native_arm64") is True,
                    "hooks_ready": current.get("hooks_ready") is True,
                    "current_phase_index":
                        phase_index if type(phase_index) is int else None,
                    "current_phase_name": ui.get("original_phase_name"),
                    "last_requested_phase_index":
                        requested if type(requested) is int else None,
                    "last_requested_phase_name":
                        ui.get("last_requested_phase_name"),
                    "go_to_phase_entries_before": before_go,
                    "go_to_phase_entries_after":
                        after_go if type(after_go) is int else None,
                    "account_registration_attempted": False,
                    "nintendo_account_linking_attempted": False,
                    "utid_saved": False,
                }
                if getattr(args, "capture_phase7_requested_screen", False):
                    # Evidence-only capture: original GoToPhase requested 7,
                    # but the current controller can be temporarily missing.
                    # Do not claim the on-screen phase is fully initialized.
                    capture_dir = out / "home41_after_phase4_agree"
                    phase_path.write_text(
                        json.dumps(result, ensure_ascii=False,
                                   indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
                    cmd = [
                        sys.executable,
                        str(Path(__file__).with_name(
                            "home41_post_phase4_agree_screen.py")),
                        "--age-report", str(report_path),
                        "--phase-report", str(phase_path),
                        "--image-out", str(capture_dir / "next_screen_masked.png"),
                        "--status-out", str(capture_dir / "capture_status.json"),
                    ]
                    try:
                        done = subprocess.run(
                            cmd, capture_output=True, text=True,
                            timeout=55, check=False)
                        result["phase7_capture_exit_code"] = done.returncode
                        status_file = capture_dir / "capture_status.json"
                        if status_file.is_file():
                            z = json.loads(status_file.read_text(encoding="utf-8"))
                            result["phase7_screen_capture"] = {
                                "status": z.get("status"),
                                "masked_image_saved":
                                    z.get("masked_image_saved") is True,
                                "phase7_requested":
                                    z.get("original_phase7_request_confirmed") is True,
                                "new_screen_interacted": False,
                                "nintendo_account_linked": False,
                                "account_registration_attempted": False,
                            }
                    except subprocess.TimeoutExpired:
                        result["phase7_screen_capture"] = {
                            "status": "phase7_masked_capture_timeout",
                            "masked_image_saved": False,
                        }
                if getattr(args, "probe_nintendo_no_link_once", False):
                    # Irreversible choice explicitly approved by user.
                    # Only the original photographed lower "不关联" control;
                    # do not touch any subsequent unknown screens.
                    result["nintendo_no_link_probe"] = {
                        "status": "original_choice_not_eligible",
                        "original_no_link_button_tapped": False,
                        "post_click_screen_changed": False,
                    }
                    capture = result.get("phase7_screen_capture", {})
                    if not (capture.get("masked_image_saved") is True
                            and capture.get("phase7_requested") is True):
                        return result
                    phase_path.write_text(
                        json.dumps(result, ensure_ascii=False,
                                   indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
                    no_link_dir = out / "home41_nintendo_no_link"
                    cmd = [
                        sys.executable,
                        str(Path(__file__).with_name(
                            "home41_nintendo_no_link_once.py")),
                        "--authorize-irreversible-no-link-once",
                        "--age-report", str(report_path),
                        "--phase-report", str(phase_path),
                        "--output-dir", str(no_link_dir),
                    ]
                    try:
                        completed = subprocess.run(
                            cmd, capture_output=True, text=True,
                            timeout=90, check=False)
                        result["nintendo_no_link_helper_exit_code"] = completed.returncode
                        status_file = no_link_dir / "no_link_once_status.json"
                        if status_file.is_file():
                            data = json.loads(status_file.read_text(encoding="utf-8"))
                            result["nintendo_no_link_probe"] = {
                                "status": data.get("status"),
                                "original_no_link_button_tapped":
                                    data.get("original_no_link_button_tapped") is True,
                                "post_click_screen_changed":
                                    data.get("post_click_screen_changed") is True,
                                "nintendo_link_button_tapped": False,
                                "further_confirmation_tapped": False,
                                "registration_button_tapped": False,
                                "utid_saved": False,
                            }
                    except subprocess.TimeoutExpired:
                        result["nintendo_no_link_probe"]["status"] = (
                            "no_link_helper_timeout")
                    if result["nintendo_no_link_probe"][
                            "original_no_link_button_tapped"]:
                        time.sleep(2)
                        snap = sanitized_arm64_snapshot(
                            observer.arm64_agent.exports_sync.snapshot())
                        ui = snap.get("firstboot_ui", {})
                        counts = snap.get("counts", {})
                        index = ui.get("original_phase_enum_index")
                        requested = ui.get("last_requested_phase_enum_index")
                        go = counts.get("firstboot_go_to_phase_entered")
                        old_go = result.get(
                            "post_phase4_agree_native", {}).get(
                                "go_to_phase_entries_after")
                        result["post_no_link_native"] = {
                            "status": (
                                "original_phase_requested_after_no_link"
                                if type(go) is int and type(old_go) is int
                                   and go > old_go
                                else "no_native_phase_request_after_no_link_yet"),
                            "native_arm64": snap.get("native_arm64") is True,
                            "hooks_ready": snap.get("hooks_ready") is True,
                            "current_phase_index":
                                index if type(index) is int else None,
                            "current_phase_name": ui.get("original_phase_name"),
                            "last_requested_phase_index":
                                requested if type(requested) is int else None,
                            "last_requested_phase_name":
                                ui.get("last_requested_phase_name"),
                            "go_to_phase_entries_before": old_go,
                            "go_to_phase_entries_after":
                                go if type(go) is int else None,
                            "nintendo_link_button_tapped": False,
                            "registration_button_tapped": False,
                            "utid_saved": False,
                            "registration_serializer_entries": counts.get(
                                "registration_request_serializer_entered", -1),
                            "first_basic_seen": snap.get("first_basic_seen"),
                            "guest_confirmation_method_entries": counts.get(
                                "firstboot_confirmation_gest_account_entered", 0),
                            "guest_first_method_entries": counts.get(
                                "firstboot_confirm_gest_first_entered", 0),
                            "guest_second_method_entries": counts.get(
                                "firstboot_confirm_gest_second_entered", 0),
                        }
                        if getattr(args, "capture_guest_confirmation_screen", False):
                            # The current controller may no longer be readable
                            # during the 7 -> 23 request; screen still needs
                            # independent visual verification, so never click.
                            phase_path.write_text(
                                json.dumps(result, ensure_ascii=False,
                                           indent=2, sort_keys=True) + "\n",
                                encoding="utf-8")
                            guest_dir = out / "home41_guest_confirmation"
                            cmd = [
                                sys.executable,
                                str(Path(__file__).with_name(
                                    "home41_guest_confirmation_visual.py")),
                                "--age-report", str(report_path),
                                "--phase-report", str(phase_path),
                                "--image-out", str(
                                    guest_dir / "guest_confirmation_masked.png"),
                                "--buttons-out", str(
                                    guest_dir / "guest_buttons_only.png"),
                                "--status-out", str(
                                    guest_dir / "guest_capture_status.json"),
                            ]
                            try:
                                completed = subprocess.run(
                                    cmd, capture_output=True, text=True,
                                    timeout=50, check=False)
                                result["guest_visual_helper_exit_code"] = (
                                    completed.returncode)
                                report_status = (
                                    guest_dir / "guest_capture_status.json")
                                if report_status.is_file():
                                    g = json.loads(report_status.read_text(
                                        encoding="utf-8"))
                                    result["guest_confirmation_visual"] = {
                                        "status": g.get("status"),
                                        "gest_request_proven":
                                            g.get(
                                                "original_gest_confirmation_request_proven"
                                            ) is True,
                                        "masked_image_saved":
                                            g.get("masked_screenshot_saved") is True,
                                        "buttons_detail_saved":
                                            g.get("guest_buttons_detail_saved") is True,
                                        "next_screen_clicked": False,
                                        "registration_attempted": False,
                                        "utid_observed": False,
                                    }
                            except subprocess.TimeoutExpired:
                                result["guest_confirmation_visual"] = {
                                    "status": "guest_visual_capture_timeout",
                                    "masked_image_saved": False,
                                }
                        if getattr(args, "confirm_guest_start_once", False):
                            # Only after original GEST_CONFIRMATION visual proof.
                            # The next official orange "是" MAY initiate one
                            # real guest registration. No repeated actions and
                            # never save account response or session credentials.
                            result["guest_start_probe"] = {
                                "status": "guest_start_preflight_rejected",
                                "guest_yes_tapped": False,
                                "post_click_screen_changed": False,
                            }
                            visual = result.get("guest_confirmation_visual", {})
                            if not (visual.get("gest_request_proven") is True
                                    and visual.get("masked_image_saved") is True
                                    and visual.get("buttons_detail_saved") is True):
                                return result
                            phase_path.write_text(
                                json.dumps(result, ensure_ascii=False,
                                           indent=2, sort_keys=True) + "\n",
                                encoding="utf-8")
                            cmd = [
                                sys.executable,
                                str(Path(__file__).with_name(
                                    "home41_guest_start_once.py")),
                                "--user-authorized-original-guest-yes-once",
                                "--age-report", str(report_path),
                                "--phase-report", str(phase_path),
                                "--output-dir", str(guest_dir),
                            ]
                            try:
                                done = subprocess.run(
                                    cmd, capture_output=True, text=True,
                                    timeout=110, check=False)
                                result["guest_start_helper_exit_code"] = (
                                    done.returncode)
                                statusfile = guest_dir / "guest_yes_once_status.json"
                                if statusfile.is_file():
                                    g = json.loads(statusfile.read_text(
                                        encoding="utf-8"))
                                    result["guest_start_probe"] = {
                                        "status": g.get("status"),
                                        "guest_yes_tapped":
                                            g.get("guest_yes_tapped") is True,
                                        "post_click_screen_changed":
                                            g.get("post_click_screen_changed") is True,
                                        "nintendo_link_tapped": False,
                                        "additional_signup_ui_tapped": False,
                                        "raw_post_click_image_saved": False,
                                        "token_saved": False,
                                    }
                            except subprocess.TimeoutExpired:
                                result["guest_start_probe"]["status"] = (
                                    "guest_start_helper_timeout")
                            if result["guest_start_probe"]["guest_yes_tapped"]:
                                time.sleep(10)
                                current = sanitized_arm64_snapshot(
                                    observer.arm64_agent.exports_sync.snapshot())
                                c = current.get("counts", {})
                                ui = current.get("firstboot_ui", {})
                                result["post_guest_start_native"] = {
                                    "native_arm64": current.get("native_arm64") is True,
                                    "hooks_ready": current.get("hooks_ready") is True,
                                    "registration_serializer_entries": c.get(
                                        "registration_request_serializer_entered", 0),
                                    "registration_response_handler_entries": c.get(
                                        "registration_response_handler_entered", 0),
                                    "first_basic_seen":
                                        current.get("first_basic_seen") is True,
                                    "first_basic_utid_event_count": c.get(
                                        "first_basic_utid_observed", 0),
                                    "guest_confirmation_method_entries": c.get(
                                        "firstboot_confirmation_gest_account_entered", 0),
                                    "guest_first_method_entries": c.get(
                                        "firstboot_confirm_gest_first_entered", 0),
                                    "guest_second_method_entries": c.get(
                                        "firstboot_confirm_gest_second_entered", 0),
                                    "last_requested_phase_index":
                                        ui.get("last_requested_phase_enum_index"),
                                    "last_requested_phase_name":
                                        ui.get("last_requested_phase_name"),
                                    "raw_utid_saved": False,
                                    "token_saved": False,
                                    "account_persisted_verified": False,
                                    "registration_completed_verified": False,
                                }
                                if getattr(args, "capture_post_guest_first_screen",
                                           False):
                                    # Require live no-registration and no-basic
                                    # counters before photographing the next
                                    # original guest confirmation page.
                                    phase_path.write_text(
                                        json.dumps(result, ensure_ascii=False,
                                                   indent=2, sort_keys=True) + "\n",
                                        encoding="utf-8")
                                    cmd = [
                                        sys.executable,
                                        str(Path(__file__).with_name(
                                            "home41_guest_after_first_visual.py")),
                                        "--age-report", str(report_path),
                                        "--phase-report", str(phase_path),
                                        "--image-out", str(
                                            guest_dir / "after_first_masked.png"),
                                        "--buttons-out", str(
                                            guest_dir / "after_first_buttons.png"),
                                        "--status-out", str(
                                            guest_dir / "after_first_capture_status.json"),
                                    ]
                                    try:
                                        proc = subprocess.run(
                                            cmd, capture_output=True, text=True,
                                            timeout=60, check=False)
                                        result["after_first_capture_exit_code"] = proc.returncode
                                        statusfile = (guest_dir /
                                            "after_first_capture_status.json")
                                        if statusfile.is_file():
                                            x = json.loads(statusfile.read_text(
                                                encoding="utf-8"))
                                            result["after_first_visual"] = {
                                                "status": x.get("status"),
                                                "native_pre_registration_confirmed":
                                                    x.get(
                                                        "native_pre_registration_confirmed"
                                                    ) is True,
                                                "masked_image_saved":
                                                    x.get("masked_image_saved") is True,
                                                "buttons_detail_saved":
                                                    x.get("buttons_detail_saved") is True,
                                                "ui_clicked": False,
                                            }
                                    except subprocess.TimeoutExpired:
                                        result["after_first_visual"] = {
                                            "status": "after_first_capture_timeout",
                                            "masked_image_saved": False,
                                        }
                                    if getattr(args,"confirm_guest_second_once",False):
                                        result["guest_final_probe"] = {
                                            "status": "final_guest_modal_not_verified",
                                            "final_guest_button_tapped": False,
                                            "post_click_screen_changed": False,
                                        }
                                        visual = result.get("after_first_visual", {})
                                        if not (visual.get(
                                                "native_pre_registration_confirmed") is True
                                                and visual.get("masked_image_saved") is True
                                                and visual.get("buttons_detail_saved") is True):
                                            return result
                                        phase_path.write_text(
                                            json.dumps(result,ensure_ascii=False,
                                                       indent=2,sort_keys=True)+"\n",
                                            encoding="utf-8")
                                        # Snapshot only fixed categorical counters BEFORE
                                        # the last UI click to exclude earlier UI calls.
                                        pre_guest_final = sanitized_arm64_snapshot(
                                            observer.arm64_agent.exports_sync.snapshot())
                                        pre_guest_final_counts = pre_guest_final.get(
                                            "counts", {})
                                        cmd = [
                                            sys.executable,
                                            str(Path(__file__).with_name(
                                                "home41_guest_second_confirm_once.py")),
                                            "--authorize-original-final-guest-once",
                                            "--age-report",str(report_path),
                                            "--phase-report",str(phase_path),
                                            "--output-dir",str(guest_dir),
                                        ]
                                        try:
                                            completed = subprocess.run(
                                                cmd,capture_output=True,text=True,
                                                timeout=95,check=False)
                                            result["guest_final_helper_exit_code"] = (
                                                completed.returncode)
                                            statusfile = guest_dir / "guest_final_once_status.json"
                                            if statusfile.is_file():
                                                g=json.loads(statusfile.read_text(
                                                    encoding="utf-8"))
                                                result["guest_final_probe"] = {
                                                    "status":g.get("status"),
                                                    "final_guest_button_tapped":
                                                        g.get("final_guest_button_tapped") is True,
                                                    "post_click_screen_changed":
                                                        g.get("post_click_screen_changed") is True,
                                                    "close_button_tapped": False,
                                                    "nintendo_link_tapped": False,
                                                    "other_ui_tapped": False,
                                                    "raw_postclick_screenshot_saved": False,
                                                    "utid_saved": False,
                                                    "token_saved": False,
                                                }
                                        except subprocess.TimeoutExpired:
                                            result["guest_final_probe"]["status"]=(
                                                "guest_final_helper_timeout")
                                        if result["guest_final_probe"].get(
                                                "final_guest_button_tapped") is True:
                                            # Allow any original server responses and
                                            # callbacks to settle; export COUNTS ONLY.
                                            time.sleep(13)
                                            live = sanitized_arm64_snapshot(
                                                observer.arm64_agent.exports_sync.snapshot())
                                            counts=live.get("counts",{})
                                            ui=live.get("firstboot_ui",{})
                                            hook_coverage=live.get(
                                                "guest_callback_hook_coverage",{})
                                            # Null means observer/counter unavailable;
                                            # zero means attached and no new native entry.
                                            call_deltas=guest_callback_count_deltas(
                                                counts,pre_guest_final_counts,
                                                hook_coverage)
                                            ui_coverage=live.get(
                                                "post_guest_ui_hook_coverage",{})
                                            ui_deltas=post_guest_ui_count_deltas(
                                                counts,pre_guest_final_counts,
                                                ui_coverage)
                                            result["post_guest_final_native"] = {
                                                "guest_callback_hook_coverage": hook_coverage,
                                                "guest_callback_entries_since_final_click":
                                                    call_deltas,
                                                "post_guest_ui_hook_coverage": ui_coverage,
                                                "post_guest_ui_entries_since_final_click":
                                                    ui_deltas,
                                                "ui_method_entry_proves_rendered_screen": False,
                                                "status": "native_guest_final_snapshot_received",
                                                "native_arm64":
                                                    live.get("native_arm64") is True,
                                                "hooks_ready":
                                                    live.get("hooks_ready") is True,
                                                "guest_confirm_second_entries": counts.get(
                                                    "firstboot_confirm_gest_second_entered",0),
                                                "registration_serializer_entries": counts.get(
                                                    "registration_request_serializer_entered",0),
                                                "registration_response_handler_entries": counts.get(
                                                    "registration_response_handler_entered",0),
                                                "token_response_handler_entries": counts.get(
                                                    "token_response_handler_entered",0),
                                                "first_basic_seen":
                                                    live.get("first_basic_seen") is True,
                                                "first_basic_utid_event_count": counts.get(
                                                    "first_basic_utid_observed",0),
                                                "last_requested_phase_index":
                                                    ui.get("last_requested_phase_enum_index"),
                                                "last_requested_phase_name":
                                                    ui.get("last_requested_phase_name"),
                                                "actual_server_registration_confirmed": False,
                                                "account_persisted_confirmed": False,
                                                "six_digit_home_id_verified": False,
                                                "utid_raw_or_candidate_logged": False,
                                                "tokens_logged": False,
                                                "response_body_logged": False,
                                                "post_registration_image_saved": False,
                                            }
            return result
        if getattr(args, "probe_phase4_decline_once", False):
            # The only permitted UI action on the new Phase 4 screen is the
            # official privacy-preserving LEFT "不同意" button. The original
            # ARM64 observer stays attached so we can verify a real Phase 5.
            result["phase4_decline_probe"] = {
                "status": "phase4_decline_preflight_rejected",
                "decline_button_tapped": False,
                "post_decline_screen_changed": False,
            }
            if phase.get("status") != "phase_4_advertisement_sdk_confirmed":
                return result
            phase_path = out / "home41_phase4_predecline_native.json"
            phase_path.write_text(
                json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8")
            phase4_dir = out / "home41_phase4_decline"
            cmd = [
                sys.executable,
                str(Path(__file__).with_name("home41_phase4_decline_once.py")),
                "--decline-optional-collection-once",
                "--age-report", str(report_path),
                "--phase-report", str(phase_path),
                "--output-dir", str(phase4_dir),
            ]
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=90, check=False)
                result["phase4_decline_helper_exit_code"] = proc.returncode
                status_path = phase4_dir / "phase4_decline_status.json"
                if status_path.is_file():
                    private = json.loads(status_path.read_text(encoding="utf-8"))
                    result["phase4_decline_probe"] = {
                        "status": private.get("status"),
                        "decline_button_tapped":
                            private.get("decline_button_tapped") is True,
                        "post_decline_screen_changed":
                            private.get("post_decline_screen_changed") is True,
                        "agree_button_tapped": False,
                        "account_registration_attempted": False,
                        "nintendo_account_linking_attempted": False,
                        "utid_saved": False,
                    }
            except subprocess.TimeoutExpired:
                result["phase4_decline_probe"]["status"] = "decline_helper_timeout"
            if result["phase4_decline_probe"]["decline_button_tapped"]:
                time.sleep(2)
                # Retained original observer, no new injected action.
                after = sanitized_arm64_snapshot(
                    observer.arm64_agent.exports_sync.snapshot())
                ui = after.get("firstboot_ui", {})
                counts = after.get("counts", {})
                before_go = phase.get("go_to_phase_entries", 0)
                after_go = counts.get("firstboot_go_to_phase_entered", 0)
                index = ui.get("original_phase_enum_index")
                requested = ui.get("last_requested_phase_enum_index")
                success = bool(
                    after.get("native_arm64") is True
                    and after.get("hooks_ready") is True
                    and ui.get("original_phase_mapping_verified") is True
                    and type(index) is int and index == 5
                    and type(requested) is int and requested == 5
                    and type(after_go) is int
                    and type(before_go) is int
                    and after_go > before_go
                )
                result["post_phase4_native"] = {
                    "status": "phase_5_warning_confirmed" if success
                              else "phase_after_decline_not_confirmed_as_warning",
                    "native_arm64": after.get("native_arm64") is True,
                    "hooks_ready": after.get("hooks_ready") is True,
                    "current_phase_index": index if type(index) is int else None,
                    "current_phase_name": ui.get("original_phase_name"),
                    "last_requested_phase_index":
                        requested if type(requested) is int else None,
                    "last_requested_phase_name": ui.get("last_requested_phase_name"),
                    "go_to_phase_entries_before": before_go,
                    "go_to_phase_entries_after": (
                        after_go if type(after_go) is int else None),
                    "account_registration_attempted": False,
                    "nintendo_account_linking_attempted": False,
                    "utid_saved": False,
                }
                # After the actual opt-out, the UI changed but the game
                # can remain in Phase 4. Take a masked screenshot ONLY if
                # a second native snapshot independently confirms Phase 4,
                # with no account creation or Nintendo linkage.
                if (
                    result["phase4_decline_probe"]["post_decline_screen_changed"]
                    and result["post_phase4_native"]["current_phase_index"] == 4
                    and result["post_phase4_native"]["last_requested_phase_index"] == 4
                ):
                    phase_path.write_text(
                        json.dumps(result, ensure_ascii=False,
                                   indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
                    capture_cmd = [
                        sys.executable,
                        str(Path(__file__).with_name(
                            "home41_phase4_post_decline_capture.py")),
                        "--age-report", str(report_path),
                        "--phase-report", str(phase_path),
                        "--output", str(phase4_dir / "post_decline_masked.png"),
                        "--status", str(phase4_dir / "post_decline_capture_status.json"),
                    ]
                    capture = subprocess.run(
                        capture_cmd, capture_output=True, text=True,
                        timeout=50, check=False)
                    result["post_decline_capture_exit_code"] = capture.returncode
                    capture_status = phase4_dir / "post_decline_capture_status.json"
                    if capture_status.is_file():
                        c = json.loads(capture_status.read_text(encoding="utf-8"))
                        result["post_decline_capture"] = {
                            "status": c.get("status"),
                            "native_phase4_gate_passed":
                                c.get("post_decline_original_phase4_confirmed") is True,
                            "masked_screenshot_saved":
                                c.get("masked_screenshot_saved") is True,
                            "screen_clicked": False,
                            "account_registration_attempted": False,
                        }
        if getattr(args, "confirm_phase4_optout_modal_once", False):
            # Separate native Phase 4 gate: only the photographed original
            # confirmation popup may receive its orange "下一步" once.
            result["phase4_modal_probe"] = {
                "status": "previous_decline_modal_not_verified",
                "original_optout_modal_next_tapped": False,
                "post_modal_screen_changed": False,
            }
            if not result.get("post_decline_capture", {}).get(
                    "masked_screenshot_saved", False):
                return result
            phase_path.write_text(
                json.dumps(result, ensure_ascii=False,
                           indent=2, sort_keys=True) + "\n",
                encoding="utf-8")
            cmd = [
                sys.executable,
                str(Path(__file__).with_name(
                    "home41_phase4_decline_modal_next_once.py")),
                "--confirm-previous-optout-once",
                "--age-report", str(report_path),
                "--phase-report", str(phase_path),
                "--output-dir", str(phase4_dir),
            ]
            try:
                done = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=90, check=False)
                result["phase4_modal_helper_exit_code"] = done.returncode
                p = phase4_dir / "phase4_modal_status.json"
                if p.is_file():
                    m = json.loads(p.read_text(encoding="utf-8"))
                    result["phase4_modal_probe"] = {
                        "status": m.get("status"),
                        "original_optout_modal_next_tapped":
                            m.get("original_optout_modal_next_tapped") is True,
                        "post_modal_screen_changed":
                            m.get("post_modal_screen_changed") is True,
                        "opt_in_clicked": False,
                        "account_registration_clicked": False,
                        "nintendo_link_clicked": False,
                    }
            except subprocess.TimeoutExpired:
                result["phase4_modal_probe"]["status"] = "modal_helper_timeout"
            if result["phase4_modal_probe"]["original_optout_modal_next_tapped"]:
                time.sleep(2)
                next_snap = sanitized_arm64_snapshot(
                    observer.arm64_agent.exports_sync.snapshot())
                next_ui = next_snap.get("firstboot_ui", {})
                next_counts = next_snap.get("counts", {})
                next_index = next_ui.get("original_phase_enum_index")
                requested = next_ui.get("last_requested_phase_enum_index")
                go = next_counts.get("firstboot_go_to_phase_entered")
                prev = result.get("post_phase4_native", {}).get(
                    "go_to_phase_entries_after")
                proved = bool(
                    next_snap.get("native_arm64") is True
                    and next_snap.get("hooks_ready") is True
                    and next_ui.get("original_phase_mapping_verified") is True
                    and type(next_index) is int and next_index == 5
                    and type(requested) is int and requested == 5
                    and type(go) is int
                    and type(prev) is int and go > prev
                )
                result["post_modal_native"] = {
                    "status": "phase_5_warning_confirmed" if proved
                              else "phase5_after_modal_not_confirmed",
                    "native_arm64": next_snap.get("native_arm64") is True,
                    "current_phase_index": (
                        next_index if type(next_index) is int else None),
                    "current_phase_name": next_ui.get("original_phase_name"),
                    "last_requested_phase_index": (
                        requested if type(requested) is int else None),
                    "last_requested_phase_name":
                        next_ui.get("last_requested_phase_name"),
                    "go_to_phase_entries_before": prev,
                    "go_to_phase_entries_after":
                        go if type(go) is int else None,
                    "account_registration_attempted": False,
                    "nintendo_account_linking_attempted": False,
                    "utid_saved": False,
                }
        return result
    except Exception as exc:
        result["status"] = "post_terms_phase_probe_exception"
        result["error_type"] = type(exc).__name__
        return result
    finally:
        finish_observer()

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
    parser.add_argument("--probe-terms-next-phase-once", action="store_true",
                        help="One disposable-AVD Terms confirmation followed by read-only native phase snapshot; never register")
    parser.add_argument("--authorize-terms-next-phase-once", action="store_true",
                        help="Explicit one-run authorization for original Terms UI on this disposable AVD")
    parser.add_argument("--confirm-guest-second-once", action="store_true",
                        help="One official final 以游客身份开始使用, may create disposable guest")
    parser.add_argument("--authorize-disposable-guest-confirm-once",
                        action="store_true",
                        help="Explicit approval of one real original final guest confirmation")
    parser.add_argument("--capture-post-guest-first-screen", action="store_true",
                        help="Read-only masked second guest prompt, only when no registration/basic")
    parser.add_argument("--confirm-guest-start-once", action="store_true",
                        help="One original guest start YES; may create a disposable guest, NEVER exports session")
    parser.add_argument("--authorize-disposable-guest-creation-once",
                        action="store_true",
                        help="Explicitly approve one guest-start UI click on disposable CI AVD")
    parser.add_argument("--capture-guest-confirmation-screen", action="store_true",
                        help="Read-only masked UI after live GEST_CONFIRMATION request; no registration")
    parser.add_argument("--probe-nintendo-no-link-once", action="store_true",
                        help="Explicit one-shot original HOME 不关联, stops at next unknown UI")
    parser.add_argument("--authorize-irreversible-nintendo-no-link-once",
                        action="store_true",
                        help="Confirm permanent inability to link this HOME account later")
    parser.add_argument("--capture-phase7-requested-screen", action="store_true",
                        help="Evidence-only masked screenshot after verified Phase7 request and opt-in")
    parser.add_argument("--probe-phase4-agree-once", action="store_true",
                        help="One user-authorized original Phase4 optional-data collection Agree")
    parser.add_argument("--authorize-phase4-agree-once", action="store_true",
                        help="Explicit one-shot authorization for right-hand Agree on verified Phase4")
    parser.add_argument("--probe-phase4-decline-once", action="store_true",
                        help="Opt-out of optional telemetry on verified original Phase 4, then read only Phase 5")
    parser.add_argument("--authorize-phase4-decline-once", action="store_true",
                        help="One-shot opt out via original LEFT different-from-agree button")
    parser.add_argument("--confirm-phase4-optout-modal-once", action="store_true",
                        help="On verified original Phase4 opt-out dialog, tap orange Next once")
    parser.add_argument("--authorize-phase4-modal-next-once", action="store_true",
                        help="Explicit one-shot authorization for original optional-data opt-out confirmation")
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
    if args.probe_terms_next_phase_once:
        if not (args.authorize_terms_next_phase_once and
                args.advance_birthday_once and
                args.probe_native_full_date_select):
            print('{"status":"terms_phase_probe_requires_explicit_optin_and_verified_age_flow"}')
            return 2
    if args.probe_phase4_decline_once:
        if not (args.authorize_phase4_decline_once and
                args.probe_terms_next_phase_once and
                args.authorize_terms_next_phase_once):
            print('{"status":"phase4_decline_requires_separate_explicit_one_shot_optin"}')
            return 2
    if args.confirm_phase4_optout_modal_once:
        if not (args.authorize_phase4_modal_next_once and
                args.probe_phase4_decline_once and
                args.authorize_phase4_decline_once):
            print('{"status":"phase4_modal_next_requires_verified_optout_one_shot"}')
            return 2
    if args.probe_phase4_agree_once:
        if not all((
            args.authorize_phase4_agree_once,
            args.probe_terms_next_phase_once,
            args.authorize_terms_next_phase_once,
            not args.probe_phase4_decline_once,
            not args.confirm_phase4_optout_modal_once,
        )):
            print('{"status":"phase4_agree_requires_exclusive_explicit_optin"}')
            return 2
    if args.capture_phase7_requested_screen and not args.probe_phase4_agree_once:
        print('{"status":"phase7_capture_requires_verified_original_phase4_agree"}')
        return 2
    if args.probe_nintendo_no_link_once:
        if not all((
            args.authorize_irreversible_nintendo_no_link_once,
            args.capture_phase7_requested_screen,
            args.probe_phase4_agree_once,
            args.authorize_phase4_agree_once,
            args.probe_terms_next_phase_once,
            args.authorize_terms_next_phase_once,
            not args.probe_phase4_decline_once,
            not args.confirm_phase4_optout_modal_once,
            not args.assisted_single_signup,
        )):
            print('{"status":"no_link_requires_explicit_approved_irreversible_one_shot"}')
            return 2
    if args.capture_guest_confirmation_screen and not (
            args.probe_nintendo_no_link_once
            and args.authorize_irreversible_nintendo_no_link_once):
        print('{"status":"guest_ui_capture_requires_one_shot_no_link_proof"}')
        return 2
    if args.confirm_guest_start_once and not all((
            args.authorize_disposable_guest_creation_once,
            args.capture_guest_confirmation_screen,
            args.probe_nintendo_no_link_once,
            args.authorize_irreversible_nintendo_no_link_once,
            args.capture_phase7_requested_screen,
            args.probe_phase4_agree_once,
            args.authorize_phase4_agree_once,
            args.probe_terms_next_phase_once,
            args.authorize_terms_next_phase_once,
            not args.assisted_single_signup,
            not args.probe_phase4_decline_once,
        )):
        print('{"status":"guest_start_requires_one_shot_user_approval_and_full_original_chain"}')
        return 2
    if args.capture_post_guest_first_screen and not (
            args.confirm_guest_start_once and
            args.authorize_disposable_guest_creation_once):
        print('{"status":"after_first_ui_requires_original_guest_yes_single_step"}')
        return 2
    if args.confirm_guest_second_once and not (
            args.authorize_disposable_guest_confirm_once
            and args.capture_post_guest_first_screen
            and args.confirm_guest_start_once
            and args.authorize_disposable_guest_creation_once
            and args.capture_guest_confirmation_screen
            and args.probe_nintendo_no_link_once
            and args.authorize_irreversible_nintendo_no_link_once
            and args.capture_phase7_requested_screen
            and args.probe_phase4_agree_once
            and args.authorize_phase4_agree_once
            and args.probe_terms_next_phase_once
            and args.authorize_terms_next_phase_once
            and not args.assisted_single_signup
            and not args.probe_phase4_decline_once):
        print('{"status":"guest_final_requires_full_original_single_signup_chain"}')
        return 2
    observer = ARM64RealmStageMonitor(
        args.server, args.network_script, args.arm64_script,
        select_year_1999=args.select_local_year_1999,
        select_month_day=args.select_local_month_day,
        probe_native_year_select=(
            args.probe_native_year_select or args.probe_native_full_date_select),
        probe_native_full_date_select=args.probe_native_full_date_select)
    observer.keep_arm64_attached = args.probe_terms_next_phase_once
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
    phase_probe_result = None
    if args.probe_terms_next_phase_once:
        phase_probe_result = run_terms_next_phase_probe(args, report, observer)
        (Path(args.output) / "home41_post_terms_phase_report.json").write_text(
            json.dumps(phase_probe_result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
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
        "account_registration": (
            "one_guest_start_ui_attempted"
            if (phase_probe_result or {}).get(
                "guest_start_probe", {}).get("guest_yes_tapped") is True
            else "not_attempted"),
        "post_terms_phase_probe": phase_probe_result,
    }, sort_keys=True))
    # Only success if the emulated ARM64 agent actually installed IL2CPP hooks.
    base_ok = (report.get("process_at_end") is True
                and arm.get("status") == "emulated_realm_attached"
                and snapshot.get("native_arm64") is True
                and snapshot.get("hooks_ready") is True)
    if args.probe_terms_next_phase_once:
        phase = (phase_probe_result or {}).get("native_phase", {})
        probe_ok = (
            (phase_probe_result or {}).get("terms_ui", {}).get("terms_next_tapped") is True
            and (phase_probe_result or {}).get("terms_ui", {}).get("post_terms_page_changed") is True
            and type(phase.get("current_phase_index")) is int
            and phase.get("native_arm64") is True
            and phase.get("hooks_ready") is True
        )
        if args.probe_phase4_agree_once:
            agree = (phase_probe_result or {}).get("phase4_agree_probe", {})
            after = (phase_probe_result or {}).get("post_phase4_agree_native", {})
            transition_ok = (
                base_ok and probe_ok
                and agree.get("optional_data_collection_agree_tapped") is True
                and agree.get("post_agree_screen_changed") is True
                and after.get("status") in (
                    "phase_5_warning_confirmed",
                    "native_phase_current_confirmed",
                    "native_phase_request_advanced_current_unreadable")
            )
            if args.capture_phase7_requested_screen:
                screen = (phase_probe_result or {}).get("phase7_screen_capture", {})
                transition_ok = (
                    transition_ok
                    and screen.get("phase7_requested") is True
                    and screen.get("masked_image_saved") is True)
            if args.probe_nintendo_no_link_once:
                choice = (phase_probe_result or {}).get(
                    "nintendo_no_link_probe", {})
                transition_ok = (
                    transition_ok
                    and choice.get("original_no_link_button_tapped") is True
                    and choice.get("post_click_screen_changed") is True
                    and choice.get("nintendo_link_button_tapped") is False
                    and choice.get("further_confirmation_tapped") is False)
            if args.capture_guest_confirmation_screen:
                visual = (phase_probe_result or {}).get(
                    "guest_confirmation_visual", {})
                req = (phase_probe_result or {}).get(
                    "post_no_link_native", {})
                transition_ok = (
                    transition_ok
                    and visual.get("gest_request_proven") is True
                    and visual.get("masked_image_saved") is True
                    and req.get("last_requested_phase_index") == 23
                    and req.get("last_requested_phase_name")
                        == "GEST_CONFIRMATION")
            if args.confirm_guest_start_once:
                start = (phase_probe_result or {}).get(
                    "guest_start_probe", {})
                native = (phase_probe_result or {}).get(
                    "post_guest_start_native", {})
                transition_ok = (
                    transition_ok
                    and start.get("guest_yes_tapped") is True
                    and start.get("post_click_screen_changed") is True
                    and start.get("nintendo_link_tapped") is False
                    and native.get("native_arm64") is True
                    and native.get("hooks_ready") is True)
            if args.capture_post_guest_first_screen:
                visual = (phase_probe_result or {}).get(
                    "after_first_visual", {})
                transition_ok = (
                    transition_ok
                    and visual.get("native_pre_registration_confirmed") is True
                    and visual.get("masked_image_saved") is True
                    and visual.get("buttons_detail_saved") is True)
            if args.confirm_guest_second_once:
                click = (phase_probe_result or {}).get("guest_final_probe",{})
                native = (phase_probe_result or {}).get(
                    "post_guest_final_native",{})
                transition_ok = (
                    transition_ok
                    and click.get("final_guest_button_tapped") is True
                    and click.get("post_click_screen_changed") is True
                    and click.get("close_button_tapped") is False
                    and native.get("native_arm64") is True
                    and native.get("hooks_ready") is True
                    and type(native.get("guest_confirm_second_entries")) is int
                    and native.get("guest_confirm_second_entries") >= 1)
            return 0 if transition_ok else 3
        if args.confirm_phase4_optout_modal_once:
            modal = (phase_probe_result or {}).get("phase4_modal_probe", {})
            post = (phase_probe_result or {}).get("post_modal_native", {})
            return 0 if (
                base_ok and probe_ok
                and modal.get("original_optout_modal_next_tapped") is True
                and modal.get("post_modal_screen_changed") is True
                and post.get("status") == "phase_5_warning_confirmed"
            ) else 3
        if args.probe_phase4_decline_once:
            nxt = (phase_probe_result or {}).get("phase4_decline_probe", {})
            post = (phase_probe_result or {}).get("post_phase4_native", {})
            return 0 if (
                base_ok and probe_ok
                and nxt.get("decline_button_tapped") is True
                and nxt.get("post_decline_screen_changed") is True
                and post.get("status") == "phase_5_warning_confirmed"
            ) else 3
        return 0 if base_ok and probe_ok else 3
    return 0 if base_ok else 3


if __name__ == "__main__":
    raise SystemExit(main())
