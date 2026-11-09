#!/usr/bin/env python3
"""Offline contract tests for the ARM64 emulated-realm experiment.

These never launch Android or touch the Pokémon HOME backend.
"""
from __future__ import annotations
import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

CI = Path(__file__).parent
sys.path.insert(0, str(CI))
spec = importlib.util.spec_from_file_location(
    "home41_emulator_arm64_realm", CI / "home41_emulator_arm64_realm.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ARM64RealmContractTests(unittest.TestCase):
    def test_reconcile_original_real_emulated_arm64_snapshot(self):
        # Minimal safe fixture distilled from actual Actions #42578851634.
        # An old generic NativeBridge "unverified" preflight is NOT final
        # evidence; the later ARM64 in-realm ready + hook snapshot is.
        observed={
            "arm64_frida_runtime_status":"unverified_x86_64_native_bridge",
            "registration_status":"not_attempted",
            "stage_monitor":{"arm64_emulated_realm":{
                "status":"emulated_realm_attached",
                "agent_script_error":False,
                "error_type":None,
                "arm64_rvas_used_in_native_x64_realm":False,
                "events":[
                    {"event":"arm64_auth_observer_ready",
                     "hook_failures":0},
                    {"event":"firstboot_birthdata_setdata_entered"}],
                "snapshot":{
                    "status":"snapshot_received",
                    "native_arm64":True,
                    "native_module_ready":True,
                    "hooks_ready":True,
                    "first_basic_seen":False,
                    "raw_utid":"MUST_NOT_COPY",
                    "token":"SECRET",
                }
            }}
        }
        outcome=mod.classify_arm64_emulated_runtime(observed)
        self.assertEqual(outcome["runtime_status"],
                         "arm64_nativebridge_frida_hooks_verified")
        self.assertTrue(outcome["frida_arm64_hooks_installed_verified"])
        self.assertFalse(outcome["registration_verified"])
        self.assertFalse(outcome["first_basic_verified"])
        self.assertNotIn("MUST_NOT_COPY",str(outcome))
        self.assertNotIn("SECRET",str(outcome))

    def test_reconcile_rejects_missing_or_forged_frida_ready(self):
        baseline={
            "stage_monitor":{"arm64_emulated_realm":{
                "status":"emulated_realm_attached",
                "agent_script_error":False,
                "error_type":None,
                "arm64_rvas_used_in_native_x64_realm":False,
                "events":[{"event":"arm64_auth_observer_ready",
                           "hook_failures":0}],
                "snapshot":{"status":"snapshot_received",
                    "native_arm64":True,
                    "native_module_ready":True,
                    "hooks_ready":True}
            }}
        }
        from copy import deepcopy
        self.assertTrue(mod.classify_arm64_emulated_runtime(
            baseline)["frida_arm64_hooks_installed_verified"])
        for p,v in (
            (("snapshot","hooks_ready"),False),
            (("snapshot","native_module_ready"),False),
            (("snapshot","native_arm64"),False),
            (("snapshot","status"),"missing"),
            (("events",),[]),
            (("status",),"preflight_only"),
            (("agent_script_error",),True),
            (("arm64_rvas_used_in_native_x64_realm",),True),
        ):
            candidate=deepcopy(baseline)
            realm=candidate["stage_monitor"]["arm64_emulated_realm"]
            if len(p)==2:
                realm[p[0]][p[1]]=v
            else:
                realm[p[0]]=v
            self.assertFalse(mod.classify_arm64_emulated_runtime(
                candidate)["frida_arm64_hooks_installed_verified"],p)
        self.assertFalse(mod.classify_arm64_emulated_runtime(
            None)["frida_arm64_hooks_installed_verified"])

    def test_adjacent_callback_is_not_registered_as_required_auth_checkpoint(self):
        snapshot=mod.sanitized_arm64_snapshot({
            "native_arm64":True, "hooks_ready":True,
            "nearby_conditional_callback_blr_hook_attached":True,
            "counts":{
                "nearby_conditional_callback_blr_entered":2,
                "raw_utid":"SECRET",
                "auth_manager_indirect_dispatch_site_entered":7,
            },
            "x8_absolute_address":"PRIVATE_ADDRESS",
        })
        self.assertTrue(snapshot["nearby_conditional_callback_blr_hook_attached"])
        self.assertEqual(snapshot["counts"][
            "nearby_conditional_callback_blr_entered"],2)
        self.assertNotIn("auth_manager_indirect_dispatch_site_entered",
                         snapshot["counts"])
        self.assertNotIn("SECRET",str(snapshot))
        self.assertNotIn("PRIVATE_ADDRESS",str(snapshot))
        absent=mod.sanitized_arm64_snapshot({
            "nearby_conditional_callback_blr_hook_attached":1})
        self.assertIsNone(absent["nearby_conditional_callback_blr_hook_attached"])

    def test_snapshot_drops_secrets_and_rejects_boolean_counters(self):
        src = {
            "native_arm64": True, "hooks_ready": True,
            "first_basic_seen": True, "raw_utid": "4012345678",
            "token": "my-secret",
            "counts": {
                "first_basic_utid_observed": 1,
                "registration_request_serializer_entered": 3,
                "login_response_handler_entered": True,
                "raw_login_cookie": "my-secret",
            },
        }
        obj = mod.sanitized_arm64_snapshot(src)
        self.assertEqual(obj["counts"]["first_basic_utid_observed"], 1)
        self.assertEqual(obj["counts"]["registration_request_serializer_entered"], 3)
        self.assertNotIn("login_response_handler_entered", obj["counts"])
        self.assertTrue(obj["native_arm64"])
        self.assertNotIn("4012345678", str(obj))
        self.assertNotIn("my-secret", str(obj))
        self.assertFalse(obj["utid_raw_or_candidate_logged"])

    def test_birthdate_ui_snapshot_strips_raw_values_and_pointers(self):
        value={
            "controller_seen":True, "year_dropdown_present":True,
            "year_option_list_present":True,
            "year_option_count":127,
            "year_1999_index":27,
            "first_option_is_2026":True,
            "inputed_year_in_supported_range":True,
            "inputed_year_equals_1999":False,
            "inputed_month_in_range":False, "inputed_day_in_range":False,
            "exact_birthdate_selected":False,
            "inputed_year":2019,"inputed_month":4,"inputed_day":5,
            "memory_pointer":"0xDEADBEEF",
            "utid":"SECRET",
        }
        result=mod.sanitized_arm64_snapshot({
            "birthdate_ui":value,
            "native_arm64":True, "hooks_ready":True,
            "counts":{"firstboot_birthdata_setdata_entered":1,
                      "firstboot_birthdata_year_change_entered":3,
                      "account_password":"secret"}
        })
        state=result["birthdate_ui"]
        self.assertTrue(state["controller_seen"])
        self.assertEqual(state["year_option_count"],127)
        self.assertEqual(state["year_1999_index"],27)
        self.assertTrue(state["first_option_is_2026"])
        self.assertFalse(state["inputed_year_equals_1999"])
        self.assertNotIn("2019",repr(result))
        self.assertNotIn("0xDEADBEEF",repr(result))
        self.assertNotIn("SECRET",repr(result))
        self.assertNotIn("password",repr(result))
        self.assertEqual(result["counts"]["firstboot_birthdata_setdata_entered"],1)

    def test_month_day_indices_and_year_dropdown_state_are_allowlisted(self):
        raw={
            "year_dropdown_value_index":27,
            "year_dropdown_value_equals_1999_option":True,
            "month_dropdown":{
                "dropdown_present":True,"option_list_present":True,
                "option_count":12,"target_index":3,
                "target_found_uniquely":True,
                "value_index_equals_target":False,
                "target_option_text_verified":True,
                "secret":"DO_NOT_UPLOAD"
            },
            "day_dropdown":{
                "dropdown_present":True,"option_list_present":True,
                "option_count":31,"target_index":4,
                "target_found_uniquely":True,
                "value_index_equals_target":False,
                "target_option_text_verified":True,
                "password":"DO_NOT_UPLOAD"
            },
            "birth_day_raw":"DO_NOT_UPLOAD"
        }
        clean=mod.sanitize_birth_ui(raw)
        self.assertEqual(clean["year_dropdown_value_index"],27)
        self.assertTrue(clean["year_dropdown_value_equals_1999_option"])
        self.assertEqual(clean["month_dropdown"]["target_index"],3)
        self.assertEqual(clean["day_dropdown"]["target_index"],4)
        self.assertNotIn("DO_NOT_UPLOAD",repr(clean))
        self.assertFalse(clean["month_dropdown"]["value_index_equals_target"])

    def test_option_sanitizer_fails_closed_on_untrusted_indices(self):
        for invalid in (True,"4",34,-4,10000):
            src={"option_count":12,"target_index":invalid,
                 "options":["DO_NOT_UPLOAD"]}
            clean=mod.sanitize_option_status(src,expected_count=12)
            self.assertIsNone(clean["target_index"])
            self.assertNotIn("DO_NOT_UPLOAD",repr(clean))

    def test_birthdate_ui_invalid_list_size_is_not_reported(self):
        for val in (501, -1, "127", True):
            with self.subTest(val=val):
                state=mod.sanitize_birth_ui({"year_option_count":val})
                self.assertIsNone(state["year_option_count"])
                self.assertFalse(state["exact_birthdate_selected"])
        for val in (301,-1,"27",True):
            self.assertIsNone(mod.sanitize_birth_ui(
                {"year_1999_index":val})["year_1999_index"])

    def test_month_day_native_item_select_requires_explicit_full_date_mode(self):
        monitor=mod.ARM64RealmStageMonitor(
            Path("unused"),Path("unused"),Path("unused"))
        monitor.arm64_realm_status="emulated_realm_attached"
        monitor.arm64_agent=SimpleNamespace(exports_sync=SimpleNamespace(
            armnativemonthitemselect=lambda: (_ for _ in ()).throw(
                AssertionError("month must stay inert")),
            armnativedayitemselect=lambda: (_ for _ in ()).throw(
                AssertionError("day must stay inert"))))
        self.assertFalse(monitor.arm_native_month_item_select())
        self.assertFalse(monitor.arm_native_day_item_select())

    def test_full_date_native_selection_rpc_is_guarded(self):
        events=[]
        monitor=mod.ARM64RealmStageMonitor(
            Path("unused"),Path("unused"),Path("unused"),
            probe_native_year_select=True,
            probe_native_full_date_select=True)
        monitor.arm64_realm_status="emulated_realm_attached"
        monitor.arm64_agent=SimpleNamespace(exports_sync=SimpleNamespace(
            armnativemonthitemselect=lambda: events.append("month") or True,
            armnativedayitemselect=lambda: events.append("day") or True))
        self.assertTrue(monitor.arm_native_month_item_select())
        self.assertTrue(monitor.arm_native_day_item_select())
        self.assertEqual(events,["month","day"])
        self.assertEqual(monitor.native_month_select_arm_result,
                         "guarded_native_month_onselect_armed")
        self.assertEqual(monitor.native_day_select_arm_result,
                         "guarded_native_day_onselect_armed")

    def test_original_month_day_selected_flags_are_reduced_to_booleans(self):
        payload={"native_month_item_select_attempted":True,
                 "native_month_item_select_returned":True,
                 "native_month_item_select_confirmed":True,
                 "native_day_item_select_attempted":True,
                 "native_day_item_select_returned":True,
                 "native_day_item_select_confirmed":True,
                 "month_dropdown_is_selected":True,
                 "day_dropdown_is_selected":True,
                 "raw_http":"NEVER_PUBLISH",
                 "person_name":"NEVER_PUBLISH"}
        clean=mod.sanitize_birth_ui(payload)
        self.assertTrue(clean["native_month_item_select_confirmed"])
        self.assertTrue(clean["native_day_item_select_confirmed"])
        self.assertNotIn("NEVER_PUBLISH",repr(clean))

    def test_native_onselect_item_is_inert_without_opt_in(self):
        monitor=mod.ARM64RealmStageMonitor(
            Path("unused"),Path("unused"),Path("unused"))
        monitor.arm64_realm_status="emulated_realm_attached"
        monitor.arm64_agent=SimpleNamespace(exports_sync=SimpleNamespace(
            armnativeyearitemselect=lambda: (_ for _ in ()).throw(
                AssertionError("native OnSelectItem MUST require explicit opt-in"))))
        self.assertFalse(monitor.arm_native_year_item_select())
        self.assertEqual(monitor.native_year_select_arm_result,"not_eligible")

    def test_native_year_select_can_only_be_armed_by_explicit_mode(self):
        calls=[]
        monitor=mod.ARM64RealmStageMonitor(
            Path("unused"),Path("unused"),Path("unused"),
            probe_native_year_select=True)
        monitor.arm64_realm_status="emulated_realm_attached"
        monitor.arm64_agent=SimpleNamespace(exports_sync=SimpleNamespace(
            armnativeyearitemselect=lambda: calls.append("original_select") or True))
        self.assertTrue(monitor.arm_native_year_item_select())
        self.assertEqual(calls,["original_select"])
        self.assertEqual(monitor.native_year_select_arm_result,
                         "guarded_native_onselect_armed")

    def test_native_ui_selection_snapshot_does_not_leak_private_data(self):
        raw={
            "year_dropdown_is_selected":True,
            "month_dropdown_is_selected":False,
            "day_dropdown_is_selected":False,
            "native_year_item_select_attempted":True,
            "native_year_item_select_returned":True,
            "native_year_item_select_confirmed":True,
            "year_item_selection_count":1,
            "year_item_selected_index":27,
            "raw_utid":"NO_REAL_PRIVATE_VALUE",
            "caption_text":"PERSONAL_INFO_MUST_NOT_LEAK",
        }
        clean=mod.sanitize_birth_ui(raw)
        self.assertTrue(clean["year_dropdown_is_selected"])
        self.assertEqual(clean["year_item_selected_index"],27)
        self.assertEqual(clean["year_item_selection_count"],1)
        self.assertNotIn("NO_REAL_PRIVATE_VALUE",repr(clean))
        self.assertNotIn("PERSONAL_INFO",repr(clean))

    def test_native_year_selection_uses_original_onselectitem_after_show(self):
        agent=(CI/"home41_arm64_auth_timeline.js").read_text(encoding="utf-8")
        self.assertIn("customDropdownOnSelectItem: 0x1F15084",agent)
        self.assertIn("originalOnSelectItem(this.nativeYearItemSelectTarget, 27)",agent)
        self.assertIn("nativeYearItemSelectConfirmed",agent)
        self.assertNotIn("Memory.write",agent)

    def test_local_year_setter_is_inert_without_explicit_optin(self):
        monitor=mod.ARM64RealmStageMonitor(
            Path("unused"),Path("unused"),Path("unused"))
        monitor.arm64_realm_status="emulated_realm_attached"
        monitor.arm64_agent=SimpleNamespace(exports_sync=SimpleNamespace(
            armlocalyear1999=lambda: (_ for _ in ()).throw(
                AssertionError("must never arm without flag"))))
        self.assertFalse(monitor.arm_local_year_1999())
        self.assertEqual(monitor.local_year_set_arm_result,"not_eligible")

    def test_local_year_setter_needs_verified_agent_rpc(self):
        calls=[]
        monitor=mod.ARM64RealmStageMonitor(
            Path("unused"),Path("unused"),Path("unused"),
            select_year_1999=True)
        monitor.arm64_realm_status="emulated_realm_attached"
        monitor.arm64_agent=SimpleNamespace(exports_sync=SimpleNamespace(
            armlocalyear1999=lambda: calls.append(True) or True))
        self.assertTrue(monitor.arm_local_year_1999())
        self.assertEqual(calls,[True])
        self.assertEqual(monitor.local_year_set_arm_result,
                         "verified_options_arm_succeeded")

    def test_local_year_setter_rejects_invalid_or_unready_agent(self):
        monitor=mod.ARM64RealmStageMonitor(
            Path("unused"),Path("unused"),Path("unused"),
            select_year_1999=True)
        monitor.arm64_realm_status="emulated_realm_not_attached"
        self.assertFalse(monitor.arm_local_year_1999())
        self.assertEqual(monitor.local_year_set_arm_result,"not_eligible")
        monitor.arm64_realm_status="emulated_realm_attached"
        monitor.arm64_agent=SimpleNamespace(exports_sync=SimpleNamespace(
            armlocalyear1999=lambda: False))
        self.assertFalse(monitor.arm_local_year_1999())
        self.assertEqual(monitor.local_year_set_arm_result,
                         "native_options_not_verified")

    def test_non_dict_snapshot_fails_closed(self):
        self.assertEqual(mod.sanitized_arm64_snapshot(None),
                         {"status":"invalid_snapshot"})

    def test_bad_agent_messages_do_not_copy_raw_private_fields(self):
        monitor = mod.ARM64RealmStageMonitor(
            Path("unused"), Path("unused"), Path("unused"))
        monitor._on_arm64_message({
            "type": "send",
            "payload": {"kind":"home41_arm64_auth_timeline",
                        "version":"4.1.0",
                        "event":"first_basic_utid_observed",
                        "elapsed_ms":12,
                        "raw_utid":"PRIVATE_UTID",
                        "candidate_matches_target":False}}, None)
        self.assertEqual(len(monitor.arm64_events),1)
        self.assertNotIn("PRIVATE_UTID",repr(monitor.arm64_events))
        monitor._on_arm64_message({
            "type": "error",
            "description": "private login token"
        },None)
        self.assertTrue(monitor.arm64_script_error)
        self.assertNotIn("private login token",repr(monitor.arm64_events))

    def test_emulated_realm_failure_has_no_false_native_success(self):
        m = mod.ARM64RealmStageMonitor(
            Path("unused"), Path("unused"), Path("unused"))
        with patch.object(mod.StageMonitor, "start",
                          return_value={"status":"native_attach_error"}):
            m.setup = "native_realm_not_ready"
            result = m.start()
        self.assertEqual(m.arm64_realm_status,"native_realm_not_ready")
        self.assertEqual(result["status"],"native_attach_error")

    def test_emulated_realm_is_only_way_to_attach_arm64(self):
        script=(CI/"home41_emulator_arm64_realm.py").read_text(encoding="utf-8")
        self.assertIn('realm="emulated"',script)
        self.assertIn('arm64_rvas_used_in_native_x64_realm": False',script)
        self.assertNotIn("getattr(args, 'token'",script)

    def test_emulated_realm_must_be_native_arm64_and_hooks_ready(self):
        bad_snapshots = [
            {"native_arm64":False,"hooks_ready":True},
            {"native_arm64":True,"hooks_ready":False},
        ]
        for raw in bad_snapshots:
            with self.subTest(raw=raw):
                clean=mod.sanitized_arm64_snapshot(raw)
                self.assertFalse(clean["native_arm64"] and clean["hooks_ready"])




class AssistedSingleAccountGuardTests(unittest.TestCase):
    """No Android, network, signup, consent or account mutation in these tests."""

    @staticmethod
    def valid_report():
        return {
            "process_at_end": True,
            "birthday_submitted": False,
            "birthday_native_preflight_passed": True,
            "birthday_next_tapped": True,
            "post_next_screen_changed": True,
            "registration_status": "not_attempted",
            "terms_accepted": False,
            "account_delete_attempted": False,
            "local_month_day_probe": {
                "year_caption_roi_changed": True,
                "month_caption_roi_changed": True,
                "day_caption_roi_changed": True,
                "native_year_item_select_armed": True,
                "native_month_item_select_armed": True,
                "native_day_item_select_armed": True,
            },
            "stage_monitor": {
                "arm64_emulated_realm": {
                    "status": "emulated_realm_attached",
                    "snapshot": {
                        "native_arm64": True,
                        "hooks_ready": True,
                        "birthdate_ui": {
                            "exact_birthdate_selected": True,
                            "inputed_year_equals_1999": True,
                            "inputed_month_equals_4": True,
                            "inputed_day_equals_5": True,
                            "year_dropdown_is_selected": True,
                            "month_dropdown_is_selected": True,
                            "day_dropdown_is_selected": True,
                            "native_year_item_select_confirmed": True,
                            "native_month_item_select_confirmed": True,
                            "native_day_item_select_confirmed": True,
                        },
                    },
                },
            },
        }

    def test_realistic_verified_date_can_proceed_to_manual_only_stage(self):
        self.assertTrue(mod.confirmed_local_date_for_assisted_signup(
            self.valid_report()))

    def test_unverified_or_auto_submitted_date_rejected(self):
        for k, bad in (
            ("process_at_end", False),
            ("birthday_submitted", True),
            ("birthday_native_preflight_passed", False),
            ("birthday_next_tapped", False),
            ("post_next_screen_changed", False),
            ("registration_status", "success"),
            ("terms_accepted", True),
            ("account_delete_attempted", True),
        ):
            with self.subTest(key=k):
                report = self.valid_report()
                report[k] = bad
                self.assertFalse(mod.confirmed_local_date_for_assisted_signup(report))

    def test_any_unverified_dropdown_or_visual_change_rejected(self):
        report = self.valid_report()
        for key in tuple(report["local_month_day_probe"]):
            with self.subTest(key=key):
                value = self.valid_report()
                value["local_month_day_probe"][key] = False
                self.assertFalse(mod.confirmed_local_date_for_assisted_signup(value))
        # The UI controller may be unloaded once the original age NEXT is
        # clicked. We rely on native preflight at the tap, not a stale pointer.
        value = self.valid_report()
        value["stage_monitor"]["arm64_emulated_realm"][
            "snapshot"]["birthdate_ui"] = {}
        self.assertTrue(mod.confirmed_local_date_for_assisted_signup(value))

    def test_missing_or_broken_frida_never_enters_signup(self):
        self.assertFalse(mod.confirmed_local_date_for_assisted_signup(None))
        self.assertFalse(mod.confirmed_local_date_for_assisted_signup({}))
        for key, val in (("status", "frida_unavailable"),
                         ("snapshot", {}),
                         ("native_arm64", False),
                         ("hooks_ready", False)):
            with self.subTest(key=key):
                value = self.valid_report()
                realm = value["stage_monitor"]["arm64_emulated_realm"]
                if key in ("status", "snapshot"):
                    realm[key] = val
                else:
                    realm["snapshot"][key] = val
                self.assertFalse(mod.confirmed_local_date_for_assisted_signup(value))

    def test_ci_cannot_arm_interactive_account_flow(self):
        argv = ["script", "--apk", "x.apk", "--output", "out",
                "--server", "frida-server",
                "--assisted-single-signup",
                "--probe-birthday-year", "--select-local-year-1999",
                "--select-local-month-day", "--probe-native-full-date-select"]
        fake_tty = SimpleNamespace(isatty=lambda: True, write=lambda _: None,
                                   flush=lambda: None)
        with patch.object(sys, "argv", argv), patch.dict(
                "os.environ", {"GITHUB_ACTIONS": "true"}), patch.object(
                    sys, "stdout", fake_tty):
            self.assertEqual(mod.main(), 2)


if __name__=="__main__":
    unittest.main()
