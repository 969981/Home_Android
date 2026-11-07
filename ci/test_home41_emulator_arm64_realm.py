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

    def test_birthdate_ui_invalid_list_size_is_not_reported(self):
        for val in (501, -1, "127", True):
            with self.subTest(val=val):
                state=mod.sanitize_birth_ui({"year_option_count":val})
                self.assertIsNone(state["year_option_count"])
                self.assertFalse(state["exact_birthdate_selected"])
        for val in (301,-1,"27",True):
            self.assertIsNone(mod.sanitize_birth_ui(
                {"year_1999_index":val})["year_1999_index"])

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


if __name__=="__main__":
    unittest.main()
