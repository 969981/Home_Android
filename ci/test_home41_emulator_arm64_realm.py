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
