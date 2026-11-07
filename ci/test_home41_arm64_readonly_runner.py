#!/usr/bin/env python3
"""Deterministic unit tests for one-shot ARM64 UTID observe gating and redaction."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).with_name("home41_arm64_readonly_runner.py")
spec = importlib.util.spec_from_file_location("home41_arm64_readonly_runner", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class Arm64ObserverTests(unittest.TestCase):
    def test_wrong_apk_is_rejected_before_adb(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "test.apk"
            path.write_bytes(b"not the original APK")
            with patch.object(mod, "adb", side_effect=AssertionError("must not reach adb")):
                result = mod.preflight(path)
            self.assertEqual(result["result"], "apk_hash_mismatch")

    def test_native_bridge_is_not_native_arm64(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "original.apk"
            path.write_bytes(b"fixture")
            def props(key, serial):
                return {"ro.product.cpu.abi": "x86_64",
                        "ro.dalvik.vm.native.bridge": "libndk_translation.so"}.get(key, "")
            with patch.object(mod, "digest", return_value=mod.APK_SHA256), \
                 patch.object(mod, "android_prop", side_effect=props):
                result = mod.preflight(path)
            self.assertEqual(result["result"], "non_native_arm64_android")

    def test_real_guest_abi_requires_installed_matching_version(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "original.apk"
            path.write_bytes(b"fixture")
            with patch.object(mod, "digest", return_value=mod.APK_SHA256), \
                 patch.object(mod, "android_prop",
                              side_effect=lambda key, serial:
                              "arm64-v8a" if key.endswith("cpu.abi") else ""), \
                 patch.object(mod, "adb", return_value=SimpleNamespace(
                     returncode=0, stdout="Package [jp.pokemon.pokemonhome] versionCode=80")):
                result=mod.preflight(path)
            self.assertEqual(result["result"], "wrong_or_missing_installed_home_version")

    def test_native_guest_matching_version_preflight_only(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "original.apk"
            path.write_bytes(b"fixture")
            with patch.object(mod, "digest", return_value=mod.APK_SHA256), \
                 patch.object(mod, "android_prop",
                              side_effect=lambda key, serial:
                              "arm64-v8a" if key.endswith("cpu.abi") else ""), \
                 patch.object(mod, "adb", return_value=SimpleNamespace(
                     returncode=0, stdout="Package [jp.pokemon.pokemonhome] versionCode=81")):
                result=mod.preflight(path)
            self.assertEqual(result["result"], "native_arm64_original_apk_preflight_ok")
            self.assertEqual(result["utid_read_status"], "not_observed")

    def test_script_replaces_only_target_in_memory(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/"hook.js"
            path.write_text("const EXPECTED_TARGET = '888888';\n", encoding="utf-8")
            modified=mod.prepare_script(path,"123456")
            self.assertIn("'123456'",modified)
            self.assertNotIn("'888888'",modified)
            self.assertIn("'888888'",path.read_text(encoding="utf-8"))
            for invalid in ("1", "1234567", "abc123", "12345x", "１２３４５６"):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    mod.prepare_script(path,invalid)

    def test_non_send_message_is_ignored(self):
        self.assertIsNone(mod.redacted_event({
            "type":"log", "payload":"private account token"}))

    def test_public_event_discards_unknown_identity_fields(self):
        message={"type":"send","payload":{
            "kind":"home41_utid_readonly", "version":"4.1.0",
            "event":"first_basic_utid_observed",
            "candidate_matches_target": True, "utid": "1234567890",
            "uuid":"PRIVATE-ID","cookie":"private-cookie","authorization":"private-token",
            "caller_source":"a-value", "public_output_is_redacted":False}}
        clean=mod.redacted_event(message)
        self.assertTrue(clean["candidate_matches_target"])
        self.assertTrue(clean["public_output_is_redacted"])
        for key in ("utid","uuid","cookie","authorization","caller_source"):
            self.assertNotIn(key, clean)

    def test_non_whitelisted_event_discarded(self):
        message={"type":"send","payload":{
            "kind":"home41_utid_readonly","version":"4.1.0",
            "event":"token_value","token":"private-token"}}
        self.assertIsNone(mod.redacted_event(message))


if __name__=="__main__":
    unittest.main()
