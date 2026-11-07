#!/usr/bin/env python3
"""Tests that the Android guest, not the GitHub host, determines ARM64 support."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

module_path = Path(__file__).with_name("home41_arm64_device_preflight.py")
spec = importlib.util.spec_from_file_location("arm64_device_preflight", module_path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class NativeAndroidGuestTests(unittest.TestCase):
    def test_arm64_host_with_x86_guest_is_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            apk=Path(d)/"test.apk"
            apk.write_bytes(b"fixture")
            with patch.object(probe,"hash_file",return_value=probe.APK_SHA256), \
                 patch.object(probe,"platform") as host, \
                 patch.object(probe,"prop") as p:
                host.machine.return_value="aarch64"
                p.side_effect=lambda k: {
                    "ro.build.version.sdk":"35",
                    "ro.product.cpu.abi":"x86_64",
                    "ro.product.cpu.abilist":"x86_64,arm64-v8a",
                    "ro.dalvik.vm.native.bridge":"libndk_translation.so"}.get(k,"")
                result=probe.report_preflight(apk, Path(d)/"report")
            self.assertEqual(result["result"],"blocked_non_native_android_guest")
            self.assertFalse(result["apk_installed"])
            self.assertFalse(result["utid_hook_attempted"])
    def test_wrong_apk_does_not_launch(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"bad.apk"
            p.write_bytes(b"fixture")
            result=probe.report_preflight(p,Path(d)/"reports")
            self.assertEqual(result["result"],"invalid_original_apk")
            self.assertFalse(result["app_launched"])

if __name__=="__main__":
    unittest.main()
