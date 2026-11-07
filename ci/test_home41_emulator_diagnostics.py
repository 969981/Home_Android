#!/usr/bin/env python3
"""Offline guards for the disposable HOME Android emulator probe."""
import importlib.util
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).with_name("home41_emulator_diagnostics.py")
spec = importlib.util.spec_from_file_location("home41_ci_probe", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProbeTests(unittest.TestCase):
    def test_unknown_png_never_clicks(self):
        self.assertIsNone(probe.match_known_ui(b"", "language"))
        self.assertIsNone(probe.match_known_ui(b"not a png", "region_dropdown"))
        self.assertIsNone(probe.match_known_ui(probe.PNG_MAGIC, "language_confirmation"))

    def test_known_ui_signature_but_unknown_stage_never_clicks(self):
        from PIL import Image
        img = Image.new("RGB", (1080, 2340), (240, 246, 236))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        self.assertIsNone(probe.match_known_ui(buf.getvalue(), "terms"))
        self.assertIsNone(probe.match_known_ui(buf.getvalue(), "registration"))
        self.assertIsNone(probe.match_known_ui(buf.getvalue(), "delete"))

    def test_native_sha_check_fails_closed_on_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "fixture.apk"
            with zipfile.ZipFile(target, "w") as z:
                z.writestr("lib/arm64-v8a/libil2cpp.so", b"fixture")
            result = probe.inspect_native(target)
            self.assertTrue(result["arm64_libil2cpp_present"])
            self.assertFalse(result["arm64_libil2cpp_hash_matched"])

    def test_native_absence_is_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "fixture.apk"
            with zipfile.ZipFile(target, "w") as z:
                z.writestr("classes.dex", b"fixture")
            result = probe.inspect_native(target)
            self.assertFalse(result["arm64_libil2cpp_present"])
            self.assertFalse(result["arm64_libil2cpp_hash_matched"])


if __name__ == "__main__":
    unittest.main()
