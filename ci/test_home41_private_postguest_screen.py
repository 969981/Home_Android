#!/usr/bin/env python3
"""Private post-guest screenshot helper regressions, no real ADB or screenshot."""
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

CI=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location(
    "home41_private_postguest_screen",CI/"home41_private_postguest_screen.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fake_adb(*args, serial=None, binary=False):
    if args[:2] == ("shell","pidof"):
        return SimpleNamespace(returncode=0,stdout="12345\n")
    if args[:2] == ("shell","dumpsys"):
        return SimpleNamespace(returncode=0,stdout=(
            "mCurrentFocus=Window{a u0 jp.pokemon.pokemonhome/Activity}\n"))
    if args[:2] == ("exec-out","screencap"):
        return SimpleNamespace(returncode=0,stdout=(
            mod.PNG_MAGIC+b"MOCK_STATIC_NOT_REAL_SCREEN"+b"x"*1100))
    raise AssertionError("Unexpected action")


class PrivateScreenTests(unittest.TestCase):
    def test_refuse_ci_and_noninteractive(self):
        with patch.object(mod.sys.stdout,"isatty",return_value=True),\
             patch.object(mod,"adb",side_effect=AssertionError("adb must not run")):
            result=mod.capture("after_guest",None,env={"GITHUB_ACTIONS":"true"})
        self.assertEqual(result["status"],"requires_local_interactive_terminal")
        with patch.object(mod.sys.stdout,"isatty",return_value=False),\
             patch.object(mod,"adb",side_effect=AssertionError("adb must not run")):
            result=mod.capture("after_guest",None,env={})
        self.assertEqual(result["status"],"requires_local_interactive_terminal")

    def test_exact_foreground_required_not_any_package_mention(self):
        def not_focus(*args,**kwargs):
            if args[:2]==("shell","pidof"):
                return SimpleNamespace(returncode=0,stdout="12345")
            return SimpleNamespace(returncode=0,stdout=(
                "Random Window: jp.pokemon.pokemonhome\n"
                "mCurrentFocus=Window{a u0 other.app/Activity}\n"))
        with patch.object(mod.sys.stdout,"isatty",return_value=True),\
             patch.object(mod,"adb",side_effect=not_focus):
            self.assertEqual(mod.eligibility(None,env={}),
                             "home_not_verified_foreground")

    def test_local_capture_ignores_and_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            out=root/"local-home41-private"
            with patch.object(mod.sys.stdout,"isatty",return_value=True),\
                 patch.object(mod,"adb",side_effect=fake_adb),\
                 patch.object(mod,"ROOT",root),\
                 patch.object(mod,"PRIVATE_DIR",out):
                r=mod.capture("after_guest",None,env={})
                self.assertEqual(r["status"],"private_local_image_saved")
                self.assertFalse(r["safe_for_public_upload"])
                self.assertFalse(r["page_classification_verified"])
                self.assertTrue((out/"after_guest.png").is_file())
                self.assertEqual(mod.capture("after_guest",None,env={})["status"],
                                 "image_exists_not_overwritten")

    def test_invalid_label_does_not_touch_device(self):
        with patch.object(mod,"adb",side_effect=AssertionError("unexpected device")):
            self.assertEqual(mod.capture("../secrets",None)["status"],
                             "invalid_label")


if __name__=="__main__":
    unittest.main()
