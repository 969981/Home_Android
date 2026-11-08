#!/usr/bin/env python3
"""Offline tests. Never launch Android or submit a HOME agreement."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from home41_terms_probe import (
    HOME_PACKAGE, classify_accessibility, center_of_bounds,
    dump_accessibility, home_is_foreground,
)


class TermsProbeTests(unittest.TestCase):
    def test_unique_official_next_is_eligible(self):
        xml = f'''<hierarchy rotation="0">
          <node package="{HOME_PACKAGE}" text="服务条款"/>
          <node package="{HOME_PACKAGE}" text="隐私政策"/>
          <node package="{HOME_PACKAGE}" text="下一步" clickable="true"
                enabled="true" bounds="[100,700][400,800]"/>
        </hierarchy>'''
        x = classify_accessibility(xml, "terms_next")
        self.assertTrue(x["eligible"])
        self.assertEqual(x["tap"], (250, 750))
        self.assertFalse(classify_accessibility(xml, "final_agree")["eligible"])

    def test_agree_is_distinct_from_next(self):
        xml = f'''<hierarchy><node package="{HOME_PACKAGE}" text="Terms of Use"/>
          <node package="{HOME_PACKAGE}" text="Privacy Notice"/>
          <node package="{HOME_PACKAGE}" text="I agree" clickable="true"
                bounds="[100,700][400,800]"/></hierarchy>'''
        self.assertTrue(classify_accessibility(xml, "final_agree")["eligible"])
        self.assertFalse(classify_accessibility(xml, "terms_next")["eligible"])

    def test_ambiguous_identical_buttons_refused(self):
        xml = f'''<hierarchy><node package="{HOME_PACKAGE}" text="服务条款"/>
          <node package="{HOME_PACKAGE}" text="隐私政策"/>
          <node package="{HOME_PACKAGE}" text="下一步" clickable="true"
                bounds="[100,700][400,800]"/>
          <node package="{HOME_PACKAGE}" text="下一步" clickable="true"
                bounds="[100,900][400,1000]"/></hierarchy>'''
        x = classify_accessibility(xml, "terms_next")
        self.assertEqual(x["button_candidates"], 2)
        self.assertFalse(x["eligible"])

    def test_missing_consent_markers_refused(self):
        xml = f'''<hierarchy><node package="{HOME_PACKAGE}" text="Welcome"/>
          <node package="{HOME_PACKAGE}" text="I agree" clickable="true"
                bounds="[100,700][400,800]"/></hierarchy>'''
        self.assertFalse(classify_accessibility(xml, "final_agree")["eligible"])

    def test_disabled_and_hidden_buttons_refused(self):
        prefix = f'''<node package="{HOME_PACKAGE}" text="Terms of Use"/>
          <node package="{HOME_PACKAGE}" text="Privacy Notice"/>'''
        for attrs in ('enabled="false"', 'visible-to-user="false"'):
            with self.subTest(attrs=attrs):
                xml = f'''<hierarchy>{prefix}
                  <node package="{HOME_PACKAGE}" text="I agree" clickable="true"
                      {attrs} bounds="[100,700][400,800]"/></hierarchy>'''
                self.assertFalse(classify_accessibility(xml, "final_agree")["eligible"])

    def test_foreign_app_overlay_not_accepted(self):
        xml = '''<hierarchy><node package="com.example.other" text="Terms of Use"/>
          <node package="com.example.other" text="Privacy Notice"/>
          <node package="com.example.other" text="Next" clickable="true"
                bounds="[100,700][400,800]"/></hierarchy>'''
        x = classify_accessibility(xml, "terms_next")
        self.assertFalse(x["eligible"])
        self.assertEqual(x["reason"], "other_app_overlay_or_package")

    def test_non_hierarchy_xml_refused(self):
        self.assertFalse(classify_accessibility("<other/>", "terms_next")["eligible"])
        self.assertFalse(classify_accessibility("garbled", "terms_next")["eligible"])

    def test_bounds_and_foreground_are_guarded(self):
        self.assertIsNone(center_of_bounds("[0,0][90000,10]"))
        self.assertIsNone(center_of_bounds("[-5,0][400,800]"))
        self.assertFalse(home_is_foreground("mCurrentFocus=other.app"))
        self.assertTrue(home_is_foreground(
            "mCurrentFocus=Window{AAA jp.pokemon.pokemonhome/X}"))

    def test_device_temporary_xml_removed_after_success(self):
        calls = []
        def adb_mock(serial, *args, **kwargs):
            calls.append(args)
            if args[1:2] == ("cat",):
                return "<hierarchy/>"
            return "ok"
        with patch("home41_terms_probe.adb", side_effect=adb_mock):
            self.assertEqual(dump_accessibility(None), "<hierarchy/>")
        self.assertTrue(any(call[1:3] == ("rm", "-f") for call in calls))

    def test_device_temporary_xml_removed_even_when_dump_fails(self):
        calls = []
        def adb_mock(serial, *args, **kwargs):
            calls.append(args)
            if args[1:3] == ("uiautomator", "dump"):
                raise RuntimeError("adb_step_failed")
            return ""
        with patch("home41_terms_probe.adb", side_effect=adb_mock):
            with self.assertRaises(RuntimeError):
                dump_accessibility(None)
        self.assertTrue(any(call[1:3] == ("rm", "-f") for call in calls))


if __name__ == "__main__":
    unittest.main()
