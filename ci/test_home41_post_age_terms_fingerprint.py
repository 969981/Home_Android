#!/usr/bin/env python3
"""Offline only: no ADB, account creation, Terms click or API requests."""
import unittest

from home41_post_age_terms_fingerprint import fingerprint


class PostAgeFingerprintTests(unittest.TestCase):
    @staticmethod
    def report():
        return {
            "birthday_native_preflight_passed": True,
            "birthday_next_tapped": True,
            "post_next_screen_changed": True,
            "registration_status": "not_attempted",
            "terms_accepted": False,
            "account_delete_attempted": False,
            "first_basic_utid_status": "not_observed",
        }

    @staticmethod
    def focus():
        return "mCurrentFocus=Window{77 jp.pokemon.pokemonhome/com.unity3d.player.UnityPlayerActivity}"

    def test_original_home_accessibility_terms_next(self):
        xml = '''<hierarchy>
          <node package="jp.pokemon.pokemonhome" text="Terms of Use"/>
          <node package="jp.pokemon.pokemonhome" text="Privacy Notice"/>
          <node package="jp.pokemon.pokemonhome" text="Next"
                clickable="true" bounds="[300,1100][800,1220]"/>
        </hierarchy>'''
        result = fingerprint(self.report(), self.focus(), xml)
        self.assertEqual(result["status"], "preconsent_terms_accessibility_verified")
        self.assertTrue(result["terms_marker"])
        self.assertTrue(result["privacy_marker"])
        self.assertTrue(result["unique_terms_next_button"])
        self.assertFalse(result["terms_click_attempted"])
        self.assertFalse(result["raw_text_or_xml_saved"])
        self.assertFalse(result["screenshot_saved"])
        self.assertNotIn("tap", result)
        self.assertNotIn("text", result)

    def test_native_terms_source_hint_does_not_claim_visible_or_agreed(self):
        age = self.report()
        age["stage_monitor"] = {"arm64_emulated_realm": {
            "snapshot": {
                "native_arm64": True, "hooks_ready": True,
                "counts": {
                    "firstboot_terms_confirmation_setup_entered": 2,
                    "firstboot_clause_agree_part_entered": 3,
                    "firstboot_agreement_checkbox_changed": 0,
                    "terms_confirm_dialog_open_entered": 0,
                    "terms_confirm_dialog_ok_clicked": 0,
                    "raw_utid": "SHOULD_NOT_LEAK",
                }
            }
        }}
        result = fingerprint(age, self.focus(), "<hierarchy/>")
        self.assertTrue(result["native_terms_setup_event_seen"])
        self.assertTrue(result["native_clause_creation_event_seen"])
        self.assertFalse(result["native_checkbox_change_event_seen"])
        self.assertFalse(result["native_terms_page_visible_verified"])
        self.assertFalse(result["terms_click_attempted"])
        self.assertNotIn("SHOULD_NOT_LEAK", repr(result))
        self.assertEqual(result["status"], "post_age_screen_not_accessible_as_terms")

    def test_native_firstboot_phase_is_read_only_and_bounded(self):
        age = self.report()
        age["stage_monitor"] = {"arm64_emulated_realm": {
            "snapshot": {
                "native_arm64": True, "hooks_ready": True,
                "counts": {"firstboot_confirmation_terms_entered": 1},
                "firstboot_ui": {
                    "original_controller_seen": True,
                    "original_phase_enum_index": 12,
                    "raw_ptr": "PRIVATE",
                }
            }
        }}
        result = fingerprint(age, self.focus(), "<hierarchy/>")
        self.assertTrue(result["native_firstboot_controller_seen"])
        self.assertEqual(result["native_firstboot_phase_index"], 12)
        self.assertTrue(result["native_firstboot_confirmation_terms_entered"])
        self.assertFalse(result["native_firstboot_phase_mapping_verified"])
        self.assertNotIn("PRIVATE", repr(result))
        self.assertFalse(result["terms_click_attempted"])

        age["stage_monitor"]["arm64_emulated_realm"]["snapshot"]["firstboot_ui"][
            "original_phase_enum_index"] = True
        self.assertIsNone(fingerprint(age, self.focus(), "<hierarchy/>")[
            "native_firstboot_phase_index"])

    def test_untrusted_boolean_native_count_is_not_positive_hit(self):
        age = self.report()
        age["stage_monitor"] = {"arm64_emulated_realm": {
            "snapshot": {
                "native_arm64": True, "hooks_ready": True,
                "counts": {"firstboot_terms_confirmation_setup_entered": True}
            }
        }}
        result = fingerprint(age, self.focus(), "<hierarchy/>")
        self.assertFalse(result["native_terms_setup_event_seen"])

    def test_foreign_overlay_untrusted(self):
        xml = '''<hierarchy>
          <node package="com.other" text="Terms of Use"/>
          <node package="com.other" text="Privacy Notice"/>
          <node package="com.other" text="Next"
                clickable="true" bounds="[300,1100][800,1220]"/>
        </hierarchy>'''
        result = fingerprint(self.report(), self.focus(), xml)
        self.assertFalse(result["terms_marker"])
        self.assertFalse(result["unique_terms_next_button"])

    def test_no_foreground_denies_ui(self):
        result = fingerprint(self.report(), "mCurrentFocus=other.app", "broken")
        self.assertEqual(result["status"], "home_not_foreground")
        self.assertFalse(result["terms_marker"])

    def test_native_age_preflight_must_exist(self):
        for key in ("birthday_next_tapped", "birthday_native_preflight_passed",
                    "post_next_screen_changed"):
            with self.subTest(key=key):
                report = self.report()
                report[key] = False
                result = fingerprint(report, self.focus(), "<hierarchy/>")
                self.assertEqual(result["status"], "preflight_failed")

    def test_registered_or_consented_session_not_scanned(self):
        for key, value in (("terms_accepted", True),
                           ("registration_status", "complete"),
                           ("account_delete_attempted", True),
                           ("first_basic_utid_status", "observed")):
            with self.subTest(key=key):
                report = self.report()
                report[key] = value
                self.assertFalse(fingerprint(report, self.focus(), "")[
                    "age_next_native_verified"])

    def test_non_accessible_unity_screen_is_not_assumed_terms(self):
        result = fingerprint(self.report(), self.focus(), "<hierarchy/>")
        self.assertEqual(result["status"], "post_age_screen_not_accessible_as_terms")
        self.assertFalse(result["unique_terms_next_button"])
        self.assertFalse(result["unique_final_agree_button"])


if __name__ == "__main__":
    unittest.main()
