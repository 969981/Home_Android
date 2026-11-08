#!/usr/bin/env python3
"""No Android device, server or screen is accessed by these unit tests."""
import unittest

from home41_terms_visual_capture import eligible_for_terms_capture


class TermsVisualCaptureGateTests(unittest.TestCase):
    @staticmethod
    def evidence():
        report = {
            "process_at_end": True,
            "birthday_native_preflight_passed": True,
            "birthday_next_tapped": True,
            "post_next_screen_changed": True,
            "registration_status": "not_attempted",
            "terms_accepted": False,
            "account_delete_attempted": False,
            "first_basic_utid_status": "not_observed",
            "stage_monitor": {
                "arm64_emulated_realm": {
                    "snapshot": {
                        "native_arm64": True,
                        "hooks_ready": True,
                        "counts": {
                            "firstboot_confirmation_terms_entered": 1,
                        },
                        "firstboot_ui": {
                            "original_controller_seen": True,
                            "original_phase_enum_index": 3,
                            "original_phase_name": "TERM_OF_SERVICE",
                            "original_phase_mapping_verified": True,
                        },
                    },
                },
            },
        }
        fingerprint = {
            "age_next_native_verified": True,
            "home_foreground": True,
            "native_firstboot_controller_seen": True,
            "native_firstboot_phase_index": 3,
            "native_firstboot_phase_name": "TERM_OF_SERVICE",
            "native_firstboot_phase_mapping_verified": True,
            "native_firstboot_confirmation_terms_entered": True,
            "terms_click_attempted": False,
            "account_registration_attempted": False,
            "basic_utid_saved": False,
        }
        return report, fingerprint

    def test_verified_original_terms_gate_can_capture_masked_evidence(self):
        report, fingerprint = self.evidence()
        self.assertTrue(eligible_for_terms_capture(report, fingerprint))

    def test_all_preconditions_fail_closed(self):
        for key in ("process_at_end", "birthday_native_preflight_passed",
                    "birthday_next_tapped", "post_next_screen_changed"):
            with self.subTest(key=key):
                report, fp = self.evidence()
                report[key] = False
                self.assertFalse(eligible_for_terms_capture(report, fp))
        for key, value in (
            ("registration_status", "success"),
            ("terms_accepted", True),
            ("account_delete_attempted", True),
            ("first_basic_utid_status", "observed"),
        ):
            with self.subTest(key=key):
                report, fp = self.evidence()
                report[key] = value
                self.assertFalse(eligible_for_terms_capture(report, fp))
        for key in ("age_next_native_verified", "home_foreground",
                    "native_firstboot_controller_seen",
                    "native_firstboot_confirmation_terms_entered"):
            with self.subTest(key=key):
                report, fp = self.evidence()
                fp[key] = False
                self.assertFalse(eligible_for_terms_capture(report, fp))

    def test_original_phase_must_be_exact_integer_three(self):
        for bad in (None, False, True, 2, 4, "3", 303):
            with self.subTest(phase=bad):
                report, fp = self.evidence()
                report["stage_monitor"]["arm64_emulated_realm"]["snapshot"][
                    "firstboot_ui"]["original_phase_enum_index"] = bad
                self.assertFalse(eligible_for_terms_capture(report, fp))

    def test_native_counts_must_be_positive_integer(self):
        for bad in (None, False, True, -1, 0, "1"):
            with self.subTest(count=bad):
                report, fp = self.evidence()
                report["stage_monitor"]["arm64_emulated_realm"]["snapshot"][
                    "counts"]["firstboot_confirmation_terms_entered"] = bad
                self.assertFalse(eligible_for_terms_capture(report, fp))

    def test_only_verified_native_arm64_can_authorize_capture(self):
        for key in ("native_arm64", "hooks_ready"):
            report, fp = self.evidence()
            report["stage_monitor"]["arm64_emulated_realm"]["snapshot"][key] = False
            self.assertFalse(eligible_for_terms_capture(report, fp))
        report, fp = self.evidence()
        fp["native_firstboot_phase_index"] = 4
        self.assertFalse(eligible_for_terms_capture(report, fp))


if __name__ == "__main__":
    unittest.main()
