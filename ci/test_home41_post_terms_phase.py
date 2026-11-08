#!/usr/bin/env python3
"""Pure evidence-classifier tests; no Android device or app interaction."""
import unittest

from home41_post_terms_phase import classify_post_terms_phase


def evidence():
    return (
        {
            "native_arm64": True,
            "hooks_ready": True,
            "firstboot_ui": {
                "original_controller_seen": True,
                "original_phase_enum_index": 4,
                "original_phase_name": "ADVERTISEMENT_SDK",
                "original_phase_mapping_verified": True,
                "last_requested_phase_enum_index": 4,
                "last_requested_phase_name": "ADVERTISEMENT_SDK",
                "go_to_phase_hook_attached": True,
                "advertisement_sdk_hook_attached": True,
            },
            "counts": {
                "firstboot_confirmation_advertisement_sdk_entered": 1,
                "firstboot_go_to_phase_entered": 4,
            },
        },
        {"terms_next_tapped": True, "post_terms_page_changed": True},
    )


class PostTermsPhaseTests(unittest.TestCase):
    def test_phase4_requires_all_native_transition_evidence(self):
        snap, terms = evidence()
        out = classify_post_terms_phase(snap, terms)
        self.assertEqual(out["status"], "phase_4_advertisement_sdk_confirmed")
        self.assertEqual(out["current_phase_name"], "ADVERTISEMENT_SDK")
        self.assertTrue(out["terms_next_tapped"])
        self.assertFalse(out["account_registration_attempted"])

    def test_phase4_without_method_entry_is_not_confirmed(self):
        snap, terms = evidence()
        snap["counts"]["firstboot_confirmation_advertisement_sdk_entered"] = 0
        out = classify_post_terms_phase(snap, terms)
        self.assertEqual(out["status"], "post_terms_phase_observed_needs_more_evidence")

    def test_phase4_without_go_to_phase_confirmation_is_not_confirmed(self):
        snap, terms = evidence()
        snap["firstboot_ui"]["last_requested_phase_enum_index"] = 3
        out = classify_post_terms_phase(snap, terms)
        self.assertEqual(out["status"], "post_terms_phase_observed_needs_more_evidence")

    def test_phase3_after_terms_navigation_is_reported_not_guessed(self):
        snap, terms = evidence()
        snap["firstboot_ui"]["original_phase_enum_index"] = 3
        snap["firstboot_ui"]["original_phase_name"] = "TERM_OF_SERVICE"
        snap["firstboot_ui"]["last_requested_phase_enum_index"] = 3
        snap["firstboot_ui"]["last_requested_phase_name"] = "TERM_OF_SERVICE"
        snap["counts"]["firstboot_confirmation_advertisement_sdk_entered"] = 0
        out = classify_post_terms_phase(snap, terms)
        self.assertEqual(out["status"], "post_terms_phase_observed_needs_more_evidence")
        self.assertEqual(out["current_phase_name"], "TERM_OF_SERVICE")

    def test_no_phase_or_no_terms_navigation_fails_closed(self):
        snap, terms = evidence()
        snap["firstboot_ui"]["original_phase_enum_index"] = None
        out = classify_post_terms_phase(snap, terms)
        self.assertEqual(out["status"], "post_terms_phase_unreadable")
        snap, terms = evidence()
        terms["post_terms_page_changed"] = False
        out = classify_post_terms_phase(snap, terms)
        self.assertEqual(out["status"], "terms_navigation_not_verified")

    def test_untrusted_types_and_out_of_range_indices_are_rejected(self):
        for bad in (True, False, "4", -1, 26, 999):
            with self.subTest(index=bad):
                snap, terms = evidence()
                snap["firstboot_ui"]["original_phase_enum_index"] = bad
                out = classify_post_terms_phase(snap, terms)
                self.assertNotEqual(out["status"], "phase_4_advertisement_sdk_confirmed")


if __name__ == "__main__":
    unittest.main()
