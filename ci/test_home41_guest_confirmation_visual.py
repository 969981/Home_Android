#!/usr/bin/env python3
"""Offline evidence-gate tests: never accesses Android/HOME or registers."""
import copy
import unittest

from home41_guest_confirmation_visual import guest_visual_allowed


def evidence():
    age = {
        "process_at_end": True,
        "birthday_native_preflight_passed": True,
        "birthday_next_tapped": True,
        "post_next_screen_changed": True,
        "registration_status": "not_attempted",
        "first_basic_utid_status": "not_observed",
    }
    phase = {
        "status": "phase_4_advertisement_sdk_confirmed",
        "native_phase": {
            "native_arm64": True,
            "hooks_ready": True,
            "current_phase_index": 4,
            "current_phase_name": "ADVERTISEMENT_SDK",
        },
        "phase4_agree_probe": {
            "optional_data_collection_agree_tapped": True,
            "post_agree_screen_changed": True,
            "disagree_button_tapped": False,
            "account_registration_attempted": False,
            "nintendo_account_linking_attempted": False,
            "utid_saved": False,
        },
        "post_phase4_agree_native": {
            "status": "native_phase_request_advanced_current_unreadable",
            "native_arm64": True,
            "hooks_ready": True,
            "last_requested_phase_index": 7,
            "last_requested_phase_name": "NA_LINK_CONTINUE",
            "go_to_phase_entries_before": 4,
            "go_to_phase_entries_after": 6,
            "account_registration_attempted": False,
            "nintendo_account_linking_attempted": False,
            "utid_saved": False,
        },
        "phase7_screen_capture": {
            "phase7_requested": True,
            "masked_image_saved": True,
        },
        "nintendo_no_link_probe": {
            "status": "original_no_link_tapped_new_screen",
            "original_no_link_button_tapped": True,
            "post_click_screen_changed": True,
            "nintendo_link_button_tapped": False,
            "further_confirmation_tapped": False,
            "registration_button_tapped": False,
        },
        "post_no_link_native": {
            "status": "original_phase_requested_after_no_link",
            "native_arm64": True,
            "hooks_ready": True,
            "last_requested_phase_index": 23,
            "last_requested_phase_name": "GEST_CONFIRMATION",
            "go_to_phase_entries_before": 6,
            "go_to_phase_entries_after": 7,
            "nintendo_link_button_tapped": False,
            "registration_button_tapped": False,
            "utid_saved": False,
            "registration_serializer_entries": 0,
            "first_basic_seen": False,
        },
    }
    return age, phase


class GuestConfirmationCaptureGateTests(unittest.TestCase):
    def test_valid_native_request_is_allowed_for_read_only_capture(self):
        self.assertTrue(guest_visual_allowed(*evidence()))

    def test_stage_request_must_be_23_but_current_stage_can_be_unreadable(self):
        for bad in (None, True, False, "23", 4, 7, 13, 24):
            with self.subTest(stage=bad):
                age, phase = evidence()
                phase["post_no_link_native"]["last_requested_phase_index"] = bad
                self.assertFalse(guest_visual_allowed(age, phase))
        age, phase = evidence()
        phase["post_no_link_native"]["current_phase_index"] = None
        self.assertTrue(guest_visual_allowed(age, phase))

    def test_click_and_followup_request_cannot_be_inferred(self):
        for key in ("original_no_link_button_tapped", "post_click_screen_changed"):
            age, phase = evidence()
            phase["nintendo_no_link_probe"][key] = False
            self.assertFalse(guest_visual_allowed(age, phase))
        for key in ("masked_image_saved", "phase7_requested"):
            age, phase = evidence()
            phase["phase7_screen_capture"][key] = False
            self.assertFalse(guest_visual_allowed(age, phase))

    def test_register_or_utid_requires_no_screenshot(self):
        for value in (None, 1, True, -1, "0"):
            age, phase = evidence()
            phase["post_no_link_native"]["registration_serializer_entries"] = value
            self.assertFalse(guest_visual_allowed(age, phase))
        for value in (None, True, "false"):
            age, phase = evidence()
            phase["post_no_link_native"]["first_basic_seen"] = value
            self.assertFalse(guest_visual_allowed(age, phase))

    def test_no_link_button_must_be_the_one_clicked(self):
        for key in ("nintendo_link_button_tapped", "further_confirmation_tapped",
                    "registration_button_tapped"):
            age, phase = evidence()
            phase["nintendo_no_link_probe"][key] = True
            self.assertFalse(guest_visual_allowed(age, phase))

    def test_native_go_to_phase_increment_and_origin_must_match(self):
        for value in (None, False, True, 5, 7, "6"):
            age, phase = evidence()
            phase["post_no_link_native"]["go_to_phase_entries_before"] = value
            self.assertFalse(guest_visual_allowed(age, phase))
        for value in (None, 6, "7", True, 100001):
            age, phase = evidence()
            phase["post_no_link_native"]["go_to_phase_entries_after"] = value
            self.assertFalse(guest_visual_allowed(age, phase))

    def test_no_account_creation_and_missing_reports(self):
        age, phase = evidence()
        age["registration_status"] = "created"
        self.assertFalse(guest_visual_allowed(age, phase))
        age, phase = evidence()
        age["first_basic_utid_status"] = "observed"
        self.assertFalse(guest_visual_allowed(age, phase))
        self.assertFalse(guest_visual_allowed(None, None))
        self.assertFalse(guest_visual_allowed({}, {}))


if __name__ == "__main__":
    unittest.main()
