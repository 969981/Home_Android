#!/usr/bin/env python3
"""Offline evidence-only tests, no ADB, account, screenshots or service use."""
import unittest

from home41_guest_after_first_visual import eligible_after_first
from test_home41_guest_confirmation_visual import evidence as base


def evidence():
    age, phase = base()
    phase["guest_start_probe"]={
        "status":"guest_yes_tapped_new_screen",
        "guest_yes_tapped":True,
        "post_click_screen_changed":True,
        "nintendo_link_tapped":False,
        "additional_signup_ui_tapped":False,
        "token_saved":False,
    }
    phase["post_guest_start_native"]={
        "native_arm64":True,"hooks_ready":True,
        "registration_serializer_entries":0,
        "registration_response_handler_entries":0,
        "first_basic_seen":False,
        "first_basic_utid_event_count":0,
        "guest_confirmation_method_entries":1,
        "guest_first_method_entries":1,
        "guest_second_method_entries":0,
        "raw_utid_saved":False,"token_saved":False,
        "account_persisted_verified":False,
        "registration_completed_verified":False,
    }
    return age,phase


class AfterFirstGuestVisualTests(unittest.TestCase):
    def test_only_original_unregistered_second_page_is_eligible(self):
        self.assertTrue(eligible_after_first(*evidence()))

    def test_registration_or_response_or_basic_blocks_photo(self):
        for field in ("registration_serializer_entries",
                      "registration_response_handler_entries",
                      "first_basic_utid_event_count"):
            for v in (True,1,None,"0"):
                with self.subTest(field=field,v=v):
                    age,phase=evidence()
                    phase["post_guest_start_native"][field]=v
                    self.assertFalse(eligible_after_first(age,phase))
        age,phase=evidence()
        phase["post_guest_start_native"]["first_basic_seen"]=True
        self.assertFalse(eligible_after_first(age,phase))

    def test_guest_first_required_and_second_must_be_zero(self):
        for field,v in (("guest_confirmation_method_entries",0),
                        ("guest_first_method_entries",0),
                        ("guest_second_method_entries",1)):
            age,phase=evidence()
            phase["post_guest_start_native"][field]=v
            self.assertFalse(eligible_after_first(age,phase))

    def test_unverified_ui_or_missing_age_is_denied(self):
        for name in ("guest_yes_tapped","post_click_screen_changed"):
            age,phase=evidence()
            phase["guest_start_probe"][name]=False
            self.assertFalse(eligible_after_first(age,phase))
        age,phase=evidence()
        phase["guest_start_probe"]["status"]="guest_start_tapped_unknown"
        self.assertFalse(eligible_after_first(age,phase))
        self.assertFalse(eligible_after_first({},{}))

    def test_raw_token_or_session_status_is_denied(self):
        for name in ("raw_utid_saved","token_saved",
                     "account_persisted_verified",
                     "registration_completed_verified"):
            age,phase=evidence()
            phase["post_guest_start_native"][name]=True
            self.assertFalse(eligible_after_first(age,phase))


if __name__ == "__main__":
    unittest.main()
