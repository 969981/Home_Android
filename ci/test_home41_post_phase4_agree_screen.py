#!/usr/bin/env python3
"""No ADB/server/account access. Strict phase7 request visual capture gate."""
import unittest
from home41_post_phase4_agree_screen import capture_allowed


def evidence():
    age={
        "process_at_end":True,
        "birthday_native_preflight_passed":True,
        "birthday_next_tapped":True,
        "post_next_screen_changed":True,
        "registration_status":"not_attempted",
        "first_basic_utid_status":"not_observed",
    }
    phase={
        "status":"phase_4_advertisement_sdk_confirmed",
        "native_phase":{
            "native_arm64":True,"hooks_ready":True,
            "current_phase_index":4,"current_phase_name":"ADVERTISEMENT_SDK",
        },
        "phase4_agree_probe":{
            "optional_data_collection_agree_tapped":True,
            "post_agree_screen_changed":True,
            "disagree_button_tapped":False,
            "account_registration_attempted":False,
            "nintendo_account_linking_attempted":False,
            "utid_saved":False,
        },
        "post_phase4_agree_native":{
            "status":"native_phase_request_advanced_current_unreadable",
            "native_arm64":True,"hooks_ready":True,
            "current_phase_index":None,
            "last_requested_phase_index":7,
            "last_requested_phase_name":"NA_LINK_CONTINUE",
            "go_to_phase_entries_before":4,
            "go_to_phase_entries_after":6,
            "account_registration_attempted":False,
            "nintendo_account_linking_attempted":False,
            "utid_saved":False,
        },
    }
    return age,phase


class Phase7RequestedScreenGateTests(unittest.TestCase):
    def test_original_phase7_request_can_be_photographed_without_clicks(self):
        self.assertTrue(capture_allowed(*evidence()))

    def test_never_accept_unknown_phase_request(self):
        for value in (None,True,False,"7",4,5,6,8,13):
            with self.subTest(value=value):
                age,phase=evidence()
                phase["post_phase4_agree_native"][
                    "last_requested_phase_index"]=value
                self.assertFalse(capture_allowed(age,phase))

    def test_no_opt_in_or_no_screen_transition_refuses(self):
        for key in ("optional_data_collection_agree_tapped",
                    "post_agree_screen_changed"):
            age,phase=evidence()
            phase["phase4_agree_probe"][key]=False
            self.assertFalse(capture_allowed(age,phase))

    def test_no_registration_or_nintendo_account_activity(self):
        for key in ("account_registration_attempted",
                    "nintendo_account_linking_attempted","utid_saved"):
            age,phase=evidence()
            phase["post_phase4_agree_native"][key]=True
            self.assertFalse(capture_allowed(age,phase))

    def test_missing_evidence_cannot_trigger_screenshot(self):
        age,phase=evidence()
        phase["post_phase4_agree_native"]["go_to_phase_entries_after"]=4
        self.assertFalse(capture_allowed(age,phase))
        self.assertFalse(capture_allowed({},{}))
        self.assertFalse(capture_allowed(None,None))

    def test_current_phase7_is_allowed_but_not_implicitly_claimed(self):
        age,phase=evidence()
        phase["post_phase4_agree_native"]["status"]="native_phase_current_confirmed"
        phase["post_phase4_agree_native"]["current_phase_index"]=7
        self.assertTrue(capture_allowed(age,phase))


if __name__=="__main__":
    unittest.main()
