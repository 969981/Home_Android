#!/usr/bin/env python3
"""No ADB or game action in tests; verify strict read-only capture boundary."""
import unittest
from home41_phase4_post_decline_capture import capture_gate


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
            "current_phase_index":4,"current_phase_name":"ADVERTISEMENT_SDK"
        },
        "phase4_decline_probe":{
            "decline_button_tapped":True,
            "post_decline_screen_changed":True,
            "agree_button_tapped":False,
            "account_registration_attempted":False,
        },
        "post_phase4_native":{
            "native_arm64":True,"hooks_ready":True,
            "current_phase_index":4,"current_phase_name":"ADVERTISEMENT_SDK",
            "last_requested_phase_index":4,
            "account_registration_attempted":False,
            "nintendo_account_linking_attempted":False,
            "utid_saved":False,
        },
    }
    return age,phase


class Phase4PostDeclineCaptureTests(unittest.TestCase):
    def test_exact_original_phase4_post_decline_allows_masked_observation(self):
        age,phase=evidence()
        self.assertTrue(capture_gate(age,phase))

    def test_no_decline_click_no_capture(self):
        age,phase=evidence()
        phase["phase4_decline_probe"]["decline_button_tapped"]=False
        self.assertFalse(capture_gate(age,phase))

    def test_any_transition_away_from_phase4_refused(self):
        for value in (3,5,13,True,None,"4"):
            with self.subTest(value=value):
                age,phase=evidence()
                phase["post_phase4_native"]["current_phase_index"]=value
                self.assertFalse(capture_gate(age,phase))

    def test_account_or_nintendo_actions_cause_refusal(self):
        for key in ("account_registration_attempted",
                    "nintendo_account_linking_attempted","utid_saved"):
            age,phase=evidence()
            phase["post_phase4_native"][key]=True
            self.assertFalse(capture_gate(age,phase))

    def test_login_or_first_basic_blocks_capture(self):
        for key,value in (("registration_status","success"),
                          ("first_basic_utid_status","observed")):
            age,phase=evidence()
            age[key]=value
            self.assertFalse(capture_gate(age,phase))

    def test_no_native_agent_or_missing_payload_refused(self):
        age,phase=evidence()
        phase["post_phase4_native"]["native_arm64"]=False
        self.assertFalse(capture_gate(age,phase))
        self.assertFalse(capture_gate(None,None))
        self.assertFalse(capture_gate({},{}))


if __name__=="__main__":
    unittest.main()
