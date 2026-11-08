#!/usr/bin/env python3
"""Pure tests for Phase 4 capture gate; no ADB or live HOME."""
import unittest
from home41_phase4_masked_capture import phase4_capture_allowed


def evidence():
    return {
        "process_at_end":True,
        "registration_status":"not_attempted",
        "account_registration":"not_attempted",
        "post_terms_phase_probe":{
            "status":"phase_4_advertisement_sdk_confirmed",
            "terms_ui":{"terms_next_tapped":True,"post_terms_page_changed":True},
            "native_phase":{
                "native_arm64":True,"hooks_ready":True,
                "firstboot_controller_seen":True,"phase_mapping_verified":True,
                "current_phase_index":4,"current_phase_name":"ADVERTISEMENT_SDK",
                "last_requested_phase_index":4,
                "last_requested_phase_name":"ADVERTISEMENT_SDK",
                "go_to_phase_hook_attached":True,
                "advertisement_sdk_hook_attached":True,
                "advertisement_sdk_method_entries":1,
                "go_to_phase_entries":4,
                "account_registration_attempted":False,
                "nintendo_account_linking_attempted":False,
                "utid_saved":False,"http_body_saved":False,"raw_screen_saved":False,
            },
        },
    }


class Phase4CaptureGateTests(unittest.TestCase):
    def test_only_fully_confirmed_phase4_allows_masked_capture(self):
        self.assertTrue(phase4_capture_allowed(evidence()))

    def test_phase3_or_phase5_rejected(self):
        for value in (3,5):
            x=evidence()
            x["post_terms_phase_probe"]["native_phase"]["current_phase_index"]=value
            self.assertFalse(phase4_capture_allowed(x))

    def test_requested_phase_must_also_be_four(self):
        x=evidence()
        x["post_terms_phase_probe"]["native_phase"]["last_requested_phase_index"]=3
        self.assertFalse(phase4_capture_allowed(x))

    def test_method_and_transition_hooks_required(self):
        keys=("advertisement_sdk_hook_attached","go_to_phase_hook_attached")
        for key in keys:
            x=evidence()
            x["post_terms_phase_probe"]["native_phase"][key]=False
            self.assertFalse(phase4_capture_allowed(x))
        x=evidence()
        x["post_terms_phase_probe"]["native_phase"]["advertisement_sdk_method_entries"]=0
        self.assertFalse(phase4_capture_allowed(x))

    def test_no_screenshot_when_not_native_or_registered(self):
        x=evidence()
        x["post_terms_phase_probe"]["native_phase"]["native_arm64"]=False
        self.assertFalse(phase4_capture_allowed(x))
        x=evidence()
        x["account_registration"]="success"
        self.assertFalse(phase4_capture_allowed(x))

    def test_no_capture_if_sensitive_actions_were_attempted(self):
        for key in ("account_registration_attempted",
                    "nintendo_account_linking_attempted",
                    "utid_saved","http_body_saved","raw_screen_saved"):
            x=evidence()
            x["post_terms_phase_probe"]["native_phase"][key]=True
            self.assertFalse(phase4_capture_allowed(x))

    def test_bool_is_not_a_phase_index_or_count(self):
        x=evidence()
        x["post_terms_phase_probe"]["native_phase"]["current_phase_index"]=True
        self.assertFalse(phase4_capture_allowed(x))
        x=evidence()
        x["post_terms_phase_probe"]["native_phase"]["advertisement_sdk_method_entries"]=True
        self.assertFalse(phase4_capture_allowed(x))


if __name__=="__main__":
    unittest.main()
