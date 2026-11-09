#!/usr/bin/env python3
"""Offline-only HOME 4.1.0 guest/registration chronology tests.

This module never starts Android, Frida or any network authentication.
"""
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import home41_arm64_auth_timeline as timeline


def ev(name, t):
    return {"event": name, "elapsed_ms": t}


class GuestChronologyFixtures(unittest.TestCase):
    def test_normal_chronology_is_observed_not_proven_server_success(self):
        events = [
            ev("arm64_auth_observer_ready", 1),
            ev("firstboot_confirmation_gest_account_entered", 10),
            ev("firstboot_confirm_gest_first_entered", 20),
            ev("firstboot_confirm_gest_second_entered", 30),
            ev("guest_second_direct_callee_unclassified_entered", 31),
            ev("auth_manager_register_user_entered", 100),
            ev("registration_request_serializer_entered", 110),
            ev("registration_response_handler_entered", 300),
            ev("token_response_handler_entered", 410),
            ev("login_response_handler_entered", 490),
            {**ev("first_basic_utid_observed", 500),
             "from_common_basic_consumer": True},
        ]
        result = timeline.analyze_events(events, True, None)
        self.assertEqual(result["status"], "basic_received_from_common_consumer")
        guest = result["guest_path"]
        self.assertTrue(guest["first_confirmation_entered"])
        self.assertTrue(guest["second_confirmation_entered"])
        self.assertTrue(guest["second_direct_callee_unclassified_entered"])
        self.assertTrue(guest["auth_manager_register_user_entered"])
        self.assertTrue(all(v is True for v in
                            guest["chronological_pairs"].values()))
        self.assertFalse(guest["same_server_transaction_verified"])
        self.assertFalse(result["http_request_transmitted_verified"])
        self.assertFalse(result["six_digit_id_equals_starter_ot_verified"])

    def test_original_phase_requests_only_after_second_are_not_render_proof(self):
        events=[
            {**ev("firstboot_go_to_phase_entered",10),"phase_index":23},
            ev("firstboot_confirm_gest_first_entered",20),
            ev("firstboot_confirm_gest_second_entered",30),
            {**ev("firstboot_go_to_phase_entered",40),"phase_index":15},
            {**ev("firstboot_go_to_phase_entered",50),"phase_index":21},
            {**ev("firstboot_go_to_phase_entered",60),"phase_index":24},
        ]
        guest=timeline.analyze_events(events,True,None)["guest_path"]
        self.assertEqual([x["enum_name"] for x in
                          guest["post_second_phase_requests"]],
                         ["MT_SELECT_ICON","PROLOGUE","ALL_END"])
        self.assertTrue(guest["second_callback_observed_before_phase_tracking"])
        self.assertFalse(guest["phase_is_actual_rendered_ui_verified"])
        self.assertTrue(all(x["request_only_not_confirmed_render"]
                            for x in guest["post_second_phase_requests"]))
        events.pop(2)
        guest=timeline.analyze_events(events,True,None)["guest_path"]
        self.assertEqual(guest["post_second_phase_requests"],[])

    def test_registration_manager_before_any_post_second_navigation(self):
        result=timeline.analyze_events([
            ev("firstboot_confirm_gest_second_entered",10),
            ev("auth_manager_register_user_entered",20),
            {**ev("firstboot_go_to_phase_entered",30),"phase_index":15},
        ],True,None)["guest_path"]
        self.assertEqual(result["next_step_order_after_second"],
                         "register_manager_entered_before_first_phase_request")
        self.assertIsNone(
            result["last_requested_phase_before_registration_manager"])

    def test_phase_request_before_registration_manager_not_actual_render(self):
        result=timeline.analyze_events([
            ev("firstboot_confirm_gest_second_entered",10),
            {**ev("firstboot_go_to_phase_entered",20),"phase_index":21},
            ev("auth_manager_register_user_entered",30),
        ],True,None)["guest_path"]
        self.assertEqual(result["next_step_order_after_second"],
                         "phase_requested_before_register_manager_entered")
        self.assertEqual(result["last_requested_phase_before_registration_manager"],
                         {"index":21,"enum_name":"PROLOGUE",
                          "request_only_not_confirmed_render":True})
        self.assertFalse(result["phase_is_actual_rendered_ui_verified"])

    def test_second_not_seen_cannot_guess_next_step_from_phase(self):
        guest=timeline.analyze_events([
            {**ev("firstboot_go_to_phase_entered",10),"phase_index":21},
            ev("auth_manager_register_user_entered",20),
        ],True,None)["guest_path"]
        self.assertEqual(guest["next_step_order_after_second"],
                         "second_confirmation_not_observed")
        self.assertEqual(guest["post_second_phase_requests"],[])

    def test_guest_second_without_registration_is_not_creation(self):
        result = timeline.analyze_events([
            ev("arm64_auth_observer_ready", 1),
            ev("firstboot_confirm_gest_second_entered", 100),
            ev("guest_second_direct_callee_unclassified_entered", 110)
        ], True, None)
        self.assertFalse(result["guest_path"]["auth_manager_register_user_entered"])
        self.assertFalse(result["auth"]["registration_serializer_entered"])
        self.assertFalse(result["auth"]["first_basic_utid_observed"])
        self.assertIsNone(result["guest_path"]["chronological_pairs"][
            "second_to_registration_manager"])

    def test_wrong_chronology_is_explicit_false_not_success(self):
        result = timeline.analyze_events([
            ev("registration_request_serializer_entered", 10),
            ev("auth_manager_register_user_entered", 50),
            ev("firstboot_confirm_gest_second_entered", 90),
            ev("registration_response_handler_entered", 110)
        ], True, None)
        self.assertFalse(result["guest_path"]["chronological_pairs"][
            "second_to_registration_manager"])
        self.assertFalse(result["guest_path"]["chronological_pairs"][
            "manager_to_serializer"])

    def test_unexpected_private_events_are_redacted(self):
        for event in (
            "guest_second_direct_callee_unclassified_entered",
            "post_guest_candidate_1098_entered",
            "post_guest_candidate_16f4_entered",
            "auth_manager_register_user_entered",
        ):
            msg = {"type": "send", "payload": {
                "kind": timeline.KIND, "version": "4.1.0",
                "event": event, "elapsed_ms": 45,
                "utid": "4012345678", "token": "PRIVATE", "uuid": "SECRET",
                "device_id": "PRIVATE",
            }}
            sanitized = timeline.sanitize_timeline_event(msg)
            self.assertEqual(sanitized, {"event": event, "elapsed_ms": 45})

    def test_hook_coverage_must_be_bounded_and_missing_unknown(self):
        expected = {"second_direct", "post_1098",
                    "post_16f4", "register_manager"}
        self.assertEqual(set(timeline.sanitize_guest_hook_coverage(None)),expected)
        self.assertTrue(all(v is None for v in
                            timeline.sanitize_guest_hook_coverage({}).values()))
        result = timeline.sanitize_guest_hook_coverage({
            "guest_callback_hook_coverage": {
                "second_direct": True, "post_1098": False,
                "post_16f4": 1, "register_manager": "yes",
                "raw_utid": "123456",
            }})
        self.assertEqual(result, {
            "second_direct": True, "post_1098": False,
            "post_16f4": None, "register_manager": None,
        })
        self.assertNotIn("123456", str(result))


if __name__ == "__main__":
    unittest.main()
