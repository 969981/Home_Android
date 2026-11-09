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
    def test_classify_second_then_positive_register_chain(self):
        full = {name: True for name in
                timeline.GUEST_CHAIN_CRITICAL_HOOK_KEYS}
        events = [
            ev("firstboot_confirm_gest_second_entered",10),
            ev("guest_second_decision_thunk_entered",11),
            ev("firstboot_decision_gest_account_entered",12),
            ev("auth_manager_register_user_entered",13),
            ev("registration_request_serializer_entered",14),
            ev("registration_response_handler_entered",20),
            {**ev("first_basic_utid_observed",30),
             "from_common_basic_consumer": True},
        ]
        result = timeline.diagnose_guest_chain(events,full)
        self.assertEqual(result["classification"],
                         "first_basic_seen_ui_six_digit_id_not_verified")
        self.assertEqual(result["observed_checkpoints"][0],
                         "second_confirmation")
        self.assertTrue(result["all_critical_hooks_installed"])
        self.assertFalse(result["server_registration_confirmed"])
        self.assertFalse(result["ui_six_digit_id_verified"])
        self.assertFalse(result["cold_start_account_restored_verified"])

    def test_basic_event_without_verified_caller_does_not_pass(self):
        full = {name: True for name in timeline.GUEST_CHAIN_CRITICAL_HOOK_KEYS}
        events = [
            ev("firstboot_confirm_gest_second_entered",10),
            ev("registration_response_handler_entered",25),
            ev("first_basic_utid_observed",30),
        ]
        result = timeline.diagnose_guest_chain(events,full)
        self.assertEqual(result["classification"],
                         "first_basic_event_without_verified_common_caller")
        self.assertFalse(result["first_basic_common_caller_verified"])
        self.assertFalse(result["ui_six_digit_id_verified"])

    def test_classify_guest_callback_gap_requires_hook_installation(self):
        good = {key: True for key in
                timeline.GUEST_CHAIN_CRITICAL_HOOK_KEYS}
        bad = {**good, "positive_thunk": False,
               "decision_controller": None}
        events=[ev("firstboot_confirm_gest_second_entered",10)]
        diagnosed=timeline.diagnose_guest_chain(events,bad)
        self.assertEqual(diagnosed["classification"],
                         "second_seen_no_followup_in_observation_window")
        self.assertFalse(diagnosed["all_critical_hooks_installed"])
        self.assertIn("positive_thunk",diagnosed[
            "missing_or_unverified_critical_hooks"])
        self.assertIn("decision_controller",diagnosed[
            "missing_or_unverified_critical_hooks"])
        self.assertTrue(timeline.diagnose_guest_chain(
            events,good)["all_critical_hooks_installed"])

    def test_mixed_decision_and_denial_never_confirm_registration(self):
        coverage={key:True for key in
                  timeline.GUEST_CHAIN_CRITICAL_HOOK_KEYS}
        events=[
            ev("firstboot_confirm_gest_second_entered",10),
            ev("guest_second_decision_thunk_entered",11),
            ev("guest_second_denial_thunk_entered",12),
            ev("auth_manager_register_user_entered",14),
        ]
        result=timeline.diagnose_guest_chain(events,coverage)
        self.assertEqual(result["classification"],
                         "mixed_guest_decisions_require_instance_correlation")
        self.assertFalse(result["server_registration_confirmed"])

    def test_critical_coverage_sanitizer_has_no_identity_channel(self):
        unverified=timeline.sanitize_guest_chain_critical_coverage(None)
        self.assertTrue(all(x is None for x in unverified.values()))
        clean=timeline.sanitize_guest_chain_critical_coverage({
            "guest_chain_critical_hook_coverage": {
                "confirm_second":True, "positive_thunk":1,
                "negative_thunk":False, "register_manager":"yes",
                "raw_utid":"SECRET", "token":"NO_LOG",
            }})
        self.assertTrue(clean["confirm_second"])
        self.assertIsNone(clean["positive_thunk"])
        self.assertFalse(clean["negative_thunk"])
        self.assertIsNone(clean["register_manager"])
        self.assertNotIn("SECRET",str(clean))
        self.assertNotIn("NO_LOG",str(clean))
        js=Path(__file__).with_name("home41_arm64_auth_timeline.js").read_text(
            encoding="utf-8")
        self.assertIn("guest_chain_critical_hook_coverage",js)
        for name in timeline.GUEST_CHAIN_CRITICAL_HOOK_KEYS:
            self.assertIn(name + ":",js)

    def test_adjacent_blr_rva_report_does_not_claim_manager_membership(self):
        cov={name:True for name in timeline.GUEST_CHAIN_CRITICAL_HOOK_KEYS}
        steps=[
            ev("firstboot_confirm_gest_second_entered",10),
            ev("auth_manager_register_user_entered",20),
            {**ev("nearby_conditional_callback_blr_entered",25),
             "dispatch_target_in_original_libil2cpp":True,
             "dispatch_target_rva":0x1D334A4},
            {**ev("nearby_conditional_callback_blr_entered",26),
             "dispatch_target_in_original_libil2cpp":True,
             "dispatch_target_rva":0x1D334A4},
            {**ev("nearby_conditional_callback_blr_entered",27),
             "dispatch_target_in_original_libil2cpp":False,
             "dispatch_target_rva":0xDEADBEEF},
        ]
        report=timeline.diagnose_guest_chain(steps,cov)
        self.assertEqual(report["nearby_callback_module_relative_target_rvas"],
                         ["0x1D334A4"])
        self.assertFalse(report["nearby_callback_function_identity_verified"])
        self.assertFalse(report["nearby_callback_belongs_to_registration_manager_verified"])
        self.assertFalse(report["server_registration_confirmed"])

    def test_adjacent_blr_does_not_count_as_manager_dispatch(self):
        full = {name:True for name in
                timeline.GUEST_CHAIN_CRITICAL_HOOK_KEYS}
        started = [
            ev("firstboot_confirm_gest_second_entered",10),
            ev("guest_second_decision_thunk_entered",20),
            ev("firstboot_decision_gest_account_entered",22),
            ev("auth_manager_register_user_entered",25),
        ]
        manager_only = timeline.diagnose_guest_chain(started,full)
        self.assertEqual(manager_only["classification"],
                         "register_manager_seen_serializer_not_observed")
        dispatch = timeline.diagnose_guest_chain(
            started + [ev("nearby_conditional_callback_blr_entered",27)],
            full)
        self.assertEqual(dispatch["classification"],
                         "register_manager_seen_serializer_not_observed")
        self.assertNotIn("registration_manager_indirect_dispatch",
                         dispatch["observed_checkpoints"])
        self.assertNotIn("register_dispatch_site",
                         timeline.GUEST_CHAIN_CRITICAL_HOOK_KEYS)
        self.assertFalse(dispatch["server_registration_confirmed"])
        self.assertFalse(dispatch["ui_six_digit_id_verified"])

    def test_verified_manager_tail_target_and_unknown_downstream(self):
        coverage={k:True for k in timeline.GUEST_CHAIN_CRITICAL_HOOK_KEYS}
        events=[
            ev("firstboot_confirm_gest_second_entered",10),
            ev("guest_second_decision_thunk_entered",12),
            ev("firstboot_decision_gest_account_entered",15),
            ev("auth_manager_register_user_entered",20),
            ev("auth_manager_tail_target_entered",21),
            ev("auth_manager_tail_callee_35cc8_entered",30),
        ]
        diagnosis=timeline.diagnose_guest_chain(events,coverage)
        self.assertEqual(diagnosis["classification"],
                         "register_tail_downstream_seen_serializer_not_observed")
        self.assertIn("register_manager_tail_target",
                      diagnosis["observed_checkpoints"])
        self.assertIn("register_manager_tail_downstream_unclassified",
                      diagnosis["observed_checkpoints"])
        self.assertFalse(diagnosis["server_registration_confirmed"])
        self.assertFalse(diagnosis["ui_six_digit_id_verified"])
        partial=timeline.diagnose_guest_chain(events[:-1],coverage)
        self.assertEqual(partial["classification"],
                         "register_tail_target_seen_downstream_not_observed")
        self.assertFalse(timeline.diagnose_guest_chain(
            events[:-2],coverage)["server_registration_confirmed"])

    def test_optional_tail_hook_coverage_is_not_assumed_success(self):
        self.assertEqual(timeline.sanitize_register_tail_hook_coverage(None),{
            "tail_target_1d2f1f8":None,
            "downstream_1d35cc8":None,
        })
        result=timeline.sanitize_register_tail_hook_coverage({
            "registration_tail_observer_hook_coverage":{
                "tail_target_1d2f1f8":True,
                "downstream_1d35cc8":2,
                "raw_account_token":"NEVER_LEAK",
            }
        })
        self.assertIs(result["tail_target_1d2f1f8"],True)
        self.assertIsNone(result["downstream_1d35cc8"])
        self.assertNotIn("NEVER_LEAK",str(result))
        source=Path(__file__).with_name("home41_arm64_auth_timeline.js").read_text(
            encoding="utf-8")
        self.assertIn("authManagerTailTarget: 0x1D2F1F8",source)
        self.assertIn("authManagerTailCallee35CC8: 0x1D35CC8",source)

    def test_normal_chronology_is_observed_not_proven_server_success(self):
        events = [
            ev("arm64_auth_observer_ready", 1),
            ev("firstboot_confirmation_gest_account_entered", 10),
            ev("firstboot_confirm_gest_first_entered", 20),
            ev("firstboot_confirm_gest_second_entered", 30),
            ev("guest_second_direct_callee_unclassified_entered", 31),
            ev("guest_second_decision_thunk_entered", 32),
            ev("firstboot_decision_gest_account_entered", 40),
            ev("auth_manager_register_user_entered", 100),
            ev("nearby_conditional_callback_blr_entered", 105),
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
        positive = {k:v for k,v in guest["chronological_pairs"].items()
                    if k not in ("second_to_denial_thunk",
                                 "denial_thunk_to_denial_controller")}
        self.assertTrue(all(v is True for v in positive.values()))
        self.assertIsNone(guest["chronological_pairs"]["second_to_denial_thunk"])
        self.assertIsNone(guest["chronological_pairs"]["denial_thunk_to_denial_controller"])
        self.assertTrue(guest["decision_thunk_entered"])
        self.assertTrue(guest["decision_controller_entered"])
        self.assertFalse(guest["denial_thunk_entered"])
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

    def test_original_avatar_and_starter_entries_before_register_manager(self):
        events = [
            ev("firstboot_confirm_gest_second_entered", 10),
            {**ev("firstboot_go_to_phase_entered", 20), "phase_index": 15},
            ev("firstboot_select_trainer_icon_entered", 30),
            ev("firstboot_add_icon_selector_entered", 40),
            ev("firstboot_icon_selector_create_images_entered", 45),
            ev("firstboot_icon_selector_on_tap_icon_entered", 80),
            ev("firstboot_play_prologue_entered", 90),
            ev("firstboot_prologue_pokemon_panel_open_entered", 100),
            ev("firstboot_prologue_pokemon_panel_on_tap_pokemon_entered", 150),
            ev("auth_manager_register_user_entered", 180),
        ]
        guest = timeline.analyze_events(events, True, None)["guest_path"]
        self.assertEqual(guest["named_ui_vs_register_manager"],
                         "named_ui_entered_before_register_manager")
        hints = [x["stage_hint"] for x in
                 guest["post_second_named_ui_method_entries"]]
        self.assertEqual(hints[0], "avatar_controller")
        self.assertIn("avatar_user_tap", hints)
        self.assertIn("starter_panel_open", hints)
        self.assertIn("starter_user_tap", hints)
        self.assertFalse(guest["named_ui_entry_confirms_actual_render"])
        self.assertTrue(all(x["entry_only_not_render_proof"] for x in
                            guest["post_second_named_ui_method_entries"]))

    def test_manager_first_and_no_second_are_distinguished(self):
        events = [
            ev("firstboot_confirm_gest_second_entered", 10),
            ev("auth_manager_register_user_entered", 20),
            ev("firstboot_select_trainer_icon_entered", 60),
        ]
        self.assertEqual(
            timeline.analyze_events(events, True, None)["guest_path"][
                "named_ui_vs_register_manager"],
            "register_manager_entered_before_named_ui")
        before_only = [
            ev("firstboot_select_trainer_icon_entered", 3),
            ev("firstboot_confirm_gest_second_entered", 10),
        ]
        guest = timeline.analyze_events(before_only, True, None)["guest_path"]
        self.assertEqual(guest["post_second_named_ui_method_entries"], [])
        self.assertEqual(guest["named_ui_vs_register_manager"],
                         "neither_named_ui_nor_manager_observed")
        no_second = timeline.analyze_events([
            ev("firstboot_select_trainer_icon_entered", 12)
        ], True, None)["guest_path"]
        self.assertEqual(no_second["named_ui_vs_register_manager"],
                         "second_confirmation_not_observed")

    def test_named_ui_hook_coverage_is_explicit_and_redacted(self):
        unknown = timeline.sanitize_post_guest_ui_hook_coverage(None)
        self.assertEqual(set(unknown),
                         set(timeline.POST_GUEST_UI_EVENTS.values()))
        self.assertTrue(all(v is None for v in unknown.values()))
        clean = timeline.sanitize_post_guest_ui_hook_coverage({
            "post_guest_ui_hook_coverage": {
                "select_trainer_icon": True,
                "prologue_pokemon_tap": False,
                "play_prologue": 1,
                "raw_utid": "12345678",
            }
        })
        self.assertTrue(clean["select_trainer_icon"])
        self.assertFalse(clean["prologue_pokemon_tap"])
        self.assertIsNone(clean["play_prologue"])
        self.assertNotIn("12345678", str(clean))

    def test_exact_original_method_rvas_are_present(self):
        src=(Path(__file__).with_name("home41_arm64_auth_timeline.js")
             .read_text(encoding="utf8"))
        for addr,name in (
            ("0x1DE48F8", "firstBootSelectTrainerIcon"),
            ("0x1DE45E8", "firstBootPlayPrologue"),
            ("0x1DE4CF4", "firstBootPlayPrologue2"),
            ("0x1DE5508", "firstBootDecisionGestAccount"),
            ("0x1DE5698", "firstBootDenialGestAccount"),
            ("0x1C803AC", "firstBootIconSelectorOnTapIcon"),
            ("0x1C7F0F4", "firstBootProloguePokemonPanelOnTapPokemon"),
            ("0x1DE1098", "postGuestCandidate1098"),
            ("0x1DE16F4", "postGuestCandidate16F4"),
        ):
            self.assertIn(name + ": " + addr, src)
        self.assertIn("FirstBootBodyController._AddWarningPart", src)
        self.assertIn("FirstBootBodyController._AddPadder", src)

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
        expected = {"second_direct", "decision_thunk", "denial_thunk",
                    "post_1098", "post_16f4", "register_manager"}
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
            "second_direct": True,
            "decision_thunk": None, "denial_thunk": None,
            "post_1098": False,
            "post_16f4": None, "register_manager": None,
        })
        self.assertNotIn("123456", str(result))


if __name__ == "__main__":
    unittest.main()
