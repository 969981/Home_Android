#!/usr/bin/env python3
"""Pure allowlist tests for the read-only FirstBoot phase transition hooks."""
import unittest

from home41_arm64_auth_timeline import sanitize_timeline_event
from home41_emulator_arm64_realm import sanitized_arm64_snapshot, sanitize_firstboot_ui


class FirstBootPhaseHookTests(unittest.TestCase):
    def test_go_to_phase_event_keeps_only_bounded_phase_index(self):
        clean = sanitize_timeline_event({
            "type": "send",
            "payload": {
                "kind": "home41_arm64_auth_timeline",
                "version": "4.1.0",
                "event": "firstboot_go_to_phase_entered",
                "phase_index": 4,
                "elapsed_ms": 1500,
                "private_pointer": "never copy",
            },
        })
        self.assertEqual(clean["event"], "firstboot_go_to_phase_entered")
        self.assertEqual(clean["phase_index"], 4)
        self.assertNotIn("private_pointer", clean)

    def test_out_of_range_and_bool_phase_indices_are_dropped(self):
        for bad in (True, False, -1, 129, "4"):
            with self.subTest(phase=bad):
                clean = sanitize_timeline_event({
                    "type": "send",
                    "payload": {
                        "kind": "home41_arm64_auth_timeline",
                        "version": "4.1.0",
                        "event": "firstboot_go_to_phase_entered",
                        "phase_index": bad,
                    },
                })
                self.assertNotIn("phase_index", clean)

    def test_phase_snapshot_maps_current_and_requested_enums(self):
        clean = sanitize_firstboot_ui({
            "original_controller_seen": True,
            "original_phase_enum_index": 4,
            "original_phase_mapping_verified": True,
            "last_requested_phase_enum_index": 4,
            "go_to_phase_hook_attached": True,
            "advertisement_sdk_hook_attached": True,
        })
        self.assertEqual(clean["original_phase_name"], "ADVERTISEMENT_SDK")
        self.assertEqual(clean["last_requested_phase_name"], "ADVERTISEMENT_SDK")
        self.assertTrue(clean["go_to_phase_hook_attached"])
        self.assertTrue(clean["advertisement_sdk_hook_attached"])

    def test_snapshot_counts_allow_sdk_and_transition_events_only(self):
        clean = sanitized_arm64_snapshot({
            "native_arm64": True,
            "hooks_ready": True,
            "firstboot_ui": {
                "original_controller_seen": True,
                "original_phase_enum_index": 4,
                "last_requested_phase_enum_index": 4,
                "original_phase_mapping_verified": True,
                "go_to_phase_hook_attached": True,
                "advertisement_sdk_hook_attached": True,
            },
            "counts": {
                "firstboot_confirmation_advertisement_sdk_entered": 1,
                "firstboot_go_to_phase_entered": 4,
                "secret": 99,
            },
        })
        self.assertEqual(
            clean["counts"]["firstboot_confirmation_advertisement_sdk_entered"], 1)
        self.assertEqual(clean["counts"]["firstboot_go_to_phase_entered"], 4)
        self.assertNotIn("secret", clean["counts"])


if __name__ == "__main__":
    unittest.main()
