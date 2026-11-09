#!/usr/bin/env python3
"""No-APK offline regression tests for guest final callback monitoring.

Execute the exact sanitizer/delta functions extracted from the script's AST
without importing Frida, ADB, or other device-facing code. No account access.
"""
import ast
import json
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent
SOURCE = (BASE / "home41_emulator_arm64_realm.py").read_text(encoding="utf-8")
JS_SOURCE = (BASE / "home41_arm64_auth_timeline.js").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


def extracted_functions():
    allowed = None
    call_events = None
    ui_events = None
    funs = {}
    for node in TREE.body:
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                target = node.targets[0].id
                if target == "_ALLOWED_AGENT_EVENTS":
                    assert isinstance(node.value, ast.Call)
                    allowed = frozenset(ast.literal_eval(node.value.args[0]))
                elif target == "_GUEST_FINAL_CALL_EVENTS":
                    call_events = ast.literal_eval(node.value)
                elif target == "_POST_GUEST_UI_EVENTS":
                    ui_events = ast.literal_eval(node.value)
        elif isinstance(node, ast.FunctionDef) and node.name in (
                "guest_callback_count_deltas", "post_guest_ui_count_deltas",
                "sanitized_arm64_snapshot"):
            funs[node.name] = node
    assert allowed is not None and call_events is not None
    assert ui_events is not None
    assert len(funs) == 3
    env = {
        "_ALLOWED_AGENT_EVENTS": allowed,
        "_GUEST_FINAL_CALL_EVENTS": call_events,
        "_POST_GUEST_UI_EVENTS": ui_events,
        "sanitize_birth_ui": lambda _x: {},
        "sanitize_firstboot_ui": lambda _x: {},
    }
    for node in funs.values():
        ast.fix_missing_locations(node)
    exec(compile(ast.Module(body=list(funs.values()), type_ignores=[]),
                 "<isolated HOME41 sanitizer>", "exec"), env)
    return env


class GuestCallbackCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ns = extracted_functions()

    def test_events_are_whitelisted_and_observed_as_read_only_counters(self):
        for name in self.ns["_GUEST_FINAL_CALL_EVENTS"].values():
            self.assertIn(name, self.ns["_ALLOWED_AGENT_EVENTS"])
            self.assertIn("'" + name + "'", JS_SOURCE)
        for source_key in ("guestSecondDirectCalleeUnclassified",
                           "postGuestCandidate1098", "postGuestCandidate16F4",
                           "authManagerRegisterUser"):
            self.assertIn(source_key + ":", JS_SOURCE)
        self.assertIn("guest_callback_hook_coverage", JS_SOURCE)

    def test_sanitization_does_not_export_secrets_or_fake_hook_success(self):
        events = self.ns["_GUEST_FINAL_CALL_EVENTS"]
        counts = {v: 2 for v in events.values()}
        counts.update({"raw_utid": "123456", "token": "secret",
                       "uuid": "private", "uncategorized": 3})
        snap = self.ns["sanitized_arm64_snapshot"]({
            "counts": counts,
            "guest_callback_hook_coverage": {
                "second_direct": True,
                "post_1098": 1,  # not strictly True
                "raw_utid": "123456",
            },
            "first_basic_seen": False,
            "utid": "123456", "token": "secret"
        })
        self.assertEqual(snap["counts"], {v: 2 for v in events.values()})
        self.assertEqual(snap["guest_callback_hook_coverage"], {
            "second_direct": True, "post_1098": False,
            "post_16f4": False, "register_manager": False,
        })
        dump = json.dumps(snap)
        for secret in ("123456", "secret", "private", "raw_utid"):
            self.assertNotIn(secret, dump)

    def test_zero_count_requires_both_snapshots_and_attached_hook(self):
        e = self.ns["_GUEST_FINAL_CALL_EVENTS"]
        after = {v: 0 for v in e.values()}
        before = {v: 0 for v in e.values()}
        hooks = {k: True for k in e}
        delta = self.ns["guest_callback_count_deltas"](after, before, hooks)
        self.assertEqual(delta, {k: 0 for k in e})
        after[e["second_direct"]] = 1
        after[e["register_manager"]] = 3
        delta = self.ns["guest_callback_count_deltas"](after, before, hooks)
        self.assertEqual(delta["second_direct"], 1)
        self.assertEqual(delta["register_manager"], 3)
        self.assertEqual(delta["post_1098"], 0)

    def test_named_original_ui_counters_require_installed_hook(self):
        events=self.ns["_POST_GUEST_UI_EVENTS"]
        self.assertGreaterEqual(len(events),24)
        self.assertEqual(len(set(events)),len(events))
        for native in events.values():
            self.assertIn(native,self.ns["_ALLOWED_AGENT_EVENTS"])
            self.assertIn("'" + native + "'",JS_SOURCE)
        before={event:0 for event in events.values()}
        after={event:0 for event in events.values()}
        coverage={label:True for label in events}
        f=self.ns["post_guest_ui_count_deltas"]
        self.assertEqual(f(after,before,coverage),{label:0 for label in events})
        after[events["guest_start_b84_6"]]=1
        after[events["select_trainer_icon"]]=2
        after[events["prologue_pokemon_tap"]]=1
        diff=f(after,before,coverage)
        self.assertEqual(diff["guest_start_b84_6"],1)
        self.assertEqual(diff["select_trainer_icon"],2)
        self.assertEqual(diff["prologue_pokemon_tap"],1)
        coverage["prologue_pokemon_tap"]=False
        self.assertIsNone(f(after,before,coverage)["prologue_pokemon_tap"])
        after[events["select_trainer_icon"]]=-1
        self.assertIsNone(f(after,before,coverage)["select_trainer_icon"])

    def test_native_snapshot_filters_private_ui_fields(self):
        events=self.ns["_POST_GUEST_UI_EVENTS"]
        raw={"counts":{events["select_trainer_icon"]:4,"raw_utid":"private"},
             "post_guest_ui_hook_coverage":{
                 "select_trainer_icon":True,
                 "prologue_pokemon_tap":False,
                 "guest_start_b84_6":1,
                 "raw_utid":"1234567890"}}
        clean=self.ns["sanitized_arm64_snapshot"](raw)
        self.assertEqual(clean["post_guest_ui_hook_coverage"]["select_trainer_icon"],True)
        self.assertEqual(clean["post_guest_ui_hook_coverage"]["prologue_pokemon_tap"],False)
        self.assertIsNone(clean["post_guest_ui_hook_coverage"]["guest_start_b84_6"])
        self.assertEqual(clean["counts"],{events["select_trainer_icon"]:4})
        self.assertNotIn("1234567890",json.dumps(clean))
        self.assertNotIn("private",json.dumps(clean))

    def test_missing_or_decreasing_counter_means_unknown_not_zero(self):
        e = self.ns["_GUEST_FINAL_CALL_EVENTS"]
        f = self.ns["guest_callback_count_deltas"]
        self.assertTrue(all(v is None for v in f({}, {}, {}).values()))
        after = {v: 1 for v in e.values()}
        before = {v: 2 for v in e.values()}
        hooks = {k: True for k in e}
        self.assertTrue(all(v is None
                            for v in f(after, before, hooks).values()))
        after[e["second_direct"]] = 2
        hooks["second_direct"] = False
        self.assertIsNone(f(after, before, hooks)["second_direct"])


if __name__ == "__main__":
    unittest.main()
