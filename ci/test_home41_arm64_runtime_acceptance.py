#!/usr/bin/env python3
"""Offline fixtures for the strict two-phase runtime acceptance protocol.

These are NOT real Android/Frida evidence and must never set runtime verified
flags in reports of actual HOME session identity.
"""
import importlib.util
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

source=Path(__file__).with_name("home41_arm64_runtime_acceptance.py")
spec=importlib.util.spec_from_file_location("home41_arm64_runtime_acceptance",source)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class FakeScript:
    def __init__(self,device):
        self.device=device
        self.callback=None
        self.loaded=False
        self.exports_sync=SimpleNamespace(comparevisibleid=self.comparevisibleid)
    def on(self,event,callback):
        assert event=="message"
        self.callback=callback
    def load(self):
        self.loaded=True
    def comparevisibleid(self,provided):
        return {"first_basic_seen":True,"valid_six_digit_input":True,
                "displayed_id_matches": provided==self.device.current_id,
                "source_common_response_consumer":True}

class FakeSession:
    def __init__(self,device):
        self.device=device
        self.detached=False
        self.script=FakeScript(device)
    def on(self,event,callback):
        assert event=="detached"
    def create_script(self,script):
        assert "stub" in script
        return self.script
    def detach(self):
        self.detached=True

class FakeDevice:
    def __init__(self, observed_ids):
        self.ids=list(observed_ids)
        self.current_id=None
        self.sessions=[]
        self.resume_count=0
        self.spawn_count=0
    def spawn(self,package):
        assert package==[mod.core.PACKAGE]
        self.current_id=self.ids[self.spawn_count]
        self.spawn_count+=1
        return 3000+self.spawn_count
    def attach(self,pid):
        s=FakeSession(self)
        self.sessions.append(s)
        return s
    def resume(self,pid):
        self.resume_count+=1
        script=self.sessions[-1].script
        assert script.loaded
        script.callback({"type":"send","payload":{
            "kind":"home41_utid_readonly","version":"4.1.0",
            "event":"read_only_observer_ready"}},None)
        script.callback({"type":"send","payload":{
            "kind":"home41_utid_readonly","version":"4.1.0",
            "event":"first_basic_utid_observed",
            "candidate_matches_target": False,
            "source_common_response_consumer":True,
            "utid":"SECRET_UTID_SHOULD_NOT_LEAK"}},None)

def run_fake(ids,visible="654321",answers=("yes","yes","yes")):
    device=FakeDevice(ids)
    frida=SimpleNamespace(get_usb_device=lambda timeout:device)
    prompt_calls=[]
    def prompt(text):
        prompt_calls.append(text)
        return next(answer_iterator)
    answer_iterator=iter(answers)
    out=io.StringIO()
    with patch.object(mod.core,"preflight",return_value={
                 "result":"native_arm64_original_apk_preflight_ok"}), \
         patch.object(mod.core,"installed_apk_integrity",
                      return_value="installed_apk_hash_verified"), \
         patch.object(mod.core,"prepare_script",return_value="stub Frida JS"), \
         patch.object(mod,"process_alive",side_effect=[True,True,False,True,True]), \
         patch.object(mod,"process_id",side_effect=[4242,4343]), \
         patch.object(mod.core,"adb",return_value=SimpleNamespace(
                      returncode=0,stdout="")), \
         patch.dict(sys.modules,{"frida":frida}),redirect_stdout(out):
        code=mod.run_acceptance(Path("unused.apk"),Path("unused.js"),None,
                                timeout=1,target="888888",
                                hidden_input=lambda text:visible,
                                input_func=prompt)
    return code,device,out.getvalue(),prompt_calls

class NativeRuntimeAcceptanceFixtures(unittest.TestCase):
    def test_two_accurate_reads_and_user_checks_reach_three_gates(self):
        result,dev,output,prompts=run_fake(["654321","654321"])
        self.assertEqual(result,0)
        self.assertEqual(dev.spawn_count,2)
        self.assertEqual(dev.resume_count,2)
        self.assertEqual(len(dev.sessions),2)
        self.assertTrue(all(s.detached for s in dev.sessions))
        self.assertIn("REAL_DEVICE_THREE_GATES_PASSED",output)
        self.assertNotIn("SECRET_UTID_SHOULD_NOT_LEAK",output)
        self.assertNotIn("654321",output)
        self.assertEqual(len(prompts),3)

    def test_second_capture_must_match_first_visible_id(self):
        result,dev,output,prompts=run_fake(["654321","123123"],answers=("yes","yes"))
        self.assertEqual(result,3)
        self.assertEqual(dev.spawn_count,2)
        self.assertNotIn("REAL_DEVICE_THREE_GATES_PASSED",output)
        self.assertIn("runtime_utid_display_id_mismatch",output)

    def test_first_capture_mismatch_must_not_force_stop(self):
        result,dev,output,prompts=run_fake(["123123"],answers=())
        self.assertEqual(result,3)
        self.assertEqual(dev.spawn_count,1)
        self.assertEqual(len(prompts),0)
        self.assertNotIn("REAL_DEVICE_THREE_GATES_PASSED",output)

    def test_manual_client_handoff_denial_blocks_restart(self):
        result,dev,output,prompts=run_fake(["654321"],answers=("no",))
        self.assertEqual(result,3)
        self.assertEqual(dev.spawn_count,1)
        self.assertIn("original_client_handoff_unverified",output)

    def test_cold_restart_requires_explicit_yes(self):
        result,dev,output,prompts=run_fake(["654321"],answers=("yes","no"))
        self.assertEqual(result,3)
        self.assertEqual(dev.spawn_count,1)
        self.assertIn("cold_restart_not_approved",output)

    def test_after_cold_start_user_can_deny_unchanged_id(self):
        result,dev,output,prompts=run_fake(
            ["654321","654321"],answers=("yes","yes","no"))
        self.assertEqual(result,3)
        self.assertEqual(dev.spawn_count,2)
        self.assertNotIn("REAL_DEVICE_THREE_GATES_PASSED",output)

    def test_force_stop_without_real_process_exit_is_not_cold_restart(self):
        dev=FakeDevice(["654321"])
        frida=SimpleNamespace(get_usb_device=lambda timeout:dev)
        output=io.StringIO()
        answers=iter(["yes","yes"])
        with patch.object(mod.core,"preflight",return_value={
                     "result":"native_arm64_original_apk_preflight_ok"}), \
             patch.object(mod.core,"installed_apk_integrity",
                          return_value="installed_apk_hash_verified"), \
             patch.object(mod.core,"prepare_script",return_value="stub Frida JS"), \
             patch.object(mod,"process_alive",return_value=True), \
             patch.object(mod,"process_id",return_value=4242), \
             patch.object(mod.core,"adb",return_value=SimpleNamespace(
                          returncode=0,stdout="")), \
             patch.dict(sys.modules,{"frida":frida}),redirect_stdout(output):
            result=mod.run_acceptance(
                Path("unused.apk"),Path("unused.js"),None,1,"888888",
                hidden_input=lambda text:"654321",
                input_func=lambda text:next(answers))
        self.assertEqual(result,3)
        self.assertEqual(dev.spawn_count,1)
        self.assertIn("previous_home_process_still_alive",output.getvalue())
        self.assertNotIn("REAL_DEVICE_THREE_GATES_PASSED",output.getvalue())

    def test_hidden_display_id_validation(self):
        self.assertEqual(mod.visible_id(lambda t:"001234"),"001234")
        self.assertIsNone(mod.visible_id(lambda t:"１２３４５６"))
        self.assertIsNone(mod.visible_id(lambda t:"ABCDEF"))
        self.assertIsNone(mod.visible_id(lambda t:"12345"))

    def test_unexpected_device_error_cannot_leak_into_report(self):
        output=io.StringIO()
        with redirect_stdout(output):
            mod.report("exception",failure_type="RuntimeError",
                       utid="1234567890",authorization="PRIVATE_TOKEN")
        self.assertNotIn("1234567890",output.getvalue())
        self.assertNotIn("PRIVATE_TOKEN",output.getvalue())

if __name__=="__main__":
    unittest.main()
