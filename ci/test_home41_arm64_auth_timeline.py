#!/usr/bin/env python3
"""Offline tests only — these fixtures do not call HOME or register accounts."""
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

CI = Path(__file__).parent
sys.path.insert(0, str(CI))
spec = importlib.util.spec_from_file_location(
    "home41_arm64_auth_timeline", CI/"home41_arm64_auth_timeline.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def evt(name, ms, **values):
    return {"event": name, "elapsed_ms": ms, **values}


def transport(name, ms, **values):
    return {"type": "send", "payload": {
        "kind": module.KIND, "version": "4.1.0",
        "event": name, "elapsed_ms": ms, **values,
    }}


class AuthTimelineTests(unittest.TestCase):
    def test_raw_identity_and_sensitive_fields_never_leave_redactor(self):
        incoming = transport(
            "first_basic_utid_observed", 700,
            raw_utid="4012345678", lng=1, cntry=99,
            token="secret-cookie", cookie="secret-cookie",
            ip="203.0.113.1", uuid="secret-id",
            candidate_matches_target=True,
            from_common_basic_consumer=True,
            source_endpoint_verified=False,
            display_id_semantics_verified=False,
            index=1)
        clean = module.sanitize_timeline_event(incoming)
        self.assertEqual(clean["event"], "first_basic_utid_observed")
        self.assertEqual(clean["elapsed_ms"], 700)
        self.assertEqual(clean["candidate_matches_target"], True)
        self.assertNotIn("4012345678", str(clean))
        self.assertNotIn("203.0.113.1", str(clean))
        self.assertNotIn("secret", str(clean))
        self.assertNotIn("lng",str(clean))
        self.assertNotIn("cntry",str(clean))

    def test_blr_x8_target_is_normalized_and_secrets_redacted(self):
        entry = transport(
            "auth_manager_indirect_dispatch_site_entered", 112,
            dispatch_target_in_original_libil2cpp=True,
            dispatch_target_rva=0x1D334A4,
            raw_target_va="0x9876543210",
            raw_x8="NON_PUBLIC_POINTER",
            token="PRIVATE_SESSION_TOKEN",
            uuid="PRIVATE_UUID")
        clean = module.sanitize_timeline_event(entry)
        self.assertEqual(clean["dispatch_target_rva"],0x1D334A4)
        self.assertIs(clean["dispatch_target_in_original_libil2cpp"],True)
        for forbidden in ("NON_PUBLIC_POINTER","0x9876543210",
                          "PRIVATE_SESSION_TOKEN","PRIVATE_UUID","raw_x8"):
            self.assertNotIn(forbidden,str(clean))
        off_module=module.sanitize_timeline_event(transport(
            "auth_manager_indirect_dispatch_site_entered",113,
            dispatch_target_in_original_libil2cpp=False,
            dispatch_target_rva=0xDEADBEEF))
        self.assertIs(off_module["dispatch_target_in_original_libil2cpp"],
                      False)
        self.assertNotIn("dispatch_target_rva",off_module)
        malformed=module.sanitize_timeline_event(transport(
            "auth_manager_indirect_dispatch_site_entered",113,
            dispatch_target_in_original_libil2cpp=True,
            dispatch_target_rva=True))
        self.assertNotIn("dispatch_target_rva",malformed)

    def test_malformed_and_js_error_events_rejected(self):
        self.assertIsNone(module.sanitize_timeline_event({"type":"error","description":"secrets"}))
        self.assertIsNone(module.sanitize_timeline_event({"type":"log","payload":"secrets"}))
        self.assertIsNone(module.sanitize_timeline_event({"type":"send","payload":{
            "kind":module.KIND, "event":"unauthorized_raw_http","version":"4.1.0"}}))
        self.assertIsNone(module.sanitize_timeline_event(transport(
            "first_basic_utid_observed",300, event_type="wrong",token="secret")
            | {"type":"error"}))

    def test_known_categorical_reason_only(self):
        clean = module.sanitize_timeline_event(transport(
            "native_preflight_failed",100,reason="secret-token"))
        self.assertEqual(clean,{"event":"native_preflight_failed","elapsed_ms":100})
        clean = module.sanitize_timeline_event(transport(
            "native_preflight_failed",101,reason="not_native_arm64"))
        self.assertEqual(clean["reason"],"not_native_arm64")

    def test_complete_timeline_does_not_claim_endpoint_or_ot_proof(self):
        data=[
            evt("arm64_auth_observer_ready",10),
            evt("registration_request_serializer_entered",100),
            evt("registration_lng_cntry_packed_write_seen",103,
                values_redacted=True),
            evt("registration_request_formatter_entered",115),
            evt("registration_response_formatter_entered",444),
            evt("registration_response_handler_entered",450),
            evt("token_request_serializer_entered",480),
            evt("token_response_handler_entered",550),
            evt("login_request_serializer_entered",600),
            evt("login_response_handler_entered",665),
            evt("common_response_handler_entered",680),
            evt("first_basic_utid_observed",715,
                from_common_basic_consumer=True,
                candidate_matches_target=False),
        ]
        result=module.analyze_events(data,ready=True,error=None)
        self.assertEqual(result["status"],"basic_received_from_common_consumer")
        self.assertEqual(result["first_basic_minus_registration_callback_ms"],265)
        self.assertTrue(result["auth"]["register_lng_cntry_packed_write_observed"])
        self.assertTrue(result["auth"]["registration_request_formatter_entered"])
        self.assertTrue(result["auth"]["registration_response_formatter_entered"])
        self.assertTrue(result["auth"]["first_basic_caller_verified"])
        self.assertFalse(result["http_request_transmitted_verified"])
        self.assertFalse(result["http_response_source_endpoint_verified"])
        self.assertFalse(result["six_digit_id_equals_starter_ot_verified"])
        self.assertFalse(result["lng_cntry_enum_ui_mapping_verified"])

    def test_response_formatter_alone_does_not_establish_basic_utid(self):
        data=[evt("arm64_auth_observer_ready",10),
              evt("registration_request_formatter_entered",20),
              evt("registration_response_formatter_entered",30)]
        out=module.analyze_events(data,ready=True,error=None)
        self.assertTrue(out["auth"]["registration_response_formatter_entered"])
        self.assertFalse(out["auth"]["first_basic_utid_observed"])
        self.assertFalse(out["http_response_source_endpoint_verified"])
        self.assertFalse(out["http_request_transmitted_verified"])

    def test_serializer_call_alone_never_claims_field_serialized(self):
        data=[evt("arm64_auth_observer_ready",5),
              evt("registration_request_serializer_entered",15)]
        result=module.analyze_events(data,ready=True,error=None)
        self.assertTrue(result["auth"]["registration_serializer_entered"])
        self.assertFalse(result["auth"]["register_lng_cntry_packed_write_observed"])
        self.assertEqual(result["status"],"observer_ready_waited_without_basic")

    def test_error_and_partial_hook_preclude_success(self):
        data=[evt("arm64_auth_observer_partial",5),
              evt("first_basic_utid_observed",100,from_common_basic_consumer=True)]
        result=module.analyze_events(data,ready=False,error=None)
        self.assertEqual(result["status"],"arm64_hooks_partial")
        result=module.analyze_events(
            [evt("native_preflight_failed",0,reason="not_native_arm64")],
            ready=False,error=None)
        self.assertEqual(result["status"],"native_arm64_preflight_failed")

    def test_local_rpc_values_not_printed_without_interactive_optin(self):
        details={"from_common_basic_caller":True,
                 "first_basic_seen":True,
                 "raw_utid":"4012345678",
                 "six_digit_candidate":"345678",
                 "request_packed_values_seen":True,
                 "lng_candidate":8,
                 "cntry_candidate":44}
        for enabled,ci in ((False,""),(True,"true")):
            with self.subTest(enabled=enabled,ci=ci):
                out=io.StringIO()
                with patch.dict("os.environ",{"GITHUB_ACTIONS":ci}),redirect_stdout(out):
                    self.assertFalse(module.local_values(details,interactive=enabled))
                self.assertEqual(out.getvalue(),"")

    def test_interactive_local_values_without_writing_public_data(self):
        details={"from_common_basic_caller":True,
                 "first_basic_seen":True,
                 "raw_utid":"4012345678",
                 "six_digit_candidate":"345678",
                 "request_packed_values_seen":True,
                 "lng_candidate":8,
                 "cntry_candidate":44}
        out=io.StringIO()
        with patch.dict("os.environ",{"GITHUB_ACTIONS":""}),redirect_stdout(out):
            self.assertTrue(module.local_values(details,interactive=True))
        self.assertIn("server basic.utid: 4012345678",out.getvalue())
        self.assertIn("derived six-digit candidate: 345678",out.getvalue())
        self.assertIn("lng integer: 8",out.getvalue())
        self.assertIn("cntry integer: 44",out.getvalue())
        self.assertNotIn("request transmitted",out.getvalue().lower())

    def test_wrong_candidate_is_not_disclosed(self):
        details={"from_common_basic_caller":True,
                 "first_basic_seen":True,
                 "raw_utid":"4012345678",
                 "six_digit_candidate":"999999",
                 "request_packed_values_seen":False}
        out=io.StringIO()
        with patch.dict("os.environ",{"GITHUB_ACTIONS":""}),redirect_stdout(out):
            module.local_values(details,interactive=True)
        self.assertEqual(out.getvalue(),"")

    def test_emulated_guest_preflight_uses_verified_apk_bridge_and_version(self):
        with tempfile.TemporaryDirectory() as root:
            apk=Path(root)/"original.apk"
            apk.write_bytes(b"synthetic")
            with patch.object(module.core, "digest",
                              return_value=module.core.APK_SHA256), \
                 patch.object(module.core, "android_prop", side_effect=[
                     "x86_64","libndk_translation.so"
                 ]), \
                 patch.object(module.core, "adb",
                              return_value=SimpleNamespace(
                                  returncode=0,
                                  stdout="versionCode=81 minSdk=23")):
                actual=module.preflight_for_realm(apk,None,"emulated")
            self.assertEqual(actual["result"],
                             "emulated_arm64_guest_preflight_ok")
            self.assertFalse(actual["guest_arm64_agent_and_hooks_verified"])

    def test_emulated_guest_without_native_bridge_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            apk=Path(root)/"original.apk"
            apk.write_bytes(b"synthetic")
            with patch.object(module.core, "digest",
                              return_value=module.core.APK_SHA256), \
                 patch.object(module.core, "android_prop", side_effect=[
                     "x86_64",""
                 ]), \
                 patch.object(module.core,"adb",
                              side_effect=AssertionError("no APK info needed")):
                actual=module.preflight_for_realm(apk,None,"emulated")
            self.assertEqual(actual["result"],
                             "native_bridge_arm_emulation_not_configured")

    def test_emulated_realm_attaches_existing_home_without_spawn(self):
        class Agent:
            def __init__(self): self.callback=None
            def on(self,name,fn): self.callback=fn
            def load(self):
                self.callback(transport("arm64_auth_observer_ready", 10),None)
                self.callback(transport("first_basic_utid_observed", 22,
                   from_common_basic_consumer=True),None)
        class Session:
            def __init__(self): self.agent=Agent(); self.detached=False
            def create_script(self,src):return self.agent
            def detach(self): self.detached=True
        class Device:
            def __init__(self):self.sess=Session();self.realm=None
            def attach(self,pid,realm):
                self.realm=realm
                assert pid==5678
                return self.sess
            def spawn(self,*args):
                raise AssertionError("emulated realm must not spawn")
        device=Device()
        frida=SimpleNamespace(get_usb_device=lambda timeout:device)
        with tempfile.TemporaryDirectory() as root:
            js=Path(root)/"agent.js"
            js.write_text("// offline mock",encoding="utf-8")
            report=Path(root)/"clean.json"
            with patch.object(module,"preflight_for_realm",return_value={
                      "result":"emulated_arm64_guest_preflight_ok",
                      "primary_abi":"x86_64"}), \
                 patch.object(module.core,"installed_apk_integrity",
                              return_value="installed_apk_hash_verified"), \
                 patch.object(module.core,"adb",return_value=SimpleNamespace(
                     returncode=0,stdout="5678\n")), \
                 patch.dict(sys.modules,{"frida":frida}), \
                 redirect_stdout(io.StringIO()):
                outcome=module.run(Path("unused.apk"),js,None,2,report,False,
                                   realm="emulated")
            self.assertEqual(outcome,0)
            self.assertTrue(device.sess.detached)
            self.assertEqual(device.realm,"emulated")
            report_data=json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(report_data["frida_realm"],"emulated")
            self.assertTrue(report_data["arm64_agent_hooks_armed"])
            self.assertFalse(report_data["six_digit_id_equals_starter_ot_verified"])

    def test_native_attach_running_does_not_spawn_or_kill_existing_home(self):
        class Agent:
            def __init__(self):
                self.callback=None
            def on(self,event,handler):
                self.callback=handler
            def load(self):
                self.callback(transport("arm64_auth_observer_ready",1),None)
                self.callback(transport("firstboot_confirm_gest_second_entered",10),None)
                self.callback(transport("auth_manager_register_user_entered",20),None)
                self.callback(transport("first_basic_utid_observed",45,
                    from_common_basic_consumer=True,
                    raw_utid="DO_NOT_LEAK"),None)
        class Session:
            def __init__(self):
                self.agent=Agent()
                self.detached=False
            def create_script(self,source):
                return self.agent
            def detach(self):
                self.detached=True
        class Device:
            def __init__(self):
                self.session=Session()
                self.attached=[]
            def spawn(self,*args):
                raise AssertionError("do not restart original session")
            def resume(self,*args):
                raise AssertionError("do not resume existing process")
            def attach(self,pid):
                self.attached.append(pid)
                return self.session
        device=Device()
        frida=SimpleNamespace(get_usb_device=lambda timeout:device)
        with tempfile.TemporaryDirectory() as root:
            js=Path(root)/"agent.js"
            js.write_text("// synthetic safe agent",encoding="utf8")
            output=Path(root)/"redacted.json"
            def only_pidof(args,serial,timeout=25):
                self.assertEqual(args,["shell","pidof",module.core.PACKAGE])
                return SimpleNamespace(returncode=0,stdout="4567\n")
            with patch.object(module,"preflight_for_realm",return_value={
                    "result":"native_arm64_original_apk_preflight_ok"}), \
                 patch.object(module.core,"installed_apk_integrity",
                              return_value="installed_apk_hash_verified"), \
                 patch.object(module.core,"adb",side_effect=only_pidof), \
                 patch.dict(sys.modules,{"frida":frida}), \
                 redirect_stdout(io.StringIO()):
                rc=module.run(Path("unused.apk"),js,None,2,output,False,
                              realm="native",attach_running=True)
            self.assertEqual(rc,0)
            self.assertEqual(device.attached,[4567])
            self.assertTrue(device.session.detached)
            public=output.read_text(encoding="utf8")
            self.assertNotIn("DO_NOT_LEAK",public)
            data=json.loads(public)
            self.assertEqual(data["process_attachment_mode"],
                             "attach_running_without_restart")
            self.assertTrue(data["observer_might_have_missed_first_basic"])

    def test_operator_interrupt_saves_redacted_report_without_restart(self):
        class Agent:
            def __init__(self):
                self.callback=None
                self.exports_sync=SimpleNamespace(snapshot=self.snapshot)
            def on(self, name, callback):
                self.callback=callback
            def load(self):
                for event,offset in (
                    ("arm64_auth_observer_ready",1),
                    ("firstboot_confirm_gest_second_entered",10),
                    ("guest_second_decision_thunk_entered",11),
                    ("firstboot_decision_gest_account_entered",12)):
                    self.callback(transport(event,offset,
                        raw_utid="SHOULD_NOT_LEAK",
                        token="SECRET"),None)
            def snapshot(self):
                return {
                    "guest_chain_critical_hook_coverage": {
                        k: True for k in module.GUEST_CHAIN_CRITICAL_HOOK_KEYS
                    },
                    "raw_utid": "SHOULD_NOT_LEAK",
                    "token": "SECRET",
                }
        class Session:
            def __init__(self):
                self.agent=Agent()
                self.detached=False
            def create_script(self, content):
                return self.agent
            def detach(self):
                self.detached=True
        class Device:
            def __init__(self):
                self.session=Session()
                self.attached=[]
            def attach(self,pid):
                self.attached.append(pid)
                return self.session
            def spawn(self,*args):
                raise AssertionError("existing HOME must not be restarted")
            def resume(self,*args):
                raise AssertionError("existing HOME must not be resumed")
        device=Device()
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/"agent.js"
            path.write_text("// test",encoding="utf8")
            report=Path(root)/"safe.json"
            with patch.object(module, "preflight_for_realm",return_value={
                    "result":"native_arm64_original_apk_preflight_ok"}), \
                 patch.object(module.core, "installed_apk_integrity",
                              return_value="installed_apk_hash_verified"), \
                 patch.object(module.core,"adb",
                     return_value=SimpleNamespace(returncode=0,stdout="2345")), \
                 patch.dict(sys.modules,{"frida":SimpleNamespace(
                     get_usb_device=lambda timeout:device)}), \
                 patch.object(module.threading.Event,"wait",
                              side_effect=KeyboardInterrupt), \
                 redirect_stdout(io.StringIO()):
                rc=module.run(Path("unused.apk"),path,None,90,report,
                              False,realm="native",attach_running=True)
            self.assertEqual(rc,3)
            self.assertTrue(device.session.detached)
            self.assertEqual(device.attached,[2345])
            exported=report.read_text(encoding="utf8")
            self.assertNotIn("SHOULD_NOT_LEAK",exported)
            self.assertNotIn("SECRET",exported)
            parsed=json.loads(exported)
            self.assertTrue(parsed["operator_stopped_without_app_reset"])
            self.assertTrue(parsed["guest_chain_diagnosis"][
                "all_critical_hooks_installed"])
            self.assertEqual(
                parsed["guest_chain_diagnosis"]["classification"],
                "decision_controller_seen_register_manager_not_observed")

    def test_native_script_contains_expected_anchors_but_no_http_replay(self):
        js=(CI/"home41_arm64_auth_timeline.js").read_text(encoding="utf-8")
        self.assertIn("0x1D334A4",js)
        self.assertIn("0x1D335C0",js)
        self.assertIn("0x205AEF0",js)
        self.assertIn("0x205DA3C",js)
        self.assertIn("0x1D2AFF0",js)
        self.assertIn("0x1D2BA68",js)
        self.assertIn("0x1D763D0",js)
        self.assertIn("source_endpoint_verified: false",js)
        self.assertNotIn("SSL_write(",js)
        self.assertNotIn("Memory.write",js)

    def test_wrong_apk_blocks_before_frida_access(self):
        with patch.object(module.core,"preflight",
                          return_value={"result":"apk_hash_mismatch"}), \
             patch.object(module.core,"installed_apk_integrity",
                          side_effect=AssertionError("do not touch device")), \
             redirect_stdout(io.StringIO()):
            code=module.run(Path("unused.apk"),Path("unused.js"),
                            None,1,None,False)
        self.assertEqual(code,2)

    def test_complete_fake_runtime_uses_real_frida_callback_contract(self):
        """Mock proves event control flow only, never a real ID from HOME."""
        class FakeScript:
            def __init__(self):
                self.callback=None
                self.loaded=False
                self.exports_sync=SimpleNamespace(
                    localvalues=lambda: (_ for _ in ()).throw(
                        AssertionError("not opted in")))
            def on(self,name,handler):
                self.callback=handler
            def load(self):
                self.loaded=True
        class FakeSession:
            def __init__(self):
                self.script=FakeScript()
                self.detached=False
            def create_script(self,content):return self.script
            def detach(self):self.detached=True
        class FakeDevice:
            def __init__(self):
                self.session=FakeSession()
                self.resumes=0
            def spawn(self,pkg):
                self.pkg=pkg
                return 1234
            def attach(self,pid):
                self.pid=pid
                return self.session
            def resume(self,pid):
                self.resumes+=1
                self.session.script.callback(transport(
                    "arm64_auth_observer_ready",1),None)
                self.session.script.callback(transport(
                    "registration_request_serializer_entered",11),None)
                self.session.script.callback(transport(
                    "registration_lng_cntry_packed_write_seen",12,
                    lng=345,cntry=77,fields_readable=True,
                    values_redacted=True),None)
                self.session.script.callback(transport(
                    "registration_response_handler_entered",61),None)
                self.session.script.callback(transport(
                    "first_basic_utid_observed",101,
                    raw_utid="PRIVATE_UTID_NEVER_PERSIST",
                    from_common_basic_consumer=True,
                    candidate_matches_target=False,
                    source_endpoint_verified=False),None)
        fake=FakeDevice()
        frida=SimpleNamespace(get_usb_device=lambda timeout:fake)
        with tempfile.TemporaryDirectory() as root:
            report_path=Path(root)/"public_evidence.json"
            js_path=Path(root)/"agent.js"
            js_path.write_text("// fake agent",encoding="utf-8")
            output=io.StringIO()
            with patch.object(module.core,"preflight",return_value={
                          "result":"native_arm64_original_apk_preflight_ok"}), \
                 patch.object(module.core,"installed_apk_integrity",
                              return_value="installed_apk_hash_verified"), \
                 patch.dict(sys.modules,{"frida":frida}), redirect_stdout(output):
                code=module.run(Path("unused.apk"),js_path,None,3,report_path,False)
            self.assertEqual(code,0)
            self.assertTrue(fake.session.detached)
            self.assertTrue(fake.session.script.loaded)
            self.assertEqual(fake.resumes,1)
            self.assertEqual(fake.pkg,[module.core.PACKAGE])
            self.assertIn("basic_received_from_common_consumer",
                          output.getvalue())
            self.assertNotIn("PRIVATE_UTID_NEVER_PERSIST",
                             report_path.read_text(encoding="utf-8"))
            self.assertNotIn("lng\": 345",report_path.read_text(encoding="utf-8"))
            self.assertNotIn("cntry\": 77",report_path.read_text(encoding="utf-8"))


if __name__=="__main__":
    unittest.main()
