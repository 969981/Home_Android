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
        self.assertTrue(result["auth"]["first_basic_caller_verified"])
        self.assertFalse(result["http_request_transmitted_verified"])
        self.assertFalse(result["http_response_source_endpoint_verified"])
        self.assertFalse(result["six_digit_id_equals_starter_ot_verified"])
        self.assertFalse(result["lng_cntry_enum_ui_mapping_verified"])

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

    def test_native_script_contains_expected_anchors_but_no_http_replay(self):
        js=(CI/"home41_arm64_auth_timeline.js").read_text(encoding="utf-8")
        self.assertIn("0x1D334A4",js)
        self.assertIn("0x1D335C0",js)
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
