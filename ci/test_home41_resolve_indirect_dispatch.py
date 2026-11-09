#!/usr/bin/env python3
"""Offline fixtures for method-entry hints only, no Android or sensitive data."""
import tempfile
import unittest
import json
import io
from contextlib import redirect_stdout
from pathlib import Path

import home41_resolve_indirect_dispatch as mod


class OriginalIndexResolverTests(unittest.TestCase):
    def test_exact_entry_and_nearby_candidate_are_not_conflated(self):
        sample={"ScriptMethod":[
            {"Name":"ApiManagerLogin$$AtuhRegisterUser","Address":"0x1D2F8DC"},
            {"Name":"InternalDispatch$$Unknown","Address":"0x1D334A4"},
            {"Name":"SomeOther$$Later","Address":"0x1D34000"},
            {"Name":"Malicious\nInjected$$Name","Address":"0x1D35100"},
            {"Name":"Bad$$Address","Address":"not-an-address"},
        ]}
        addresses, mapping=mod.parse_script_index(sample)
        self.assertEqual(len(addresses),3)
        result=mod.resolve_index(addresses,mapping,[0x1D334A4,0x1D33520])
        a,b=result["resolved_code_targets"]
        self.assertTrue(a["exact_method_entry_in_index"])
        self.assertEqual(a["exact_method_names"],["InternalDispatch$$Unknown"])
        self.assertFalse(b["exact_method_entry_in_index"])
        self.assertEqual(b["nearest_preceding_method_entry"]["byte_distance"],
                         0x7C)
        self.assertEqual(b["next_indexed_method_entry"]["rva"],"0x1D34000")
        self.assertFalse(b["non_exact_function_ownership_verified"])
        self.assertFalse(result["server_guest_registration_verified"])

    def test_redacted_report_only_whitelists_bounded_hex_rvas(self):
        report={
            "guest_chain_diagnosis":{
                "indirect_dispatch_module_relative_target_rvas":[
                    "0x1D334A4","0x1D334A4","0xZZ","0x40000000",
                    "0xDEADBEEF",{"raw_utid":"secret"}, "0x0"
                ],
                "raw_utid":"VERY_SECRET",
            },
            "token":"PRIVATE_TOKEN",
        }
        self.assertEqual(mod.extract_observed_rvas(report),[
            0x1D334A4,0,
        ])
        self.assertEqual(mod.extract_observed_rvas({}),[])
        self.assertEqual(mod.extract_observed_rvas({"guest_chain_diagnosis":"x"}),[])

    def test_end_to_end_references_only_safe_method_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            script=root/"script.json"
            timeline=root/"safe-timeline.json"
            output=root/"method-hints.json"
            script.write_text(json.dumps({"ScriptMethod":[
                {"Name":"Fn$$Known","Address":"0x1D334A4"},
                {"Name":"Fn$$Later","Address":"0x1D335E4"},
            ]}),encoding="utf8")
            timeline.write_text(json.dumps({
                "guest_chain_diagnosis":{
                    "indirect_dispatch_module_relative_target_rvas":[
                        "0x1D334A4","0x1D334A8"
                    ]},
                "utid":"SENSITIVE_UTID",
                "token":"SENSITIVE_TOKEN"
            }),encoding="utf8")
            from unittest.mock import patch
            with patch("sys.argv",["offline","--script",str(script),
                                   "--timeline",str(timeline),
                                   "--output",str(output)]),redirect_stdout(io.StringIO()):
                self.assertEqual(mod.main(),0)
            saved=output.read_text(encoding="utf8")
            self.assertNotIn("SENSITIVE_UTID",saved)
            self.assertNotIn("SENSITIVE_TOKEN",saved)
            saved_json=json.loads(saved)
            self.assertEqual(saved_json["observed_indirect_dispatch_targets"],2)
            self.assertFalse(saved_json["raw_account_data_exported"])
            self.assertEqual(saved_json["resolved_code_targets"][0][
                "exact_method_names"],["Fn$$Known"])

    def test_reject_missing_script_method_list(self):
        with self.assertRaisesRegex(ValueError,"missing_ScriptMethod"):
            mod.parse_script_index({})


if __name__=="__main__":
    unittest.main()
