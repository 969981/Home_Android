"""Offline fixture checks; no Android, network, tokens, or actual account."""
import unittest
import home41_original_symbol_exact_audit as mod


class OriginalRvaLookupTests(unittest.TestCase):
    def sample(self, callee_name="ApiRequestAuthRegisterUser$$TestCandidate"):
        names = [
            {"Name":"ApiManagerLogin$$AtuhRegisterUser",
             "Address":"0x1D2F8DC"},
            {"Name":callee_name, "Address":"0x1D35CC8"},
            {"Name":"Other$$Previous", "Address":"0x1D2F1F0"},
            {"Name":"Other$$Following", "Address":"0x1D2F208"},
        ]
        # Contract validation requires a genuine-sized index.
        names.extend({"Name":"Another$$Method", "Address":"0x1100"}
                     for _ in range(100001))
        return {"ScriptMethod":names}

    def test_exact_callee_is_identity_not_execution(self):
        report = mod.inspect(self.sample())
        target = report["methods"]["manager_tail_direct_callee"]
        self.assertTrue(target["is_exact_method_entry"])
        self.assertEqual(target["exact_names"],
                         ["ApiRequestAuthRegisterUser$$TestCandidate"])
        self.assertFalse(target["runtime_entry_observed"])
        self.assertFalse(report["runtime_registration_observed"])

    def test_nearest_only_is_not_ownership_proof(self):
        report = mod.inspect(self.sample())
        tail = report["methods"]["manager_tail_target"]
        self.assertFalse(tail["is_exact_method_entry"])
        self.assertEqual(tail["nearest_previous"]["rva"], "0x1D2F1F0")
        self.assertEqual(tail["nearest_next"]["rva"], "0x1D2F208")
        self.assertFalse(tail["nearby_method_ownership_verified"])

    def test_wrong_game_version_fails_closed(self):
        sample = self.sample()
        sample["ScriptMethod"][0]["Name"]="ApiManagerLogin$$OtherMethod"
        with self.assertRaisesRegex(ValueError, "index_does_not_match_original"):
            mod.inspect(sample)

    def test_source_table_is_bounded_and_no_credentials(self):
        report = mod.inspect(self.sample())
        rendered = mod.markdown(report)
        self.assertIn("0x1D35CC8", rendered)
        self.assertIn("ApiRequestAuthRegisterUser", rendered)
        self.assertNotIn("secret", rendered)
        self.assertFalse(report["server_guest_account_confirmed"])
        self.assertFalse(report["six_digit_home_id_verified"])


if __name__ == "__main__":
    unittest.main()
