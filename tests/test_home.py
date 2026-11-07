import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "home.py"
spec = importlib.util.spec_from_file_location("home", SCRIPT)
home = importlib.util.module_from_spec(spec)
spec.loader.exec_module(home)

class TestHome(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.apk = self.root / "fixture.apk"
        with zipfile.ZipFile(self.apk, "w") as f:
            f.writestr("classes.dex", bytes.fromhex("6465780a30333500") + b"sample")
            f.writestr("lib/arm64-v8a/libunity.so", bytes.fromhex("7f454c46") + b"fixture")
            f.writestr("assets/bin/Data/bundle", b"UnityFS" + bytes([0]) + b"fixture")
            f.writestr("assets/sample.png", bytes.fromhex("89504e470d0a1a0a") + b"fixture")

    def test_audit_extract_scan(self):
        report = self.root / "report"
        result = home.audit("4.1.0", self.apk, report)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["zip_entries"], 4)
        self.assertEqual(result["by_kind"]["unity_bundle"], 1)
        dest = self.root / "raw"
        self.assertEqual(home.extract(self.apk, dest)["extracted_new_or_replaced"], 4)
        self.assertEqual(home.extract(self.apk, dest)["skipped_verified_crc"], 4)
        summary = home.scan("4.1.0", dest, report)
        self.assertTrue(summary["unity_runtime_present"])
        self.assertTrue(summary["unity_possible"])
        self.assertFalse(summary["il2cpp_ready_for_analysis"])
        self.assertTrue((report / "resource_candidates.csv").exists())

    def test_traversal_blocked(self):
        with self.assertRaises(ValueError):
            home.safe_relative("../../attack.txt")
        with self.assertRaises(ValueError):
            home.safe_relative("/tmp/attack.txt")
        with self.assertRaises(ValueError):
            home.safe_relative("C:/attack.txt")

if __name__ == "__main__":
    unittest.main()
