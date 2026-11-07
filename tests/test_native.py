import importlib.util
import tempfile
import unittest
from pathlib import Path

class TestNativeHeader(unittest.TestCase):
    def test_dex_header(self):
        import sys
        tools=Path(__file__).resolve().parents[1]/"tools"
        sys.path.insert(0,str(tools))
        from native_audit import examine_dex
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/"classes.dex"
            h=bytearray(112)
            h[:8]=bytes.fromhex("6465780a30333500")
            h[32:36]=(112).to_bytes(4,"little")
            h[36:40]=(112).to_bytes(4,"little")
            h[96:100]=(3).to_bytes(4,"little")
            p.write_bytes(h)
            x=examine_dex(p)
            self.assertEqual(x["version"],"035")
            self.assertEqual(x["class_defs"],3)
            self.assertTrue(x["size_matches"])

if __name__=="__main__":
    unittest.main()
