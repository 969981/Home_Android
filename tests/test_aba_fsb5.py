import importlib.util
import struct
import sys
import unittest
from pathlib import Path

root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/"tools"))
from aba_fsb5 import inspect_embedded

class TestCarveFSB5(unittest.TestCase):
    def test_version_one_valid_and_bounds(self):
        fsb=b"FSB5"+struct.pack("<6I",1,1,8,0,16,2)+bytes(32)+bytes(8+16)
        self.assertEqual(len(fsb),84)
        wrapper=b"prelude"+fsb+b"trailer"
        h=inspect_embedded(wrapper,len(b"prelude"))
        self.assertEqual(h["fsb_bytes"],84)
        self.assertEqual(h["remaining_wrapper_bytes"],7)
    def test_truncated_rejected(self):
        fsb=b"FSB5"+struct.pack("<6I",1,1,8,0,1000000,2)+bytes(32)
        with self.assertRaises(ValueError):
            inspect_embedded(fsb,0)

if __name__=="__main__":
    unittest.main()
