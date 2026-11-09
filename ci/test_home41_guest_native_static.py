#!/usr/bin/env python3
"""Offline A64 instruction and ELF program-header tests; no original APK needed."""
import struct
import unittest

from home41_guest_native_static import (
    a64_bl_target,a64_b_target,audit_bytes,elf_load_segments,extract_at_rva,
)


class RawA64GuestAuditTests(unittest.TestCase):
    def test_bl_forward_and_backward_sign_extension(self):
        self.assertEqual(a64_bl_target(0x1000,0x94000004),0x1010)
        self.assertEqual(a64_bl_target(0x1000,0x97FFFFFF),0xFFC)
        self.assertIsNone(a64_bl_target(0x1000,0x14000004))

    def test_b_forward_and_backward(self):
        self.assertEqual(a64_b_target(0x1000,0x14000004),0x1010)
        self.assertEqual(a64_b_target(0x1000,0x17FFFFFF),0xFFC)
        self.assertIsNone(a64_b_target(0x1000,0x94000004))

    def test_call_and_return_are_offset_grounded(self):
        b=struct.pack("<IIII",0x94000002,0xD63F0000,0xD65F03C0,0x17FFFFFF)
        r=audit_bytes(b,0x3000)
        self.assertEqual(r["direct_bl"][0]["target_rva"],"0x3008")
        self.assertEqual(r["ret_sites"],["0x3008"])
        self.assertEqual(r["indirect_blr_sites"],["0x3004"])
        self.assertTrue(r["trailing_bytes_may_be_next_method"])

    def test_reject_non_aarch64_and_invalid_segment_table(self):
        b=bytearray(64)
        b[:4]=b"\x7fELF"
        b[4]=2
        b[5]=1
        struct.pack_into("<H",b,18,62)
        with self.assertRaisesRegex(ValueError,"AArch64"):
            elf_load_segments(bytes(b))
        struct.pack_into("<H",b,18,183)
        with self.assertRaisesRegex(ValueError,"program header"):
            elf_load_segments(bytes(b))

    def test_executable_segment_is_required_for_rva(self):
        x=b"\0"*128
        with self.assertRaises(ValueError):
            extract_at_rva(x,[{"off":0,"vaddr":0x1000,
                "filesz":128,"executable":False}],0x1000,32)


if __name__=="__main__":
    unittest.main()
