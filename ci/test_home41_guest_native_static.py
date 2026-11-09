#!/usr/bin/env python3
"""Offline A64 instruction and ELF program-header tests; no original APK needed."""
import struct
import unittest
from unittest.mock import patch

import home41_guest_native_static as native

from home41_guest_native_static import (
    a64_bl_target,a64_b_target,audit_bytes,elf_load_segments,extract_at_rva,
    WINDOWS, KNOWN,
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

    def test_new_exact_firstboot_windows_and_non_auth_ui_helpers(self):
        self.assertEqual(WINDOWS["FirstBoot._AddWarningPart"][0],0x1DE1098)
        self.assertEqual(WINDOWS["FirstBoot._AddPadder"][0],0x1DE16F4)
        self.assertEqual(WINDOWS["FirstBoot.DecisionGestAccount"],(0x1DE5508,0x190))
        self.assertEqual(WINDOWS["FirstBoot.DenialGestAccount"],(0x1DE5698,0xAC))
        self.assertEqual(WINDOWS["FirstBoot.GuestResultCallback_b84_6"],
                         (0x1DE64C0,0x14))
        self.assertEqual(WINDOWS["FirstBoot.SelectTrainerIcon"][0],0x1DE48F8)
        self.assertEqual(WINDOWS["FirstBoot.ProloguePokemonPanel.OnTapPokemon"][0],
                         0x1C7F0F4)
        self.assertEqual(WINDOWS["FirstBoot.PlayPrologue"][0],0x1DE45E8)
        self.assertEqual(WINDOWS["FirstBoot.PlayPrologue2"][0],0x1DE4CF4)
        self.assertNotIn("FirstBoot.post_guest_0x1DE1098",WINDOWS)
        self.assertNotIn("FirstBoot.post_guest_0x1DE16F4",WINDOWS)
        self.assertEqual(KNOWN[0x1DE64C0],"FirstBoot.GuestResultCallback_b84_6")
        # Name/position association remains static, not proof of actual call.
        self.assertNotEqual(KNOWN[0x1DE64C0],"ApiManagerLogin.AtuhRegisterUser")

    def test_exact_guest_branch_invariant_passes_synthetic_A64_bytes(self):
        encoded={}
        for pc,kind,target in native.EXPECTED_BRANCHES:
            imm=((target-pc)//4)&0x03ffffff
            encoded[pc]=struct.pack(
                "<I", (0x94000000 if kind=="BL" else 0x14000000)|imm)
        encoded[0x1DE64C0]=struct.pack(
            "<IIIII",*native.EXPECTED_GUEST_START_THUNK)
        store_pc,store_insn=native.EXPECTED_GUEST_DECISION_STORE
        encoded[store_pc]=struct.pack("<I",store_insn)
        # BLR X13 in an ADJACENT callback (synthetic), not the manager.
        encoded[native.EXPECTED_NEARBY_CALLBACK_BLR_PC]=struct.pack(
            "<I",0xD63F0000 | (13<<5))
        for pc,insn in (
            native.EXPECTED_PRECEDING_BRANCH,
            native.EXPECTED_ADJACENT_PROLOGUE,
            native.EXPECTED_ADJACENT_RETURN,
        ):
            encoded[pc]=struct.pack("<I",insn)
        for pc,insn,label in native.EXPECTED_CONDITIONAL_CALLBACK_INSTRUCTIONS:
            encoded[pc]=struct.pack("<I",insn)
        def fake_extract(_so,_segs,pc,length):
            blob=encoded[pc]
            self.assertEqual(len(blob),length)
            return blob
        with patch.object(native,"extract_at_rva",side_effect=fake_extract):
            report=native.verify_verified_guest_branch_chain(b"",[])
        self.assertEqual(report["verified_edge_count"],8)
        helper=report["adjacent_conditional_callback_blr"]
        self.assertEqual(helper["rva"],"0x1D2FA20")
        self.assertEqual(helper["branch_register"],"X13")
        self.assertFalse(helper["callee_identity_verified"])
        self.assertFalse(helper["http_request_send_verified"])
        self.assertFalse(helper["atuh_register_user_body_membership_verified"])
        self.assertFalse(helper["original_IL2CPP_method_identity_verified"])
        self.assertEqual(helper["target_pointer_source_static"],"*(X3+0x18)")
        self.assertEqual(helper["arg0_source_static"],"*(X3+0x40)")
        self.assertEqual(helper["arg1_source_static"],"*(X3+0x28)")
        self.assertFalse(helper["guard_business_meaning_verified"])
        self.assertEqual(len(helper["guard_and_callback_field_loads"]),8)
        self.assertEqual(helper["boundary_evidence"][
            "adjacent_prologue"]["rva"],"0x1D2F9F8")
        self.assertEqual(helper["boundary_evidence"][
            "preceding_tail_branch"]["rva"],"0x1D2F9E8")
        self.assertFalse(report["actual_server_registration_confirmed"])
        self.assertFalse(report["button_to_delegate_runtime_identity_verified"])
        self.assertEqual(report["guest_start_callback"]["if_true"],
                         "GoToPhase(14) MT_LOGIN")
        self.assertEqual(report["guest_start_callback"]["if_false"],
                         "GoToPhase(7) NA_LINK_CONTINUE")
        self.assertTrue(any(
            x["pc"]=="0x1DE5690" and
            x["instruction"]=="B" and
            x["target_rva"]=="0x1D2F8DC"
            for x in report["edges"]))
        broken=dict(encoded)
        broken[native.EXPECTED_NEARBY_CALLBACK_BLR_PC]=struct.pack(
            "<I",0xD503201F)
        with patch.object(
                native,"extract_at_rva",
                side_effect=lambda so,segs,pc,length:broken[pc]):
            with self.assertRaisesRegex(ValueError,"adjacent callback callsite missing BLR"):
                native.verify_verified_guest_branch_chain(b"",[])
        broken=dict(encoded)
        broken[native.EXPECTED_CONDITIONAL_CALLBACK_INSTRUCTIONS[5][0]]=struct.pack(
            "<I",0xD503201F)
        with patch.object(native,"extract_at_rva",
                          side_effect=lambda so,segs,pc,length:broken[pc]):
            with self.assertRaisesRegex(
                    ValueError,"adjacent callback parameter/guard mismatch"):
                native.verify_verified_guest_branch_chain(b"",[])
        broken=dict(encoded)
        broken[native.EXPECTED_ADJACENT_PROLOGUE[0]]=struct.pack(
            "<I",0xD503201F)
        with patch.object(native,"extract_at_rva",
                          side_effect=lambda so,segs,pc,length:broken[pc]):
            with self.assertRaisesRegex(
                    ValueError,"adjacent function boundary opcode mismatch"):
                native.verify_verified_guest_branch_chain(b"",[])
        broken=dict(encoded)
        broken[0x1DE5690]=struct.pack("<I",0xD503201F)
        with patch.object(
                native,"extract_at_rva",
                side_effect=lambda so,segs,pc,length:broken[pc]):
            with self.assertRaisesRegex(ValueError,"branch opcode mismatch"):
                native.verify_verified_guest_branch_chain(b"",[])

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
