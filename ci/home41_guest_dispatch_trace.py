#!/usr/bin/env python3
"""SHA-locked HOME 4.1.0 AArch64 manager/adjacent-callback boundary inspection.

Static ELF only: no Android, registration, replay, Frida, HTTP or private data.
A register-definition trace is a static CODE hint; it cannot determine a
runtime X8 pointer or which callback actually runs on the official client.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import zipfile
from pathlib import Path

from home41_guest_native_static import (
    APK_SHA, SO_SHA, SO_NAME, elf_load_segments, extract_at_rva,
    EXPECTED_NEARBY_CALLBACK_BLR_PC, EXPECTED_ADJACENT_PROLOGUE,
    EXPECTED_PRECEDING_BRANCH, EXPECTED_ADJACENT_RETURN,
)

START_RVA = 0x1D2F8DC
STOP_RVA_EXCLUSIVE = 0x1D2FA30
BLR_PC = EXPECTED_NEARBY_CALLBACK_BLR_PC
MAX_FILE = 250_000_000


def analyze_original_manager(so: bytes) -> dict:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from capstone.arm64 import ARM64_REG_X8, ARM64_REG_W8

    segs=elf_load_segments(so)
    data=extract_at_rva(so,segs,START_RVA,STOP_RVA_EXCLUSIVE-START_RVA)
    decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    decoder.detail=True
    instructions=[]
    x8_definitions=[]
    for ins in decoder.disasm(data,START_RVA):
        if ins.address < START_RVA or ins.address >= STOP_RVA_EXCLUSIVE:
            continue
        row={
            "rva":f"0x{ins.address:X}",
            "opcode":f"0x{struct.unpack('<I', ins.bytes)[0]:08X}",
            "mnemonic":ins.mnemonic,
            "operands":ins.op_str,
        }
        instructions.append(row)
        try:
            _, writes = ins.regs_access()
            if any(r in (ARM64_REG_X8, ARM64_REG_W8) for r in writes):
                x8_definitions.append(row)
        except Exception:
            pass
    match=[r for r in instructions if r["rva"]==f"0x{BLR_PC:X}"]
    prologue=[r for r in instructions
              if r["rva"]==f"0x{EXPECTED_ADJACENT_PROLOGUE[0]:X}"]
    boundary=[r for r in instructions
              if r["rva"]==f"0x{EXPECTED_PRECEDING_BRANCH[0]:X}"]
    returns=[r for r in instructions
             if r["rva"]==f"0x{EXPECTED_ADJACENT_RETURN[0]:X}"]
    if not (len(prologue)==len(boundary)==len(returns)==1):
        raise ValueError("adjacent_boundary_evidence_missing")
    for row,(address,expected) in (
        (prologue[0],EXPECTED_ADJACENT_PROLOGUE),
        (boundary[0],EXPECTED_PRECEDING_BRANCH),
        (returns[0],EXPECTED_ADJACENT_RETURN),
    ):
        if int(row["opcode"],16)!=expected:
            raise ValueError(f"adjacent_boundary_opcode_mismatch_at_0x{address:X}")
    if len(match)!=1 or match[0]["mnemonic"]!="blr" or match[0]["operands"]!="x8":
        raise ValueError("expected_original_A64_BLR_X8_instruction_missing")
    return {
        "status":"SHA_locked_static_adjacent_callback_boundary_audit",
        "prior_method":"ApiManagerLogin.AtuhRegisterUser",
        "prior_method_entry_rva":f"0x{START_RVA:X}",
        "prior_method_unconditional_tail_branch":boundary[0],
        "unclassified_adjacent_function_prologue":prologue[0],
        "unclassified_adjacent_function_return":returns[0],
        "adjacent_helper_official_method_name_verified":False,
        "blr_is_proven_in_prior_register_manager_body":False,
        "disassembly_end_exclusive":f"0x{STOP_RVA_EXCLUSIVE:X}",
        "instruction_count":len(instructions),
        "dispatch_site_rva":f"0x{BLR_PC:X}",
        "dispatch_instruction":match[0],
        "static_potential_x8_write_sites":x8_definitions,
        "instructions":instructions,
        "static_preceding_code_window_only":True,
        "runtime_x8_value_known":False,
        "runtime_target_function_identity_proven":False,
        "same_registration_transaction_proven":False,
        "guest_registration_proven":False,
        "raw_account_data_included":False,
    }


def main() -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apk",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()
    if not args.apk.is_file() or args.apk.stat().st_size>400_000_000:
        raise SystemExit("original_apk_missing_or_too_large")
    if hashlib.sha256(args.apk.read_bytes()).hexdigest()!=APK_SHA:
        raise SystemExit("original_APK_SHA_mismatch")
    with zipfile.ZipFile(args.apk) as z:
        info=z.getinfo(SO_NAME)
        if info.file_size>MAX_FILE:
            raise SystemExit("original_libil2cpp_too_large")
        so=z.read(SO_NAME)
    if hashlib.sha256(so).hexdigest()!=SO_SHA:
        raise SystemExit("original_libil2cpp_SHA_mismatch")
    result=analyze_original_manager(so)
    args.output.parent.mkdir(exist_ok=True,parents=True)
    args.output.write_text(
        json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True)+"\n",
        encoding="utf-8")
    print("Original HOME 4.1.0 preceding manager / separate adjacent conditional callback:")
    print("BLR X8:",result["dispatch_instruction"])
    print("Prior body tail exit:",result["prior_method_unconditional_tail_branch"])
    print("Next prologue:",result["unclassified_adjacent_function_prologue"])
    print("Adjacent callback return:",result["unclassified_adjacent_function_return"])
    print("Potential register definitions; no runtime target claim:")
    for row in result["static_potential_x8_write_sites"]:
        print(row["rva"],row["mnemonic"],row["operands"])
    print("Last 26 A64 instructions in bounded method window:")
    insns=result["instructions"]
    index=next(i for i,v in enumerate(insns) if v["rva"]==f"0x{BLR_PC:X}")
    for row in insns[max(0,index-25):index+4]:
        print(row["rva"],row["opcode"],row["mnemonic"],row["operands"])
    return 0


if __name__=="__main__":
    raise SystemExit(main())
