#!/usr/bin/env python3
"""Reproducible local-only AArch64 direct-call audit of original HOME 4.1.0 APK.

No app launch, network authentication, credentials, login or account creation.
Validate original APK + libil2cpp hashes and decode A64 BL and RET instructions
from bounded *inspection windows*, not inferred complete function bodies.

This is a directed-call cross-reference aid, not a full CFG decompiler.
Indirect calls (BLR, vtable, delegate, async task) are intentionally unresolved.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
import zipfile
from pathlib import Path

APK_SHA="8dee598028cd70441f645c8fff96b093b76778d625cdf07c60109eced50ffac1"
SO_SHA="80bfbc3d480bf3c91297d65a441a37e40260b70fd8b0ddc8da70c34f0870b6fe"
SO_NAME="lib/arm64-v8a/libil2cpp.so"
WINDOWS={
    "FirstBoot.ConfirmationGestAccount":(0x1DE369C,0x1E0),
    "FirstBoot.ConfirmGestAccountFirst":(0x1DE5140,0x1D8),
    "FirstBoot.ConfirmGestAccountSecond":(0x1DE5318,0x180),
    # Concrete first-level BL targets verified in the original bytecode.
    # These labels are evidence-relative, not inferred official symbols.
    "GuestConfirmation.initial_direct_callee_unclassified":(0x1DEAFDC,0x180),
    "GuestConfirmation.first_direct_callee_unclassified":(0x1DEB1E8,0x1B0),
    "GuestConfirmation.second_direct_callee_unclassified":(0x1DEB3C0,0x1F0),
    "FirstBoot.post_guest_0x1DE1098":(0x1DE1098,0x110),
    "FirstBoot.post_guest_0x1DE16F4":(0x1DE16F4,0x130),
    "FirstBoot.GoToPhase":(0x1DE1C10,0x160),
    "ApiManagerLogin.AtuhRegisterUser":(0x1D2F8DC,0x200),
    "ApiRequestAuthRegisterUser.SerializeRequestParameter":(0x1D334A4,0x130),
    "ApiRequestAuthRegisterUser.CallAfterResponse":(0x1D33294,0x180),
}
KNOWN={start:name for name,(start,_) in WINDOWS.items()}


def a64_bl_target(pc:int, insn:int) -> int | None:
    if insn&0xFC000000 != 0x94000000:
        return None
    imm=insn & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    return pc+(imm<<2)


def a64_b_target(pc:int,insn:int)->int|None:
    if insn&0xFC000000 != 0x14000000:
        return None
    imm=insn & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    return pc+(imm<<2)


def elf_load_segments(so:bytes)->list[dict]:
    if len(so)<64 or so[:4]!=b"\x7fELF" or so[4]!=2 or so[5]!=1:
        raise ValueError("not ELF64 little endian")
    if struct.unpack_from("<H",so,18)[0]!=183:
        raise ValueError("not AArch64")
    off=struct.unpack_from("<Q",so,32)[0]
    entsize=struct.unpack_from("<H",so,54)[0]
    count=struct.unpack_from("<H",so,56)[0]
    if not 56<=entsize<=512 or not 1<=count<=1024:
        raise ValueError("invalid program header count or size")
    out=[]
    for i in range(count):
        start=off+i*entsize
        if start+56>len(so):
            raise ValueError("truncated program headers")
        typ, flags=struct.unpack_from("<II",so,start)
        if typ!=1:
            continue
        foff,vaddr,filesz,memsz=(
            struct.unpack_from("<Q",so,start+8)[0],
            struct.unpack_from("<Q",so,start+16)[0],
            struct.unpack_from("<Q",so,start+32)[0],
            struct.unpack_from("<Q",so,start+40)[0],
        )
        if foff+filesz>len(so) or filesz>memsz:
            raise ValueError("malformed PT_LOAD")
        out.append({"off":foff,"vaddr":vaddr,
                    "filesz":filesz,"memsz":memsz,
                    "executable":bool(flags&1)})
    if not out:
        raise ValueError("no PT_LOAD")
    return out


def extract_at_rva(so:bytes, segs:list[dict], rva:int, size:int)->bytes:
    for p in segs:
        if p["executable"] and p["vaddr"]<=rva and (
                rva+size<=p["vaddr"]+p["filesz"]):
            start=p["off"]+rva-p["vaddr"]
            return so[start:start+size]
    raise ValueError("RVA not covered by executable PT_LOAD")


def audit_bytes(data:bytes, start:int)->dict:
    if len(data)%4:
        raise ValueError("A64 window must be 4-byte aligned")
    calls=[]
    branches=[]
    returns=[]
    indirect_calls=[]
    for i in range(0,len(data),4):
        pc=start+i
        op=struct.unpack_from("<I",data,i)[0]
        dst=a64_bl_target(pc,op)
        if dst is not None:
            calls.append({"rva":f"0x{pc:X}",
                          "target_rva":f"0x{dst:X}",
                          "target_name":KNOWN.get(dst)})
        b=a64_b_target(pc,op)
        if b is not None:
            branches.append({"rva":f"0x{pc:X}","target_rva":f"0x{b:X}"})
        if op&0xFFFFFC1F==0xD63F0000:
            indirect_calls.append(f"0x{pc:X}")
        if op&0xFFFFFC1F==0xD65F0000:
            returns.append(f"0x{pc:X}")
    return {"inspection_start_rva":f"0x{start:X}",
            "inspection_end_rva_exclusive":f"0x{start+len(data):X}",
            "first_ret":returns[0] if returns else None,
            "ret_sites":returns,
            "direct_bl":calls,
            "direct_b":branches[:24],
            "indirect_blr_sites":indirect_calls,
            "trailing_bytes_may_be_next_method":True}


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--apk",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    apk=args.apk.read_bytes()
    if hashlib.sha256(apk).hexdigest()!=APK_SHA:
        raise SystemExit("APK SHA mismatch")
    with zipfile.ZipFile(args.apk) as z:
        info=z.getinfo(SO_NAME)
        if info.file_size>250_000_000:
            raise SystemExit("libil2cpp size over limit")
        so=z.read(SO_NAME)
    if hashlib.sha256(so).hexdigest()!=SO_SHA:
        raise SystemExit("libil2cpp SHA mismatch")
    segs=elf_load_segments(so)
    report={
        "status":"raw_original_4.1.0_executable_bytes_verified",
        "apk_sha256":APK_SHA,
        "libil2cpp_sha256":SO_SHA,
        "architecture":"AArch64/ELF64",
        "method_windows_scope":"bounded bytes, not complete function boundaries",
        "indirect_calls_resolved":False,
        "network_or_guest_account_accessed":False,
        "windows":{},
    }
    for name,(start,size) in WINDOWS.items():
        data=extract_at_rva(so,segs,start,size)
        report["windows"][name]=audit_bytes(data,start)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",
                           encoding="utf8")
    for name,d in report["windows"].items():
        print(name,d["inspection_start_rva"],"first_ret",d["first_ret"],
              "BL",len(d["direct_bl"]),"BLR",len(d["indirect_blr_sites"]))
        print("   targets",", ".join(x["target_rva"]+
              (" ["+x["target_name"]+"]" if x["target_name"] else "")
              for x in d["direct_bl"][:40]))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
