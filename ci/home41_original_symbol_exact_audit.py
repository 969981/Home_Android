#!/usr/bin/env python3
"""Offline exact-RVA lookup in SHA-pinned HOME 4.1.0 IL2CppDumper index."""
import argparse
import bisect
import json
from collections import defaultdict
from pathlib import Path

PINNED_BLOB_SHA = "895419550af1e00a2482f01fcc6d1c07592a5995"
TARGETS = {
    "ApiManagerLogin.AtuhRegisterUser": 0x1D2F8DC,
    "manager_inner_callee": 0x1D2F584,
    "manager_tail_target": 0x1D2F1F8,
    "manager_tail_direct_callee": 0x1D35CC8,
    "tail_other_callee_a": 0x1D4BF14,
    "tail_other_callee_b": 0x1D656BC,
    "tail_other_callee_c": 0x1D8AA54,
    "adjacent_conditional_callback": 0x1D2F9F8,
    "register_serializer": 0x1D334A4,
    "registration_response": 0x1D33294,
}


def inspect(script):
    records = script.get("ScriptMethod") if isinstance(script, dict) else None
    if not isinstance(records, list) or not 100000 < len(records) < 400000:
        raise ValueError("invalid_original_il2cpp_method_index")
    methods = defaultdict(list)
    for m in records:
        if not isinstance(m, dict):
            continue
        name, addr = m.get("Name"), m.get("Address")
        if not isinstance(name, str) or not 0 < len(name) < 350:
            continue
        if any(ord(c) < 32 or ord(c) > 126 for c in name) or type(addr) is bool:
            continue
        try:
            rva = int(addr, 0) if isinstance(addr, str) else int(addr)
        except (TypeError, ValueError, OverflowError):
            continue
        if not 0 < rva < 0x40000000:
            continue
        if name not in methods[rva] and len(methods[rva]) < 12:
            methods[rva].append(name)
    addresses = sorted(methods)
    result = {}
    for label, rva in TARGETS.items():
        i = bisect.bisect_left(addresses, rva)
        exact = i < len(addresses) and addresses[i] == rva
        prev = addresses[i-1] if i else None
        following = addresses[i] if i < len(addresses) else None
        result[label] = {
            "rva": "0x%X" % rva,
            "is_exact_method_entry": exact,
            "exact_names": methods.get(rva, []) if exact else [],
            "nearest_previous": (
                {"rva": "0x%X" % prev,
                 "distance_bytes": rva-prev,
                 "names": methods[prev]}
                if prev is not None and not exact else None),
            "nearest_next": (
                {"rva": "0x%X" % following,
                 "distance_bytes": following-rva,
                 "names": methods[following]}
                if following is not None and not exact else None),
            "nearby_method_ownership_verified": False,
            "runtime_entry_observed": False,
        }
    manager = result["ApiManagerLogin.AtuhRegisterUser"]
    if not manager["is_exact_method_entry"] or not any(
        "ApiManagerLogin" in s and "AtuhRegisterUser" in s
        for s in manager["exact_names"]
    ):
        raise ValueError("index_does_not_match_original_HOME_4_1_0")
    return {
        "status": "original_static_scriptmethod_RVA_lookup",
        "source_git_blob_sha1": PINNED_BLOB_SHA,
        "source_method_count": len(records),
        "index_entry_count": len(addresses),
        "methods": result,
        "runtime_registration_observed": False,
        "server_guest_account_confirmed": False,
        "six_digit_home_id_verified": False,
    }


def markdown(report):
    out = [
        "---", "title: HOME 4.1.0 游客注册候选原版 IL2CPP 地址精确映射",
        "date: 2026-11-09", "status: 仅原版 ScriptMethod 静态验证",
        "tags: [HOME, Android, AArch64, IL2CPP, guest]",
        "---", "", "# 原版 ScriptMethod 入口 RVA 对照", "",
        "方法数量：" + str(report["source_method_count"]),
        "源 Git blob SHA：§" + PINNED_BLOB_SHA + "§。", "",
        "| 研究节点 | RVA | 原版方法入口名 | 精确匹配 |",
        "| --- | --- | --- | --- |",
    ]
    for label, item in report["methods"].items():
        names = ", ".join("§" + n + "§" for n in item["exact_names"])
        out.append("| §{}§ | §{}§ | {} | {} |".format(
            label, item["rva"], names or "没有（不可推断归属）",
            "是" if item["is_exact_method_entry"] else "否"))
    out += ["", "注意：仅验证原始方法地址索引与实际静态 BL/B 的对应关系。",
            "没有实际运行 HOME，不证明真实委托触发、HTTP 请求发送、",
            "服务端注册成功、首次 basic.utid 或冷启动 ID 恢复。"]
    return "\n".join(out).replace("§", chr(96)) + "\n"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--script", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--markdown", required=True, type=Path)
    args = p.parse_args()
    if not args.script.is_file() or args.script.stat().st_size > 160000000:
        raise SystemExit("original_script_missing_or_oversize")
    report = inspect(json.loads(args.script.read_text(encoding="utf-8-sig")))
    args.output.parent.mkdir(exist_ok=True, parents=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf8")
    args.markdown.parent.mkdir(exist_ok=True, parents=True)
    args.markdown.write_text(markdown(report), encoding="utf8")
    for key, m in report["methods"].items():
        print("ORIGINAL_METHOD", key, m["rva"], "EXACT",
              m["is_exact_method_entry"], m["exact_names"],
              "NEAREST", m["nearest_previous"])
    print("ORIGINAL_SCRIPT_METHOD_COUNT", report["source_method_count"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
