#!/usr/bin/env python3
"""Native ARM64 Android runtime feasibility test; zero account operations.

An ARM64 Linux runner is not proof of an ARM64 Android emulator.
Only report success if the booted Android guest itself identifies as arm64,
the original HOME APK installs, and its own process launches.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import platform
import subprocess
import time
from pathlib import Path

APK_SHA256 = "8dee598028cd70441f645c8fff96b093b76778d625cdf07c60109eced50ffac1"
PACKAGE = "jp.pokemon.pokemonhome"

def call(args, timeout=45):
    try:
        return subprocess.run(args, capture_output=True, text=True, errors="replace",
                              check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None

def adb(*args, timeout=45):
    return call(["adb", *args], timeout=timeout)

def prop(key):
    res = adb("shell", "getprop", key)
    return (res.stdout or "").strip()[:120] if res and res.returncode == 0 else ""

def hash_file(p):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def report_preflight(apk:Path, out:Path):
    out.mkdir(parents=True, exist_ok=True)
    report = {
        "host_machine":platform.machine(),
        "android_native_arm64_status":"not_checked",
        "original_apk_hash_match":False,
        "apk_installed":False,
        "app_launched":False,
        "app_process_alive":False,
        "nintendo_account_bound":False,
        "registration_attempted":False,
        "terms_accepted":False,
        "utid_hook_attempted":False,
        "first_basic_utid_status":"not_observed",
        "account_identifiers_or_tokens_saved":False,
    }
    try:
        report["original_apk_hash_match"] = hash_file(apk) == APK_SHA256
        if not report["original_apk_hash_match"]:
            report["result"]="invalid_original_apk"
            return report
        report["android_api"] = prop("ro.build.version.sdk")
        report["android_primary_abi"] = prop("ro.product.cpu.abi")
        report["android_supported_abis"] = prop("ro.product.cpu.abilist")
        bridge = prop("ro.dalvik.vm.native.bridge")
        report["android_native_bridge_configured"] = bool(bridge and bridge not in {"0", "false"})
        native = report["android_primary_abi"] == "arm64-v8a" and not report["android_native_bridge_configured"]
        report["android_native_arm64_status"] = "verified_guest_abi_only" if native else "not_native_arm64_guest"
        if not native:
            report["result"]="blocked_non_native_android_guest"
            return report
        install = adb("install", "-r", str(apk), timeout=180)
        report["apk_installed"] = bool(install and install.returncode == 0)
        if not report["apk_installed"]:
            report["result"]="blocked_apk_install"
            return report
        launch = adb("shell", "monkey", "-p", PACKAGE,
                     "-c", "android.intent.category.LAUNCHER", "1", timeout=50)
        report["app_launched"] = bool(launch and launch.returncode == 0
                                     and "Events injected: 1" in (launch.stdout or ""))
        time.sleep(12)
        process = adb("shell", "pidof", PACKAGE)
        report["app_process_alive"] = bool(process and process.returncode == 0
                                           and (process.stdout or "").strip())
        report["result"] = ("native_arm64_android_home_process_verified"
                             if report["app_launched"] and report["app_process_alive"]
                             else "native_arm64_guest_but_home_not_running")
    except Exception as err:
        report["result"]="probe_exception"
        report["error_type"]=type(err).__name__
    finally:
        path=out/"home41_arm64_guest_preflight.json"
        path.write_text(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({"result":report.get("result"),
                          "android_native_arm64_status":report["android_native_arm64_status"],
                          "app_process_alive":report["app_process_alive"],
                          "first_basic_utid_status":report["first_basic_utid_status"]},
                         ensure_ascii=False))
    return report

if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--apk",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    answer=report_preflight(args.apk,args.output)
    if answer["result"] != "native_arm64_android_home_process_verified":
        raise SystemExit(2)
