#!/usr/bin/env python3
"""One-shot read-only Pokémon HOME 4.1.0 UTID observation on *native* ARM64 Android.

Runs on a PC with adb and Python frida; requires a personally controlled
Android ARM64 device with compatible Frida instrumentation already available.
Does not bind Nintendo Account, modify HOME, make auth HTTP requests,
accept Terms, create/delete accounts, or print/store IDs or credentials.

This deliberately refuses x86_64 + ARM Native Bridge and incorrect APKs.
The visible Trainer ID conversion remains unverified until compared in HOME.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import threading
from pathlib import Path

PACKAGE = "jp.pokemon.pokemonhome"
APK_SHA256 = "8dee598028cd70441f645c8fff96b093b76778d625cdf07c60109eced50ffac1"
APP_VERSION_CODE = "81"
EVENT_NAMES = frozenset({
    "guest_arch_preflight", "hook_preflight_failed", "hook_armed",
    "registration_callback_entered", "token_callback_entered",
    "login_callback_entered", "basic_received_without_numeric_utid",
    "first_basic_utid_observed", "read_failed", "read_only_observer_ready",
})
# Exactly the fields that may enter the public-safe stdout event channel.
EVENT_FIELDS = frozenset({
    "kind", "version", "event", "ms_since_attach", "observer",
    "process_arch", "native_arm64", "status", "reason",
    "public_output_is_redacted", "candidate_matches_target",
    "source_common_response_consumer", "registration_callback_seen",
    "token_callback_seen", "login_callback_seen", "ui_tid_conversion_status",
    "normal_client_handoff_status", "nintendo_binding_attempted",
})


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def adb(args: list[str], serial: str | None = None, timeout: int = 25):
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    try:
        return subprocess.run(cmd + args, capture_output=True, text=True,
                              errors="replace", timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def android_prop(key: str, serial: str | None):
    r = adb(["shell", "getprop", key], serial)
    return (r.stdout or "").strip()[:100] if r and r.returncode == 0 else ""


def preflight(apk: Path, serial: str | None = None) -> dict:
    report = {
        "result": "not_checked", "package": PACKAGE,
        "nintendo_account_binding_attempted": False,
        "server_registration_attempted": False,
        "account_deletion_attempted": False,
        "utid_read_status": "not_observed",
        "secrets_collected": False,
        "original_apk_hash_matched": False,
    }
    if not apk.is_file():
        report["result"] = "apk_missing"
        return report
    if digest(apk) != APK_SHA256:
        report["result"] = "apk_hash_mismatch"
        return report
    report["original_apk_hash_matched"] = True
    device_abi = android_prop("ro.product.cpu.abi", serial)
    bridge = android_prop("ro.dalvik.vm.native.bridge", serial)
    report["android_primary_abi"] = device_abi
    report["native_bridge_configured"] = bool(bridge and bridge not in {"0", "false"})
    if device_abi != "arm64-v8a" or report["native_bridge_configured"]:
        report["result"] = "non_native_arm64_android"
        return report
    r = adb(["shell", "dumpsys", "package", PACKAGE], serial)
    output = (r.stdout or "") if r and r.returncode == 0 else ""
    matches = re.findall(r"\bversionCode=(\d+)\b", output)
    if APP_VERSION_CODE not in matches:
        report["result"] = "wrong_or_missing_installed_home_version"
        return report
    report["installed_version_code"] = APP_VERSION_CODE
    report["result"] = "native_arm64_original_apk_preflight_ok"
    report["note"] = ("Installed versionCode checked; locally supplied APK SHA-256 verified. "
                      "Installed package's byte-for-byte integrity is not independently proven.")
    return report



def installed_apk_integrity(serial: str | None = None) -> str:
    """Check the Android-installed base.apk SHA before touching process memory.

    Returns only a categorical result. Android system app paths are never
    printed, and a missing permission is not treated as a matching build.
    """
    listing = adb(["shell", "pm", "path", PACKAGE], serial)
    if not listing or listing.returncode != 0:
        return "installed_apk_path_unavailable"
    locations = [line.removeprefix("package:").strip()
                 for line in (listing.stdout or "").splitlines()
                 if line.startswith("package:")]
    base = next((p for p in locations if p.endswith("/base.apk")), None)
    if not base:
        return "installed_base_apk_missing"
    checked = adb(["shell", "sha256sum", base], serial, timeout=50)
    if not checked or checked.returncode != 0:
        return "installed_apk_hash_unavailable"
    match = re.match(r"^([0-9a-fA-F]{64})\\s", (checked.stdout or ""))
    if not match:
        return "installed_apk_hash_unavailable"
    return "installed_apk_hash_verified" if match.group(1).lower() == APK_SHA256 else "installed_apk_hash_mismatch"


def prepare_script(path: Path, target_tid: str) -> str:
    if not re.fullmatch(r"[0-9]{6}", target_tid):
        raise ValueError("Target must be exactly six ASCII digits")
    source = path.read_text(encoding="utf-8")
    marker = "const EXPECTED_TARGET = '888888';"
    if source.count(marker) != 1:
        raise RuntimeError("Frida script target marker missing or duplicated")
    return source.replace(marker, "const EXPECTED_TARGET = '" + target_tid + "';")


def redacted_event(message: dict) -> dict | None:
    """Discard all non-whitelisted logs and arbitrary Frida payload fields."""
    if message.get("type") != "send":
        return None
    obj = message.get("payload")
    if not isinstance(obj, dict) or obj.get("kind") != "home41_utid_readonly":
        return None
    if obj.get("event") not in EVENT_NAMES or obj.get("version") != "4.1.0":
        return None
    clean = {k: v for k, v in obj.items()
             if k in EVENT_FIELDS and isinstance(v, (str, int, float, bool, type(None)))}
    if clean.get("event") == "first_basic_utid_observed":
        # Fail closed: never accept or print apparent raw identities.
        clean.pop("observer", None)
        clean.pop("reason", None)
        clean["public_output_is_redacted"] = True
    return clean


def print_report(report: dict) -> None:
    print(json.dumps(report, ensure_ascii=False, sort_keys=True), flush=True)


def observe(apk: Path, target_tid: str, serial: str | None,
            script_path: Path, timeout: int = 180) -> int:
    check = preflight(apk, serial)
    print_report(check)
    if check["result"] != "native_arm64_original_apk_preflight_ok":
        return 2
    installed_integrity = installed_apk_integrity(serial)
    print_report({"installed_apk_integrity": installed_integrity})
    if installed_integrity != "installed_apk_hash_verified":
        print_report({"result": "instrumentation_blocked_installed_apk_not_verified"})
        return 2
    source = prepare_script(script_path, target_tid)
    try:
        import frida  # installed separately on the controlling PC
    except ImportError:
        print_report({"result": "frida_python_not_installed",
                      "hint": "Install Python package frida on your local PC"})
        return 2

    try:
        device = (frida.get_device(serial, timeout=12) if serial
                  else frida.get_usb_device(timeout=12))
    except Exception as err:
        print_report({"result": "frida_device_unavailable", "error_type": type(err).__name__})
        return 2

    got_first = threading.Event()
    detached = threading.Event()
    observation = {"result": "awaiting_first_basic", "first_basic_utid_observed": False}
    session = None
    spawned_pid = None
    resumed = False

    def on_message(message, _data):
        clean = redacted_event(message)
        if clean is None:
            return
        print_report(clean)
        if clean["event"] == "first_basic_utid_observed":
            observation["first_basic_utid_observed"] = True
            observation["candidate_matches_target"] = bool(clean.get("candidate_matches_target"))
            observation["result"] = "first_basic_captured_unverified_display_semantics"
            got_first.set()

    def on_detached(*_args):
        detached.set()

    try:
        # Frida spawn is needed to observe the *first* SetBasic invocation.
        # It is not account creation and cannot automate HOME registration.
        spawned_pid = device.spawn([PACKAGE])
        session = device.attach(spawned_pid)
        session.on("detached", on_detached)
        script = session.create_script(source)
        script.on("message", on_message)
        script.load()
        device.resume(spawned_pid)
        resumed = True
        print_report({"result": "original_home_running_with_read_only_hooks",
                      "method": "frida_spawn_then_resume",
                      "nintendo_account_binding_attempted": False,
                      "accounts_created_or_deleted_by_runner": False})
        if not got_first.wait(timeout=max(1, min(timeout, 3600))):
            observation["result"] = ("frida_session_detached_before_basic"
                                     if detached.is_set() else "timeout_no_basic_observed")
        print_report(observation)
        return 0 if got_first.is_set() else 3
    except Exception as err:
        print_report({"result": "frida_instrumentation_failed",
                      "error_type": type(err).__name__,
                      "first_basic_utid_observed": False})
        return 2
    finally:
        # An interrupted spawn would otherwise leave the process suspended.
        if spawned_pid is not None and not resumed:
            try:
                device.resume(spawned_pid)
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()  # Do NOT kill HOME, clear data or log out.
            except Exception:
                pass


def restart_smoke(apk: Path, serial: str | None = None) -> int:
    check = preflight(apk, serial)
    if check["result"] != "native_arm64_original_apk_preflight_ok":
        print_report(check)
        return 2
    stop = adb(["shell", "am", "force-stop", PACKAGE], serial)
    launch = adb(["shell", "monkey", "-p", PACKAGE, "-c",
                  "android.intent.category.LAUNCHER", "1"], serial, timeout=45)
    success = bool(stop and stop.returncode == 0 and launch and
                   launch.returncode == 0 and "Events injected: 1" in (launch.stdout or ""))
    print_report({"result": "cold_launch_command_sent" if success else "cold_launch_failed",
                  "same_utid_verified": False,
                  "server_session_restored_verified": False,
                  "manual_check_needed": "Compare displayed HOME Trainer ID on actual device",
                  "app_data_cleared": False})
    return 0 if success else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["preflight", "observe", "restart-smoke"])
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--target", default="888888")
    parser.add_argument("--serial", help="ADB serial, when more than one device is present")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--script", type=Path,
                        default=Path(__file__).with_name("home41_utid_readonly_arm64.js"))
    args = parser.parse_args()
    if args.mode == "preflight":
        result = preflight(args.apk, args.serial)
        print_report(result)
        return 0 if result["result"] == "native_arm64_original_apk_preflight_ok" else 2
    if args.mode == "restart-smoke":
        return restart_smoke(args.apk, args.serial)
    return observe(args.apk, args.target, args.serial, args.script, args.timeout)


if __name__ == "__main__":
    sys.exit(main())
