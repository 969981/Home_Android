#!/usr/bin/env python3
"""Two-phase acceptance of HOME 4.1.0's original ARM64 client.

Only operates on an authorized local, native ARM64 Android device.
No Nintendo Account binding, registration, deletion, API replay, data reset,
network interception, token capture or account-ID logging.

Evidence gates:
1. First real UDManager.SetBasic read + comparison against user-visible UI ID.
2. Frida detach + original client remains alive and manually usable.
3. Force-stop, new Frida spawn, read again + same original UI ID comparison,
   detach, and user confirmation that the same ID is displayed.

The UI ID is typed locally using getpass and held in process memory only.
A green CI run of mocks is never real-device evidence.
"""
from __future__ import annotations

import argparse
import getpass
import json
import re
import sys
import threading
from pathlib import Path

# Imported from the same folder even when invoked from a different directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import home41_arm64_readonly_runner as core


def report(event: str, **fields) -> None:
    """Fixed-shape public-safe reports: never pass an ID or a Frida error body."""
    allowed = {
        "phase", "result", "read_only_observer_ready", "first_basic_seen",
        "source_common_response_consumer", "ui_id_matches", "process_alive",
        "normal_client_usable", "same_displayed_id_after_restart",
        "cold_start_performed", "failure_type",
    }
    item = {"event": event}
    item.update({k: v for k, v in fields.items() if k in allowed
                 and isinstance(v, (bool, int, str, type(None)))})
    print(json.dumps(item, ensure_ascii=False, sort_keys=True), flush=True)


def process_alive(serial: str | None) -> bool:
    r = core.adb(["shell", "pidof", core.PACKAGE], serial, timeout=12)
    return bool(r and r.returncode == 0 and (r.stdout or "").strip())


def confirm(prompt_text: str, input_func=input) -> bool:
    # Require a deliberate yes, never default to assuming success.
    try:
        return input_func(prompt_text).strip().casefold() == "yes"
    except (EOFError, KeyboardInterrupt):
        return False


def visible_id(hidden_input=getpass.getpass) -> str | None:
    try:
        raw = hidden_input("Enter the six digits shown in HOME (input hidden): ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if not re.fullmatch(r"[0-9]{6}", raw):
        return None
    return raw


def capture_once(device, prepared_script: str, first_ui_id: str | None,
                 timeout: int, phase: int, hidden_input=getpass.getpass) -> tuple[dict, str | None]:
    got = threading.Event()
    detached_unexpectedly = threading.Event()
    state = {
        "phase": phase, "read_only_observer_ready": False,
        "first_basic_seen": False, "source_common_response_consumer": False,
        "ui_id_matches": False, "process_alive": False,
        "result": "not_started"
    }
    session = None
    pid = None
    resumed = False

    def on_message(message, _data):
        clean = core.redacted_event(message)
        if not clean:
            if isinstance(message, dict) and message.get("type") == "error":
                state["result"] = "frida_script_error"
                got.set()
            return
        event = clean.get("event")
        if event == "read_only_observer_ready":
            state["read_only_observer_ready"] = True
        elif event == "first_basic_utid_observed":
            state["first_basic_seen"] = True
            state["source_common_response_consumer"] = bool(
                clean.get("source_common_response_consumer"))
            got.set()
        elif event in {"hook_preflight_failed"}:
            state["result"] = "hook_preflight_failed"
            got.set()
        elif event == "guest_arch_preflight" and clean.get("native_arm64") is False:
            state["result"] = "not_arm64"
            got.set()

    try:
        pid = device.spawn([core.PACKAGE])
        session = device.attach(pid)
        session.on("detached", lambda *_: detached_unexpectedly.set())
        script = session.create_script(prepared_script)
        script.on("message", on_message)
        script.load()
        device.resume(pid)
        resumed = True

        if not got.wait(max(1, min(timeout, 3600))):
            state["result"] = (
                "detached_before_first_basic" if detached_unexpectedly.is_set()
                else "timeout_no_basic" if state["read_only_observer_ready"]
                else "timeout_hook_not_ready")
            return state, first_ui_id
        if not state["first_basic_seen"]:
            if state["result"] == "not_started":
                state["result"] = "no_valid_first_basic"
            return state, first_ui_id

        if first_ui_id is None:
            report("manual_ui_comparison_required", phase=phase,
                   first_basic_seen=True)
            first_ui_id = visible_id(hidden_input)
        if first_ui_id is None:
            state["result"] = "invalid_or_missing_displayed_id"
            return state, None

        # Frida's RPC retains the observed candidate *inside HOME's memory*.
        # It returns only booleans, never the observed number.
        compare = script.exports_sync.comparevisibleid(first_ui_id)
        if (not isinstance(compare, dict)
                or not compare.get("first_basic_seen")
                or not compare.get("valid_six_digit_input")):
            state["result"] = "frida_rpc_compare_unavailable"
            return state, first_ui_id

        state["ui_id_matches"] = compare.get("displayed_id_matches") is True
        if not state["ui_id_matches"]:
            state["result"] = "runtime_utid_display_id_mismatch"
            return state, first_ui_id
        state["result"] = "first_basic_matches_displayed_id"
        return state, first_ui_id
    except Exception as err:
        state["result"] = "capture_exception"
        state["failure_type"] = type(err).__name__
        return state, first_ui_id
    finally:
        if pid is not None and not resumed:
            try:
                device.resume(pid)
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()  # Never kill HOME or discard its data.
            except Exception:
                pass
        state["process_alive"] = process_alive(None if not hasattr(device, "_home_serial") else device._home_serial)
        report("phase_complete", **state)


def run_acceptance(apk: Path, script_path: Path, serial: str | None,
                   timeout: int, target: str,
                   hidden_input=getpass.getpass, input_func=input) -> int:
    guard = core.preflight(apk, serial)
    if guard["result"] != "native_arm64_original_apk_preflight_ok":
        report("preflight_failed", result=guard["result"])
        return 2
    installed = core.installed_apk_integrity(serial)
    if installed != "installed_apk_hash_verified":
        report("preflight_failed", result=installed)
        return 2
    try:
        source = core.prepare_script(script_path, target)
        import frida
        device = (frida.get_device(serial, timeout=12) if serial
                  else frida.get_usb_device(timeout=12))
    except Exception as exc:
        report("preflight_failed", result="frida_unavailable",
               failure_type=type(exc).__name__)
        return 2

    # First phase: initial, authorized normal HOME initialization.
    first, original_display_id = capture_once(
        device, source, None, timeout, 1, hidden_input=hidden_input)
    first["process_alive"] = process_alive(serial)
    if first["result"] != "first_basic_matches_displayed_id" or not first["process_alive"]:
        report("acceptance_failed", phase=1, result=first["result"],
               process_alive=first["process_alive"])
        return 3

    normal_client_usable = confirm(
        "Frida detached. Can you navigate the original HOME app normally? Type yes: ",
        input_func)
    report("client_handoff", phase=1, normal_client_usable=normal_client_usable)
    if not normal_client_usable:
        report("acceptance_failed", phase=1, result="original_client_handoff_unverified")
        return 3

    # Cold restart is destructive only to the *running process*, NOT to HOME
    # account or app data. Require explicit yes at the local device console.
    if not confirm("Force-stop HOME and verify a cold restart? Type yes: ", input_func):
        report("acceptance_incomplete", result="cold_restart_not_approved")
        return 3
    stop = core.adb(["shell", "am", "force-stop", core.PACKAGE], serial, timeout=25)
    if not stop or stop.returncode != 0:
        report("acceptance_failed", phase=2, result="cold_force_stop_failed")
        return 3

    # Native callback must fire again in the restarted original app; compare
    # to the same *locally held* first UI number without logging either one.
    second, _ = capture_once(device, source, original_display_id, timeout, 2,
                             hidden_input=hidden_input)
    second["process_alive"] = process_alive(serial)
    if second["result"] != "first_basic_matches_displayed_id" or not second["process_alive"]:
        report("acceptance_failed", phase=2, result=second["result"],
               process_alive=second["process_alive"], cold_start_performed=True)
        return 3
    same_in_ui = confirm(
        "After cold start, does HOME display the SAME six-digit ID and work normally? Type yes: ",
        input_func)
    report("cold_restart_ui_check", phase=2,
           same_displayed_id_after_restart=same_in_ui)
    if not same_in_ui:
        report("acceptance_failed", phase=2, result="cold_ui_unverified")
        return 3
    report("acceptance_complete", result="REAL_DEVICE_THREE_GATES_PASSED",
           first_basic_seen=True, source_common_response_consumer=bool(
               first.get("source_common_response_consumer") and second.get(
                   "source_common_response_consumer")),
           ui_id_matches=True, process_alive=True,
           normal_client_usable=True, same_displayed_id_after_restart=True,
           cold_start_performed=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--script", type=Path,
                        default=Path(__file__).with_name("home41_utid_readonly_arm64.js"))
    parser.add_argument("--target", default="888888")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--serial")
    args = parser.parse_args()
    return run_acceptance(args.apk, args.script, args.serial, args.timeout,
                          args.target)


if __name__ == "__main__":
    sys.exit(main())
