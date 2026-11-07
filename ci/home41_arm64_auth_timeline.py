#!/usr/bin/env python3
"""Observe Pokémon HOME 4.1.0 native ARM64 auth/request/response time line.

Run on a computer connected to a personally controlled Android arm64-v8a
device with a compatible Frida server. This observes the ORIGINAL client.

No Nintendo Account linking, network modification, signup/delete API calls,
automatic consent, account creation, request replay or token/ID logging.
The optional --show-local-values prints only on an interactive local terminal.
CI can test this implementation but CANNOT claim live server-response proof.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
from pathlib import Path

# Reuse the strict installed APK SHA + native architecture guards.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import home41_arm64_readonly_runner as core

KIND = "home41_arm64_auth_timeline"
EXPECTED_VERSION = "4.1.0"
EVENT_NAMES = frozenset({
    "native_preflight_failed",
    "hook_attach_failed",
    "arm64_auth_observer_ready",
    "arm64_auth_observer_partial",
    "registration_request_serializer_entered",
    "registration_lng_cntry_packed_write_seen",
    "registration_request_formatter_entered",
    "registration_response_formatter_entered",
    "registration_packed_fields_invalid",
    "registration_packed_fields_unreadable",
    "registration_response_handler_entered",
    "token_request_serializer_entered",
    "token_response_handler_entered",
    "login_request_serializer_entered",
    "login_response_handler_entered",
    "common_response_handler_entered",
    "setbasic_unverified_caller",
    "basic_caller_unreadable",
    "basic_missing_numeric_utid",
    "basic_read_failed",
    "first_basic_utid_observed",
    "firstboot_birthdata_setdata_entered",
    "firstboot_birthdata_year_change_entered",
    "firstboot_birthdata_month_change_entered",
    "firstboot_birthdata_day_change_entered",
    "year_1999_local_setter_armed",
    "year_1999_local_setter_returned",
    "year_1999_local_setter_failed",
})
CATEGORICAL_REASON = frozenset({
    "not_native_arm64", "rva_outside_module", "module_watcher_failed"
})
OBSERVER_NAMES = frozenset({
    "register_serialize", "register_packed_write", "register_callback",
    "register_request_formatter", "register_response_formatter",
    "birthview_setdata", "birthview_year_change",
    "birthview_month_change", "birthview_day_change",
    "token_serialize", "token_callback", "login_serialize",
    "login_callback", "common_response", "set_basic"
})
TIMELINE_FIELDS = frozenset({
    "event", "elapsed_ms", "index", "observer", "reason",
    "from_common_basic_consumer", "candidate_matches_target",
    "source_endpoint_verified", "display_id_semantics_verified",
    "values_redacted", "fields_readable", "hook_failures",
    "actual_http_request_send_verified",
})
STATUS_VALUES = frozenset({
    "native_arm64_only", "runtime_not_tested",
    "native_arm64_preflight_failed", "frida_unavailable",
    "frida_spawn_or_attach_failed", "arm64_hooks_partial",
    "runtime_script_error", "no_auth_events_observed",
    "auth_events_without_basic", "basic_received_from_common_consumer",
    "observer_ready_waited_without_basic",
})


def sanitize_timeline_event(message: object) -> dict | None:
    """Strictly whitelist reported values, never native script error text."""
    if not isinstance(message, dict) or message.get("type") != "send":
        return None
    source = message.get("payload")
    if not isinstance(source, dict) or source.get("kind") != KIND:
        return None
    if source.get("version") != EXPECTED_VERSION or source.get("event") not in EVENT_NAMES:
        return None
    clean = {"event": source["event"]}
    ms = source.get("elapsed_ms")
    if type(ms) is int and 0 <= ms < 86400000:
        clean["elapsed_ms"] = ms
    index = source.get("index")
    if type(index) is int and 1 <= index <= 16:
        clean["index"] = index
    if source.get("observer") in OBSERVER_NAMES:
        clean["observer"] = source["observer"]
    if source.get("reason") in CATEGORICAL_REASON:
        clean["reason"] = source["reason"]
    for key in ("original_dropdown_index_verified", "birthday_submission_attempted",
                "original_setter_called", "year1999_controller_field_verified",
                "raw_birthdate_values_redacted", "field_offsets_static_only",
                "raw_year_value_redacted", "raw_month_value_redacted",
                "raw_day_value_redacted",
                "from_common_basic_consumer", "candidate_matches_target",
                "source_endpoint_verified", "display_id_semantics_verified",
                "values_redacted", "fields_readable",
                "actual_http_request_send_verified"):
        if type(source.get(key)) is bool:
            clean[key] = source[key]
    failures = source.get("hook_failures")
    if type(failures) is int and 0 <= failures <= 16:
        clean["hook_failures"] = failures
    # Explicitly DO NOT copy raw UTID, lng, cntry, UUID, cookie, URL, JSON etc.
    return clean


def analyze_events(events: list[dict], ready: bool, error: str | None) -> dict:
    """Produce a conservative sanitized timeline and causality warnings."""
    order = [x.get("event") for x in events]
    first_basic = next((x for x in events if x.get("event") ==
                        "first_basic_utid_observed"), None)
    register_request = "registration_request_serializer_entered" in order
    register_fields = "registration_lng_cntry_packed_write_seen" in order
    register_callback = "registration_response_handler_entered" in order
    register_formatter = "registration_request_formatter_entered" in order
    response_formatter = "registration_response_formatter_entered" in order
    token_callback = "token_response_handler_entered" in order
    login_callback = "login_response_handler_entered" in order
    login_request = "login_request_serializer_entered" in order

    status = ("runtime_script_error" if error == "runtime_script_error"
              else "native_arm64_preflight_failed" if any(
                  e in order for e in ("native_preflight_failed",))
              else "arm64_hooks_partial" if "arm64_auth_observer_partial" in order
              else "basic_received_from_common_consumer" if first_basic and
                   ready and first_basic.get("from_common_basic_consumer") is True
              else "observer_ready_waited_without_basic" if ready
              else "no_auth_events_observed" if not events
              else "auth_events_without_basic")
    times = {}
    for event in (
        "registration_request_serializer_entered",
        "registration_lng_cntry_packed_write_seen",
        "registration_request_formatter_entered",
        "registration_response_formatter_entered",
        "registration_response_handler_entered",
        "token_request_serializer_entered",
        "token_response_handler_entered",
        "login_request_serializer_entered",
        "login_response_handler_entered",
        "common_response_handler_entered",
        "first_basic_utid_observed",
    ):
        sample = next((x for x in events if x.get("event") == event and
                       "elapsed_ms" in x), None)
        times[event] = sample["elapsed_ms"] if sample else None
    delta = None
    if times["first_basic_utid_observed"] is not None and \
            times["registration_response_handler_entered"] is not None:
        delta = (times["first_basic_utid_observed"] -
                 times["registration_response_handler_entered"])
    return {
        "status": status,
        "real_android_capture_proven_by_this_report_alone": False,
        "source_apk_must_be_sha_verified": True,
        "events_observed": len(events),
        "first_event_ms": times,
        "first_basic_minus_registration_callback_ms": delta,
        "auth": {
            "registration_serializer_entered": register_request,
            "register_lng_cntry_packed_write_observed": register_fields,
            "registration_request_formatter_entered": register_formatter,
            "registration_response_formatter_entered": response_formatter,
            "register_response_handler_entered": register_callback,
            "token_response_handler_entered": token_callback,
            "login_serializer_entered": login_request,
            "login_response_handler_entered": login_callback,
            "first_basic_utid_observed": first_basic is not None,
            "first_basic_caller_verified": bool(first_basic and
                first_basic.get("from_common_basic_consumer") is True),
            "candidate_matches_target": (
                first_basic.get("candidate_matches_target")
                if first_basic else None),
        },
        # These are always false until additional independent evidence exists.
        "http_request_transmitted_verified": False,
        "http_response_source_endpoint_verified": False,
        "birthday_controller_hook_activity": {
            "setdata_entered": "firstboot_birthdata_setdata_entered" in order,
            "year_change_entered": "firstboot_birthdata_year_change_entered" in order,
            "month_change_entered": "firstboot_birthdata_month_change_entered" in order,
            "day_change_entered": "firstboot_birthdata_day_change_entered" in order,
        },
        "lng_cntry_enum_ui_mapping_verified": False,
        "six_digit_id_equals_starter_ot_verified": False,
        "nintendo_account_binding_attempted_by_runner": False,
        "account_registration_attempted_by_runner": False,
        "account_deletion_attempted_by_runner": False,
        "secrets_included": False,
        "timeline": events[:200],
    }


def local_values(values: object, *, interactive: bool) -> bool:
    """Print local RPC values only with explicit interactive consent."""
    if (not interactive or os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
            or not isinstance(values, dict)):
        return False
    if values.get("from_common_basic_caller") is not True and \
       values.get("request_packed_values_seen") is not True:
        return False
    if values.get("request_packed_values_seen") is True:
        lang, country = values.get("lng_candidate"), values.get("cntry_candidate")
        if (type(lang) is int and type(country) is int and
                0 <= lang <= 10000 and 0 <= country <= 10000):
            print("[LOCAL ONLY] register request DTO lng integer:", lang, flush=True)
            print("[LOCAL ONLY] register request DTO cntry integer:", country, flush=True)
            print("[UNVERIFIED] DTO enum numbers; HTTP transmission and country UI mapping not proven.")
    if values.get("first_basic_seen") is True and values.get("from_common_basic_caller") is True:
        raw = values.get("raw_utid")
        candidate = values.get("six_digit_candidate")
        if (isinstance(raw, str) and re.fullmatch(r"[0-9]{1,10}", raw)
                and int(raw) <= 0xffffffff
                and isinstance(candidate, str)
                and re.fullmatch(r"[0-9]{6}", candidate)
                and str(int(raw) % 1000000).zfill(6) == candidate):
            print("[LOCAL ONLY] server basic.utid:", raw, flush=True)
            print("[LOCAL ONLY] derived six-digit candidate:", candidate, flush=True)
            print("[UNVERIFIED] Candidate TID7 is not proven equal to starter Pokémon OT.")
    return True


def preflight_for_realm(apk: Path, serial: str | None, realm: str) -> dict:
    """A native ARM64 device or a known x86+ARM native-bridge guest.

    The emulated agent itself MUST still report ARM64 + all native hooks
    installed; allowing this preflight does not certify translated execution.
    """
    if realm == "native":
        return core.preflight(apk, serial)
    if realm != "emulated":
        return {"result": "invalid_frida_realm"}
    if not apk.is_file():
        return {"result": "apk_missing"}
    if core.digest(apk) != core.APK_SHA256:
        return {"result": "apk_hash_mismatch"}
    abi = core.android_prop("ro.product.cpu.abi", serial)
    bridge = core.android_prop("ro.dalvik.vm.native.bridge", serial)
    if abi not in ("x86_64", "x86") or not bridge or bridge in ("0", "false"):
        return {"result": "native_bridge_arm_emulation_not_configured"}
    installed = core.adb(["shell", "dumpsys", "package", core.PACKAGE], serial)
    from_text = installed.stdout if installed and installed.returncode == 0 else ""
    if "81" not in re.findall(r"\bversionCode=(\d+)\b", from_text or ""):
        return {"result": "wrong_or_missing_installed_home_version"}
    return {
        "result": "emulated_arm64_guest_preflight_ok",
        "primary_abi": abi,
        "native_bridge_present": True,
        "original_apk_hash_matched": True,
        "installed_home_version_code": "81",
        "guest_arm64_agent_and_hooks_verified": False,
    }


def run(apk: Path, script_path: Path, serial: str | None,
        timeout: int, output: Path | None, show_local_values: bool,
        realm: str = "native", remote_frida: bool = False) -> int:
    verified = preflight_for_realm(apk, serial, realm)
    good = ("native_arm64_original_apk_preflight_ok" if realm == "native"
            else "emulated_arm64_guest_preflight_ok")
    if verified.get("result") != good:
        print(json.dumps({"status": "native_arm64_preflight_failed",
                          "preflight_result": verified.get("result")}, sort_keys=True))
        return 2
    installed = core.installed_apk_integrity(serial)
    if installed != "installed_apk_hash_verified":
        print(json.dumps({"status": "native_arm64_preflight_failed",
                          "installed_apk_integrity": installed}, sort_keys=True))
        return 2
    if show_local_values and (not sys.stdout.isatty() or
                              os.environ.get("GITHUB_ACTIONS", "").lower() == "true"):
        print('{"status":"local_values_require_interactive_terminal"}')
        return 2

    script_source = script_path.read_text(encoding="utf-8")
    try:
        import frida
        device = (frida.get_device_manager().add_remote_device(
                    "127.0.0.1:27042") if remote_frida
                  else frida.get_device(serial, timeout=12) if serial
                  else frida.get_usb_device(timeout=12))
    except Exception as err:
        print(json.dumps({"status": "frida_unavailable",
                          "error_type": type(err).__name__}))
        return 2

    events: list[dict] = []
    got_first_basic = threading.Event()
    stop_early = threading.Event()
    ready = False
    script_error = None
    pid = None
    resumed = False
    session = None
    script = None

    def on_message(message, _data):
        nonlocal ready, script_error
        if isinstance(message, dict) and message.get("type") == "error":
            script_error = "runtime_script_error"
            stop_early.set()
            return
        item = sanitize_timeline_event(message)
        if item is None:
            return
        events.append(item)
        if item["event"] == "arm64_auth_observer_ready":
            ready = True
        elif item["event"] in ("arm64_auth_observer_partial", "native_preflight_failed"):
            stop_early.set()
        elif item["event"] == "first_basic_utid_observed":
            got_first_basic.set()
        if item["event"] in ("arm64_auth_observer_ready",
                             "registration_lng_cntry_packed_write_seen",
                             "first_basic_utid_observed"):
            print(json.dumps(item, ensure_ascii=False, sort_keys=True), flush=True)

    try:
        if realm == "emulated":
            # The translated realm exists only AFTER HOME's ARM64 native
            # libraries were brought up. Attach to the user's ALREADY RUNNING
            # original HOME before they advance the registration UI.
            p = core.adb(["shell", "pidof", core.PACKAGE], serial)
            candidates = re.findall(
                r"\b\d+\b", p.stdout or "") if p and p.returncode == 0 else []
            if not candidates:
                raise RuntimeError("HOME_not_running_for_emulated_realm")
            pid = int(candidates[0])
            resumed = True  # never resume or kill someone else's process
            session = device.attach(pid, realm="emulated")
        else:
            pid = device.spawn([core.PACKAGE])
            session = device.attach(pid)
        script = session.create_script(script_source)
        script.on("message", on_message)
        script.load()
        if realm == "native":
            device.resume(pid)
            resumed = True
        # Wait for either first validated basic, hook failure or timeout.
        # Do NOT wait for the whole deadline after first_basic was observed.
        deadline = time.monotonic() + min(max(1, timeout), 3600)
        while time.monotonic() < deadline:
            if got_first_basic.is_set() or stop_early.is_set():
                break
            stop_early.wait(min(0.25, max(0, deadline - time.monotonic())))
        # The first UTID may be received while waiting; it is never printed in
        # the public event stream. Explicit local RPC optionally displays it.
        if show_local_values and script is not None and ready:
            try:
                local_values(script.exports_sync.localvalues(),
                             interactive=sys.stdout.isatty())
            except Exception:
                pass
    except Exception as err:
        script_error = type(err).__name__
    finally:
        if pid is not None and not resumed:
            try:
                device.resume(pid)
            except Exception:
                pass
        if session:
            try:
                session.detach()
            except Exception:
                pass

    report = analyze_events(events, ready, script_error)
    report["execution_context"] = (
        "runtime_emulated_arm64_agent" if realm == "emulated"
        else "runtime_device_direct")
    report["host_android_primary_abi"] = verified.get("primary_abi", "arm64-v8a")
    report["frida_realm"] = realm
    # The ready event proves hook installation inside the guest realm,
    # not that a registration callback or a backend response was observed.
    report["arm64_agent_hooks_armed"] = ready and report["status"] not in {
        "arm64_hooks_partial", "runtime_script_error",
        "native_arm64_preflight_failed",
    }
    report["frida_exception_type"] = script_error if script_error in {
        "runtime_script_error", "TransportError", "ServerNotRunningError",
        "InvalidOperationError", "TimedOutError"} else (
        "other_failure" if script_error else None)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True)
                          + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return (0 if report["status"] == "basic_received_from_common_consumer"
            else 3)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--script", type=Path,
                        default=Path(__file__).with_name("home41_arm64_auth_timeline.js"))
    parser.add_argument("--serial")
    parser.add_argument("--realm", choices=("native", "emulated"), default="native",
                        help="Use emulated only for x86+ARM NativeBridge Frida realm")
    parser.add_argument("--remote-frida", action="store_true",
                        help="Connect to locally adb-forwarded 127.0.0.1:27042")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--output", type=Path,
                        help="Optional sanitized summary, never raw IDs or request contents")
    parser.add_argument("--show-local-values", action="store_true",
                        help="Explicit opt-in: display DTO integers and UTID on a local TTY only")
    args = parser.parse_args()
    return run(args.apk, args.script, args.serial, args.timeout,
               args.output, args.show_local_values,
               realm=args.realm, remote_frida=args.remote_frida)


if __name__ == "__main__":
    raise SystemExit(main())
