#!/usr/bin/env python3
"""HOME 4.1.0 disposable Android emulator diagnostic; no account activity.

This is NOT an ID generator or a validated ARM64 Frida runtime test.
Never submit Terms, birth date, account registration, credentials or deletion.
Do not upload full logcat, tokens, network traffic or app private data.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import subprocess
import time
import urllib.request
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

EXPECTED_APK = "8dee598028cd70441f645c8fff96b093b76778d625cdf07c60109eced50ffac1"
EXPECTED_IL2CPP = "80bfbc3d480bf3c91297d65a441a37e40260b70fd8b0ddc8da70c34f0870b6fe"
PACKAGE = "jp.pokemon.pokemonhome"
PNG_MAGIC = bytes.fromhex("89504e470d0a1a0a")


def command(args: list[str], timeout: int = 45, binary: bool = False):
    try:
        return subprocess.run(args, capture_output=True, check=False, timeout=timeout,
                              text=not binary, errors=None if binary else "replace")
    except (subprocess.TimeoutExpired, OSError):
        return None


def adb(*args: str, timeout: int = 45, binary: bool = False):
    return command(["adb", *args], timeout=timeout, binary=binary)


def getprop(key: str) -> str:
    res = adb("shell", "getprop", key)
    return (res.stdout or "").strip()[:96] if res and res.returncode == 0 else ""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def inspect_native(apk: Path) -> dict:
    """Validate exact ARM64 library inside the actual original APK."""
    with zipfile.ZipFile(apk) as z:
        names = z.namelist()
        target = "lib/arm64-v8a/libil2cpp.so"
        if target not in names:
            return {"arm64_libil2cpp_present": False, "arm64_libil2cpp_hash_matched": False}
        h = hashlib.sha256()
        with z.open(target) as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                h.update(block)
        digest = h.hexdigest()
    return {"arm64_libil2cpp_present": True,
            "arm64_libil2cpp_sha256": digest,
            "arm64_libil2cpp_hash_matched": digest == EXPECTED_IL2CPP,
            "static_setbasic_rva": "0x1D763D0",
            "static_registration_callback_rva": "0x1D33294",
            "rva_status": "prior_static_research_not_runtime_reverified"}


def network_probe() -> dict:
    """Reachability indicators only; neither proves HOME backend availability."""
    result = {"scope": "generic_host_and_android_network_only"}
    try:
        request = urllib.request.Request("https://www.google.com/generate_204",
                                         headers={"User-Agent": "HOME41-Disposable-CI/1.0"})
        with urllib.request.urlopen(request, timeout=10) as resp:
            result["host_https_status"] = int(resp.status)
    except Exception as e:
        result["host_https_status"] = None
        result["host_error_type"] = type(e).__name__
    android = adb("shell", "ping", "-c", "1", "-W", "3", "8.8.8.8", timeout=12)
    result["android_icmp_success"] = bool(android and android.returncode == 0)
    result["android_icmp_is_conclusive"] = False  # ICMP may be filtered.
    return result


def screenshot(out: Path, name: str) -> bytes:
    res = adb("exec-out", "screencap", "-p", timeout=30, binary=True)
    if res and res.returncode == 0 and res.stdout.startswith(PNG_MAGIC):
        png = res.stdout
        (out / name).write_bytes(png)
        return png
    return b""


def match_known_ui(data: bytes, stage: str):
    """Only known harmless first-run navigation; unknown/error screens fail closed."""
    if not data.startswith(PNG_MAGIC):
        return None
    try:
        from PIL import Image
        with Image.open(io.BytesIO(data)) as raw:
            im = raw.convert("RGB")
    except (ImportError, OSError, ValueError):
        return None
    w, h = im.size
    if w < 600 or h < 1200 or not 1.9 < h / w < 2.5:
        return None

    def at(x, y):
        return im.getpixel((int(w * x), int(h * y)))

    def near(point, expected, tolerance=16):
        return all(abs(a - b) <= tolerance for a, b in zip(point, expected))

    if stage == "language":
        if (near(at(.5, .02), (202, 244, 161)) and
                near(at(.5, .14), (38, 179, 151)) and
                near(at(.3, .24), (240, 246, 236)) and
                near(at(.3, .775), (240, 246, 236)) and
                near(at(.3, .83), (240, 246, 236))):
            return (int(w * .5), int(h * .775))
    elif stage == "language_confirmation":
        if (near(at(.5, .03), (124, 149, 100)) and
                near(at(.5, .14), (23, 107, 91)) and
                near(at(.5, .35), (247, 251, 247)) and
                near(at(.12, .53), (247, 251, 247)) and
                near(at(.68, .64), (255, 173, 4)) and
                near(at(.5, .8), (144, 148, 142))):
            return (int(w * .68), int(h * .64))
    elif stage == "region_dropdown":
        if (near(at(.5, .02), (210, 252, 169), 12) and
                near(at(.5, .15), (38, 179, 151), 12) and
                near(at(.5, .8), (158, 243, 215), 12) and
                all(near(at(.3, y), (248, 250, 245), 12)
                    for y in (.24, .30, .36, .42, .48, .54, .60))):
            return (int(w * .82), int(h * .48))
    return None



def immersive_hint_position(data: bytes):
    """Use only the observed Android OS full-screen overlay color signature."""
    if not data.startswith(PNG_MAGIC):
        return None
    try:
        from PIL import Image
        with Image.open(io.BytesIO(data)) as src:
            im = src.convert("RGB")
    except (ImportError, OSError, ValueError):
        return None
    w, h = im.size
    if w < 600 or h < 1200 or not 1.9 < h / w < 2.5:
        return None

    def pixel(x, y):
        return im.getpixel((int(w * x), int(h * y)))

    def near(a, b, t=16):
        return all(abs(x - y) <= t for x, y in zip(a, b))

    if (near(pixel(.5, .055), (238, 237, 244)) and
            near(pixel(.75, .24), (238, 237, 244)) and
            near(pixel(.85, .28), (71, 93, 146)) and
            near(pixel(.5, .39), (51, 51, 51))):
        return int(w * .85), int(h * .28)
    return None


def launcher_anr_close_position(xml_text: str):
    """Require explicit *Pixel Launcher* OS error and system-owned Close app."""
    if "Pixel Launcher isn't responding" not in xml_text:
        return None
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    for node in root.iter("node"):
        a = node.attrib
        if (a.get("text", "").strip() != "Close app"
                or a.get("package", "") not in {"android", "com.android.systemui"}):
            continue
        m = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]",
                         a.get("bounds", ""))
        if m:
            x1, y1, x2, y2 = map(int, m.groups())
            if x2 > x1 and y2 > y1:
                return (x1 + x2) // 2, (y1 + y2) // 2
    return None


def dismiss_known_os_overlays() -> list[dict]:
    """Only Android overlay + known Pixel Launcher ANR, never HOME buttons."""
    events = []
    for _ in range(4):
        cap = adb("exec-out", "screencap", "-p", timeout=25, binary=True)
        png = cap.stdout if cap and cap.returncode == 0 else b""
        pos = immersive_hint_position(png)
        event = "dismiss_android_fullscreen_hint"
        if pos is None:
            event = "close_android_pixel_launcher_anr"
            dump = adb("shell", "uiautomator", "dump",
                       "/sdcard/window.xml", timeout=25)
            read = adb("shell", "cat", "/sdcard/window.xml", timeout=12) if (
                dump and dump.returncode == 0) else None
            pos = launcher_anr_close_position(
                (read.stdout or "") if read and read.returncode == 0 else "")
        if pos is None:
            break
        clicked = adb("shell", "input", "tap", str(pos[0]), str(pos[1]), timeout=15)
        success = bool(clicked and clicked.returncode == 0)
        events.append({"action": event, "success": success})
        if not success:
            break
        time.sleep(3)
    return events

def click_if_known(png: bytes, stage: str) -> bool:
    target = match_known_ui(png, stage)
    if target is None:
        return False
    r = adb("shell", "input", "tap", str(target[0]), str(target[1]), timeout=15)
    return bool(r and r.returncode == 0)


def process_alive() -> bool:
    r = adb("shell", "pidof", PACKAGE, timeout=15)
    return bool(r and r.returncode == 0 and (r.stdout or "").strip())


def redacted_system_diagnostics() -> dict:
    """Only aggregate crash counters; deliberately NEVER store full logcat."""
    log = adb("logcat", "-d", "-t", "7000", timeout=25)
    content = (log.stdout or "") if log and log.returncode == 0 else ""
    # Report counts rather than sensitive lines; 100101 match alone is not
    # conclusive evidence of the same HOME on-screen error.
    terms = ["FATAL EXCEPTION", "Fatal signal", "am_crash",
             "ANR in", "UnsatisfiedLinkError", "100101"]
    return {"logcat_available": bool(log and log.returncode == 0),
            "signal_counts": {term: content.lower().count(term.lower()) for term in terms},
            "raw_log_saved": False}


def run(apk: Path, out: Path, settle: int = 25) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    report = {
        "version": "4.1.0", "device": "disposable_github_actions_avd",
        "apk_sha256": sha256_file(apk),
        "registration_status": "not_attempted",
        "terms_accepted": False,
        "country_selected": False,
        "birthday_entered": False,
        "account_delete_attempted": False,
        "first_basic_utid_status": "not_observed",
        "trainer_id_semantic_match": "not_tested",
        "arm64_frida_runtime_status": "not_attempted",
        "credential_or_logcat_dump_saved": False,
        "result": "not_started"
    }
    try:
        if report["apk_sha256"] != EXPECTED_APK:
            report["result"] = "blocked_apk_hash_mismatch"
            return report
        report["native_preflight"] = inspect_native(apk)
        report["android_abis"] = getprop("ro.product.cpu.abilist")
        report["android_native_bridge"] = getprop("ro.dalvik.vm.native.bridge")
        report["android_api"] = getprop("ro.build.version.sdk")
        report["network"] = network_probe()
        report["arm64_frida_runtime_status"] = (
            "unverified_x86_64_native_bridge" if "x86_64" in report["android_abis"]
            else "unverified_requires_arm64_device")
        installed = adb("install", "-r", str(apk), timeout=180)
        report["install_success"] = bool(installed and installed.returncode == 0)
        if not report["install_success"]:
            report["result"] = "blocked_install"
            return report
        # Grant CAMERA only on this camera-less, throwaway AVD; not HOME consent.
        grant = adb("shell", "pm", "grant", PACKAGE, "android.permission.CAMERA")
        report["camera_permission_grant"] = bool(grant and grant.returncode == 0)
        # Prevent the standard OS immersive prompt from hiding HOME.
        immersive = adb("shell", "settings", "put", "secure",
                        "immersive_mode_confirmations", "confirmed", timeout=15)
        report["android_immersive_setting_written"] = bool(
            immersive and immersive.returncode == 0)
        adb("logcat", "-c", timeout=15)
        launched = adb("shell", "monkey", "-p", PACKAGE,
                       "-c", "android.intent.category.LAUNCHER", "1", timeout=50)
        report["launch_event_sent"] = bool(launched and launched.returncode == 0
                                          and "Events injected: 1" in (launched.stdout or ""))
        time.sleep(18)
        report["os_overlay_actions"] = dismiss_known_os_overlays()
        initial = screenshot(out, "01_initial.png")
        report["process_after_18_seconds"] = process_alive()
        report["language_clicked"] = click_if_known(initial, "language")
        if report["language_clicked"]:
            time.sleep(8)
            confirm = screenshot(out, "02_after_language.png")
            report["language_confirmation_clicked"] = click_if_known(
                confirm, "language_confirmation")
        else:
            report["language_confirmation_clicked"] = False
        if report["language_confirmation_clicked"]:
            time.sleep(18)
            region = screenshot(out, "03_after_confirmation.png")
            report["region_dropdown_expanded"] = click_if_known(
                region, "region_dropdown")
        else:
            report["region_dropdown_expanded"] = False
        time.sleep(settle)
        report["final_screenshot_saved"] = bool(
            screenshot(out, "04_final.png"))
        report["process_at_end"] = process_alive()
        report["diagnostics"] = redacted_system_diagnostics()
        report["ui_navigation_status"] = (
            "region_dropdown_reached" if report["region_dropdown_expanded"] else
            "language_confirmed" if report["language_confirmation_clicked"] else
            "language_selected" if report["language_clicked"] else
            "unknown_or_blocked")
        report["result"] = (
            "app_process_not_running" if not report["process_at_end"] else
            "app_running_ui_not_verified" if not report["language_clicked"] else
            "app_running_partial_onboarding_no_registration")
        report["interpretation"] = (
            "Screenshots must be visually reviewed. Neither CI success nor "
            "network reachability establishes HOME login or a real server UTID.")
    except Exception as e:
        report["result"] = "diagnostic_exception"
        report["error_type"] = type(e).__name__
        # Do not publish exception content that may expose paths or credentials.
    finally:
        (out / "home41_emulator_report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        print(json.dumps({
            "result": report["result"],
            "process_at_end": report.get("process_at_end"),
            "first_basic_utid_status": report["first_basic_utid_status"],
            "registration_status": report["registration_status"],
            "arm64_frida_runtime_status": report["arm64_frida_runtime_status"],
        }, ensure_ascii=False))
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--settle-seconds", type=int, default=25)
    args = parser.parse_args()
    r = run(args.apk, args.output, max(0, min(args.settle_seconds, 120)))
    if r["result"] in {"blocked_apk_hash_mismatch", "blocked_install",
                       "diagnostic_exception", "app_process_not_running",
                       "app_running_ui_not_verified"}:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
