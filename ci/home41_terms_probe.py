#!/usr/bin/env python3
"""Guarded original Pokémon HOME 4.1.0 local consent-page probe.

Does not create accounts, replay APIs or read tokens. Read-only by default.
A consent click requires --tap-confirmed-consent and a uniquely identified,
enabled original button on a HOME foreground accessibility hierarchy.
Unknown Unity-drawn or non-accessible screens fail closed.
"""
from __future__ import annotations

import argparse
import io
import json
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

HOME_PACKAGE = "jp.pokemon.pokemonhome"
PNG_MAGIC = bytes.fromhex("89504e470d0a1a0a")
TERMS = ("服务条款", "用户协议", "使用条款", "terms of use",
         "terms and conditions", "利用規約")
PRIVACY = ("隐私", "privacy notice", "privacy policy", "プライバシー")
NEXT = ("下一步", "继续", "next", "continuar", "suite", "próximo", "次へ")
AGREE = ("我同意", "同意", "i agree", "agree", "同意する", "同意します")
REMOTE_XML = "/sdcard/home41_terms_probe_temporary.xml"


def adb(serial: str | None, *args: str, binary: bool = False,
        timeout: int = 30) -> bytes | str:
    command = ["adb"] + (["-s", serial] if serial else []) + list(args)
    completed = subprocess.run(command, capture_output=True, check=False, timeout=timeout)
    if completed.returncode != 0:
        raise RuntimeError("adb_step_failed")
    return (completed.stdout if binary else
            completed.stdout.decode("utf-8", errors="replace"))


def home_is_foreground(text: str) -> bool:
    return any(HOME_PACKAGE in line and (
        "mCurrentFocus" in line or "mFocusedApp" in line
    ) for line in text.splitlines())


def normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().lower()


def center_of_bounds(bounds: str) -> tuple[int, int] | None:
    match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds)
    if match is None:
        return None
    x0, y0, x1, y1 = map(int, match.groups())
    if not (0 <= x0 < x1 <= 4096 and 0 <= y0 < y1 <= 8192):
        return None
    return ((x0 + x1) // 2, (y0 + y1) // 2)


def classify_accessibility(xml: str, stage: str) -> dict:
    """Allowlisted consent markers only; never return raw XML or page text."""
    result = {
        "stage": stage, "terms_marker": False, "privacy_marker": False,
        "button_candidates": 0, "eligible": False, "tap": None,
        "reason": "unknown_or_inaccessible_screen",
    }
    if stage not in ("terms_next", "final_agree"):
        result["reason"] = "unrecognized_stage"
        return result
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        result["reason"] = "invalid_accessibility_xml"
        return result
    if root.tag != "hierarchy":
        result["reason"] = "not_android_ui_hierarchy"
        return result
    nodes = list(root.iter("node"))
    if not nodes or len(nodes) > 5000:
        return result
    packages = {n.attrib.get("package") for n in nodes
                if n.attrib.get("package")}
    if packages and HOME_PACKAGE not in packages:
        result["reason"] = "other_app_overlay_or_package"
        return result
    # A notification, Android overlay or accessibility service may add nodes
    # even while HOME remains the focused Activity. Only HOME-owned nodes
    # can establish the consent page identity or supply a tappable action.
    labels = [
        normalize(n.attrib.get("text", "") + " " +
                  n.attrib.get("content-desc", ""))
        if n.attrib.get("package", HOME_PACKAGE) == HOME_PACKAGE else ""
        for n in nodes
    ]
    result["terms_marker"] = any(any(t in label for t in TERMS)
                                 for label in labels)
    result["privacy_marker"] = any(any(t in label for t in PRIVACY)
                                   for label in labels)
    if not (result["terms_marker"] and result["privacy_marker"]):
        result["reason"] = "terms_or_privacy_marker_missing"
        return result
    targets = NEXT if stage == "terms_next" else AGREE
    points = []
    for node, label in zip(nodes, labels):
        if (node.attrib.get("package", HOME_PACKAGE) != HOME_PACKAGE
                or label not in targets or node.attrib.get("clickable") != "true"
                or node.attrib.get("enabled", "true") != "true"
                or node.attrib.get("visible-to-user", "true") != "true"):
            continue
        point = center_of_bounds(node.attrib.get("bounds", ""))
        if point is not None:
            points.append(point)
    result["button_candidates"] = len(points)
    if len(points) != 1:
        result["reason"] = "missing_or_ambiguous_original_button"
        return result
    result["eligible"] = True
    result["tap"] = points[0]
    result["reason"] = "unique_original_accessibility_button"
    return result


def dump_accessibility(serial: str | None) -> str:
    # UIAutomator writes on-device XML. Remove in finally even when it fails.
    try:
        adb(serial, "shell", "uiautomator", "dump", REMOTE_XML, timeout=55)
        return str(adb(serial, "shell", "cat", REMOTE_XML))
    finally:
        try:
            adb(serial, "shell", "rm", "-f", REMOTE_XML)
        except (RuntimeError, subprocess.TimeoutExpired, OSError):
            pass


def save_masked_consent_screen(path: Path, data: bytes) -> bool:
    if not data.startswith(PNG_MAGIC):
        return False
    try:
        from PIL import Image, ImageDraw
        with Image.open(io.BytesIO(data)) as original:
            frame = original.convert("RGB")
        if not (600 <= frame.width <= 2200 and 1100 <= frame.height <= 4000):
            return False
        w, h = frame.size
        pen = ImageDraw.Draw(frame)
        pen.rectangle((0, 0, w, int(h * .055)), fill=(0, 0, 0))
        pen.rectangle((0, int(h * .97), w, h), fill=(0, 0, 0))
        path.parent.mkdir(parents=True, exist_ok=True)
        frame.save(path, format="PNG", optimize=True)
        return True
    except (OSError, ImportError, ValueError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", help="Your private, persistent ADB emulator")
    parser.add_argument("--stage", choices=("terms_next", "final_agree"),
                        default="terms_next")
    parser.add_argument("--output", type=Path,
                        default=Path("home41-consent-pre-registration.png"))
    parser.add_argument("--tap-confirmed-consent", action="store_true",
                        help="Opt in to ONE uniquely identified consent action")
    args = parser.parse_args()

    status = {"status": "not_started", "tap_performed": False,
              "raw_accessibility_xml_saved": False,
              "credential_data_saved": False,
              "masked_screenshot_saved": False}
    try:
        if not home_is_foreground(str(adb(args.serial, "shell", "dumpsys", "window"))):
            status["status"] = "home_not_foreground_or_unverified"
            print(json.dumps(status))
            return 2
        classified = classify_accessibility(dump_accessibility(args.serial), args.stage)
        status.update({k: v for k, v in classified.items() if k != "tap"})
        status["status"] = classified["reason"]
        if not classified["eligible"]:
            print(json.dumps(status, ensure_ascii=False))
            return 3
        # A screenshot may be saved ONLY once verified to be the consent page.
        frame = adb(args.serial, "exec-out", "screencap", "-p", binary=True)
        status["masked_screenshot_saved"] = save_masked_consent_screen(
            args.output, frame)
        if args.tap_confirmed_consent:
            # Recheck full page + exact button before each real tap: an
            # Android overlay or auto-navigation could change the page.
            if not home_is_foreground(str(adb(args.serial, "shell", "dumpsys", "window"))):
                status["status"] = "home_focus_lost_no_tap"
                print(json.dumps(status, ensure_ascii=False))
                return 2
            current = classify_accessibility(
                dump_accessibility(args.serial), args.stage)
            if not current["eligible"] or current["tap"] != classified["tap"]:
                status["status"] = "consent_page_changed_no_tap"
                print(json.dumps(status, ensure_ascii=False))
                return 3
            x, y = current["tap"]
            adb(args.serial, "shell", "input", "tap", str(x), str(y))
            status["tap_performed"] = True
            status["status"] = "one_verified_consent_button_tapped"
        print(json.dumps(status, ensure_ascii=False))
        return 0
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as exc:
        status["status"] = "local_probe_unavailable"
        status["error_type"] = type(exc).__name__
        print(json.dumps(status, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
