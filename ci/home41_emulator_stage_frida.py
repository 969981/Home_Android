#!/usr/bin/env python3
"""Run original HOME 4.1.0 on a disposable Android x86_64 emulator.

Set up an x86_64 Frida server, observe native socket/DNS *counts*, and
correlate them with verified language/region UI stages. No HTTP payloads,
server response bodies, credentials, UTID, accounts or user registration.

This does NOT attach 4.1.0 ARM64 IL2CPP offsets in a native-bridge emulator.
"""
from __future__ import annotations
import argparse
import json
import time
from pathlib import Path
from typing import Any
import home41_emulator_diagnostics as diag

STAGES = ("launch", "language_selected", "language_confirmed",
          "region_expanded", "country_selected")
COUNTERS = ("connect", "resolver", "ipv4_connect", "ipv6_connect",
            "other_socket_connect")


def report_only_safe_counts(raw: Any) -> dict:
    """Never pass arbitrary Frida payload keys into public artifacts."""
    if not isinstance(raw, dict):
        return {"status": "invalid_snapshot"}
    src = raw.get("counts")
    clean = {}
    if isinstance(src, dict):
        for stage in STAGES:
            datum = src.get(stage, {})
            if not isinstance(datum, dict):
                datum = {}
            clean[stage] = {
                field: (datum[field] if (type(datum.get(field)) is int
                                         and 0 <= datum[field] <= 10000)
                        else None)
                for field in COUNTERS
            }
    return {
        "status": "snapshot_received",
        "guest_process_arch": raw.get("process_arch")
          if raw.get("process_arch") in ("x64", "ia32", "arm", "arm64") else "unknown",
        "current_stage": raw.get("stage") if raw.get("stage") in STAGES else "unknown",
        "connect_hook": raw.get("connect_hook_status")
          if raw.get("connect_hook_status") in ("attached", "symbol_not_found", "hook_failed")
          else "unknown",
        "resolver_hook": raw.get("resolver_hook_status")
          if raw.get("resolver_hook_status") in ("attached", "symbol_not_found", "hook_failed")
          else "unknown",
        "callback_cap_reached": raw.get("callbacks_capped") is True,
        "counts": clean,
        "payload_or_response_body_captured": False,
        "utid_captured": False,
    }


class StageMonitor:
    def __init__(self, server: Path, script: Path):
        self.server = server
        self.script_path = script
        self.device = None
        self.session = None
        self.agent = None
        self.setup = "not_started"
        self.current_stage = "launch"
        self.stages_marked = []
        self.agent_status = "no_agent_message"
        self.error_type = None

    def _setup_server(self) -> bool:
        if not self.server.is_file() or not self.script_path.is_file():
            self.setup = "frida_server_or_script_missing"
            return False
        root = diag.adb("root", timeout=40)
        if not root or root.returncode != 0:
            self.setup = "adb_root_unavailable"
            return False
        diag.adb("wait-for-device", timeout=40)
        probe = diag.adb("shell", "getprop", "ro.product.cpu.abi")
        if not probe or probe.returncode != 0 or probe.stdout.strip() != "x86_64":
            self.setup = "not_x86_64_guest"
            return False
        pushed = diag.adb("push", str(self.server), "/data/local/tmp/home41_frida_server", timeout=75)
        if not pushed or pushed.returncode != 0:
            self.setup = "server_push_failed"
            return False
        chmod = diag.adb("shell", "chmod", "700",
                         "/data/local/tmp/home41_frida_server", timeout=15)
        if not chmod or chmod.returncode != 0:
            self.setup = "server_chmod_failed"
            return False
        # Server is started in the guest only; adb-forward keeps RPC on the
        # CI host loopback. Never expose it to the public Internet.
        launched = diag.adb("shell", "/data/local/tmp/home41_frida_server",
                            "-D", timeout=18)
        if not launched or launched.returncode != 0:
            self.setup = "server_launch_failed"
            return False
        forwarded = diag.adb("forward", "tcp:27042", "tcp:27042", timeout=15)
        if not forwarded or forwarded.returncode != 0:
            self.setup = "adb_forward_failed"
            return False
        self.setup = "x86_64_frida_server_started"
        return True

    def start(self) -> dict:
        if not self._setup_server():
            return {"status": self.setup}
        try:
            import frida
            manager = frida.get_device_manager()
            self.device = manager.add_remote_device("127.0.0.1:27042")
            pid = None
            for _ in range(16):
                p = diag.adb("shell", "pidof", diag.PACKAGE, timeout=10)
                if p and p.returncode == 0 and (p.stdout or "").strip().split():
                    pid = int(p.stdout.strip().split()[0])
                    break
                time.sleep(1)
            if pid is None:
                self.setup = "home_process_not_found"
                return {"status": self.setup}
            self.session = self.device.attach(pid)
            self.agent = self.session.create_script(
                self.script_path.read_text(encoding="utf-8"))
            self.agent.on("message", self._on_message)
            self.agent.load()
            self.setup = "frida_attached_to_home_x86_64"
            self.mark("launch")
        except Exception as err:
            self.setup = "frida_instrumentation_failed"
            self.error_type = type(err).__name__
        return {"status": self.setup, "error_type": self.error_type}

    def _on_message(self, message, _data):
        if not isinstance(message, dict):
            return
        if message.get("type") == "error":
            self.agent_status = "agent_runtime_error"
            return
        obj = message.get("payload")
        if (message.get("type") == "send" and isinstance(obj, dict)
                and obj.get("kind") == "home41_emulator_network_meta"
                and obj.get("event") == "observer_installed"):
            self.agent_status = "agent_installed"

    def mark(self, stage: str) -> bool:
        if stage not in STAGES:
            return False
        self.current_stage = stage
        if self.agent is None:
            return False
        try:
            if self.agent.exports_sync.setstage(stage):
                self.stages_marked.append(stage)
                return True
        except Exception as err:
            self.error_type = type(err).__name__
        return False

    def finish(self) -> dict:
        summary = {
            "status": self.setup,
            "error_type": self.error_type,
            "agent_status": self.agent_status,
            "marked_stages": list(self.stages_marked),
            "arm64_il2cpp_hook_attempted": False,
            "http_body_intercepted": False,
            "account_registration_attempted": False,
            "raw_device_logs_saved": False,
        }
        if self.agent:
            try:
                summary["network"] = report_only_safe_counts(
                    self.agent.exports_sync.snapshot())
            except Exception as err:
                summary["snapshot_error_type"] = type(err).__name__
        if self.session:
            try:
                self.session.detach()
            except Exception:
                summary["detach_status"] = "failed"
        if self.device:
            try:
                diag.adb("forward", "--remove", "tcp:27042", timeout=15)
            except Exception:
                pass
        return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--script", type=Path,
                        default=Path(__file__).with_name("home41_emulator_network_meta.js"))
    parser.add_argument("--settle-seconds", type=int, default=16)
    args = parser.parse_args()
    observer = StageMonitor(args.server, args.script)
    result = diag.run(args.apk, args.output,
                      settle=max(3, min(60, args.settle_seconds)),
                      observer=observer, select_china_mainland=True)
    status = result.get("stage_monitor", {})
    print(json.dumps({
        "result": result.get("result"),
        "frida_status": status.get("status"),
        "guest_process_arch": status.get("network", {}).get("guest_process_arch"),
        "network_telemetry": status.get("network", {}).get("status", "unavailable"),
        "region_expanded": result.get("region_dropdown_expanded"),
        "country_selected": result.get("country_selected"),
        "registration_attempted": False,
        "first_basic_utid_status": "not_observed",
    }, ensure_ascii=False))
    # Fail the experiment when Frida was never actually attached.
    return (0 if status.get("status") == "frida_attached_to_home_x86_64"
            and status.get("network", {}).get("status") == "snapshot_received"
            else 3)


if __name__ == "__main__":
    raise SystemExit(main())
