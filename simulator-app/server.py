#!/usr/bin/env python3
"""PacGate Simulator App backend.

Runs a lightweight web server with:
- Static UI under / (simulator-app/web)
- JSON API under /api/*

The backend shells out to PacGate's existing CLI simulator command.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

HOST = os.environ.get("SIMULATOR_HOST", "127.0.0.1")
PORT = int(os.environ.get("SIMULATOR_PORT", "8787"))

ROOT_DIR = Path(__file__).resolve().parent.parent
APP_DIR = Path(__file__).resolve().parent
WEB_DIR = APP_DIR / "web"
DATA_DIR = APP_DIR / "data"
CUSTOM_SCENARIOS_PATH = DATA_DIR / "custom_scenarios.json"


# Useful baseline scenarios that test common behavior quickly.
SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "allow_arp_then_drop_ipv4",
        "name": "Allow ARP then drop IPv4",
        "description": "Verifies allow_arp example passes ARP and drops unmatched IPv4.",
        "default_rules_file": "rules/examples/allow_arp.yaml",
        "events": [
            {
                "name": "ARP should pass",
                "packet": {
                    "ethertype": "0x0806",
                    "src_mac": "00:11:22:33:44:55",
                    "dst_mac": "ff:ff:ff:ff:ff:ff",
                },
                "expected_action": "pass",
            },
            {
                "name": "IPv4 should drop",
                "packet": {
                    "ethertype": "0x0800",
                    "src_ip": "10.0.0.10",
                    "dst_ip": "10.0.0.11",
                    "ip_protocol": 6,
                    "dst_port": 443,
                },
                "expected_action": "drop",
            },
        ],
    },
    {
        "id": "enterprise_web_dns",
        "name": "Enterprise Web + DNS",
        "description": "Exercises common enterprise traffic in the enterprise example policy.",
        "default_rules_file": "rules/examples/enterprise.yaml",
        "events": [
            {
                "name": "HTTPS flow",
                "packet": {
                    "ethertype": "0x0800",
                    "src_ip": "10.10.10.2",
                    "dst_ip": "172.16.0.20",
                    "ip_protocol": 6,
                    "src_port": 51000,
                    "dst_port": 443,
                },
                "expected_action": "pass",
            },
            {
                "name": "DNS flow",
                "packet": {
                    "ethertype": "0x0800",
                    "src_ip": "10.10.10.2",
                    "dst_ip": "8.8.8.8",
                    "ip_protocol": 17,
                    "src_port": 53000,
                    "dst_port": 53,
                },
                "expected_action": "pass",
            },
        ],
    },
    {
        "id": "syn_flood_stateful",
        "name": "SYN Flood Stateful",
        "description": "Runs repeated SYN-like packets in stateful mode for quick stress checks.",
        "default_rules_file": "rules/examples/syn_flood_detect.yaml",
        "stateful": True,
        "events": [
            {
                "name": "SYN #1",
                "packet": {
                    "ethertype": "0x0800",
                    "src_ip": "192.0.2.50",
                    "dst_ip": "192.0.2.1",
                    "ip_protocol": 6,
                    "dst_port": 443,
                    "tcp_flags": "0x02",
                    "tcp_flags_mask": "0x02",
                },
            },
            {
                "name": "SYN #2",
                "packet": {
                    "ethertype": "0x0800",
                    "src_ip": "192.0.2.50",
                    "dst_ip": "192.0.2.1",
                    "ip_protocol": 6,
                    "dst_port": 443,
                    "tcp_flags": "0x02",
                    "tcp_flags_mask": "0x02",
                },
                "delay_ms": 50,
            },
            {
                "name": "SYN #3",
                "packet": {
                    "ethertype": "0x0800",
                    "src_ip": "192.0.2.50",
                    "dst_ip": "192.0.2.1",
                    "ip_protocol": 6,
                    "dst_port": 443,
                    "tcp_flags": "0x02",
                    "tcp_flags_mask": "0x02",
                },
                "delay_ms": 50,
            },
        ],
    },
]


@dataclass
class LogEntry:
    ts: float
    kind: str
    rules_file: str
    packet_spec: str
    response: dict[str, Any]


class SimulatorService:
    def __init__(self) -> None:
        self._log: deque[LogEntry] = deque(maxlen=200)
        self._lock = threading.Lock()
        self._custom_scenarios: list[dict[str, Any]] = []
        self._load_custom_scenarios()

    def list_rules_files(self) -> list[str]:
        files: set[Path] = set()
        for base in (ROOT_DIR / "rules", ROOT_DIR / "tests"):
            if not base.exists():
                continue
            for path in base.rglob("*.yaml"):
                files.add(path)
            for path in base.rglob("*.yml"):
                files.add(path)

        rel = [str(p.relative_to(ROOT_DIR)) for p in sorted(files)]
        return rel

    def list_scenarios(self) -> list[dict[str, Any]]:
        builtins = [{**s, "source": "builtin"} for s in SCENARIOS]
        custom = [{**s, "source": "custom"} for s in self._custom_scenarios]
        return builtins + custom

    def save_custom_scenario(self, scenario: dict[str, Any]) -> dict[str, Any]:
        normalized = normalize_custom_scenario(scenario)
        sid = normalized["id"]
        if any(s["id"] == sid for s in SCENARIOS):
            raise ValueError(f"Scenario id '{sid}' conflicts with builtin scenario")

        updated = False
        for i, existing in enumerate(self._custom_scenarios):
            if existing["id"] == sid:
                self._custom_scenarios[i] = normalized
                updated = True
                break
        if not updated:
            self._custom_scenarios.append(normalized)
        self._persist_custom_scenarios()
        return normalized

    def delete_custom_scenario(self, scenario_id: str) -> None:
        if any(s["id"] == scenario_id for s in SCENARIOS):
            raise ValueError(f"Scenario id '{scenario_id}' is builtin and cannot be deleted")

        original = len(self._custom_scenarios)
        self._custom_scenarios = [s for s in self._custom_scenarios if s["id"] != scenario_id]
        if len(self._custom_scenarios) == original:
            raise ValueError(f"Unknown custom scenario_id '{scenario_id}'")
        self._persist_custom_scenarios()

    def simulate(self, rules_file: str, packet: dict[str, Any], stateful: bool = False) -> dict[str, Any]:
        packet_spec = packet_to_spec(packet)
        payload = run_pacgate_simulate(rules_file, packet_spec, stateful=stateful)
        self._append_log("simulate", rules_file, packet_spec, payload)
        return payload

    def run_scenario(self, scenario_id: str, rules_file: str | None, stateful: bool | None) -> dict[str, Any]:
        scenario = self._find_scenario(scenario_id)
        if scenario is None:
            raise ValueError(f"Unknown scenario_id '{scenario_id}'")

        resolved_rules = rules_file or scenario.get("default_rules_file")
        if not resolved_rules:
            raise ValueError("Scenario requires a rules_file")
        resolved_stateful = bool(scenario.get("stateful", False) if stateful is None else stateful)

        results: list[dict[str, Any]] = []
        mismatch_count = 0
        for i, event in enumerate(scenario["events"]):
            delay_ms = int(event.get("delay_ms", 0))
            if i > 0 and delay_ms > 0:
                time.sleep(delay_ms / 1000.0)

            packet_spec = packet_to_spec(event["packet"])
            response = run_pacgate_simulate(resolved_rules, packet_spec, stateful=resolved_stateful)
            expected_action = event.get("expected_action")
            actual_action = response.get("action")
            action_matches = (
                expected_action is None
                or str(expected_action).lower().strip() == str(actual_action).lower().strip()
            )
            if not action_matches:
                mismatch_count += 1
            results.append(
                {
                    "event_name": event.get("name", f"event_{i + 1}"),
                    "packet": event["packet"],
                    "packet_spec": packet_spec,
                    "expected_action": expected_action,
                    "actual_action": actual_action,
                    "action_matches": action_matches,
                    "response": response,
                }
            )
            self._append_log("scenario", resolved_rules, packet_spec, response)

        return {
            "scenario_id": scenario_id,
            "rules_file": resolved_rules,
            "stateful": resolved_stateful,
            "mismatch_count": mismatch_count,
            "results": results,
        }

    def log(self) -> list[dict[str, Any]]:
        with self._lock:
            return [asdict(entry) for entry in reversed(self._log)]

    def _append_log(self, kind: str, rules_file: str, packet_spec: str, response: dict[str, Any]) -> None:
        entry = LogEntry(ts=time.time(), kind=kind, rules_file=rules_file, packet_spec=packet_spec, response=response)
        with self._lock:
            self._log.append(entry)

    def _find_scenario(self, scenario_id: str) -> dict[str, Any] | None:
        for scenario in self.list_scenarios():
            if scenario["id"] == scenario_id:
                return scenario
        return None

    def _load_custom_scenarios(self) -> None:
        if not CUSTOM_SCENARIOS_PATH.exists():
            self._custom_scenarios = []
            return
        try:
            payload = json.loads(CUSTOM_SCENARIOS_PATH.read_text(encoding="utf-8"))
            items = payload.get("items", [])
            if not isinstance(items, list):
                raise ValueError("custom_scenarios.json items must be a list")
            normalized: list[dict[str, Any]] = []
            for item in items:
                normalized.append(normalize_custom_scenario(item))
            self._custom_scenarios = normalized
        except Exception as exc:
            raise RuntimeError(f"Failed to load custom scenarios: {exc}") from exc

    def _persist_custom_scenarios(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        payload = {"items": self._custom_scenarios}
        CUSTOM_SCENARIOS_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def normalize_custom_scenario(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("Scenario must be an object")

    sid = str(raw.get("id", "")).strip()
    if not sid:
        raise ValueError("Scenario id is required")
    if any(ch.isspace() for ch in sid):
        raise ValueError("Scenario id cannot contain whitespace")

    name = str(raw.get("name", sid)).strip() or sid
    description = str(raw.get("description", "")).strip()
    default_rules_file = str(raw.get("default_rules_file", "")).strip()
    stateful = bool(raw.get("stateful", False))

    events_raw = raw.get("events")
    if not isinstance(events_raw, list) or not events_raw:
        raise ValueError("Scenario events must be a non-empty array")

    events: list[dict[str, Any]] = []
    for i, event in enumerate(events_raw):
        if not isinstance(event, dict):
            raise ValueError(f"Event #{i + 1} must be an object")
        packet = event.get("packet")
        if not isinstance(packet, dict) or not packet:
            raise ValueError(f"Event #{i + 1} packet must be a non-empty object")
        delay_ms = int(event.get("delay_ms", 0))
        if delay_ms < 0:
            raise ValueError(f"Event #{i + 1} delay_ms must be >= 0")
        expected_action = event.get("expected_action")
        if expected_action is not None:
            expected_action = str(expected_action).strip().lower()
            if expected_action not in ("pass", "drop"):
                raise ValueError(f"Event #{i + 1} expected_action must be 'pass' or 'drop'")
        events.append(
            {
                "name": str(event.get("name", f"event_{i + 1}")).strip() or f"event_{i + 1}",
                "packet": packet,
                "delay_ms": delay_ms,
                "expected_action": expected_action,
            }
        )

    return {
        "id": sid,
        "name": name,
        "description": description,
        "default_rules_file": default_rules_file,
        "stateful": stateful,
        "events": events,
    }


def packet_to_spec(packet: dict[str, Any]) -> str:
    parts = []
    for key, value in packet.items():
        if value is None:
            continue
        text = str(value).strip()
        if text == "":
            continue
        parts.append(f"{key}={text}")
    if not parts:
        raise ValueError("Packet has no fields")
    return ",".join(parts)


def run_pacgate_simulate(rules_file: str, packet_spec: str, stateful: bool = False) -> dict[str, Any]:
    rules_path = ROOT_DIR / rules_file
    if not rules_path.exists():
        raise ValueError(f"Rules file not found: {rules_file}")

    pacgate_bin = ROOT_DIR / "target" / "debug" / "pacgate"
    if pacgate_bin.exists():
        cmd = [str(pacgate_bin), "simulate", str(rules_path), "--packet", packet_spec, "--json"]
    else:
        cmd = ["cargo", "run", "--quiet", "--", "simulate", str(rules_path), "--packet", packet_spec, "--json"]

    if stateful:
        cmd.append("--stateful")

    proc = subprocess.run(
        cmd,
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "PacGate simulate failed")

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"PacGate returned non-JSON output: {exc}") from exc


SERVICE = SimulatorService()


class Handler(BaseHTTPRequestHandler):
    server_version = "pacgate-simulator/0.1"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)

        if parsed.path == "/api/health":
            self._write_json({"status": "ok", "time": time.time()})
            return
        if parsed.path == "/api/rules-files":
            self._write_json({"items": SERVICE.list_rules_files()})
            return
        if parsed.path == "/api/scenarios":
            self._write_json({"items": SERVICE.list_scenarios()})
            return
        if parsed.path == "/api/log":
            self._write_json({"items": SERVICE.log()})
            return

        self._serve_static(parsed.path)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            payload = self._read_json_body()
            if parsed.path == "/api/simulate":
                rules_file = str(payload.get("rules_file", "")).strip()
                packet = payload.get("packet", {})
                stateful = bool(payload.get("stateful", False))
                expected_action = payload.get("expected_action")
                if not rules_file:
                    self._write_error(HTTPStatus.BAD_REQUEST, "rules_file is required")
                    return
                if not isinstance(packet, dict):
                    self._write_error(HTTPStatus.BAD_REQUEST, "packet must be an object")
                    return

                result = SERVICE.simulate(rules_file, packet, stateful=stateful)
                if expected_action is not None:
                    expected = str(expected_action).strip().lower()
                    actual = str(result.get("action", "")).strip().lower()
                    if expected not in ("pass", "drop"):
                        self._write_error(HTTPStatus.BAD_REQUEST, "expected_action must be 'pass' or 'drop'")
                        return
                    result["expected_action"] = expected
                    result["action_matches"] = expected == actual
                self._write_json({"status": "ok", "result": result})
                return

            if parsed.path == "/api/scenario/run":
                scenario_id = str(payload.get("scenario_id", "")).strip()
                rules_file = payload.get("rules_file")
                stateful = payload.get("stateful")
                if not scenario_id:
                    self._write_error(HTTPStatus.BAD_REQUEST, "scenario_id is required")
                    return

                if rules_file is not None:
                    rules_file = str(rules_file).strip()
                if stateful is not None:
                    stateful = bool(stateful)

                result = SERVICE.run_scenario(scenario_id, rules_file, stateful)
                self._write_json({"status": "ok", "result": result})
                return

            if parsed.path == "/api/scenario/save":
                scenario = payload.get("scenario")
                if not isinstance(scenario, dict):
                    self._write_error(HTTPStatus.BAD_REQUEST, "scenario must be an object")
                    return
                saved = SERVICE.save_custom_scenario(scenario)
                self._write_json({"status": "ok", "result": saved})
                return

            if parsed.path == "/api/scenario/delete":
                scenario_id = str(payload.get("scenario_id", "")).strip()
                if not scenario_id:
                    self._write_error(HTTPStatus.BAD_REQUEST, "scenario_id is required")
                    return
                SERVICE.delete_custom_scenario(scenario_id)
                self._write_json({"status": "ok", "deleted": scenario_id})
                return

            self._write_error(HTTPStatus.NOT_FOUND, "Unknown endpoint")
        except ValueError as exc:
            self._write_error(HTTPStatus.BAD_REQUEST, str(exc))
        except RuntimeError as exc:
            self._write_error(HTTPStatus.BAD_GATEWAY, str(exc))
        except Exception as exc:  # defensive fallback
            self._write_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Internal error: {exc}")

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _serve_static(self, path: str) -> None:
        if path in ("", "/"):
            path = "/index.html"

        clean = path.lstrip("/")
        if ".." in clean.split("/"):
            self._write_error(HTTPStatus.BAD_REQUEST, "Invalid path")
            return

        target = (WEB_DIR / clean).resolve()
        if not str(target).startswith(str(WEB_DIR.resolve())):
            self._write_error(HTTPStatus.BAD_REQUEST, "Invalid path")
            return
        if not target.exists() or not target.is_file():
            self._write_error(HTTPStatus.NOT_FOUND, "Not found")
            return

        ctype = "text/plain"
        if target.suffix == ".html":
            ctype = "text/html; charset=utf-8"
        elif target.suffix == ".css":
            ctype = "text/css; charset=utf-8"
        elif target.suffix == ".js":
            ctype = "application/javascript; charset=utf-8"
        elif target.suffix == ".json":
            ctype = "application/json; charset=utf-8"

        data = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length > 0 else b"{}"
        if not raw.strip():
            return {}
        decoded = json.loads(raw.decode("utf-8"))
        if not isinstance(decoded, dict):
            raise ValueError("JSON body must be an object")
        return decoded

    def _write_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _write_error(self, status: HTTPStatus, message: str) -> None:
        self._write_json({"status": "error", "error": message}, status=status)


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"PacGate Simulator running on http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
