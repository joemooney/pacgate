#!/usr/bin/env python3
"""Run PacLab topology scenarios with a software 2-port L3 switch model.

Model stages per event:
1) RMAC ingress checks (error injection + ingress subnet eligibility)
2) PacGate policy decision (simulate --json)
3) Switch forwarding/drop decision (dst subnet lookup)
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scenario_lib import validate_scenario_obj


@dataclass
class PortCfg:
    id: int
    name: str
    subnet: ipaddress.IPv4Network
    mac: str


class TopologyRunner:
    def __init__(self, scenario: dict[str, Any], pacgate_bin: str) -> None:
        self.scenario = scenario
        self.pacgate_bin = pacgate_bin
        self.rules_file = str(scenario.get("default_rules_file", "")).strip()
        if not self.rules_file:
            raise ValueError("scenario.default_rules_file is required for topology runs")

        topo = scenario.get("topology")
        if not isinstance(topo, dict):
            raise ValueError("scenario.topology is required")
        self.ports = self._parse_ports(topo.get("ports", []))
        self.by_id = {p.id: p for p in self.ports}

    @staticmethod
    def _parse_ports(raw_ports: list[dict[str, Any]]) -> list[PortCfg]:
        ports = []
        for p in raw_ports:
            ports.append(
                PortCfg(
                    id=int(p["id"]),
                    name=str(p["name"]),
                    subnet=ipaddress.ip_network(str(p["subnet"]), strict=False),
                    mac=str(p["mac"]),
                )
            )
        return ports

    def _run_pacgate(self, packet: dict[str, Any], stateful: bool) -> dict[str, Any]:
        packet_spec = self._packet_to_spec(packet)
        cmd = [self.pacgate_bin, "simulate", self.rules_file, "--packet", packet_spec, "--json"]
        if stateful:
            cmd.append("--stateful")
        out = subprocess.check_output(cmd, text=True)
        return json.loads(out)

    @staticmethod
    def _packet_to_spec(packet: dict[str, Any]) -> str:
        parts = []
        for k, v in packet.items():
            if v is None:
                continue
            text = str(v).strip()
            if text:
                parts.append(f"{k}={text}")
        if not parts:
            raise ValueError("packet has no fields")
        return ",".join(parts)

    @staticmethod
    def _in_subnet(ip_text: str | None, subnet: ipaddress.IPv4Network) -> bool:
        if not ip_text:
            return False
        try:
            return ipaddress.ip_address(ip_text) in subnet
        except ValueError:
            return False

    def _lookup_egress_port(self, ingress_port: int, dst_ip: str | None) -> int | None:
        if not dst_ip:
            return None
        for p in self.ports:
            if p.id == ingress_port:
                continue
            if self._in_subnet(dst_ip, p.subnet):
                return p.id
        return None

    def run(self) -> dict[str, Any]:
        stateful = bool(self.scenario.get("stateful", False))

        stats = {
            "total_events": 0,
            "rmac_error_count": 0,
            "rmac_dropped": 0,
            "switch_forwarded": 0,
            "switch_dropped": 0,
            "switch_drop_reasons": {
                "rmac_error": 0,
                "ingress_subnet_mismatch": 0,
                "pacgate_drop": 0,
                "no_route": 0,
            },
        }

        results = []
        mismatch_count = 0

        for i, ev in enumerate(self.scenario["events"]):
            stats["total_events"] += 1
            delay_ms = int(ev.get("delay_ms", 0))
            if i > 0 and delay_ms > 0:
                time.sleep(delay_ms / 1000.0)

            packet = ev["packet"]
            ingress_port = int(ev.get("ingress_port", 0))
            if ingress_port not in self.by_id:
                raise ValueError(f"events[{i}].ingress_port {ingress_port} is not in topology.ports")

            ingress_cfg = self.by_id[ingress_port]
            src_ip = str(packet.get("src_ip", "")).strip() or None
            dst_ip = str(packet.get("dst_ip", "")).strip() or None

            rmac_error = bool(ev.get("inject_rmac_error", False))
            pacgate_result = None
            switch_action = "drop"
            drop_reason = ""
            egress_port = None

            if rmac_error:
                stats["rmac_error_count"] += 1
                stats["rmac_dropped"] += 1
                stats["switch_dropped"] += 1
                stats["switch_drop_reasons"]["rmac_error"] += 1
                drop_reason = "rmac_error"
            elif src_ip and not self._in_subnet(src_ip, ingress_cfg.subnet):
                stats["rmac_dropped"] += 1
                stats["switch_dropped"] += 1
                stats["switch_drop_reasons"]["ingress_subnet_mismatch"] += 1
                drop_reason = "ingress_subnet_mismatch"
            else:
                pacgate_result = self._run_pacgate(packet, stateful=stateful)
                if pacgate_result.get("action") == "drop":
                    stats["switch_dropped"] += 1
                    stats["switch_drop_reasons"]["pacgate_drop"] += 1
                    drop_reason = "pacgate_drop"
                else:
                    egress_port = self._lookup_egress_port(ingress_port, dst_ip)
                    if egress_port is None:
                        stats["switch_dropped"] += 1
                        stats["switch_drop_reasons"]["no_route"] += 1
                        drop_reason = "no_route"
                    else:
                        switch_action = "forward"
                        stats["switch_forwarded"] += 1

            expected_action = ev.get("expected_action")
            expected_switch_action = ev.get("expected_switch_action")
            expected_egress_port = ev.get("expected_egress_port")

            action_matches = True
            if expected_action is not None:
                actual_pacgate_action = pacgate_result.get("action") if pacgate_result else "drop"
                action_matches = str(expected_action).lower() == str(actual_pacgate_action).lower()

            switch_action_matches = True
            if expected_switch_action is not None:
                switch_action_matches = str(expected_switch_action).lower() == switch_action

            egress_matches = True
            if expected_egress_port is not None:
                egress_matches = int(expected_egress_port) == int(egress_port if egress_port is not None else -1)

            event_ok = action_matches and switch_action_matches and egress_matches
            if not event_ok:
                mismatch_count += 1

            results.append(
                {
                    "event_index": i,
                    "event_name": ev.get("name", f"event_{i + 1}"),
                    "ingress_port": ingress_port,
                    "packet": packet,
                    "pacgate": pacgate_result,
                    "switch_action": switch_action,
                    "egress_port": egress_port,
                    "drop_reason": drop_reason,
                    "expected_action": expected_action,
                    "expected_switch_action": expected_switch_action,
                    "expected_egress_port": expected_egress_port,
                    "action_matches": action_matches,
                    "switch_action_matches": switch_action_matches,
                    "egress_matches": egress_matches,
                    "event_ok": event_ok,
                }
            )

        return {
            "scenario_id": self.scenario["id"],
            "rules_file": self.rules_file,
            "topology_kind": self.scenario["topology"]["kind"],
            "ports": [
                {
                    "id": p.id,
                    "name": p.name,
                    "subnet": str(p.subnet),
                    "mac": p.mac,
                }
                for p in self.ports
            ],
            "stateful": stateful,
            "mismatch_count": mismatch_count,
            "stats": stats,
            "results": results,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a PacLab topology scenario")
    parser.add_argument("scenario", help="Path to scenario JSON (v2 recommended)")
    parser.add_argument("--bin", default="target/debug/pacgate", help="Path to pacgate binary")
    parser.add_argument("--output", help="Optional output JSON file")
    args = parser.parse_args()

    raw = json.loads(Path(args.scenario).read_text(encoding="utf-8"))
    scenario = validate_scenario_obj(raw)
    runner = TopologyRunner(scenario, pacgate_bin=args.bin)
    result = runner.run()

    text = json.dumps(result, indent=2)
    print(text)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")

    raise SystemExit(0 if result["mismatch_count"] == 0 else 1)


if __name__ == "__main__":
    main()
