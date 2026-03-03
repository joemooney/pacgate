#!/usr/bin/env python3
"""Shared PacLab scenario validation and normalization helpers."""

from __future__ import annotations

import re
from typing import Any

SCENARIO_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
ALLOWED_TOP_KEYS = {
    "schema_version",
    "id",
    "name",
    "description",
    "default_rules_file",
    "stateful",
    "tags",
    "events",
    "topology",
}
ALLOWED_EVENT_KEYS = {
    "name",
    "packet",
    "expected_action",
    "delay_ms",
    "meta",
    "ingress_port",
    "expected_egress_port",
    "expected_switch_action",
    "inject_rmac_error",
}
ALLOWED_TOPOLOGY_KEYS = {"kind", "ports"}
ALLOWED_TOPOLOGY_PORT_KEYS = {"id", "name", "subnet", "mac"}


class ScenarioValidationError(ValueError):
    """Scenario validation error."""


def validate_scenario_obj(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ScenarioValidationError("scenario must be an object")

    schema_version = str(raw.get("schema_version", "v1")).strip().lower()
    if schema_version not in ("v1", "v2"):
        raise ScenarioValidationError("schema_version must be 'v1' or 'v2'")

    unknown_top = set(raw.keys()) - ALLOWED_TOP_KEYS
    if unknown_top:
        raise ScenarioValidationError(f"unknown top-level keys: {sorted(unknown_top)}")

    sid = str(raw.get("id", "")).strip()
    if not sid:
        raise ScenarioValidationError("id is required")
    if not SCENARIO_ID_RE.match(sid):
        raise ScenarioValidationError("id must match ^[A-Za-z0-9_.-]+$")

    name = str(raw.get("name", "")).strip()
    if not name:
        raise ScenarioValidationError("name is required")

    description = str(raw.get("description", ""))

    default_rules_file = raw.get("default_rules_file")
    if default_rules_file is not None:
        default_rules_file = str(default_rules_file).strip()
        if not default_rules_file:
            raise ScenarioValidationError("default_rules_file cannot be empty when provided")

    stateful = bool(raw.get("stateful", False))

    tags_in = raw.get("tags", [])
    if tags_in is None:
        tags_in = []
    if not isinstance(tags_in, list):
        raise ScenarioValidationError("tags must be an array")
    tags: list[str] = []
    seen_tags = set()
    for i, tag in enumerate(tags_in):
        t = str(tag).strip()
        if not t:
            raise ScenarioValidationError(f"tags[{i}] cannot be empty")
        if t in seen_tags:
            raise ScenarioValidationError(f"tags[{i}] duplicates '{t}'")
        seen_tags.add(t)
        tags.append(t)

    events_raw = raw.get("events")
    if not isinstance(events_raw, list) or not events_raw:
        raise ScenarioValidationError("events must be a non-empty array")

    events: list[dict[str, Any]] = []
    for i, ev in enumerate(events_raw):
        if not isinstance(ev, dict):
            raise ScenarioValidationError(f"events[{i}] must be an object")

        unknown_ev = set(ev.keys()) - ALLOWED_EVENT_KEYS
        if unknown_ev:
            raise ScenarioValidationError(f"events[{i}] unknown keys: {sorted(unknown_ev)}")

        ev_name = str(ev.get("name", "")).strip()
        if not ev_name:
            raise ScenarioValidationError(f"events[{i}].name is required")

        packet = ev.get("packet")
        if not isinstance(packet, dict) or not packet:
            raise ScenarioValidationError(f"events[{i}].packet must be a non-empty object")

        normalized_packet: dict[str, Any] = {}
        for key, value in packet.items():
            if not isinstance(key, str) or not key.strip():
                raise ScenarioValidationError(f"events[{i}].packet contains invalid key")
            if not isinstance(value, (str, int, float, bool)):
                raise ScenarioValidationError(
                    f"events[{i}].packet['{key}'] must be string/integer/number/boolean"
                )
            normalized_packet[key.strip()] = value

        expected = ev.get("expected_action")
        if expected is not None:
            expected = str(expected).strip().lower()
            if expected not in ("pass", "drop"):
                raise ScenarioValidationError(f"events[{i}].expected_action must be 'pass' or 'drop'")

        delay_ms = int(ev.get("delay_ms", 0))
        if delay_ms < 0:
            raise ScenarioValidationError(f"events[{i}].delay_ms must be >= 0")

        meta = ev.get("meta")
        if meta is not None and not isinstance(meta, dict):
            raise ScenarioValidationError(f"events[{i}].meta must be an object")

        ingress_port = ev.get("ingress_port")
        if ingress_port is not None:
            ingress_port = int(ingress_port)
            if ingress_port < 0:
                raise ScenarioValidationError(f"events[{i}].ingress_port must be >= 0")

        expected_egress_port = ev.get("expected_egress_port")
        if expected_egress_port is not None:
            expected_egress_port = int(expected_egress_port)
            if expected_egress_port < 0:
                raise ScenarioValidationError(f"events[{i}].expected_egress_port must be >= 0")

        expected_switch_action = ev.get("expected_switch_action")
        if expected_switch_action is not None:
            expected_switch_action = str(expected_switch_action).strip().lower()
            if expected_switch_action not in ("forward", "drop"):
                raise ScenarioValidationError(
                    f"events[{i}].expected_switch_action must be 'forward' or 'drop'"
                )

        inject_rmac_error = bool(ev.get("inject_rmac_error", False))

        entry: dict[str, Any] = {
            "name": ev_name,
            "packet": normalized_packet,
        }
        if expected is not None:
            entry["expected_action"] = expected
        if delay_ms != 0:
            entry["delay_ms"] = delay_ms
        if meta is not None:
            entry["meta"] = meta
        if ingress_port is not None:
            entry["ingress_port"] = ingress_port
        if expected_egress_port is not None:
            entry["expected_egress_port"] = expected_egress_port
        if expected_switch_action is not None:
            entry["expected_switch_action"] = expected_switch_action
        if inject_rmac_error:
            entry["inject_rmac_error"] = True
        events.append(entry)

    topology = raw.get("topology")
    if topology is not None:
        if not isinstance(topology, dict):
            raise ScenarioValidationError("topology must be an object")
        unknown_topology = set(topology.keys()) - ALLOWED_TOPOLOGY_KEYS
        if unknown_topology:
            raise ScenarioValidationError(f"topology unknown keys: {sorted(unknown_topology)}")

        kind = str(topology.get("kind", "l3_switch_2port")).strip()
        if not kind:
            raise ScenarioValidationError("topology.kind cannot be empty")

        ports_raw = topology.get("ports")
        if not isinstance(ports_raw, list) or len(ports_raw) < 2:
            raise ScenarioValidationError("topology.ports must be an array of at least 2 ports")
        ports = []
        seen_port_ids: set[int] = set()
        for i, port in enumerate(ports_raw):
            if not isinstance(port, dict):
                raise ScenarioValidationError(f"topology.ports[{i}] must be an object")
            unknown_port = set(port.keys()) - ALLOWED_TOPOLOGY_PORT_KEYS
            if unknown_port:
                raise ScenarioValidationError(
                    f"topology.ports[{i}] unknown keys: {sorted(unknown_port)}"
                )
            pid = int(port.get("id", -1))
            if pid < 0:
                raise ScenarioValidationError(f"topology.ports[{i}].id must be >= 0")
            if pid in seen_port_ids:
                raise ScenarioValidationError(f"topology.ports[{i}].id duplicates {pid}")
            seen_port_ids.add(pid)

            pname = str(port.get("name", f"port{pid}")).strip() or f"port{pid}"
            subnet = str(port.get("subnet", "")).strip()
            if not subnet:
                raise ScenarioValidationError(f"topology.ports[{i}].subnet is required")
            mac = str(port.get("mac", "")).strip()
            if not mac:
                raise ScenarioValidationError(f"topology.ports[{i}].mac is required")
            ports.append({"id": pid, "name": pname, "subnet": subnet, "mac": mac})

        topology = {"kind": kind, "ports": ports}

    out: dict[str, Any] = {
        "id": sid,
        "name": name,
        "events": events,
    }
    if description:
        out["description"] = description
    if default_rules_file:
        out["default_rules_file"] = default_rules_file
    if stateful:
        out["stateful"] = True
    if tags:
        out["tags"] = tags
    if schema_version != "v1":
        out["schema_version"] = schema_version
    if topology is not None:
        out["topology"] = topology

    return out
