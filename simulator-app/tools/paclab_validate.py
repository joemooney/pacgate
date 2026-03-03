#!/usr/bin/env python3
"""Validate PacLab scenario JSON files."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from scenario_lib import ScenarioValidationError, validate_scenario_obj


def try_jsonschema_validate(instance: dict[str, Any], schema_path: Path) -> str | None:
    try:
        import jsonschema  # type: ignore
    except Exception:
        return "jsonschema-not-installed"

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.validate(instance=instance, schema=schema)
    return None


def validate_file(path: Path, schema_path: Path, use_jsonschema: bool) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    normalized = validate_scenario_obj(raw)

    schema_mode = "builtin"
    if use_jsonschema:
        outcome = try_jsonschema_validate(raw, schema_path)
        if outcome is None:
            schema_mode = "jsonschema+builtin"
        else:
            schema_mode = f"builtin ({outcome})"

    return {
        "file": str(path),
        "id": normalized["id"],
        "events": len(normalized["events"]),
        "mode": schema_mode,
        "ok": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate PacLab scenario JSON files")
    parser.add_argument("files", nargs="+", help="Scenario JSON files to validate")
    parser.add_argument(
        "--schema",
        default="docs/management/paclab/scenario_v2.schema.json",
        help="Path to JSON schema file (used when --jsonschema is enabled)",
    )
    parser.add_argument(
        "--jsonschema",
        action="store_true",
        help="Also validate with python-jsonschema if installed",
    )
    parser.add_argument("--json", action="store_true", help="Output JSON summary")
    args = parser.parse_args()

    schema_path = Path(args.schema)
    results = []
    errors = []

    for name in args.files:
        path = Path(name)
        try:
            res = validate_file(path, schema_path, args.jsonschema)
            results.append(res)
        except (OSError, json.JSONDecodeError, ScenarioValidationError, ValueError) as exc:
            errors.append({"file": str(path), "ok": False, "error": str(exc)})

    summary = {
        "status": "ok" if not errors else "error",
        "validated": len(results),
        "failed": len(errors),
        "results": results,
        "errors": errors,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        for row in results:
            print(f"OK  {row['file']}  id={row['id']} events={row['events']} mode={row['mode']}")
        for err in errors:
            print(f"ERR {err['file']}  {err['error']}")

    raise SystemExit(0 if not errors else 1)


if __name__ == "__main__":
    main()
