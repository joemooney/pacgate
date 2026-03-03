#!/usr/bin/env python3
"""Import/export custom scenarios between simulator-app storage and PacLab files."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scenario_lib import validate_scenario_obj

DEFAULT_STORE = Path("simulator-app/data/custom_scenarios.json")
DEFAULT_DIR = Path("docs/management/paclab/scenarios")


def load_store(path: Path) -> list[dict]:
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    items = payload.get("items", [])
    if not isinstance(items, list):
        raise ValueError("custom scenario store must have an array 'items'")
    out = []
    for item in items:
        out.append(validate_scenario_obj(item))
    return out


def save_store(path: Path, items: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"items": items}, indent=2) + "\n", encoding="utf-8")


def export_to_dir(store_path: Path, out_dir: Path) -> dict:
    items = load_store(store_path)
    out_dir.mkdir(parents=True, exist_ok=True)

    for scenario in items:
        target = out_dir / f"{scenario['id']}.json"
        target.write_text(json.dumps(scenario, indent=2) + "\n", encoding="utf-8")

    return {"exported": len(items), "store": str(store_path), "out_dir": str(out_dir)}


def import_from_dir(in_dir: Path, store_path: Path, mode: str) -> dict:
    if not in_dir.exists():
        raise ValueError(f"input directory does not exist: {in_dir}")

    files = sorted(p for p in in_dir.glob("*.json") if p.is_file())
    imported = [validate_scenario_obj(json.loads(p.read_text(encoding="utf-8"))) for p in files]

    if mode == "replace":
        merged = imported
    else:
        existing = load_store(store_path)
        by_id = {s["id"]: s for s in existing}
        for s in imported:
            by_id[s["id"]] = s
        merged = sorted(by_id.values(), key=lambda x: x["id"])

    save_store(store_path, merged)
    return {
        "imported_files": len(files),
        "stored_total": len(merged),
        "mode": mode,
        "in_dir": str(in_dir),
        "store": str(store_path),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync simulator custom scenarios with PacLab scenario files")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_export = sub.add_parser("export", help="Export simulator custom scenarios to PacLab scenario files")
    p_export.add_argument("--store", default=str(DEFAULT_STORE), help="Path to custom_scenarios.json")
    p_export.add_argument("--out-dir", default=str(DEFAULT_DIR), help="Output directory for scenario json files")

    p_import = sub.add_parser("import", help="Import PacLab scenario files into simulator custom store")
    p_import.add_argument("--in-dir", default=str(DEFAULT_DIR), help="Directory with scenario json files")
    p_import.add_argument("--store", default=str(DEFAULT_STORE), help="Path to custom_scenarios.json")
    p_import.add_argument("--mode", choices=["merge", "replace"], default="merge", help="Import mode")

    p_round = sub.add_parser("roundtrip", help="Import then export to verify conversion path")
    p_round.add_argument("--in-dir", default=str(DEFAULT_DIR))
    p_round.add_argument("--store", default=str(DEFAULT_STORE))
    p_round.add_argument("--out-dir", default=str(DEFAULT_DIR))

    p_validate = sub.add_parser("validate", help="Validate all scenarios in a directory")
    p_validate.add_argument("--in-dir", default=str(DEFAULT_DIR))

    args = parser.parse_args()

    if args.cmd == "export":
        result = export_to_dir(Path(args.store), Path(args.out_dir))
    elif args.cmd == "import":
        result = import_from_dir(Path(args.in_dir), Path(args.store), args.mode)
    elif args.cmd == "roundtrip":
        mid = import_from_dir(Path(args.in_dir), Path(args.store), "replace")
        out = export_to_dir(Path(args.store), Path(args.out_dir))
        result = {"import": mid, "export": out}
    elif args.cmd == "validate":
        in_dir = Path(args.in_dir)
        files = sorted(p for p in in_dir.glob("*.json") if p.is_file())
        for p in files:
            validate_scenario_obj(json.loads(p.read_text(encoding="utf-8")))
        result = {"validated_files": len(files), "in_dir": str(in_dir)}
    else:
        raise ValueError(f"unknown command: {args.cmd}")

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
