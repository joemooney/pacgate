#!/usr/bin/env python3
"""Run a simple 1000-packet regression against PacGate simulate."""

import argparse
import json
import subprocess
import time


PKT_PASS = "ethertype=0x0806,src_mac=00:11:22:33:44:55,dst_mac=ff:ff:ff:ff:ff:ff"
PKT_DROP = "ethertype=0x0800,src_ip=10.0.0.1,dst_ip=10.0.0.2,ip_protocol=6,dst_port=443"


def run_one(bin_path: str, rules: str, packet: str, stateful: bool) -> dict:
    cmd = [bin_path, "simulate", rules, "--packet", packet, "--json"]
    if stateful:
        cmd.append("--stateful")
    out = subprocess.check_output(cmd, text=True)
    return json.loads(out)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run 1000-packet PacGate regression")
    parser.add_argument("--rules", default="rules/examples/allow_arp.yaml", help="Rules YAML file")
    parser.add_argument("--bin", default="target/debug/pacgate", help="Path to pacgate binary")
    parser.add_argument("--count", type=int, default=1000, help="Packet count")
    parser.add_argument("--stateful", action="store_true", help="Enable --stateful")
    args = parser.parse_args()

    mismatches = 0
    start = time.perf_counter()

    for i in range(args.count):
        expected = "pass" if i % 2 == 0 else "drop"
        packet = PKT_PASS if expected == "pass" else PKT_DROP
        action = run_one(args.bin, args.rules, packet, args.stateful).get("action")
        if action != expected:
            mismatches += 1

    elapsed = time.perf_counter() - start
    result = {
        "rules": args.rules,
        "count": args.count,
        "mismatches": mismatches,
        "elapsed_sec": round(elapsed, 3),
        "packets_per_sec": round(args.count / elapsed, 2) if elapsed > 0 else None,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
