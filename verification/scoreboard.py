"""
PacGate Scoreboard — Reference model for packet filter decisions.

Implements the same rule-matching logic as the generated Verilog,
in Python, for independent verification. Compares DUT decisions
against expected results and reports mismatches.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from .packet import EthernetFrame, mac_matches


@dataclass
class Rule:
    """A packet filter rule (mirrors the Verilog rule_match module)."""
    name: str
    priority: int
    action: str  # "pass" or "drop"
    ethertype: Optional[int] = None
    dst_mac: Optional[str] = None
    src_mac: Optional[str] = None
    vlan_id: Optional[int] = None
    vlan_pcp: Optional[int] = None

    def matches(self, frame: EthernetFrame) -> bool:
        """Check if this rule matches the given frame."""
        if self.ethertype is not None:
            if frame.ethertype != self.ethertype:
                return False
        if self.dst_mac is not None:
            if not mac_matches(frame.dst_mac, self.dst_mac):
                return False
        if self.src_mac is not None:
            if not mac_matches(frame.src_mac, self.src_mac):
                return False
        if self.vlan_id is not None:
            if frame.vlan_tag is None or frame.vlan_tag.vid != self.vlan_id:
                return False
        if self.vlan_pcp is not None:
            if frame.vlan_tag is None or frame.vlan_tag.pcp != self.vlan_pcp:
                return False
        return True


class ScoreboardMismatch(Exception):
    """Raised when DUT decision doesn't match reference model."""
    def __init__(self, frame, expected_action, actual_pass, matched_rule):
        self.frame = frame
        self.expected_action = expected_action
        self.actual_pass = actual_pass
        self.matched_rule = matched_rule
        expected_pass = 1 if expected_action == "pass" else 0
        super().__init__(
            f"MISMATCH: frame dst={frame.dst_mac_str} src={frame.src_mac_str} "
            f"etype=0x{frame.ethertype:04x} | "
            f"expected={'pass' if expected_pass else 'drop'} (rule={matched_rule}) "
            f"got={'pass' if actual_pass else 'drop'}"
        )


@dataclass
class ScoreboardStats:
    """Statistics from scoreboard checking."""
    total_packets: int = 0
    matches: int = 0
    mismatches: int = 0
    rule_hit_count: dict = field(default_factory=lambda: defaultdict(int))
    pass_count: int = 0
    drop_count: int = 0


class PacketFilterScoreboard:
    """
    Golden reference model for the packet filter.

    Evaluates rules in priority order (highest first) and returns
    the action of the first matching rule, or the default action.
    This mirrors the Verilog priority encoder exactly.
    """

    def __init__(self, rules: list[Rule], default_action: str = "drop"):
        self.rules = sorted(rules, key=lambda r: -r.priority)
        self.default_action = default_action
        self.stats = ScoreboardStats()

    def predict(self, frame: EthernetFrame) -> tuple[str, str]:
        """
        Predict the expected decision for a frame.
        Returns (action, matched_rule_name).
        """
        for rule in self.rules:
            if rule.matches(frame):
                return rule.action, rule.name
        return self.default_action, "__default__"

    def check(self, frame: EthernetFrame, actual_pass: int) -> tuple[str, str]:
        """
        Compare DUT decision against reference model.
        Raises ScoreboardMismatch on disagreement.
        Returns (action, matched_rule_name).
        """
        self.stats.total_packets += 1
        expected_action, matched_rule = self.predict(frame)
        expected_pass = 1 if expected_action == "pass" else 0

        self.stats.rule_hit_count[matched_rule] += 1
        if expected_pass:
            self.stats.pass_count += 1
        else:
            self.stats.drop_count += 1

        if actual_pass == expected_pass:
            self.stats.matches += 1
        else:
            self.stats.mismatches += 1
            raise ScoreboardMismatch(frame, expected_action, actual_pass, matched_rule)

        return expected_action, matched_rule

    def report(self) -> str:
        """Generate scoreboard summary report."""
        lines = [
            "=" * 60,
            "SCOREBOARD REPORT",
            "=" * 60,
            f"Total packets checked: {self.stats.total_packets}",
            f"Matches:               {self.stats.matches}",
            f"Mismatches:            {self.stats.mismatches}",
            f"Pass decisions:        {self.stats.pass_count}",
            f"Drop decisions:        {self.stats.drop_count}",
            "",
            "Rule Hit Distribution:",
        ]
        for rule_name, count in sorted(self.stats.rule_hit_count.items(),
                                        key=lambda x: -x[1]):
            pct = 100.0 * count / max(self.stats.total_packets, 1)
            bar = "#" * int(pct / 2)
            lines.append(f"  {rule_name:25s} {count:5d} ({pct:5.1f}%) {bar}")
        lines.append("=" * 60)
        return "\n".join(lines)
