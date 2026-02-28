"""
PacGate Scoreboard — Reference model for packet filter decisions.

Implements the same rule-matching logic as the generated Verilog,
in Python, for independent verification. Compares DUT decisions
against expected results and reports mismatches.
"""

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, Tuple

from .packet import EthernetFrame, mac_matches


def ipv4_matches_cidr(addr: str, cidr: str) -> bool:
    """Check if an IPv4 address matches a CIDR prefix."""
    try:
        if "/" not in cidr:
            cidr = cidr + "/32"
        network = ipaddress.ip_network(cidr, strict=False)
        return ipaddress.ip_address(addr) in network
    except (ValueError, TypeError):
        return False


def ipv6_matches_cidr(addr: str, cidr: str) -> bool:
    """Check if an IPv6 address matches a CIDR prefix."""
    try:
        if "/" not in cidr:
            cidr = cidr + "/128"
        network = ipaddress.ip_network(cidr, strict=False)
        return ipaddress.ip_address(addr) in network
    except (ValueError, TypeError):
        return False


def port_matches(port: int, exact: Optional[int] = None,
                 port_range: Optional[Tuple[int, int]] = None) -> bool:
    """Check if a port matches an exact value or range."""
    if exact is not None:
        return port == exact
    if port_range is not None:
        return port_range[0] <= port <= port_range[1]
    return True


def byte_match_matches(payload: bytes, matches: list) -> bool:
    """Check if raw bytes match byte_match rules.

    Each match is a dict with 'offset', 'value', and optional 'mask'.
    Values are integers.
    """
    for bm in matches:
        offset = bm["offset"]
        value = bm["value"]
        mask = bm.get("mask", 0xFF)
        if offset >= len(payload):
            return False
        if (payload[offset] & mask) != (value & mask):
            return False
    return True


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
    # L3/L4 fields
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_protocol: Optional[int] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    src_port_range: Optional[Tuple[int, int]] = None
    dst_port_range: Optional[Tuple[int, int]] = None
    # Tunnel fields
    vxlan_vni: Optional[int] = None
    # IPv6 fields
    src_ipv6: Optional[str] = None
    dst_ipv6: Optional[str] = None
    ipv6_next_header: Optional[int] = None
    # Byte-offset matching
    byte_match: Optional[list] = None
    # GTP-U tunnel
    gtp_teid: Optional[int] = None
    # MPLS label stack
    mpls_label: Optional[int] = None
    mpls_tc: Optional[int] = None
    mpls_bos: Optional[int] = None
    # IGMP/MLD multicast
    igmp_type: Optional[int] = None
    mld_type: Optional[int] = None
    # QoS fields (IPv4 TOS byte)
    ip_dscp: Optional[int] = None
    ip_ecn: Optional[int] = None
    # IPv6 Traffic Class
    ipv6_dscp: Optional[int] = None
    ipv6_ecn: Optional[int] = None
    # TCP flags
    tcp_flags: Optional[int] = None
    tcp_flags_mask: Optional[int] = None
    # ICMP Type/Code
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    # ICMPv6 Type/Code
    icmpv6_type: Optional[int] = None
    icmpv6_code: Optional[int] = None
    # ARP fields
    arp_opcode: Optional[int] = None
    arp_spa: Optional[str] = None
    arp_tpa: Optional[str] = None
    # IPv6 extension fields
    ipv6_hop_limit: Optional[int] = None
    ipv6_flow_label: Optional[int] = None

    def matches(self, frame: EthernetFrame, extracted: Optional[dict] = None) -> bool:
        """Check if this rule matches the given frame.

        Args:
            frame: The Ethernet frame to check
            extracted: Optional dict with parsed L3/L4 fields:
                src_ip, dst_ip, ip_protocol, src_port, dst_port,
                src_ipv6, dst_ipv6, ipv6_next_header, vxlan_vni, raw_bytes
        """
        if extracted is None:
            extracted = {}

        # L2 matching
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

        # L3 IPv4 matching
        if self.src_ip is not None:
            pkt_ip = extracted.get("src_ip")
            if pkt_ip is None or not ipv4_matches_cidr(pkt_ip, self.src_ip):
                return False
        if self.dst_ip is not None:
            pkt_ip = extracted.get("dst_ip")
            if pkt_ip is None or not ipv4_matches_cidr(pkt_ip, self.dst_ip):
                return False
        if self.ip_protocol is not None:
            pkt_proto = extracted.get("ip_protocol")
            if pkt_proto is None or pkt_proto != self.ip_protocol:
                return False

        # L4 port matching
        if self.src_port is not None:
            pkt_port = extracted.get("src_port")
            if pkt_port is None or not port_matches(pkt_port, exact=self.src_port):
                return False
        if self.dst_port is not None:
            pkt_port = extracted.get("dst_port")
            if pkt_port is None or not port_matches(pkt_port, exact=self.dst_port):
                return False
        if self.src_port_range is not None:
            pkt_port = extracted.get("src_port")
            if pkt_port is None or not port_matches(pkt_port, port_range=self.src_port_range):
                return False
        if self.dst_port_range is not None:
            pkt_port = extracted.get("dst_port")
            if pkt_port is None or not port_matches(pkt_port, port_range=self.dst_port_range):
                return False

        # VXLAN matching
        if self.vxlan_vni is not None:
            pkt_vni = extracted.get("vxlan_vni")
            if pkt_vni is None or pkt_vni != self.vxlan_vni:
                return False

        # IPv6 matching
        if self.src_ipv6 is not None:
            pkt_ip = extracted.get("src_ipv6")
            if pkt_ip is None or not ipv6_matches_cidr(pkt_ip, self.src_ipv6):
                return False
        if self.dst_ipv6 is not None:
            pkt_ip = extracted.get("dst_ipv6")
            if pkt_ip is None or not ipv6_matches_cidr(pkt_ip, self.dst_ipv6):
                return False
        if self.ipv6_next_header is not None:
            pkt_nh = extracted.get("ipv6_next_header")
            if pkt_nh is None or pkt_nh != self.ipv6_next_header:
                return False

        # Byte-offset matching
        if self.byte_match is not None:
            raw = extracted.get("raw_bytes", frame.payload)
            if not byte_match_matches(raw, self.byte_match):
                return False

        # GTP-U tunnel matching
        if self.gtp_teid is not None:
            pkt_teid = extracted.get("gtp_teid")
            if pkt_teid is None or pkt_teid != self.gtp_teid:
                return False

        # MPLS label stack matching
        if self.mpls_label is not None:
            pkt_label = extracted.get("mpls_label")
            if pkt_label is None or pkt_label != self.mpls_label:
                return False
        if self.mpls_tc is not None:
            pkt_tc = extracted.get("mpls_tc")
            if pkt_tc is None or pkt_tc != self.mpls_tc:
                return False
        if self.mpls_bos is not None:
            pkt_bos = extracted.get("mpls_bos")
            if pkt_bos is None or pkt_bos != self.mpls_bos:
                return False

        # IGMP/MLD multicast matching
        if self.igmp_type is not None:
            pkt_igmp = extracted.get("igmp_type")
            if pkt_igmp is None or pkt_igmp != self.igmp_type:
                return False
        if self.mld_type is not None:
            pkt_mld = extracted.get("mld_type")
            if pkt_mld is None or pkt_mld != self.mld_type:
                return False

        # QoS DSCP/ECN matching
        if self.ip_dscp is not None:
            pkt_dscp = extracted.get("ip_dscp")
            if pkt_dscp is None or pkt_dscp != self.ip_dscp:
                return False
        if self.ip_ecn is not None:
            pkt_ecn = extracted.get("ip_ecn")
            if pkt_ecn is None or pkt_ecn != self.ip_ecn:
                return False

        # IPv6 Traffic Class matching
        if self.ipv6_dscp is not None:
            pkt_dscp = extracted.get("ipv6_dscp")
            if pkt_dscp is None or pkt_dscp != self.ipv6_dscp:
                return False
        if self.ipv6_ecn is not None:
            pkt_ecn = extracted.get("ipv6_ecn")
            if pkt_ecn is None or pkt_ecn != self.ipv6_ecn:
                return False

        # TCP flags matching (mask-aware)
        if self.tcp_flags is not None:
            pkt_flags = extracted.get("tcp_flags")
            if pkt_flags is None:
                return False
            mask = self.tcp_flags_mask if self.tcp_flags_mask is not None else 0xFF
            if (pkt_flags & mask) != (self.tcp_flags & mask):
                return False

        # ICMP Type/Code matching
        if self.icmp_type is not None:
            pkt_icmp_type = extracted.get("icmp_type")
            if pkt_icmp_type is None or pkt_icmp_type != self.icmp_type:
                return False
        if self.icmp_code is not None:
            pkt_icmp_code = extracted.get("icmp_code")
            if pkt_icmp_code is None or pkt_icmp_code != self.icmp_code:
                return False

        # ICMPv6 Type/Code matching
        if self.icmpv6_type is not None:
            pkt_icmpv6_type = extracted.get("icmpv6_type")
            if pkt_icmpv6_type is None or pkt_icmpv6_type != self.icmpv6_type:
                return False
        if self.icmpv6_code is not None:
            pkt_icmpv6_code = extracted.get("icmpv6_code")
            if pkt_icmpv6_code is None or pkt_icmpv6_code != self.icmpv6_code:
                return False

        # ARP fields matching
        if self.arp_opcode is not None:
            pkt_arp_opcode = extracted.get("arp_opcode")
            if pkt_arp_opcode is None or pkt_arp_opcode != self.arp_opcode:
                return False
        if self.arp_spa is not None:
            pkt_arp_spa = extracted.get("arp_spa")
            if pkt_arp_spa is None or not ipv4_matches_cidr(pkt_arp_spa, self.arp_spa):
                return False
        if self.arp_tpa is not None:
            pkt_arp_tpa = extracted.get("arp_tpa")
            if pkt_arp_tpa is None or not ipv4_matches_cidr(pkt_arp_tpa, self.arp_tpa):
                return False

        # IPv6 extension fields matching
        if self.ipv6_hop_limit is not None:
            pkt_hop_limit = extracted.get("ipv6_hop_limit")
            if pkt_hop_limit is None or pkt_hop_limit != self.ipv6_hop_limit:
                return False
        if self.ipv6_flow_label is not None:
            pkt_flow_label = extracted.get("ipv6_flow_label")
            if pkt_flow_label is None or pkt_flow_label != self.ipv6_flow_label:
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

    def predict(self, frame: EthernetFrame, extracted: Optional[dict] = None) -> tuple[str, str]:
        """
        Predict the expected decision for a frame.
        Returns (action, matched_rule_name).

        Args:
            frame: The Ethernet frame
            extracted: Optional dict with parsed L3/L4 fields
        """
        for rule in self.rules:
            if rule.matches(frame, extracted):
                return rule.action, rule.name
        return self.default_action, "__default__"

    def check(self, frame: EthernetFrame, actual_pass: int,
              extracted: Optional[dict] = None) -> tuple[str, str]:
        """
        Compare DUT decision against reference model.
        Raises ScoreboardMismatch on disagreement.
        Returns (action, matched_rule_name).

        Args:
            frame: The Ethernet frame
            actual_pass: DUT decision (1=pass, 0=drop)
            extracted: Optional dict with parsed L3/L4 fields
        """
        self.stats.total_packets += 1
        expected_action, matched_rule = self.predict(frame, extracted)
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
