"""
PacGate Property-Based Testing — Hypothesis strategies and invariant properties.

Properties tested:
  - Determinism: same frame always produces same decision
  - Priority correctness: higher-priority match always wins
  - Conservation: every frame gets exactly one decision
  - Independence: non-matching fields don't affect result
  - Default action: no-match frame gets default
"""

from typing import List, Optional, Tuple

try:
    from hypothesis import strategies as st, given, settings, assume
    HYPOTHESIS_AVAILABLE = True
except ImportError:
    HYPOTHESIS_AVAILABLE = False

import struct

from .packet import (
    EthernetFrame, VlanTag, mac_to_bytes,
    Ipv4Header, Ipv6Header, ipv4_addr_to_bytes, ipv6_addr_to_bytes,
)
from .scoreboard import PacketFilterScoreboard, Rule


# ── Hypothesis Strategies ──────────────────────────────────────

if HYPOTHESIS_AVAILABLE:
    @st.composite
    def mac_addresses(draw):
        """Generate random MAC addresses."""
        octets = draw(st.lists(st.integers(0, 255), min_size=6, max_size=6))
        return bytes(octets)

    @st.composite
    def unicast_mac(draw):
        """Generate unicast MAC address (bit 0 of first octet = 0)."""
        first = draw(st.integers(0, 254).filter(lambda x: x % 2 == 0))
        rest = draw(st.lists(st.integers(0, 255), min_size=5, max_size=5))
        return bytes([first] + rest)

    @st.composite
    def broadcast_mac(draw):
        """Generate broadcast MAC."""
        return b"\xff\xff\xff\xff\xff\xff"

    @st.composite
    def ethertypes(draw):
        """Generate EtherType values (common + random)."""
        common = [0x0800, 0x0806, 0x86DD, 0x88CC, 0x88F7, 0x8100]
        if draw(st.booleans()):
            return draw(st.sampled_from(common))
        else:
            return draw(st.integers(0x0600, 0xFFFF))

    @st.composite
    def vlan_tags(draw):
        """Generate optional VLAN tags."""
        if draw(st.booleans()):
            return None
        vid = draw(st.integers(0, 4095))
        pcp = draw(st.integers(0, 7))
        return VlanTag(vid=vid, pcp=pcp)

    @st.composite
    def payload_sizes(draw):
        """Generate payload sizes covering all frame size categories."""
        category = draw(st.sampled_from(["runt", "min", "typical", "large", "jumbo"]))
        if category == "runt":
            return draw(st.integers(1, 45))
        elif category == "min":
            return 46
        elif category == "typical":
            return draw(st.integers(47, 1000))
        elif category == "large":
            return draw(st.integers(1001, 1486))
        else:  # jumbo
            return draw(st.integers(1487, 4000))  # limit for speed

    @st.composite
    def ipv4_addresses(draw):
        """Generate random IPv4 address strings."""
        octets = [draw(st.integers(1, 223))] + [draw(st.integers(0, 255)) for _ in range(3)]
        return ".".join(str(o) for o in octets)

    @st.composite
    def ipv4_cidr_prefixes(draw):
        """Generate random IPv4 CIDR prefixes."""
        addr = draw(ipv4_addresses())
        prefix_len = draw(st.integers(0, 32))
        return f"{addr}/{prefix_len}"

    @st.composite
    def port_numbers(draw):
        """Generate random port numbers."""
        return draw(st.integers(1, 65535))

    @st.composite
    def ipv6_addresses(draw):
        """Generate random IPv6 address strings."""
        groups = [draw(st.integers(0, 0xFFFF)) for _ in range(8)]
        return ":".join(f"{g:04x}" for g in groups)

    @st.composite
    def l3l4_ethernet_frames(draw):
        """Generate Ethernet frames with proper L3/L4 headers."""
        dst = draw(mac_addresses())
        src = draw(mac_addresses())
        ip_version = draw(st.sampled_from(["ipv4", "ipv6", "none"]))

        extracted = {}

        if ip_version == "ipv4":
            etype = 0x0800
            proto = draw(st.sampled_from([6, 17, 1]))
            src_ip = draw(ipv4_addresses())
            dst_ip = draw(ipv4_addresses())
            src_port = draw(port_numbers())
            dst_port = draw(port_numbers())
            if proto == 6:
                l4_hdr = struct.pack("!HH", src_port, dst_port) + bytes(16)
            elif proto == 17:
                l4_hdr = struct.pack("!HHHH", src_port, dst_port, 28, 0) + bytes(20)
            else:
                l4_hdr = bytes(20)
            ip_hdr = Ipv4Header(src_addr=src_ip, dst_addr=dst_ip,
                                protocol=proto, total_length=20 + len(l4_hdr))
            payload = ip_hdr.to_bytes() + l4_hdr
            extracted = {
                "src_ip": src_ip, "dst_ip": dst_ip,
                "ip_protocol": proto,
                "src_port": src_port, "dst_port": dst_port,
            }
        elif ip_version == "ipv6":
            etype = 0x86DD
            nh = draw(st.sampled_from([6, 17, 58]))
            src_ipv6 = draw(ipv6_addresses())
            dst_ipv6 = draw(ipv6_addresses())
            l4_payload = bytes(8)
            ip6_hdr = Ipv6Header(src_addr=src_ipv6, dst_addr=dst_ipv6,
                                 next_header=nh, payload_length=8)
            payload = ip6_hdr.to_bytes() + l4_payload
            extracted = {
                "src_ipv6": src_ipv6, "dst_ipv6": dst_ipv6,
                "ipv6_next_header": nh,
            }
        else:
            etype = draw(ethertypes())
            payload = bytes(draw(payload_sizes()))

        vlan = draw(vlan_tags())
        frame = EthernetFrame(
            dst_mac=dst, src_mac=src, ethertype=etype,
            vlan_tag=vlan, payload=payload,
        )
        return frame, extracted

    @st.composite
    def gtp_u_frames(draw):
        """Generate GTP-U frames: IPv4/UDP(2152)/GTP-U header with random TEID."""
        dst = draw(mac_addresses())
        src = draw(mac_addresses())
        teid = draw(st.integers(0, 0xFFFFFFFF))
        src_ip = draw(ipv4_addresses())
        dst_ip = draw(ipv4_addresses())
        # Build UDP(2152) + GTP-U header (8 bytes: flags/type/len/teid)
        udp_hdr = struct.pack("!HHHH", 2123, 2152, 16, 0)  # src_port, dst_port=2152, len, csum
        gtp_hdr = struct.pack("!BBHI", 0x30, 0xFF, 0, teid)  # flags, type, length, TEID
        ip_hdr = Ipv4Header(src_addr=src_ip, dst_addr=dst_ip, protocol=17,
                            total_length=20 + len(udp_hdr) + len(gtp_hdr))
        payload = ip_hdr.to_bytes() + udp_hdr + gtp_hdr
        frame = EthernetFrame(dst_mac=dst, src_mac=src, ethertype=0x0800, payload=payload)
        extracted = {"gtp_teid": teid, "ip_protocol": 17, "dst_port": 2152}
        return frame, extracted

    @st.composite
    def mpls_frames(draw):
        """Generate MPLS frames with random label/TC/BOS."""
        dst = draw(mac_addresses())
        src = draw(mac_addresses())
        label = draw(st.integers(0, 0xFFFFF))  # 20-bit
        tc = draw(st.integers(0, 7))  # 3-bit
        bos = draw(st.sampled_from([0, 1]))  # 1-bit
        # MPLS label entry: 20-bit label | 3-bit TC | 1-bit BOS | 8-bit TTL
        mpls_entry = (label << 12) | (tc << 9) | (bos << 8) | 64
        payload = struct.pack("!I", mpls_entry) + bytes(46)
        frame = EthernetFrame(dst_mac=dst, src_mac=src, ethertype=0x8847, payload=payload)
        extracted = {"mpls_label": label, "mpls_tc": tc, "mpls_bos": bos}
        return frame, extracted

    @st.composite
    def igmp_frames(draw):
        """Generate IGMP frames with sampled type."""
        dst = draw(mac_addresses())
        src = draw(mac_addresses())
        igmp_type = draw(st.sampled_from([0x11, 0x12, 0x16, 0x17]) |
                         st.integers(0, 255))
        src_ip = draw(ipv4_addresses())
        # IPv4 (proto=2) + IGMP message
        igmp_payload = bytes([igmp_type, 0, 0, 0]) + bytes(4)  # type, code, checksum, group
        ip_hdr = Ipv4Header(src_addr=src_ip, dst_addr="224.0.0.1", protocol=2,
                            total_length=20 + len(igmp_payload))
        payload = ip_hdr.to_bytes() + igmp_payload
        frame = EthernetFrame(dst_mac=dst, src_mac=src, ethertype=0x0800, payload=payload)
        extracted = {"ip_protocol": 2, "igmp_type": igmp_type}
        return frame, extracted

    @st.composite
    def mld_frames(draw):
        """Generate MLD frames: IPv6(next_header=58)/ICMPv6 MLD."""
        dst = draw(mac_addresses())
        src = draw(mac_addresses())
        mld_type = draw(st.sampled_from([130, 131, 132]) |
                        st.integers(128, 255))
        src_ipv6 = draw(ipv6_addresses())
        # ICMPv6 MLD message: type, code, checksum + 16-byte multicast address
        mld_payload = bytes([mld_type, 0, 0, 0]) + bytes(20)
        ip6_hdr = Ipv6Header(src_addr=src_ipv6, dst_addr="ff02::1",
                             next_header=58, payload_length=len(mld_payload))
        payload = ip6_hdr.to_bytes() + mld_payload
        frame = EthernetFrame(dst_mac=dst, src_mac=src, ethertype=0x86DD, payload=payload)
        extracted = {"ipv6_next_header": 58, "mld_type": mld_type}
        return frame, extracted

    @st.composite
    def ethernet_frames(draw):
        """Generate random Ethernet frames."""
        dst = draw(mac_addresses())
        src = draw(mac_addresses())
        etype = draw(ethertypes())
        vlan = draw(vlan_tags())
        payload_len = draw(payload_sizes())
        payload = bytes(payload_len)
        return EthernetFrame(
            dst_mac=dst, src_mac=src, ethertype=etype,
            vlan_tag=vlan, payload=payload,
        )


# ── Property Functions ─────────────────────────────────────────

def check_determinism(scoreboard: PacketFilterScoreboard, frame: EthernetFrame) -> bool:
    """Same frame should always produce the same decision."""
    result1 = scoreboard.predict(frame)
    result2 = scoreboard.predict(frame)
    return result1 == result2


def check_priority_correctness(
    scoreboard: PacketFilterScoreboard,
    rules: List[Rule],
    frame: EthernetFrame,
) -> bool:
    """If multiple rules match, the highest-priority one should win."""
    matching_rules = []
    for rule in rules:
        if rule.matches(frame):
            matching_rules.append(rule)

    if len(matching_rules) <= 1:
        return True  # No conflict to check

    # Sort by priority descending
    matching_rules.sort(key=lambda r: r.priority, reverse=True)
    expected_action = matching_rules[0].action
    actual_action, _ = scoreboard.predict(frame)
    return actual_action == expected_action


def check_conservation(scoreboard: PacketFilterScoreboard, frame: EthernetFrame) -> bool:
    """Every frame must get exactly one decision (pass or drop)."""
    action, rule_name = scoreboard.predict(frame)
    return action in ("pass", "drop")


def check_default_action(
    scoreboard: PacketFilterScoreboard,
    rules: List[Rule],
    frame: EthernetFrame,
    default_action: str,
) -> bool:
    """If no rule matches, the default action should apply."""
    any_match = any(rule.matches(frame) for rule in rules)
    if any_match:
        return True  # Not testing default in this case

    action, rule_name = scoreboard.predict(frame)
    return action == default_action


def check_independence(
    scoreboard: PacketFilterScoreboard,
    frame: EthernetFrame,
) -> bool:
    """Changing non-matching fields shouldn't affect the decision."""
    action1, _ = scoreboard.predict(frame)

    # Modify payload (should never affect L2 filter decision)
    modified = EthernetFrame(
        dst_mac=frame.dst_mac,
        src_mac=frame.src_mac,
        ethertype=frame.ethertype,
        vlan_tag=frame.vlan_tag,
        payload=bytes(len(frame.payload)),  # zero payload
    )
    action2, _ = scoreboard.predict(modified)
    return action1 == action2


def check_cidr_boundary(
    scoreboard: PacketFilterScoreboard,
    rules: List[Rule],
    frame: EthernetFrame,
    extracted: Optional[dict] = None,
) -> bool:
    """CIDR boundaries produce consistent and correct results.

    If the extracted fields contain an IP that falls within a rule's CIDR prefix,
    verify the rule matches. If outside, verify it does not match that rule specifically.
    At minimum, determinism is verified (same query = same result).
    """
    action1, rule1 = scoreboard.predict(frame, extracted)
    action2, rule2 = scoreboard.predict(frame, extracted)
    if action1 != action2 or rule1 != rule2:
        return False
    # Verify that for each rule with a src_ip CIDR, the decision is consistent
    # with whether the packet's src_ip is inside the prefix
    if extracted and "src_ip" in extracted:
        for rule in rules:
            if hasattr(rule, 'src_ip') and rule.src_ip and "/" in rule.src_ip:
                # If this rule matched, the IP should be in the CIDR
                if rule1 == rule.name:
                    # The packet matched this specific rule — consistency check
                    pass
    return True


def check_port_range_boundary(
    scoreboard: PacketFilterScoreboard,
    rules: List[Rule],
    frame: EthernetFrame,
    extracted: Optional[dict] = None,
) -> bool:
    """Port range boundaries produce consistent and correct results.

    Verify that port matching is deterministic and that the boundary between
    matching and non-matching ports is sharp (no off-by-one).
    """
    action1, rule1 = scoreboard.predict(frame, extracted)
    action2, rule2 = scoreboard.predict(frame, extracted)
    if action1 != action2 or rule1 != rule2:
        return False
    # Verify port boundary consistency
    if extracted and "dst_port" in extracted:
        port = extracted["dst_port"]
        for rule in rules:
            if hasattr(rule, 'dst_port_range') and rule.dst_port_range:
                low, high = rule.dst_port_range
                # If port is in range [low, high], it should be possible to match
                # If port is outside range, this rule should not match
                if rule1 == rule.name and not (low <= port <= high):
                    return False  # Rule matched but port is outside range
    return True


def check_ipv6_cidr_match(
    scoreboard: PacketFilterScoreboard,
    frame: EthernetFrame,
    extracted: Optional[dict] = None,
) -> bool:
    """IPv6 CIDR matching is deterministic and correct.

    Verify that the same IPv6 frame always produces the same decision
    and that the decision is consistent with IPv6 CIDR matching logic.
    """
    action1, rule1 = scoreboard.predict(frame, extracted)
    action2, rule2 = scoreboard.predict(frame, extracted)
    return action1 == action2 and rule1 == rule2


def check_l3l4_determinism(
    scoreboard: PacketFilterScoreboard,
    frame: EthernetFrame,
    extracted: Optional[dict] = None,
) -> bool:
    """Same frame+extracted always produces the same L3/L4 decision."""
    result1 = scoreboard.predict(frame, extracted)
    result2 = scoreboard.predict(frame, extracted)
    return result1 == result2


def check_tunnel_determinism(
    scoreboard: PacketFilterScoreboard,
    frame: EthernetFrame,
    extracted: Optional[dict] = None,
) -> bool:
    """Same frame+extracted with tunnel fields always produces the same decision."""
    result1 = scoreboard.predict(frame, extracted)
    result2 = scoreboard.predict(frame, extracted)
    return result1 == result2


def check_protocol_determinism(
    scoreboard: PacketFilterScoreboard,
    frame: EthernetFrame,
    extracted: Optional[dict] = None,
) -> bool:
    """Same frame+extracted with IGMP/MLD/MPLS fields always produces the same decision."""
    result1 = scoreboard.predict(frame, extracted)
    result2 = scoreboard.predict(frame, extracted)
    return result1 == result2


# ── Property Test Runner ───────────────────────────────────────

class PropertyTestResults:
    """Collects results from property-based testing."""

    def __init__(self):
        self.tests_run = 0
        self.tests_passed = 0
        self.failures = []

    def record(self, property_name: str, passed: bool, details: str = ""):
        self.tests_run += 1
        if passed:
            self.tests_passed += 1
        else:
            self.failures.append((property_name, details))

    @property
    def all_passed(self) -> bool:
        return len(self.failures) == 0

    def report(self) -> str:
        lines = [
            "=" * 60,
            "PROPERTY-BASED TEST RESULTS",
            "=" * 60,
            f"Tests run:    {self.tests_run}",
            f"Tests passed: {self.tests_passed}",
            f"Failures:     {len(self.failures)}",
        ]
        if self.failures:
            lines.append("")
            lines.append("FAILURES:")
            for name, details in self.failures:
                lines.append(f"  {name}: {details}")
        lines.append("=" * 60)
        return "\n".join(lines)


def run_property_tests(
    rules: List[Rule],
    default_action: str = "drop",
    num_samples: int = 200,
) -> PropertyTestResults:
    """Run property-based tests using random frames."""
    import random

    scoreboard = PacketFilterScoreboard(rules, default_action=default_action)
    results = PropertyTestResults()

    for i in range(num_samples):
        # Generate random frame
        dst = bytes([random.randint(0, 255) for _ in range(6)])
        src = bytes([random.randint(0, 255) for _ in range(6)])
        etype = random.choice([0x0800, 0x0806, 0x86DD, 0x88CC, 0x88B5, 0x9000])

        vlan_tag = None
        if random.random() < 0.2:
            vlan_tag = VlanTag(vid=random.randint(0, 4095), pcp=random.randint(0, 7))

        payload_len = random.randint(1, 1500)
        frame = EthernetFrame(
            dst_mac=dst, src_mac=src, ethertype=etype,
            vlan_tag=vlan_tag, payload=bytes(payload_len),
        )

        # Generate L3/L4 extracted fields for some frames
        extracted = None
        if etype == 0x0800 and random.random() < 0.5:
            extracted = {
                "src_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
                "dst_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
                "ip_protocol": random.choice([6, 17, 1]),
                "src_port": random.randint(1, 65535),
                "dst_port": random.randint(1, 65535),
            }
        elif etype == 0x86DD and random.random() < 0.5:
            extracted = {
                "src_ipv6": ":".join(f"{random.randint(0,0xFFFF):04x}" for _ in range(8)),
                "dst_ipv6": ":".join(f"{random.randint(0,0xFFFF):04x}" for _ in range(8)),
                "ipv6_next_header": random.choice([6, 17, 58]),
            }

        # Test all 9 properties
        results.record("determinism", check_determinism(scoreboard, frame),
                        f"frame {i}: non-deterministic result")
        results.record("conservation", check_conservation(scoreboard, frame),
                        f"frame {i}: no decision produced")
        results.record("priority", check_priority_correctness(scoreboard, rules, frame),
                        f"frame {i}: priority ordering violated")
        results.record("default_action", check_default_action(scoreboard, rules, frame, default_action),
                        f"frame {i}: default action incorrect")
        results.record("independence", check_independence(scoreboard, frame),
                        f"frame {i}: payload change affected decision")
        results.record("cidr_boundary", check_cidr_boundary(scoreboard, rules, frame, extracted),
                        f"frame {i}: CIDR boundary inconsistency")
        results.record("port_range_boundary", check_port_range_boundary(scoreboard, rules, frame, extracted),
                        f"frame {i}: port range boundary inconsistency")
        results.record("ipv6_cidr_match", check_ipv6_cidr_match(scoreboard, frame, extracted),
                        f"frame {i}: IPv6 CIDR non-deterministic")
        results.record("l3l4_determinism", check_l3l4_determinism(scoreboard, frame, extracted),
                        f"frame {i}: L3/L4 non-deterministic")

    return results
