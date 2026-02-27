"""
Unit tests for PacGate scoreboard — L3/L4/IPv6/VXLAN matching.

Run with: python -m pytest verification/test_scoreboard.py -v
"""

import os
import sys

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from verification.packet import EthernetFrame, mac_to_bytes
from verification.scoreboard import (
    Rule, PacketFilterScoreboard,
    ipv4_matches_cidr, ipv6_matches_cidr, port_matches, byte_match_matches,
)


def _make_frame(ethertype=0x0800):
    """Create a basic Ethernet frame for testing."""
    return EthernetFrame(
        dst_mac=mac_to_bytes("de:ad:be:ef:00:01"),
        src_mac=mac_to_bytes("02:00:00:00:00:01"),
        ethertype=ethertype,
        payload=bytes(46),
    )


class TestIpv4CidrMatch:
    def test_ipv4_cidr_match(self):
        assert ipv4_matches_cidr("10.1.2.3", "10.0.0.0/8")

    def test_ipv4_cidr_no_match(self):
        assert not ipv4_matches_cidr("192.168.1.1", "10.0.0.0/8")

    def test_ipv4_host_match(self):
        assert ipv4_matches_cidr("10.0.0.1", "10.0.0.1")

    def test_ipv4_any_match(self):
        assert ipv4_matches_cidr("172.16.0.1", "0.0.0.0/0")


class TestPortMatch:
    def test_port_exact_match(self):
        assert port_matches(80, exact=80)

    def test_port_exact_no_match(self):
        assert not port_matches(443, exact=80)

    def test_port_range_match(self):
        assert port_matches(8080, port_range=(1024, 65535))

    def test_port_range_boundary(self):
        assert port_matches(1024, port_range=(1024, 65535))
        assert port_matches(65535, port_range=(1024, 65535))
        assert not port_matches(1023, port_range=(1024, 65535))


class TestIpv6CidrMatch:
    def test_ipv6_cidr_match(self):
        assert ipv6_matches_cidr("2001:db8::1", "2001:db8::/32")

    def test_ipv6_cidr_no_match(self):
        assert not ipv6_matches_cidr("2001:db9::1", "2001:db8::/32")

    def test_ipv6_link_local(self):
        assert ipv6_matches_cidr("fe80::1", "fe80::/10")


class TestVxlanVniMatch:
    def test_vxlan_vni_match(self):
        rule = Rule(name="tenant", priority=100, action="pass", vxlan_vni=100)
        frame = _make_frame()
        assert rule.matches(frame, extracted={"vxlan_vni": 100})

    def test_vxlan_vni_no_match(self):
        rule = Rule(name="tenant", priority=100, action="pass", vxlan_vni=100)
        frame = _make_frame()
        assert not rule.matches(frame, extracted={"vxlan_vni": 200})


class TestByteMatchMatch:
    def test_byte_match_simple(self):
        payload = bytes([0x45, 0x00, 0x00, 0x28])
        matches = [{"offset": 0, "value": 0x45}]
        assert byte_match_matches(payload, matches)

    def test_byte_match_with_mask(self):
        payload = bytes([0x45, 0x00, 0x00, 0x28])
        matches = [{"offset": 0, "value": 0x40, "mask": 0xF0}]
        assert byte_match_matches(payload, matches)

    def test_byte_match_out_of_range(self):
        payload = bytes([0x45])
        matches = [{"offset": 5, "value": 0x45}]
        assert not byte_match_matches(payload, matches)


class TestMultiFieldL3L4:
    def test_multi_field_l3l4(self):
        """Rule matching on src_ip + ip_protocol + dst_port."""
        rule = Rule(
            name="web_server", priority=100, action="pass",
            ethertype=0x0800, src_ip="10.0.0.0/8", ip_protocol=6, dst_port=80,
        )
        frame = _make_frame(ethertype=0x0800)
        extracted = {
            "src_ip": "10.1.2.3",
            "ip_protocol": 6,
            "dst_port": 80,
        }
        assert rule.matches(frame, extracted)

    def test_multi_field_l3l4_wrong_port(self):
        rule = Rule(
            name="web_server", priority=100, action="pass",
            ethertype=0x0800, src_ip="10.0.0.0/8", ip_protocol=6, dst_port=80,
        )
        frame = _make_frame(ethertype=0x0800)
        extracted = {
            "src_ip": "10.1.2.3",
            "ip_protocol": 6,
            "dst_port": 443,
        }
        assert not rule.matches(frame, extracted)


class TestScoreboardWithExtracted:
    def test_predict_with_l3(self):
        rules = [
            Rule(name="allow_subnet", priority=100, action="pass",
                 src_ip="10.0.0.0/8"),
        ]
        sb = PacketFilterScoreboard(rules, default_action="drop")
        frame = _make_frame()
        action, name = sb.predict(frame, extracted={"src_ip": "10.1.2.3"})
        assert action == "pass"
        assert name == "allow_subnet"

    def test_predict_l3_no_match(self):
        rules = [
            Rule(name="allow_subnet", priority=100, action="pass",
                 src_ip="10.0.0.0/8"),
        ]
        sb = PacketFilterScoreboard(rules, default_action="drop")
        frame = _make_frame()
        action, name = sb.predict(frame, extracted={"src_ip": "192.168.1.1"})
        assert action == "drop"
        assert name == "__default__"

    def test_check_with_extracted(self):
        rules = [
            Rule(name="allow_web", priority=100, action="pass",
                 dst_port=80),
        ]
        sb = PacketFilterScoreboard(rules, default_action="drop")
        frame = _make_frame()
        action, name = sb.check(frame, actual_pass=1, extracted={"dst_port": 80})
        assert action == "pass"
        assert name == "allow_web"

    def test_port_range_scoreboard(self):
        rules = [
            Rule(name="high_ports", priority=100, action="pass",
                 dst_port_range=(1024, 65535)),
        ]
        sb = PacketFilterScoreboard(rules, default_action="drop")
        frame = _make_frame()
        action, _ = sb.predict(frame, extracted={"dst_port": 8080})
        assert action == "pass"
        action, _ = sb.predict(frame, extracted={"dst_port": 80})
        assert action == "drop"

    def test_ipv6_scoreboard(self):
        rules = [
            Rule(name="allow_ipv6", priority=100, action="pass",
                 src_ipv6="2001:db8::/32", ipv6_next_header=6),
        ]
        sb = PacketFilterScoreboard(rules, default_action="drop")
        frame = _make_frame(ethertype=0x86DD)
        action, _ = sb.predict(frame, extracted={
            "src_ipv6": "2001:db8::1", "ipv6_next_header": 6,
        })
        assert action == "pass"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
