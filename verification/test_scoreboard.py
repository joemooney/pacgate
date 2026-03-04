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
    Rule, PacketFilterScoreboard, PipelineStage, PipelineScoreboard,
    ipv4_matches_cidr, ipv6_matches_cidr, port_matches, byte_match_matches,
    toeplitz_hash, compute_rss_queue, _parse_ip_bytes, RSS_DEFAULT_KEY,
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


class TestGtpTeidMatch:
    def test_gtp_teid_exact_match(self):
        rule = Rule(name="gtp_tunnel", priority=100, action="pass", gtp_teid=1000)
        frame = _make_frame()
        assert rule.matches(frame, extracted={"gtp_teid": 1000})

    def test_gtp_teid_no_match(self):
        rule = Rule(name="gtp_tunnel", priority=100, action="pass", gtp_teid=1000)
        frame = _make_frame()
        assert not rule.matches(frame, extracted={"gtp_teid": 2000})

    def test_gtp_teid_none_rule_matches_any(self):
        rule = Rule(name="any_rule", priority=100, action="pass")
        frame = _make_frame()
        assert rule.matches(frame, extracted={"gtp_teid": 5000})

    def test_gtp_teid_missing_extracted(self):
        rule = Rule(name="gtp_tunnel", priority=100, action="pass", gtp_teid=1000)
        frame = _make_frame()
        assert not rule.matches(frame, extracted={})


class TestMplsMatch:
    def test_mpls_label_match(self):
        rule = Rule(name="mpls_vpn", priority=100, action="pass", mpls_label=100)
        frame = _make_frame(ethertype=0x8847)
        assert rule.matches(frame, extracted={"mpls_label": 100})

    def test_mpls_label_no_match(self):
        rule = Rule(name="mpls_vpn", priority=100, action="pass", mpls_label=100)
        frame = _make_frame(ethertype=0x8847)
        assert not rule.matches(frame, extracted={"mpls_label": 200})

    def test_mpls_tc_match(self):
        rule = Rule(name="mpls_prio", priority=100, action="pass", mpls_tc=7)
        frame = _make_frame(ethertype=0x8847)
        assert rule.matches(frame, extracted={"mpls_tc": 7})

    def test_mpls_bos_match(self):
        rule = Rule(name="mpls_bos", priority=100, action="pass", mpls_bos=1)
        frame = _make_frame(ethertype=0x8847)
        assert rule.matches(frame, extracted={"mpls_bos": 1})

    def test_mpls_multi_field_match(self):
        rule = Rule(name="mpls_full", priority=100, action="pass",
                    mpls_label=200, mpls_tc=3, mpls_bos=1)
        frame = _make_frame(ethertype=0x8847)
        assert rule.matches(frame, extracted={"mpls_label": 200, "mpls_tc": 3, "mpls_bos": 1})
        assert not rule.matches(frame, extracted={"mpls_label": 200, "mpls_tc": 3, "mpls_bos": 0})


class TestIgmpMldMatch:
    def test_igmp_type_match(self):
        rule = Rule(name="igmp_query", priority=100, action="pass", igmp_type=0x11)
        frame = _make_frame()
        assert rule.matches(frame, extracted={"igmp_type": 0x11})

    def test_igmp_type_no_match(self):
        rule = Rule(name="igmp_query", priority=100, action="pass", igmp_type=0x11)
        frame = _make_frame()
        assert not rule.matches(frame, extracted={"igmp_type": 0x22})

    def test_mld_type_match(self):
        rule = Rule(name="mld_query", priority=100, action="pass", mld_type=130)
        frame = _make_frame(ethertype=0x86DD)
        assert rule.matches(frame, extracted={"mld_type": 130})

    def test_mld_type_no_match(self):
        rule = Rule(name="mld_query", priority=100, action="pass", mld_type=130)
        frame = _make_frame(ethertype=0x86DD)
        assert not rule.matches(frame, extracted={"mld_type": 131})


class TestCoverageProtocols:
    """Tests for protocol-specific coverage sampling."""

    def _make_coverage(self):
        from verification.coverage import FilterCoverage
        return FilterCoverage(default_action="drop")

    def test_tunnel_type_vxlan_sampled(self):
        cov = self._make_coverage()
        frame = _make_frame()
        cov.sample(frame, decision_pass=True, vxlan_vni=100)
        assert cov.coverpoints["tunnel_type"].bins["vxlan"].hit

    def test_tunnel_type_gtp_sampled(self):
        cov = self._make_coverage()
        frame = _make_frame()
        cov.sample(frame, decision_pass=True, gtp_teid=1000)
        assert cov.coverpoints["tunnel_type"].bins["gtp_u"].hit

    def test_tunnel_type_plain_sampled(self):
        cov = self._make_coverage()
        frame = _make_frame()
        cov.sample(frame, decision_pass=True)
        assert cov.coverpoints["tunnel_type"].bins["plain"].hit

    def test_mpls_present_sampled(self):
        cov = self._make_coverage()
        frame = _make_frame()
        cov.sample(frame, decision_pass=True, mpls_label=100)
        assert cov.coverpoints["mpls_present"].bins["with_mpls"].hit

    def test_igmp_query_sampled(self):
        cov = self._make_coverage()
        frame = _make_frame()
        cov.sample(frame, decision_pass=True, igmp_type=0x11)
        assert cov.coverpoints["igmp_type_range"].bins["query"].hit

    def test_mld_listener_query_sampled(self):
        cov = self._make_coverage()
        frame = _make_frame(ethertype=0x86DD)
        cov.sample(frame, decision_pass=True, mld_type=130)
        assert cov.coverpoints["mld_type_range"].bins["listener_query"].hit

    def test_gtp_teid_range_sampled(self):
        cov = self._make_coverage()
        frame = _make_frame()
        cov.sample(frame, decision_pass=True, gtp_teid=5000)
        assert cov.coverpoints["gtp_teid_range"].bins["mid"].hit


class TestNshMatch:
    def test_nsh_spi_match(self):
        rule = Rule(name="nsh_path", priority=100, action="pass", nsh_spi=100)
        frame = _make_frame(ethertype=0x894F)
        assert rule.matches(frame, extracted={"nsh_spi": 100})

    def test_nsh_spi_no_match(self):
        rule = Rule(name="nsh_path", priority=100, action="pass", nsh_spi=100)
        frame = _make_frame(ethertype=0x894F)
        assert not rule.matches(frame, extracted={"nsh_spi": 200})

    def test_nsh_si_match(self):
        rule = Rule(name="nsh_index", priority=100, action="pass", nsh_si=255)
        frame = _make_frame(ethertype=0x894F)
        assert rule.matches(frame, extracted={"nsh_si": 255})

    def test_nsh_si_no_match(self):
        rule = Rule(name="nsh_index", priority=100, action="pass", nsh_si=255)
        frame = _make_frame(ethertype=0x894F)
        assert not rule.matches(frame, extracted={"nsh_si": 254})

    def test_nsh_multi_field_match(self):
        rule = Rule(name="nsh_full", priority=100, action="pass",
                    nsh_spi=100, nsh_si=255, nsh_next_protocol=1)
        frame = _make_frame(ethertype=0x894F)
        assert rule.matches(frame, extracted={"nsh_spi": 100, "nsh_si": 255, "nsh_next_protocol": 1})
        assert not rule.matches(frame, extracted={"nsh_spi": 100, "nsh_si": 255, "nsh_next_protocol": 2})

    def test_nsh_missing_extracted(self):
        rule = Rule(name="nsh_path", priority=100, action="pass", nsh_spi=100)
        frame = _make_frame(ethertype=0x894F)
        assert not rule.matches(frame, extracted={})


class TestGeneveVniMatch:
    def test_geneve_vni_match(self):
        """Test Geneve VNI matching"""
        rule = Rule(name="tenant", priority=100, action="pass",
                    ethertype=0x0800, ip_protocol=17, geneve_vni=1000)
        frame = _make_frame(ethertype=0x0800)
        assert rule.matches(frame, extracted={"ethertype": 0x0800, "ip_protocol": 17, "geneve_vni": 1000})

    def test_geneve_vni_mismatch(self):
        rule = Rule(name="tenant", priority=100, action="pass",
                    ethertype=0x0800, ip_protocol=17, geneve_vni=1000)
        frame = _make_frame(ethertype=0x0800)
        assert not rule.matches(frame, extracted={"ethertype": 0x0800, "ip_protocol": 17, "geneve_vni": 2000})

    def test_geneve_vni_missing_extracted(self):
        rule = Rule(name="tenant", priority=100, action="pass",
                    ethertype=0x0800, ip_protocol=17, geneve_vni=1000)
        frame = _make_frame(ethertype=0x0800)
        assert not rule.matches(frame, extracted={"ethertype": 0x0800, "ip_protocol": 17})


class TestIpTtlMatch:
    def test_ip_ttl_match(self):
        rule = Rule(name="low_ttl", priority=100, action="drop",
                    ethertype=0x0800, ip_ttl=1)
        frame = _make_frame(ethertype=0x0800)
        assert rule.matches(frame, extracted={"ip_ttl": 1})

    def test_ip_ttl_mismatch(self):
        rule = Rule(name="low_ttl", priority=100, action="drop",
                    ethertype=0x0800, ip_ttl=1)
        frame = _make_frame(ethertype=0x0800)
        assert not rule.matches(frame, extracted={"ip_ttl": 64})

    def test_ip_ttl_missing_extracted(self):
        rule = Rule(name="low_ttl", priority=100, action="drop",
                    ethertype=0x0800, ip_ttl=1)
        frame = _make_frame(ethertype=0x0800)
        assert not rule.matches(frame, extracted={})


class TestFrameLenMatch:
    def test_frame_len_match(self):
        rule = Rule(name="normal", priority=100, action="pass",
                    ethertype=0x0800, frame_len_min=64, frame_len_max=1518)
        frame = _make_frame(ethertype=0x0800)
        assert rule.matches(frame, extracted={"frame_len": 512})

    def test_frame_len_too_short(self):
        rule = Rule(name="normal", priority=100, action="pass",
                    ethertype=0x0800, frame_len_min=64, frame_len_max=1518)
        frame = _make_frame(ethertype=0x0800)
        assert not rule.matches(frame, extracted={"frame_len": 32})

    def test_frame_len_too_long(self):
        rule = Rule(name="normal", priority=100, action="pass",
                    ethertype=0x0800, frame_len_min=64, frame_len_max=1518)
        frame = _make_frame(ethertype=0x0800)
        assert not rule.matches(frame, extracted={"frame_len": 9000})

    def test_frame_len_boundary_min(self):
        rule = Rule(name="normal", priority=100, action="pass",
                    ethertype=0x0800, frame_len_min=64, frame_len_max=1518)
        frame = _make_frame(ethertype=0x0800)
        assert rule.matches(frame, extracted={"frame_len": 64})
        assert not rule.matches(frame, extracted={"frame_len": 63})

    def test_frame_len_boundary_max(self):
        rule = Rule(name="normal", priority=100, action="pass",
                    ethertype=0x0800, frame_len_min=64, frame_len_max=1518)
        frame = _make_frame(ethertype=0x0800)
        assert rule.matches(frame, extracted={"frame_len": 1518})
        assert not rule.matches(frame, extracted={"frame_len": 1519})

    def test_frame_len_min_only(self):
        """frame_len_min without frame_len_max: only lower bound enforced."""
        rule = Rule(name="jumbo", priority=100, action="pass",
                    ethertype=0x0800, frame_len_min=1519)
        frame = _make_frame(ethertype=0x0800)
        assert rule.matches(frame, extracted={"frame_len": 9000})
        assert not rule.matches(frame, extracted={"frame_len": 1518})

    def test_frame_len_max_only(self):
        """frame_len_max without frame_len_min: only upper bound enforced."""
        rule = Rule(name="small", priority=100, action="pass",
                    ethertype=0x0800, frame_len_max=128)
        frame = _make_frame(ethertype=0x0800)
        assert rule.matches(frame, extracted={"frame_len": 64})
        assert not rule.matches(frame, extracted={"frame_len": 129})

    def test_frame_len_no_extracted_uses_defaults(self):
        """Missing frame_len in extracted uses safe defaults (0 / 65535)."""
        rule_min = Rule(name="big_only", priority=100, action="pass",
                        ethertype=0x0800, frame_len_min=100)
        frame = _make_frame(ethertype=0x0800)
        # Default for min check is 0 — fails the min=100 test
        assert not rule_min.matches(frame, extracted={})

        rule_max = Rule(name="small_only", priority=100, action="pass",
                        ethertype=0x0800, frame_len_max=100)
        # Default for max check is 65535 — fails the max=100 test
        assert not rule_max.matches(frame, extracted={})


class TestProtocolDeterminism:
    """Tests for protocol-specific determinism check functions."""

    def test_gtp_determinism_check(self):
        from verification.properties import check_tunnel_determinism
        rule = Rule(name="gtp", priority=100, action="pass", gtp_teid=1000)
        sb = PacketFilterScoreboard([rule], default_action="drop")
        frame = _make_frame()
        assert check_tunnel_determinism(sb, frame, {"gtp_teid": 1000})

    def test_mpls_determinism_check(self):
        from verification.properties import check_tunnel_determinism
        rule = Rule(name="mpls", priority=100, action="pass", mpls_label=200)
        sb = PacketFilterScoreboard([rule], default_action="drop")
        frame = _make_frame(ethertype=0x8847)
        assert check_tunnel_determinism(sb, frame, {"mpls_label": 200})

    def test_igmp_determinism_check(self):
        from verification.properties import check_protocol_determinism
        rule = Rule(name="igmp", priority=100, action="pass", igmp_type=0x11)
        sb = PacketFilterScoreboard([rule], default_action="drop")
        frame = _make_frame()
        assert check_protocol_determinism(sb, frame, {"igmp_type": 0x11})

    def test_mld_determinism_check(self):
        from verification.properties import check_protocol_determinism
        rule = Rule(name="mld", priority=100, action="pass", mld_type=130)
        sb = PacketFilterScoreboard([rule], default_action="drop")
        frame = _make_frame(ethertype=0x86DD)
        assert check_protocol_determinism(sb, frame, {"mld_type": 130})


class TestPipelineScoreboard:
    """Tests for multi-stage pipeline scoreboard."""

    def test_both_stages_pass(self):
        stage1 = PipelineStage("classify", [Rule(name="web", priority=100, action="pass", dst_port=80)], "drop")
        stage2 = PipelineStage("enforce", [Rule(name="allow", priority=100, action="pass", dst_port=80)], "drop")
        sb = PipelineScoreboard([stage1, stage2])
        frame = _make_frame()
        action, rule = sb.predict(frame, {"dst_port": 80})
        assert action == "pass"
        assert rule == "allow"

    def test_first_stage_drops(self):
        stage1 = PipelineStage("classify", [], "drop")  # no rules, default drop
        stage2 = PipelineStage("enforce", [Rule(name="allow", priority=100, action="pass")], "pass")
        sb = PipelineScoreboard([stage1, stage2])
        frame = _make_frame()
        action, rule = sb.predict(frame, {})
        assert action == "drop"

    def test_second_stage_drops(self):
        stage1 = PipelineStage("classify", [Rule(name="web", priority=100, action="pass")], "drop")
        stage2 = PipelineStage("enforce", [], "drop")  # no rules, default drop
        sb = PipelineScoreboard([stage1, stage2])
        frame = _make_frame()
        action, rule = sb.predict(frame, {})
        assert action == "drop"

    def test_three_stages_all_pass(self):
        stage1 = PipelineStage("s1", [Rule(name="r1", priority=100, action="pass")], "drop")
        stage2 = PipelineStage("s2", [Rule(name="r2", priority=100, action="pass")], "drop")
        stage3 = PipelineStage("s3", [Rule(name="r3", priority=100, action="pass")], "drop")
        sb = PipelineScoreboard([stage1, stage2, stage3])
        frame = _make_frame()
        action, rule = sb.predict(frame, {})
        assert action == "pass"
        assert rule == "r3"  # last stage's rule

    def test_middle_stage_drops(self):
        stage1 = PipelineStage("s1", [Rule(name="r1", priority=100, action="pass")], "drop")
        stage2 = PipelineStage("s2", [], "drop")  # drops
        stage3 = PipelineStage("s3", [Rule(name="r3", priority=100, action="pass")], "drop")
        sb = PipelineScoreboard([stage1, stage2, stage3])
        frame = _make_frame()
        action, rule = sb.predict(frame, {})
        assert action == "drop"

    def test_check_raises_on_mismatch(self):
        stage1 = PipelineStage("s1", [], "drop")
        sb = PipelineScoreboard([stage1])
        frame = _make_frame()
        import pytest
        with pytest.raises(Exception):  # ScoreboardMismatch
            sb.check(frame, 1)  # actual=pass but expected=drop


class TestPtpMatch:
    def test_ptp_sync_match(self):
        rule = Rule(name="ptp_sync", priority=100, action="pass",
                    ethertype=0x88F7, ptp_message_type=0, ptp_version=2)
        frame = _make_frame(ethertype=0x88F7)
        assert rule.matches(frame, extracted={"ptp_message_type": 0, "ptp_version": 2})

    def test_ptp_domain_match(self):
        rule = Rule(name="ptp_dom", priority=100, action="pass",
                    ethertype=0x88F7, ptp_domain=1)
        frame = _make_frame(ethertype=0x88F7)
        assert rule.matches(frame, extracted={"ptp_domain": 1})

    def test_ptp_message_type_mismatch(self):
        rule = Rule(name="ptp_sync", priority=100, action="pass",
                    ethertype=0x88F7, ptp_message_type=0)
        frame = _make_frame(ethertype=0x88F7)
        assert not rule.matches(frame, extracted={"ptp_message_type": 1})

    def test_ptp_domain_mismatch(self):
        rule = Rule(name="ptp_dom", priority=100, action="pass",
                    ethertype=0x88F7, ptp_domain=0)
        frame = _make_frame(ethertype=0x88F7)
        assert not rule.matches(frame, extracted={"ptp_domain": 1})

    def test_ptp_multi_field_match(self):
        rule = Rule(name="ptp_full", priority=100, action="pass",
                    ethertype=0x88F7, ptp_message_type=0, ptp_domain=0, ptp_version=2)
        frame = _make_frame(ethertype=0x88F7)
        assert rule.matches(frame, extracted={"ptp_message_type": 0, "ptp_domain": 0, "ptp_version": 2})

    def test_ptp_missing_extracted(self):
        rule = Rule(name="ptp_sync", priority=100, action="pass",
                    ethertype=0x88F7, ptp_message_type=0)
        frame = _make_frame(ethertype=0x88F7)
        assert not rule.matches(frame, extracted={})


class TestRssQueueAssignment:
    def test_toeplitz_hash_deterministic(self):
        src = _parse_ip_bytes("10.0.0.1")
        dst = _parse_ip_bytes("10.0.0.2")
        h1 = toeplitz_hash(src, dst, 12345, 80, 6)
        h2 = toeplitz_hash(src, dst, 12345, 80, 6)
        assert h1 == h2

    def test_toeplitz_hash_different_ips_differ(self):
        src1 = _parse_ip_bytes("10.0.0.1")
        src2 = _parse_ip_bytes("10.0.0.2")
        dst = _parse_ip_bytes("10.0.0.3")
        h1 = toeplitz_hash(src1, dst, 80, 80, 6)
        h2 = toeplitz_hash(src2, dst, 80, 80, 6)
        assert h1 != h2

    def test_toeplitz_hash_nonzero(self):
        src = _parse_ip_bytes("192.168.1.1")
        dst = _parse_ip_bytes("10.0.0.1")
        h = toeplitz_hash(src, dst, 443, 8080, 6)
        assert h != 0

    def test_compute_rss_queue_within_range(self):
        src = _parse_ip_bytes("10.0.0.1")
        dst = _parse_ip_bytes("10.0.0.2")
        for num_q in [1, 2, 4, 8, 16]:
            q = compute_rss_queue(src, dst, 12345, 80, 6, num_queues=num_q)
            assert 0 <= q < num_q

    def test_rss_queue_override_in_scoreboard(self):
        rule = Rule(name="pin_q3", priority=100, action="pass",
                    ethertype=0x0800, rss_queue=3)
        sb = PacketFilterScoreboard(rules=[rule], default_action="drop")
        frame = _make_frame(ethertype=0x0800)
        q = sb.predict_rss_queue(frame, num_queues=4,
                                  extracted={"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"})
        assert q == 3

    def test_rss_queue_hash_based_in_scoreboard(self):
        rule = Rule(name="allow_web", priority=100, action="pass",
                    ethertype=0x0800)
        sb = PacketFilterScoreboard(rules=[rule], default_action="drop")
        frame = _make_frame(ethertype=0x0800)
        q = sb.predict_rss_queue(frame, num_queues=4,
                                  extracted={"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                                             "src_port": 12345, "dst_port": 80, "ip_protocol": 6})
        assert 0 <= q < 4


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
