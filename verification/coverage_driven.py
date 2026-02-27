"""
Coverage-Directed Test Generation for PacGate verification.

Analyzes coverage state, identifies uncovered bins, and generates
targeted packets to fill coverage gaps.
"""

import random
from typing import Optional

from .packet import (
    EthernetFrame, PacketFactory, VlanTag, Ipv4Header, Ipv6Header,
    mac_to_bytes, ipv4_addr_to_bytes, ipv6_addr_to_bytes,
)
from .coverage import FilterCoverage
import struct


class CoverageDirector:
    """Analyzes coverage and generates targeted packets to close gaps."""

    def __init__(self, coverage: FilterCoverage):
        self.coverage = coverage

    def get_uncovered_bins(self) -> list:
        """Return list of (coverpoint_name, bin_name) tuples not yet hit."""
        uncovered = []
        for cp_name, cp in self.coverage.coverpoints.items():
            for bin_name, cbin in cp.bins.items():
                if not cbin.hit:
                    uncovered.append((cp_name, bin_name))
        return uncovered

    def generate_targeted_packet(self, cp_name: str, bin_name: str) -> Optional[EthernetFrame]:
        """Generate a packet targeting a specific uncovered bin."""
        generators = {
            "ethertype": self._gen_ethertype,
            "dst_mac_type": self._gen_dst_mac_type,
            "frame_size": self._gen_frame_size,
            "vlan_present": self._gen_vlan,
            "corner_cases": self._gen_corner_case,
            "ip_protocol": self._gen_ip_protocol,
            "dst_port_range": self._gen_dst_port_range,
            "ipv6_address_type": self._gen_ipv6_addr_type,
            "l3_type": self._gen_l3_type,
        }
        gen = generators.get(cp_name)
        if gen:
            return gen(bin_name)
        return None

    def generate_coverage_closure_packets(self, max_packets: int = 100) -> list:
        """Generate packets targeting all uncovered bins."""
        packets = []
        uncovered = self.get_uncovered_bins()
        for cp_name, bin_name in uncovered:
            if len(packets) >= max_packets:
                break
            pkt = self.generate_targeted_packet(cp_name, bin_name)
            if pkt is not None:
                packets.append(pkt)
        return packets

    def _gen_ethertype(self, bin_name: str) -> Optional[EthernetFrame]:
        etype_map = {
            "ipv4": 0x0800, "arp": 0x0806, "ipv6": 0x86DD,
            "vlan_tag": 0x8100, "lldp": 0x88CC, "ptp": 0x88F7,
            "other": 0x88B5,
        }
        etype = etype_map.get(bin_name)
        if etype:
            return EthernetFrame(
                dst_mac=mac_to_bytes("de:ad:be:ef:00:01"),
                src_mac=mac_to_bytes("02:00:00:00:00:01"),
                ethertype=etype,
                payload=bytes(46),
            )
        return None

    def _gen_dst_mac_type(self, bin_name: str) -> Optional[EthernetFrame]:
        if bin_name == "broadcast":
            return PacketFactory.broadcast()
        elif bin_name == "multicast":
            dst = bytes([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01])
            return EthernetFrame(dst_mac=dst, src_mac=mac_to_bytes("02:00:00:00:00:01"),
                                 ethertype=0x0800, payload=bytes(46))
        elif bin_name == "zero":
            return EthernetFrame(dst_mac=bytes(6), src_mac=mac_to_bytes("02:00:00:00:00:01"),
                                 ethertype=0x0800, payload=bytes(46))
        elif bin_name == "unicast":
            return PacketFactory.ipv4()
        return None

    def _gen_frame_size(self, bin_name: str) -> Optional[EthernetFrame]:
        if bin_name == "runt":
            return PacketFactory.runt_frame()
        elif bin_name == "min":
            return EthernetFrame(dst_mac=mac_to_bytes("de:ad:be:ef:00:01"),
                                 src_mac=mac_to_bytes("02:00:00:00:00:01"),
                                 ethertype=0x0800, payload=bytes(50))
        elif bin_name == "typical":
            return PacketFactory.ipv4(payload_size=200)
        elif bin_name == "large":
            return PacketFactory.ipv4(payload_size=1400)
        elif bin_name == "jumbo":
            return PacketFactory.jumbo_frame()
        return None

    def _gen_vlan(self, bin_name: str) -> Optional[EthernetFrame]:
        if bin_name == "tagged":
            return PacketFactory.vlan_tagged(vid=100, pcp=3)
        elif bin_name == "untagged":
            return PacketFactory.ipv4()
        return None

    def _gen_corner_case(self, bin_name: str) -> Optional[EthernetFrame]:
        if bin_name == "runt_frame":
            return PacketFactory.runt_frame()
        elif bin_name == "jumbo_frame":
            return PacketFactory.jumbo_frame()
        elif bin_name == "all_zero_mac":
            return EthernetFrame(dst_mac=bytes(6), src_mac=mac_to_bytes("02:00:00:00:00:01"),
                                 ethertype=0x0800, payload=bytes(46))
        elif bin_name == "all_ff_mac":
            return PacketFactory.broadcast()
        elif bin_name == "vlan_pcp_7":
            return PacketFactory.vlan_tagged(vid=1, pcp=7)
        elif bin_name == "back_to_back":
            return PacketFactory.ipv4()
        return None

    def _gen_ip_protocol(self, bin_name: str) -> Optional[EthernetFrame]:
        if bin_name == "tcp":
            return PacketFactory.ipv4_tcp()
        elif bin_name == "udp":
            return PacketFactory.ipv4_udp()
        elif bin_name == "icmp":
            ip_hdr = Ipv4Header(protocol=1, total_length=28)
            payload = ip_hdr.to_bytes() + bytes(8)
            return EthernetFrame(dst_mac=mac_to_bytes("de:ad:be:ef:00:01"),
                                 src_mac=mac_to_bytes("02:00:00:00:00:01"),
                                 ethertype=0x0800, payload=payload)
        elif bin_name == "icmpv6":
            return PacketFactory.ipv6_icmp()
        elif bin_name == "other":
            ip_hdr = Ipv4Header(protocol=47, total_length=28)  # GRE
            payload = ip_hdr.to_bytes() + bytes(8)
            return EthernetFrame(dst_mac=mac_to_bytes("de:ad:be:ef:00:01"),
                                 src_mac=mac_to_bytes("02:00:00:00:00:01"),
                                 ethertype=0x0800, payload=payload)
        return None

    def _gen_dst_port_range(self, bin_name: str) -> Optional[EthernetFrame]:
        if bin_name == "well_known":
            return PacketFactory.ipv4_tcp(dst_port=80)
        elif bin_name == "registered":
            return PacketFactory.ipv4_tcp(dst_port=8080)
        elif bin_name == "ephemeral":
            return PacketFactory.ipv4_tcp(dst_port=50000)
        return None

    def _gen_ipv6_addr_type(self, bin_name: str) -> Optional[EthernetFrame]:
        if bin_name == "link_local":
            return PacketFactory.ipv6_link_local()
        elif bin_name == "global_unicast":
            return PacketFactory.ipv6_tcp(src_ip="2001:db8::1", dst_ip="2001:db8::2")
        elif bin_name == "multicast":
            return PacketFactory.ipv6_icmp(src_ip="fe80::1", dst_ip="ff02::1")
        elif bin_name == "loopback":
            ip6_hdr = Ipv6Header(src_addr="::1", dst_addr="::1", next_header=58, payload_length=8)
            payload = ip6_hdr.to_bytes() + bytes(8)
            return EthernetFrame(dst_mac=mac_to_bytes("00:00:00:00:00:01"),
                                 src_mac=mac_to_bytes("00:00:00:00:00:01"),
                                 ethertype=0x86DD, payload=payload)
        return None

    def _gen_l3_type(self, bin_name: str) -> Optional[EthernetFrame]:
        if bin_name == "ipv4":
            return PacketFactory.ipv4()
        elif bin_name == "ipv6":
            return PacketFactory.ipv6()
        elif bin_name == "arp":
            return PacketFactory.arp()
        elif bin_name == "other":
            return EthernetFrame(dst_mac=mac_to_bytes("de:ad:be:ef:00:01"),
                                 src_mac=mac_to_bytes("02:00:00:00:00:01"),
                                 ethertype=0x88B5, payload=bytes(46))
        return None
