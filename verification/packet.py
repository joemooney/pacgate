"""
Ethernet frame construction and manipulation for PacGate verification.

Provides a PacketFactory for building directed and random test frames,
plus utilities for MAC address and EtherType handling.
Includes IPv4/IPv6 L3 headers and TCP/UDP L4 headers.
"""

import random
import socket
import struct
from dataclasses import dataclass, field
from typing import Optional


def mac_to_bytes(mac_str: str) -> bytes:
    """Convert 'aa:bb:cc:dd:ee:ff' to 6-byte bytes object."""
    return bytes(int(x, 16) for x in mac_str.split(":"))


def bytes_to_mac(b: bytes) -> str:
    """Convert 6-byte bytes to 'aa:bb:cc:dd:ee:ff' string."""
    return ":".join(f"{x:02x}" for x in b)


def mac_matches(frame_mac: bytes, rule_mac: str) -> bool:
    """Check if a frame MAC matches a rule MAC (with wildcard support)."""
    parts = rule_mac.split(":")
    for i, part in enumerate(parts):
        if part == "*":
            continue
        if frame_mac[i] != int(part, 16):
            return False
    return True


def ipv4_addr_to_bytes(addr_str: str) -> bytes:
    """Convert '10.0.0.1' to 4-byte bytes."""
    return socket.inet_aton(addr_str)


def ipv6_addr_to_bytes(addr_str: str) -> bytes:
    """Convert IPv6 address string to 16-byte bytes."""
    return socket.inet_pton(socket.AF_INET6, addr_str)


@dataclass
class VlanTag:
    """802.1Q VLAN tag."""
    pcp: int = 0      # 3-bit priority
    dei: int = 0      # 1-bit drop eligible
    vid: int = 0      # 12-bit VLAN ID

    def to_bytes(self) -> bytes:
        """Encode as 4 bytes: 0x8100 + TCI."""
        tci = (self.pcp << 13) | (self.dei << 12) | self.vid
        return struct.pack(">HH", 0x8100, tci)


@dataclass
class OuterVlanTag:
    """802.1ad outer VLAN tag (QinQ / double tagging).

    Encodes as 4 bytes: 0x88A8 (S-Tag TPID) + TCI.
    Used in service provider networks for stacking an outer (S-Tag)
    VLAN around the customer's inner 802.1Q C-Tag.
    """
    outer_vlan_id: int = 0     # 12-bit outer VLAN ID
    outer_vlan_pcp: int = 0    # 3-bit outer priority code point
    dei: int = 0               # 1-bit drop eligible indicator

    def to_bytes(self) -> bytes:
        """Encode as 4 bytes: 0x88A8 + TCI."""
        tci = (self.outer_vlan_pcp << 13) | (self.dei << 12) | self.outer_vlan_id
        return struct.pack(">HH", 0x88A8, tci)


@dataclass
class Ipv4Header:
    """IPv4 header (20 bytes minimum)."""
    src_addr: str = "10.0.0.1"
    dst_addr: str = "10.0.0.2"
    protocol: int = 6       # TCP by default
    ttl: int = 64
    total_length: int = 40  # IP header + payload
    dont_fragment: bool = False    # DF flag (1-bit)
    more_fragments: bool = False   # MF flag (1-bit)
    frag_offset: int = 0           # 13-bit fragment offset (in 8-byte units)

    def to_bytes(self) -> bytes:
        """Serialize to 20-byte IPv4 header (no options)."""
        ver_ihl = 0x45  # version=4, IHL=5 (20 bytes)
        dscp_ecn = 0
        # Flags (3 bits) + Fragment Offset (13 bits) = 16-bit field
        # Bit 15: reserved (0), Bit 14: DF, Bit 13: MF, Bits 12-0: frag_offset
        flags = 0
        if self.dont_fragment:
            flags |= 0x4000  # DF bit (bit 14)
        if self.more_fragments:
            flags |= 0x2000  # MF bit (bit 13)
        flags_frag = flags | (self.frag_offset & 0x1FFF)
        identification = 0
        checksum = 0  # simplified (not computed)
        src = ipv4_addr_to_bytes(self.src_addr)
        dst = ipv4_addr_to_bytes(self.dst_addr)
        return struct.pack(">BBHHHBBH4s4s",
            ver_ihl, dscp_ecn, self.total_length,
            identification, flags_frag,
            self.ttl, self.protocol, checksum,
            src, dst)


@dataclass
class Ipv6Header:
    """IPv6 header (40 bytes fixed)."""
    src_addr: str = "2001:db8::1"
    dst_addr: str = "2001:db8::2"
    next_header: int = 6    # TCP by default
    hop_limit: int = 64
    payload_length: int = 20
    traffic_class: int = 0
    flow_label: int = 0

    def to_bytes(self) -> bytes:
        """Serialize to 40-byte IPv6 header."""
        ver_tc_fl = (6 << 28) | (self.traffic_class << 20) | self.flow_label
        src = ipv6_addr_to_bytes(self.src_addr)
        dst = ipv6_addr_to_bytes(self.dst_addr)
        return struct.pack(">IHBB16s16s",
            ver_tc_fl, self.payload_length,
            self.next_header, self.hop_limit,
            src, dst)


@dataclass
class EthernetFrame:
    """Ethernet frame representation for verification."""
    dst_mac: bytes = field(default_factory=lambda: bytes(6))
    src_mac: bytes = field(default_factory=lambda: bytes(6))
    ethertype: int = 0x0800
    vlan_tag: Optional[VlanTag] = None
    outer_vlan_tag: Optional[OuterVlanTag] = None
    payload: bytes = field(default_factory=lambda: bytes(46))

    def to_bytes(self) -> bytes:
        """Serialize to wire format.

        For QinQ (802.1ad) double tagging, the outer S-Tag (0x88A8)
        precedes the inner C-Tag (0x8100) on the wire:
            DST + SRC + [outer 0x88A8 TCI] + [inner 0x8100 TCI] + EtherType + payload
        """
        frame = self.dst_mac + self.src_mac
        if self.outer_vlan_tag:
            frame += self.outer_vlan_tag.to_bytes()
        if self.vlan_tag:
            frame += self.vlan_tag.to_bytes()
        frame += struct.pack(">H", self.ethertype)
        frame += self.payload
        return frame

    @property
    def dst_mac_str(self) -> str:
        return bytes_to_mac(self.dst_mac)

    @property
    def src_mac_str(self) -> str:
        return bytes_to_mac(self.src_mac)

    def __len__(self):
        return len(self.to_bytes())


class PacketFactory:
    """Factory for constructing test Ethernet frames."""

    BROADCAST_MAC = b"\xff\xff\xff\xff\xff\xff"
    ZERO_MAC = b"\x00\x00\x00\x00\x00\x00"

    @staticmethod
    def arp(dst_mac="ff:ff:ff:ff:ff:ff", src_mac="02:00:00:00:00:01") -> EthernetFrame:
        """ARP request frame."""
        return EthernetFrame(
            dst_mac=mac_to_bytes(dst_mac),
            src_mac=mac_to_bytes(src_mac),
            ethertype=0x0806,
            payload=bytes(28),  # ARP payload
        )

    @staticmethod
    def ipv4(dst_mac="de:ad:be:ef:00:01", src_mac="02:00:00:00:00:01",
             payload_size=46) -> EthernetFrame:
        """IPv4 frame (basic, no L3 header)."""
        return EthernetFrame(
            dst_mac=mac_to_bytes(dst_mac),
            src_mac=mac_to_bytes(src_mac),
            ethertype=0x0800,
            payload=bytes(payload_size),
        )

    @staticmethod
    def ipv4_tcp(
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=12345, dst_port=80,
        dst_mac="de:ad:be:ef:00:01", src_mac="02:00:00:00:00:01",
        payload_size=20,
    ) -> EthernetFrame:
        """IPv4 TCP frame with proper L3/L4 headers."""
        tcp_hdr = struct.pack(">HH", src_port, dst_port) + bytes(16)  # minimal TCP
        ip_hdr = Ipv4Header(
            src_addr=src_ip, dst_addr=dst_ip,
            protocol=6, total_length=20 + len(tcp_hdr) + payload_size,
        )
        payload = ip_hdr.to_bytes() + tcp_hdr + bytes(payload_size)
        return EthernetFrame(
            dst_mac=mac_to_bytes(dst_mac),
            src_mac=mac_to_bytes(src_mac),
            ethertype=0x0800,
            payload=payload,
        )

    @staticmethod
    def ipv4_udp(
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=12345, dst_port=53,
        dst_mac="de:ad:be:ef:00:01", src_mac="02:00:00:00:00:01",
        payload_size=20,
    ) -> EthernetFrame:
        """IPv4 UDP frame with proper L3/L4 headers."""
        udp_hdr = struct.pack(">HHHH", src_port, dst_port, 8 + payload_size, 0)
        ip_hdr = Ipv4Header(
            src_addr=src_ip, dst_addr=dst_ip,
            protocol=17, total_length=20 + len(udp_hdr) + payload_size,
        )
        payload = ip_hdr.to_bytes() + udp_hdr + bytes(payload_size)
        return EthernetFrame(
            dst_mac=mac_to_bytes(dst_mac),
            src_mac=mac_to_bytes(src_mac),
            ethertype=0x0800,
            payload=payload,
        )

    @staticmethod
    def ipv6(dst_mac="de:ad:be:ef:00:01", src_mac="02:00:00:00:00:01") -> EthernetFrame:
        """IPv6 frame (basic, no L3 header)."""
        return EthernetFrame(
            dst_mac=mac_to_bytes(dst_mac),
            src_mac=mac_to_bytes(src_mac),
            ethertype=0x86DD,
            payload=bytes(46),
        )

    @staticmethod
    def ipv6_tcp(
        src_ip="2001:db8::1", dst_ip="2001:db8::2",
        src_port=12345, dst_port=80,
        dst_mac="de:ad:be:ef:00:01", src_mac="02:00:00:00:00:01",
        payload_size=20,
    ) -> EthernetFrame:
        """IPv6 TCP frame with proper L3/L4 headers."""
        tcp_hdr = struct.pack(">HH", src_port, dst_port) + bytes(16)
        ip6_hdr = Ipv6Header(
            src_addr=src_ip, dst_addr=dst_ip,
            next_header=6, payload_length=len(tcp_hdr) + payload_size,
        )
        payload = ip6_hdr.to_bytes() + tcp_hdr + bytes(payload_size)
        return EthernetFrame(
            dst_mac=mac_to_bytes(dst_mac),
            src_mac=mac_to_bytes(src_mac),
            ethertype=0x86DD,
            payload=payload,
        )

    @staticmethod
    def ipv6_udp(
        src_ip="2001:db8::1", dst_ip="2001:db8::2",
        src_port=12345, dst_port=53,
        dst_mac="de:ad:be:ef:00:01", src_mac="02:00:00:00:00:01",
        payload_size=20,
    ) -> EthernetFrame:
        """IPv6 UDP frame with proper L3/L4 headers."""
        udp_hdr = struct.pack(">HHHH", src_port, dst_port, 8 + payload_size, 0)
        ip6_hdr = Ipv6Header(
            src_addr=src_ip, dst_addr=dst_ip,
            next_header=17, payload_length=len(udp_hdr) + payload_size,
        )
        payload = ip6_hdr.to_bytes() + udp_hdr + bytes(payload_size)
        return EthernetFrame(
            dst_mac=mac_to_bytes(dst_mac),
            src_mac=mac_to_bytes(src_mac),
            ethertype=0x86DD,
            payload=payload,
        )

    @staticmethod
    def ipv6_icmp(
        src_ip="fe80::1", dst_ip="ff02::1",
        dst_mac="33:33:00:00:00:01", src_mac="02:00:00:00:00:01",
    ) -> EthernetFrame:
        """IPv6 ICMPv6 frame (next_header=58)."""
        icmp_payload = bytes(8)  # minimal ICMPv6
        ip6_hdr = Ipv6Header(
            src_addr=src_ip, dst_addr=dst_ip,
            next_header=58, payload_length=len(icmp_payload),
        )
        payload = ip6_hdr.to_bytes() + icmp_payload
        return EthernetFrame(
            dst_mac=mac_to_bytes(dst_mac),
            src_mac=mac_to_bytes(src_mac),
            ethertype=0x86DD,
            payload=payload,
        )

    @staticmethod
    def ipv6_link_local(
        src_ip="fe80::1", dst_ip="fe80::2",
        next_header=58,
        dst_mac="de:ad:be:ef:00:01", src_mac="02:00:00:00:00:01",
    ) -> EthernetFrame:
        """IPv6 link-local frame."""
        payload_data = bytes(8)
        ip6_hdr = Ipv6Header(
            src_addr=src_ip, dst_addr=dst_ip,
            next_header=next_header, payload_length=len(payload_data),
        )
        payload = ip6_hdr.to_bytes() + payload_data
        return EthernetFrame(
            dst_mac=mac_to_bytes(dst_mac),
            src_mac=mac_to_bytes(src_mac),
            ethertype=0x86DD,
            payload=payload,
        )

    @staticmethod
    def vlan_tagged(vid: int, pcp: int = 0, ethertype: int = 0x0800,
                    dst_mac="de:ad:be:ef:00:01", src_mac="02:00:00:00:00:01") -> EthernetFrame:
        """VLAN-tagged frame."""
        return EthernetFrame(
            dst_mac=mac_to_bytes(dst_mac),
            src_mac=mac_to_bytes(src_mac),
            ethertype=ethertype,
            vlan_tag=VlanTag(pcp=pcp, vid=vid),
            payload=bytes(46),
        )

    @staticmethod
    def broadcast(ethertype: int = 0x0800) -> EthernetFrame:
        """Broadcast frame."""
        return EthernetFrame(
            dst_mac=PacketFactory.BROADCAST_MAC,
            src_mac=mac_to_bytes("02:00:00:00:00:01"),
            ethertype=ethertype,
        )

    @staticmethod
    def from_vendor(oui: str = "00:1a:2b", ethertype: int = 0x0800) -> EthernetFrame:
        """Frame from a specific vendor OUI."""
        oui_bytes = mac_to_bytes(oui + ":00:00:00")[:3]
        src = oui_bytes + bytes([random.randint(0, 255) for _ in range(3)])
        return EthernetFrame(
            dst_mac=mac_to_bytes("de:ad:be:ef:00:01"),
            src_mac=src,
            ethertype=ethertype,
            payload=bytes(46),
        )

    @staticmethod
    def random_frame(
        ethertype_pool=None,
        mac_type="unicast",
        min_payload=46,
        max_payload=1500,
    ) -> EthernetFrame:
        """Generate a random frame with controlled properties."""
        if ethertype_pool is None:
            ethertype_pool = [0x0800, 0x0806, 0x86DD, 0x88CC, 0x88B5]

        # Random destination MAC
        if mac_type == "broadcast":
            dst = PacketFactory.BROADCAST_MAC
        elif mac_type == "multicast":
            dst = bytes([random.randint(0, 255) | 0x01] + [random.randint(0, 255) for _ in range(5)])
        else:
            dst = bytes([random.randint(0, 255) & 0xFE] + [random.randint(0, 255) for _ in range(5)])

        src = bytes([random.randint(0, 255) & 0xFE] + [random.randint(0, 255) for _ in range(5)])

        payload_size = random.randint(min_payload, max_payload)

        return EthernetFrame(
            dst_mac=dst,
            src_mac=src,
            ethertype=random.choice(ethertype_pool),
            payload=bytes(random.randint(0, 255) for _ in range(payload_size)),
        )

    @staticmethod
    def gtp_u(
        teid: int = 1000,
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        dst_mac="de:ad:be:ef:00:01", src_mac="02:00:00:00:00:01",
    ) -> EthernetFrame:
        """GTP-U frame: Ethernet + IPv4(UDP:2152) + GTP header with TEID."""
        # GTP header (8 bytes): flags=0x30 (v1, PT=1), type=0xFF (T-PDU), length, TEID
        inner_payload = bytes(20)
        gtp_hdr = struct.pack(">BBHI",
            0x30,       # flags: version=1, PT=1
            0xFF,       # message type: T-PDU
            len(inner_payload),  # length
            teid,       # TEID (32-bit)
        ) + inner_payload
        # UDP header: src=random, dst=2152
        udp_hdr = struct.pack(">HHHH", 12345, 2152, 8 + len(gtp_hdr), 0)
        # IPv4 header
        ip_hdr = Ipv4Header(
            src_addr=src_ip, dst_addr=dst_ip,
            protocol=17, total_length=20 + len(udp_hdr) + len(gtp_hdr),
        )
        payload = ip_hdr.to_bytes() + udp_hdr + gtp_hdr
        return EthernetFrame(
            dst_mac=mac_to_bytes(dst_mac),
            src_mac=mac_to_bytes(src_mac),
            ethertype=0x0800,
            payload=payload,
        )

    @staticmethod
    def mpls(
        label: int = 100,
        tc: int = 0,
        bos: int = 1,
        dst_mac="de:ad:be:ef:00:01", src_mac="02:00:00:00:00:01",
    ) -> EthernetFrame:
        """MPLS frame: Ethernet(0x8847) + MPLS label entry + inner payload."""
        # MPLS header (4 bytes): label(20) + TC(3) + BOS(1) + TTL(8)
        mpls_word = (label << 12) | (tc << 9) | (bos << 8) | 64  # TTL=64
        mpls_hdr = struct.pack(">I", mpls_word)
        inner_payload = bytes(46)
        payload = mpls_hdr + inner_payload
        return EthernetFrame(
            dst_mac=mac_to_bytes(dst_mac),
            src_mac=mac_to_bytes(src_mac),
            ethertype=0x8847,
            payload=payload,
        )

    @staticmethod
    def igmp(
        igmp_type: int = 0x11,
        src_ip="10.0.0.1", dst_ip="224.0.0.1",
        dst_mac="01:00:5e:00:00:01", src_mac="02:00:00:00:00:01",
    ) -> EthernetFrame:
        """IGMP frame: Ethernet + IPv4(proto=2) + IGMP message."""
        # IGMP message (8 bytes): type + max_resp + checksum + group_addr
        igmp_msg = struct.pack(">BBH4s",
            igmp_type,
            0,          # max response time
            0,          # checksum (simplified)
            ipv4_addr_to_bytes("0.0.0.0"),  # group address
        )
        ip_hdr = Ipv4Header(
            src_addr=src_ip, dst_addr=dst_ip,
            protocol=2, total_length=20 + len(igmp_msg),
        )
        payload = ip_hdr.to_bytes() + igmp_msg
        return EthernetFrame(
            dst_mac=mac_to_bytes(dst_mac),
            src_mac=mac_to_bytes(src_mac),
            ethertype=0x0800,
            payload=payload,
        )

    @staticmethod
    def mld(
        mld_type: int = 130,
        src_ip="fe80::1", dst_ip="ff02::1",
        dst_mac="33:33:00:00:00:01", src_mac="02:00:00:00:00:01",
    ) -> EthernetFrame:
        """MLD frame: Ethernet + IPv6(next_header=58) + ICMPv6 MLD message."""
        # MLD message (24 bytes): type + code + checksum + max_resp + reserved + mcast_addr
        mld_msg = struct.pack(">BBH",
            mld_type,   # ICMPv6 type (130=query, 131=report, 132=done)
            0,          # code
            0,          # checksum (simplified)
        ) + struct.pack(">HH", 0, 0) + bytes(16)  # max_resp + reserved + multicast_addr
        ip6_hdr = Ipv6Header(
            src_addr=src_ip, dst_addr=dst_ip,
            next_header=58, payload_length=len(mld_msg),
        )
        payload = ip6_hdr.to_bytes() + mld_msg
        return EthernetFrame(
            dst_mac=mac_to_bytes(dst_mac),
            src_mac=mac_to_bytes(src_mac),
            ethertype=0x86DD,
            payload=payload,
        )

    @staticmethod
    def oam_cfm(
        oam_level: int = 3,
        oam_opcode: int = 1,
        dst_mac="01:80:c2:00:00:30", src_mac="02:00:00:00:00:01",
    ) -> EthernetFrame:
        """IEEE 802.1ag CFM (OAM) frame: EtherType 0x8902.

        CFM header (4 bytes minimum):
          - MD Level (3 bits, top of byte 0) + Version (5 bits, bottom of byte 0)
          - OpCode (byte 1)
          - Flags (byte 2)
          - First TLV Offset (byte 3)
        """
        # CFM common header
        md_level_version = ((oam_level & 0x07) << 5) | 0  # version=0
        cfm_hdr = struct.pack(">BBBB",
            md_level_version,
            oam_opcode,
            0,      # flags
            4,      # first TLV offset (minimal: point past header)
        )
        # Minimal TLV (End TLV = 0x00)
        cfm_payload = cfm_hdr + bytes([0x00]) + bytes(45)
        return EthernetFrame(
            dst_mac=mac_to_bytes(dst_mac),
            src_mac=mac_to_bytes(src_mac),
            ethertype=0x8902,
            payload=cfm_payload,
        )

    @staticmethod
    def runt_frame() -> EthernetFrame:
        """Frame shorter than minimum Ethernet size (corner case)."""
        return EthernetFrame(
            dst_mac=mac_to_bytes("de:ad:be:ef:00:01"),
            src_mac=mac_to_bytes("02:00:00:00:00:01"),
            ethertype=0x0800,
            payload=bytes(2),  # Way too short
        )

    @staticmethod
    def jumbo_frame(size=9000) -> EthernetFrame:
        """Jumbo frame (corner case)."""
        payload_size = size - 14  # Subtract header
        return EthernetFrame(
            dst_mac=mac_to_bytes("de:ad:be:ef:00:01"),
            src_mac=mac_to_bytes("02:00:00:00:00:01"),
            ethertype=0x0800,
            payload=bytes(payload_size),
        )
