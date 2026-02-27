"""
Ethernet frame construction and manipulation for PacGate verification.

Provides a PacketFactory for building directed and random test frames,
plus utilities for MAC address and EtherType handling.
"""

import random
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
class EthernetFrame:
    """Ethernet frame representation for verification."""
    dst_mac: bytes = field(default_factory=lambda: bytes(6))
    src_mac: bytes = field(default_factory=lambda: bytes(6))
    ethertype: int = 0x0800
    vlan_tag: Optional[VlanTag] = None
    payload: bytes = field(default_factory=lambda: bytes(46))

    def to_bytes(self) -> bytes:
        """Serialize to wire format."""
        frame = self.dst_mac + self.src_mac
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
        """IPv4 frame."""
        return EthernetFrame(
            dst_mac=mac_to_bytes(dst_mac),
            src_mac=mac_to_bytes(src_mac),
            ethertype=0x0800,
            payload=bytes(payload_size),
        )

    @staticmethod
    def ipv6(dst_mac="de:ad:be:ef:00:01", src_mac="02:00:00:00:00:01") -> EthernetFrame:
        """IPv6 frame."""
        return EthernetFrame(
            dst_mac=mac_to_bytes(dst_mac),
            src_mac=mac_to_bytes(src_mac),
            ethertype=0x86DD,
            payload=bytes(46),
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
