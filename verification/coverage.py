"""
PacGate Coverage Collector — Functional coverage for packet filter verification.

Tracks coverage across multiple dimensions:
- Protocol/EtherType distribution
- MAC address types
- Rule activation (every rule hit at least once)
- Decision outcomes
- Corner cases
- Cross coverage
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from .packet import EthernetFrame


@dataclass
class CoverBin:
    """A single coverage bin."""
    name: str
    hit: bool = False
    count: int = 0

    def sample(self):
        self.hit = True
        self.count += 1


@dataclass
class CoverPoint:
    """A coverage point with multiple bins."""
    name: str
    bins: dict = field(default_factory=dict)  # bin_name -> CoverBin

    def add_bin(self, name: str):
        self.bins[name] = CoverBin(name)

    def sample(self, bin_name: str):
        if bin_name in self.bins:
            self.bins[bin_name].sample()

    @property
    def coverage_pct(self) -> float:
        if not self.bins:
            return 100.0
        hit = sum(1 for b in self.bins.values() if b.hit)
        return 100.0 * hit / len(self.bins)

    @property
    def total_bins(self) -> int:
        return len(self.bins)

    @property
    def hit_bins(self) -> int:
        return sum(1 for b in self.bins.values() if b.hit)


class FilterCoverage:
    """
    Functional coverage collector for the packet filter.

    Auto-configurable from rule definitions — call add_rule()
    for each rule to set up per-rule coverage bins.
    """

    def __init__(self, default_action: str = "drop"):
        self.default_action = default_action
        self.coverpoints: dict[str, CoverPoint] = {}
        self.cross_coverage: dict[str, dict] = {}
        self._sample_count = 0

        # EtherType coverage
        cp = CoverPoint("ethertype")
        for name, _ in [("ipv4", 0x0800), ("arp", 0x0806), ("ipv6", 0x86DD),
                         ("vlan_tag", 0x8100), ("lldp", 0x88CC), ("ptp", 0x88F7),
                         ("other", 0)]:
            cp.add_bin(name)
        self.coverpoints["ethertype"] = cp

        # DST MAC type coverage
        cp = CoverPoint("dst_mac_type")
        for name in ["broadcast", "multicast", "unicast", "zero"]:
            cp.add_bin(name)
        self.coverpoints["dst_mac_type"] = cp

        # Frame size coverage
        cp = CoverPoint("frame_size")
        for name in ["runt", "min", "typical", "large", "jumbo"]:
            cp.add_bin(name)
        self.coverpoints["frame_size"] = cp

        # VLAN presence
        cp = CoverPoint("vlan_present")
        cp.add_bin("tagged")
        cp.add_bin("untagged")
        self.coverpoints["vlan_present"] = cp

        # Decision coverage
        cp = CoverPoint("decision")
        cp.add_bin("pass")
        cp.add_bin("drop")
        self.coverpoints["decision"] = cp

        # Rule hit coverage (populated via add_rule)
        self.coverpoints["rule_hit"] = CoverPoint("rule_hit")
        self.coverpoints["rule_hit"].add_bin("__default__")

        # Corner cases
        cp = CoverPoint("corner_cases")
        for name in ["runt_frame", "jumbo_frame", "back_to_back",
                      "all_zero_mac", "all_ff_mac", "vlan_pcp_7"]:
            cp.add_bin(name)
        self.coverpoints["corner_cases"] = cp

        # Cross coverage tracking
        self.cross_coverage["ethertype_x_decision"] = defaultdict(int)
        self.cross_coverage["rule_x_decision"] = defaultdict(int)

    def add_rule(self, rule_name: str):
        """Add a rule to the coverage model."""
        self.coverpoints["rule_hit"].add_bin(rule_name)

    def sample(self, frame: EthernetFrame, decision_pass: bool,
               matched_rule: str = "__default__"):
        """Sample coverage for a frame and its decision."""
        self._sample_count += 1

        # EtherType
        etype_bin = {
            0x0800: "ipv4", 0x0806: "arp", 0x86DD: "ipv6",
            0x8100: "vlan_tag", 0x88CC: "lldp", 0x88F7: "ptp",
        }.get(frame.ethertype, "other")
        self.coverpoints["ethertype"].sample(etype_bin)

        # DST MAC type
        if frame.dst_mac == b"\xff\xff\xff\xff\xff\xff":
            mac_bin = "broadcast"
        elif frame.dst_mac == b"\x00\x00\x00\x00\x00\x00":
            mac_bin = "zero"
        elif frame.dst_mac[0] & 0x01:
            mac_bin = "multicast"
        else:
            mac_bin = "unicast"
        self.coverpoints["dst_mac_type"].sample(mac_bin)

        # Frame size
        size = len(frame)
        if size < 64:
            size_bin = "runt"
        elif size == 64:
            size_bin = "min"
        elif size <= 576:
            size_bin = "typical"
        elif size <= 1518:
            size_bin = "large"
        else:
            size_bin = "jumbo"
        self.coverpoints["frame_size"].sample(size_bin)

        # VLAN
        vlan_bin = "tagged" if frame.vlan_tag else "untagged"
        self.coverpoints["vlan_present"].sample(vlan_bin)

        # Decision
        dec_bin = "pass" if decision_pass else "drop"
        self.coverpoints["decision"].sample(dec_bin)

        # Rule hit
        self.coverpoints["rule_hit"].sample(matched_rule)

        # Corner cases
        if size < 64:
            self.coverpoints["corner_cases"].sample("runt_frame")
        if size > 1518:
            self.coverpoints["corner_cases"].sample("jumbo_frame")
        if frame.dst_mac == b"\x00\x00\x00\x00\x00\x00":
            self.coverpoints["corner_cases"].sample("all_zero_mac")
        if frame.dst_mac == b"\xff\xff\xff\xff\xff\xff":
            self.coverpoints["corner_cases"].sample("all_ff_mac")
        if frame.vlan_tag and frame.vlan_tag.pcp == 7:
            self.coverpoints["corner_cases"].sample("vlan_pcp_7")

        # Cross coverage
        self.cross_coverage["ethertype_x_decision"][(etype_bin, dec_bin)] += 1
        self.cross_coverage["rule_x_decision"][(matched_rule, dec_bin)] += 1

    @property
    def overall_coverage(self) -> float:
        """Overall functional coverage percentage."""
        total_bins = 0
        hit_bins = 0
        for cp in self.coverpoints.values():
            total_bins += cp.total_bins
            hit_bins += cp.hit_bins
        return 100.0 * hit_bins / max(total_bins, 1)

    def merge_from(self, other: 'FilterCoverage'):
        """Merge coverage data from another FilterCoverage instance."""
        self._sample_count += other._sample_count
        for cp_name, other_cp in other.coverpoints.items():
            if cp_name not in self.coverpoints:
                self.coverpoints[cp_name] = other_cp
            else:
                for bin_name, other_bin in other_cp.bins.items():
                    if bin_name not in self.coverpoints[cp_name].bins:
                        self.coverpoints[cp_name].add_bin(bin_name)
                    our_bin = self.coverpoints[cp_name].bins[bin_name]
                    our_bin.count += other_bin.count
                    our_bin.hit = our_bin.hit or other_bin.hit
        for cross_name, other_data in other.cross_coverage.items():
            if cross_name not in self.cross_coverage:
                self.cross_coverage[cross_name] = defaultdict(int)
            for key, count in other_data.items():
                self.cross_coverage[cross_name][key] += count

    def to_xml(self) -> str:
        """Export coverage data as XML string compatible with standard coverage tools."""
        import xml.etree.ElementTree as ET
        from xml.dom import minidom

        root = ET.Element("coverage", {
            "tool": "pacgate",
            "version": "1.0",
            "samples": str(self._sample_count),
            "overall_pct": f"{self.overall_coverage:.1f}",
        })

        for cp_name, cp in self.coverpoints.items():
            cp_elem = ET.SubElement(root, "coverpoint", {
                "name": cp_name,
                "coverage_pct": f"{cp.coverage_pct:.1f}",
                "hit_bins": str(cp.hit_bins),
                "total_bins": str(cp.total_bins),
            })
            for bin_name, cbin in cp.bins.items():
                ET.SubElement(cp_elem, "bin", {
                    "name": bin_name,
                    "hit": str(cbin.hit).lower(),
                    "count": str(cbin.count),
                })

        cross_elem = ET.SubElement(root, "cross_coverage")
        for cross_name, data in self.cross_coverage.items():
            cross_cp = ET.SubElement(cross_elem, "cross", {"name": cross_name})
            for key, count in sorted(data.items()):
                ET.SubElement(cross_cp, "entry", {
                    "key": str(key),
                    "count": str(count),
                })

        rough = ET.tostring(root, encoding="unicode")
        parsed = minidom.parseString(rough)
        return parsed.toprettyxml(indent="  ", encoding=None)

    def save_xml(self, path: str):
        """Save coverage data to an XML file."""
        xml_str = self.to_xml()
        with open(path, "w") as f:
            f.write(xml_str)

    @classmethod
    def load_xml(cls, path: str) -> 'FilterCoverage':
        """Load coverage data from an XML file for merging."""
        import xml.etree.ElementTree as ET
        tree = ET.parse(path)
        root = tree.getroot()

        cov = cls()
        cov._sample_count = int(root.get("samples", "0"))

        for cp_elem in root.findall("coverpoint"):
            cp_name = cp_elem.get("name")
            if cp_name not in cov.coverpoints:
                cov.coverpoints[cp_name] = CoverPoint(cp_name)
            for bin_elem in cp_elem.findall("bin"):
                bin_name = bin_elem.get("name")
                if bin_name not in cov.coverpoints[cp_name].bins:
                    cov.coverpoints[cp_name].add_bin(bin_name)
                cov.coverpoints[cp_name].bins[bin_name].hit = bin_elem.get("hit") == "true"
                cov.coverpoints[cp_name].bins[bin_name].count = int(bin_elem.get("count", "0"))

        cross_elem = root.find("cross_coverage")
        if cross_elem is not None:
            for cross in cross_elem.findall("cross"):
                cross_name = cross.get("name")
                if cross_name not in cov.cross_coverage:
                    cov.cross_coverage[cross_name] = defaultdict(int)
                for entry in cross.findall("entry"):
                    key = entry.get("key")
                    count = int(entry.get("count", "0"))
                    cov.cross_coverage[cross_name][key] += count

        return cov

    def report(self) -> str:
        """Generate a formatted coverage report."""
        lines = [
            "=" * 70,
            "PACGATE COVERAGE REPORT",
            "=" * 70,
            f"Total samples: {self._sample_count}",
            "",
        ]

        for cp_name, cp in self.coverpoints.items():
            status = "OK" if cp.coverage_pct >= 100 else f"{cp.coverage_pct:.1f}%"
            lines.append(f"COVERPOINT: {cp_name:25s} {cp.hit_bins}/{cp.total_bins} bins  [{status}]")
            for bin_name, cbin in cp.bins.items():
                marker = "HIT" if cbin.hit else "MISS"
                bar = "#" * min(int(cbin.count / max(self._sample_count, 1) * 50), 50)
                lines.append(f"  {bin_name:25s} {cbin.count:5d}  [{marker:4s}]  {bar}")
            lines.append("")

        lines.append("CROSS COVERAGE:")
        for cross_name, data in self.cross_coverage.items():
            lines.append(f"  {cross_name}:")
            for key, count in sorted(data.items()):
                lines.append(f"    {str(key):40s} {count:5d}")
            lines.append("")

        lines.append(f"OVERALL FUNCTIONAL COVERAGE: {self.overall_coverage:.1f}%")
        lines.append("=" * 70)
        return "\n".join(lines)
