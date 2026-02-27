"""
Flippy Packet Driver — Bus Functional Model for the packet stream interface.

Converts EthernetFrame objects into pin-level pkt_data/valid/sof/eof signals
for driving the DUT. Supports configurable inter-frame gaps and error injection.
"""

import cocotb
from cocotb.triggers import RisingEdge, ClockCycles

from .packet import EthernetFrame


class PacketDriver:
    """
    Drives Ethernet frames onto the pkt_data/valid/sof/eof interface.

    Usage:
        driver = PacketDriver(dut)
        await driver.send(frame)
        await driver.send_burst([frame1, frame2, frame3], gap=0)
    """

    def __init__(self, dut, inter_frame_gap=1):
        self.dut = dut
        self.inter_frame_gap = inter_frame_gap
        self.frames_sent = 0

    async def reset(self, cycles=5):
        """Apply reset to DUT."""
        self.dut.rst_n.value = 0
        self.dut.pkt_valid.value = 0
        self.dut.pkt_sof.value = 0
        self.dut.pkt_eof.value = 0
        self.dut.pkt_data.value = 0
        await ClockCycles(self.dut.clk, cycles)
        self.dut.rst_n.value = 1
        await ClockCycles(self.dut.clk, 2)

    async def send(self, frame: EthernetFrame):
        """Send a single frame byte-by-byte."""
        frame_bytes = frame.to_bytes()

        for i, byte in enumerate(frame_bytes):
            self.dut.pkt_data.value = byte
            self.dut.pkt_valid.value = 1
            self.dut.pkt_sof.value = 1 if i == 0 else 0
            self.dut.pkt_eof.value = 1 if i == len(frame_bytes) - 1 else 0
            await RisingEdge(self.dut.clk)

        # Deassert after frame
        self.dut.pkt_valid.value = 0
        self.dut.pkt_sof.value = 0
        self.dut.pkt_eof.value = 0

        # Inter-frame gap
        for _ in range(self.inter_frame_gap):
            await RisingEdge(self.dut.clk)

        self.frames_sent += 1

    async def send_burst(self, frames: list, gap: int = None):
        """Send multiple frames with configurable gap."""
        old_gap = self.inter_frame_gap
        if gap is not None:
            self.inter_frame_gap = gap
        for frame in frames:
            await self.send(frame)
        self.inter_frame_gap = old_gap

    async def send_raw_bytes(self, data: bytes):
        """Send raw bytes (for corner case testing like runt frames)."""
        for i, byte in enumerate(data):
            self.dut.pkt_data.value = byte
            self.dut.pkt_valid.value = 1
            self.dut.pkt_sof.value = 1 if i == 0 else 0
            self.dut.pkt_eof.value = 1 if i == len(data) - 1 else 0
            await RisingEdge(self.dut.clk)

        self.dut.pkt_valid.value = 0
        self.dut.pkt_sof.value = 0
        self.dut.pkt_eof.value = 0
        await RisingEdge(self.dut.clk)


class DecisionMonitor:
    """
    Monitors the decision_valid/decision_pass output signals.

    Captures each decision and provides it to the scoreboard and coverage.
    """

    def __init__(self, dut):
        self.dut = dut
        self.decisions = []

    async def wait_for_decision(self, timeout_cycles=200) -> int:
        """Wait for decision_valid to assert, return decision_pass."""
        for _ in range(timeout_cycles):
            await RisingEdge(self.dut.clk)
            if int(self.dut.decision_valid.value) == 1:
                result = int(self.dut.decision_pass.value)
                self.decisions.append(result)
                return result
        raise TimeoutError("decision_valid never asserted within timeout")

    @property
    def pass_count(self):
        return sum(1 for d in self.decisions if d == 1)

    @property
    def drop_count(self):
        return sum(1 for d in self.decisions if d == 0)
