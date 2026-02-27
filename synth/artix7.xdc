## PacGate — Artix-7 XC7A35T Constraints
## Target: Digilent Arty A7-35T or similar

## Clock — 125 MHz (8 ns period) for Gigabit Ethernet
create_clock -period 8.000 -name sys_clk [get_ports clk]

## Reset (active-low)
set_property PACKAGE_PIN C2 [get_ports rst_n]
set_property IOSTANDARD LVCMOS33 [get_ports rst_n]

## Clock input
set_property PACKAGE_PIN E3 [get_ports clk]
set_property IOSTANDARD LVCMOS33 [get_ports clk]

## AXI-Stream Slave Input (RX from PHY)
set_property PACKAGE_PIN V15 [get_ports {s_axis_tdata[0]}]
set_property PACKAGE_PIN U16 [get_ports {s_axis_tdata[1]}]
set_property PACKAGE_PIN P14 [get_ports {s_axis_tdata[2]}]
set_property PACKAGE_PIN T11 [get_ports {s_axis_tdata[3]}]
set_property PACKAGE_PIN R12 [get_ports {s_axis_tdata[4]}]
set_property PACKAGE_PIN T14 [get_ports {s_axis_tdata[5]}]
set_property PACKAGE_PIN T15 [get_ports {s_axis_tdata[6]}]
set_property PACKAGE_PIN T16 [get_ports {s_axis_tdata[7]}]
set_property IOSTANDARD LVCMOS33 [get_ports {s_axis_tdata[*]}]

set_property PACKAGE_PIN U11 [get_ports s_axis_tvalid]
set_property IOSTANDARD LVCMOS33 [get_ports s_axis_tvalid]
set_property PACKAGE_PIN V16 [get_ports s_axis_tready]
set_property IOSTANDARD LVCMOS33 [get_ports s_axis_tready]
set_property PACKAGE_PIN U14 [get_ports s_axis_tlast]
set_property IOSTANDARD LVCMOS33 [get_ports s_axis_tlast]

## AXI-Stream Master Output (TX to PHY)
set_property PACKAGE_PIN E15 [get_ports {m_axis_tdata[0]}]
set_property PACKAGE_PIN E16 [get_ports {m_axis_tdata[1]}]
set_property PACKAGE_PIN D15 [get_ports {m_axis_tdata[2]}]
set_property PACKAGE_PIN C15 [get_ports {m_axis_tdata[3]}]
set_property PACKAGE_PIN J17 [get_ports {m_axis_tdata[4]}]
set_property PACKAGE_PIN J18 [get_ports {m_axis_tdata[5]}]
set_property PACKAGE_PIN K15 [get_ports {m_axis_tdata[6]}]
set_property PACKAGE_PIN J15 [get_ports {m_axis_tdata[7]}]
set_property IOSTANDARD LVCMOS33 [get_ports {m_axis_tdata[*]}]

set_property PACKAGE_PIN U12 [get_ports m_axis_tvalid]
set_property IOSTANDARD LVCMOS33 [get_ports m_axis_tvalid]
set_property PACKAGE_PIN V12 [get_ports m_axis_tready]
set_property IOSTANDARD LVCMOS33 [get_ports m_axis_tready]
set_property PACKAGE_PIN V10 [get_ports m_axis_tlast]
set_property IOSTANDARD LVCMOS33 [get_ports m_axis_tlast]

## Status LEDs
set_property PACKAGE_PIN H5  [get_ports decision_valid]
set_property IOSTANDARD LVCMOS33 [get_ports decision_valid]
set_property PACKAGE_PIN J5  [get_ports decision_pass]
set_property IOSTANDARD LVCMOS33 [get_ports decision_pass]
set_property PACKAGE_PIN T9  [get_ports fifo_overflow]
set_property IOSTANDARD LVCMOS33 [get_ports fifo_overflow]
set_property PACKAGE_PIN T10 [get_ports fifo_empty]
set_property IOSTANDARD LVCMOS33 [get_ports fifo_empty]

## Timing constraints
set_input_delay  -clock sys_clk -max 2.0 [get_ports {s_axis_tdata[*] s_axis_tvalid s_axis_tlast}]
set_input_delay  -clock sys_clk -min 0.5 [get_ports {s_axis_tdata[*] s_axis_tvalid s_axis_tlast}]
set_output_delay -clock sys_clk -max 2.0 [get_ports {m_axis_tdata[*] m_axis_tvalid m_axis_tlast s_axis_tready}]
set_output_delay -clock sys_clk -min 0.5 [get_ports {m_axis_tdata[*] m_axis_tvalid m_axis_tlast s_axis_tready}]

## FPGA configuration
set_property CFGBVS VCCO [current_design]
set_property CONFIG_VOLTAGE 3.3 [current_design]
set_property BITSTREAM.CONFIG.SPI_BUSWIDTH 4 [current_design]
