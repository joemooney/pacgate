// frame_parser.v — Ethernet frame field extractor
// Extracts: dst_mac, src_mac, ethertype, vlan_id, vlan_pcp
//           src_ip, dst_ip, ip_protocol, src_port, dst_port (IPv4/TCP/UDP)
//           src_ipv6, dst_ipv6, ipv6_next_header (IPv6)
//           vxlan_vni (VXLAN Network Identifier)
// Handles 802.1Q VLAN-tagged frames (EtherType 0x8100)
// Handles IPv4 header parsing (20-byte fixed, IHL=5)
// Handles IPv6 header parsing (40-byte fixed)
// Handles TCP/UDP port extraction (first 4 bytes of L4 header)
// Handles VXLAN tunnel detection (UDP dst port 4789)
//
// Interface: simple byte-stream (not AXI-Stream)
//   pkt_data[7:0], pkt_valid, pkt_sof, pkt_eof — input
//   Extracted fields + fields_valid pulse — output

module frame_parser (
    input  wire        clk,
    input  wire        rst_n,

    // Packet byte stream input
    input  wire [7:0]  pkt_data,
    input  wire        pkt_valid,
    input  wire        pkt_sof,    // start of frame (first byte)
    input  wire        pkt_eof,    // end of frame (last byte)

    // L2 extracted fields
    output reg  [47:0] dst_mac,
    output reg  [47:0] src_mac,
    output reg  [15:0] ethertype,
    output reg  [11:0] vlan_id,
    output reg  [2:0]  vlan_pcp,
    output reg         vlan_valid,  // frame had 802.1Q tag

    // L3 extracted fields (IPv4)
    output reg  [31:0] src_ip,
    output reg  [31:0] dst_ip,
    output reg  [7:0]  ip_protocol,
    output reg         l3_valid,    // frame had IPv4 header

    // L3 extracted fields (IPv6)
    output reg  [127:0] src_ipv6,
    output reg  [127:0] dst_ipv6,
    output reg  [7:0]   ipv6_next_header,
    output reg          ipv6_valid,  // frame had IPv6 header

    // L4 extracted fields (TCP/UDP)
    output reg  [15:0] src_port,
    output reg  [15:0] dst_port,
    output reg         l4_valid,    // frame had TCP/UDP header

    // VXLAN fields
    output reg  [23:0] vxlan_vni,
    output reg         vxlan_valid, // frame is VXLAN-encapsulated

    output reg         fields_valid // pulse: all header fields extracted
);

    // Parser states
    localparam S_IDLE      = 4'd0;
    localparam S_DST_MAC   = 4'd1;
    localparam S_SRC_MAC   = 4'd2;
    localparam S_ETYPE     = 4'd3;
    localparam S_VLAN_TAG  = 4'd4;
    localparam S_ETYPE2    = 4'd5;  // real ethertype after VLAN
    localparam S_IP_HDR    = 4'd6;  // IPv4 header (20 bytes)
    localparam S_L4_HDR    = 4'd7;  // TCP/UDP first 4 bytes
    localparam S_VXLAN_HDR = 4'd8;  // VXLAN header (8 bytes)
    localparam S_PAYLOAD   = 4'd9;
    localparam S_IPV6_HDR  = 4'd10; // IPv6 header (40 bytes)

    reg [3:0] state;
    reg [5:0] byte_cnt;  // counts bytes within current state (up to 39 for IPv6)

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state        <= S_IDLE;
            byte_cnt     <= 6'd0;
            dst_mac      <= 48'd0;
            src_mac      <= 48'd0;
            ethertype    <= 16'd0;
            vlan_id      <= 12'd0;
            vlan_pcp     <= 3'd0;
            vlan_valid   <= 1'b0;
            src_ip       <= 32'd0;
            dst_ip       <= 32'd0;
            ip_protocol  <= 8'd0;
            l3_valid     <= 1'b0;
            src_ipv6     <= 128'd0;
            dst_ipv6     <= 128'd0;
            ipv6_next_header <= 8'd0;
            ipv6_valid   <= 1'b0;
            src_port     <= 16'd0;
            dst_port     <= 16'd0;
            l4_valid     <= 1'b0;
            vxlan_vni    <= 24'd0;
            vxlan_valid  <= 1'b0;
            fields_valid <= 1'b0;
        end else begin
            fields_valid <= 1'b0;  // default: deassert

            if (pkt_sof && pkt_valid) begin
                // Start of new frame — reset and capture first byte of dst_mac
                state    <= S_DST_MAC;
                byte_cnt <= 6'd1;
                dst_mac  <= {pkt_data, 40'd0};
                src_mac  <= 48'd0;
                ethertype <= 16'd0;
                vlan_id  <= 12'd0;
                vlan_pcp <= 3'd0;
                vlan_valid <= 1'b0;
                src_ip   <= 32'd0;
                dst_ip   <= 32'd0;
                ip_protocol <= 8'd0;
                l3_valid <= 1'b0;
                src_ipv6 <= 128'd0;
                dst_ipv6 <= 128'd0;
                ipv6_next_header <= 8'd0;
                ipv6_valid <= 1'b0;
                src_port <= 16'd0;
                dst_port <= 16'd0;
                l4_valid <= 1'b0;
                vxlan_vni   <= 24'd0;
                vxlan_valid <= 1'b0;
            end else if (pkt_valid) begin
                case (state)
                    S_DST_MAC: begin
                        dst_mac <= dst_mac | ({48'd0, pkt_data} << ((5 - byte_cnt) * 8));
                        if (byte_cnt == 6'd5) begin
                            state    <= S_SRC_MAC;
                            byte_cnt <= 6'd0;
                        end else begin
                            byte_cnt <= byte_cnt + 6'd1;
                        end
                    end

                    S_SRC_MAC: begin
                        src_mac <= src_mac | ({48'd0, pkt_data} << ((5 - byte_cnt) * 8));
                        if (byte_cnt == 6'd5) begin
                            state    <= S_ETYPE;
                            byte_cnt <= 6'd0;
                        end else begin
                            byte_cnt <= byte_cnt + 6'd1;
                        end
                    end

                    S_ETYPE: begin
                        if (byte_cnt == 6'd0) begin
                            ethertype[15:8] <= pkt_data;
                            byte_cnt <= 6'd1;
                        end else begin
                            ethertype[7:0] <= pkt_data;
                            // Check for VLAN tag
                            if (ethertype[15:8] == 8'h81 && pkt_data == 8'h00) begin
                                state    <= S_VLAN_TAG;
                                byte_cnt <= 6'd0;
                                vlan_valid <= 1'b1;
                            end
                            // Check for IPv4
                            else if (ethertype[15:8] == 8'h08 && pkt_data == 8'h00) begin
                                state    <= S_IP_HDR;
                                byte_cnt <= 6'd0;
                            end
                            // Check for IPv6
                            else if (ethertype[15:8] == 8'h86 && pkt_data == 8'hDD) begin
                                state    <= S_IPV6_HDR;
                                byte_cnt <= 6'd0;
                            end else begin
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                        end
                    end

                    S_VLAN_TAG: begin
                        // 2 bytes: PCP(3) + DEI(1) + VID(12)
                        if (byte_cnt == 6'd0) begin
                            vlan_pcp <= pkt_data[7:5];
                            vlan_id[11:8] <= pkt_data[3:0];
                            byte_cnt <= 6'd1;
                        end else begin
                            vlan_id[7:0] <= pkt_data;
                            state    <= S_ETYPE2;
                            byte_cnt <= 6'd0;
                        end
                    end

                    S_ETYPE2: begin
                        // Real ethertype after VLAN tag
                        if (byte_cnt == 6'd0) begin
                            ethertype[15:8] <= pkt_data;
                            byte_cnt <= 6'd1;
                        end else begin
                            ethertype[7:0] <= pkt_data;
                            // Check for IPv4 after VLAN
                            if (ethertype[15:8] == 8'h08 && pkt_data == 8'h00) begin
                                state    <= S_IP_HDR;
                                byte_cnt <= 6'd0;
                            end
                            // Check for IPv6 after VLAN
                            else if (ethertype[15:8] == 8'h86 && pkt_data == 8'hDD) begin
                                state    <= S_IPV6_HDR;
                                byte_cnt <= 6'd0;
                            end else begin
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                        end
                    end

                    S_IP_HDR: begin
                        // Parse 20-byte IPv4 header (assuming IHL=5, standard header)
                        // Byte  9: Protocol
                        // Bytes 12-15: Source IP
                        // Bytes 16-19: Destination IP
                        case (byte_cnt)
                            6'd9:  ip_protocol <= pkt_data;
                            6'd12: src_ip[31:24] <= pkt_data;
                            6'd13: src_ip[23:16] <= pkt_data;
                            6'd14: src_ip[15:8]  <= pkt_data;
                            6'd15: src_ip[7:0]   <= pkt_data;
                            6'd16: dst_ip[31:24] <= pkt_data;
                            6'd17: dst_ip[23:16] <= pkt_data;
                            6'd18: dst_ip[15:8]  <= pkt_data;
                            6'd19: begin
                                dst_ip[7:0] <= pkt_data;
                                l3_valid <= 1'b1;
                                // Check if protocol is TCP (6) or UDP (17)
                                if (ip_protocol == 8'd6 || ip_protocol == 8'd17) begin
                                    state    <= S_L4_HDR;
                                    byte_cnt <= 6'd0;
                                end else begin
                                    state        <= S_PAYLOAD;
                                    fields_valid <= 1'b1;
                                end
                            end
                            default: ;  // skip other IPv4 header bytes
                        endcase

                        if (byte_cnt != 6'd19) begin
                            byte_cnt <= byte_cnt + 6'd1;
                        end
                    end

                    S_L4_HDR: begin
                        // Parse first 4 bytes of TCP/UDP header
                        // Bytes 0-1: Source port
                        // Bytes 2-3: Destination port
                        case (byte_cnt)
                            6'd0: src_port[15:8] <= pkt_data;
                            6'd1: src_port[7:0]  <= pkt_data;
                            6'd2: dst_port[15:8] <= pkt_data;
                            6'd3: begin
                                dst_port[7:0] <= pkt_data;
                                l4_valid     <= 1'b1;
                                // Check for VXLAN: UDP (protocol already checked) + dst port 4789
                                if (ip_protocol == 8'd17 &&
                                    dst_port[15:8] == 8'h12 && pkt_data == 8'hB5) begin
                                    // dst_port == 16'd4789 (0x12B5)
                                    // Skip 4 bytes of remaining UDP header (length + checksum)
                                    // then parse 8-byte VXLAN header
                                    state    <= S_VXLAN_HDR;
                                    byte_cnt <= 6'd0;
                                end else begin
                                    state        <= S_PAYLOAD;
                                    fields_valid <= 1'b1;
                                end
                            end
                        endcase

                        if (byte_cnt != 6'd3) begin
                            byte_cnt <= byte_cnt + 6'd1;
                        end
                    end

                    S_VXLAN_HDR: begin
                        // Parse VXLAN header: 4 bytes UDP remainder + 8 bytes VXLAN
                        // Bytes 0-3: UDP length + checksum (skip)
                        // Bytes 4: VXLAN flags
                        // Bytes 5-7: Reserved
                        // Bytes 8-10: VNI (24-bit)
                        // Byte 11: Reserved
                        case (byte_cnt)
                            6'd8:  vxlan_vni[23:16] <= pkt_data;
                            6'd9:  vxlan_vni[15:8]  <= pkt_data;
                            6'd10: vxlan_vni[7:0]   <= pkt_data;
                            6'd11: begin
                                vxlan_valid  <= 1'b1;
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                            default: ;
                        endcase

                        if (byte_cnt != 6'd11) begin
                            byte_cnt <= byte_cnt + 6'd1;
                        end
                    end

                    S_IPV6_HDR: begin
                        // Parse 40-byte IPv6 header (fixed length)
                        // Byte  6: Next Header
                        // Bytes 8-23: Source IPv6 (16 bytes)
                        // Bytes 24-39: Destination IPv6 (16 bytes)
                        case (byte_cnt)
                            6'd6: ipv6_next_header <= pkt_data;
                            // Source IPv6: bytes 8-23
                            6'd8:  src_ipv6[127:120] <= pkt_data;
                            6'd9:  src_ipv6[119:112] <= pkt_data;
                            6'd10: src_ipv6[111:104] <= pkt_data;
                            6'd11: src_ipv6[103:96]  <= pkt_data;
                            6'd12: src_ipv6[95:88]   <= pkt_data;
                            6'd13: src_ipv6[87:80]   <= pkt_data;
                            6'd14: src_ipv6[79:72]   <= pkt_data;
                            6'd15: src_ipv6[71:64]   <= pkt_data;
                            6'd16: src_ipv6[63:56]   <= pkt_data;
                            6'd17: src_ipv6[55:48]   <= pkt_data;
                            6'd18: src_ipv6[47:40]   <= pkt_data;
                            6'd19: src_ipv6[39:32]   <= pkt_data;
                            6'd20: src_ipv6[31:24]   <= pkt_data;
                            6'd21: src_ipv6[23:16]   <= pkt_data;
                            6'd22: src_ipv6[15:8]    <= pkt_data;
                            6'd23: src_ipv6[7:0]     <= pkt_data;
                            // Destination IPv6: bytes 24-39
                            6'd24: dst_ipv6[127:120] <= pkt_data;
                            6'd25: dst_ipv6[119:112] <= pkt_data;
                            6'd26: dst_ipv6[111:104] <= pkt_data;
                            6'd27: dst_ipv6[103:96]  <= pkt_data;
                            6'd28: dst_ipv6[95:88]   <= pkt_data;
                            6'd29: dst_ipv6[87:80]   <= pkt_data;
                            6'd30: dst_ipv6[79:72]   <= pkt_data;
                            6'd31: dst_ipv6[71:64]   <= pkt_data;
                            6'd32: dst_ipv6[63:56]   <= pkt_data;
                            6'd33: dst_ipv6[55:48]   <= pkt_data;
                            6'd34: dst_ipv6[47:40]   <= pkt_data;
                            6'd35: dst_ipv6[39:32]   <= pkt_data;
                            6'd36: dst_ipv6[31:24]   <= pkt_data;
                            6'd37: dst_ipv6[23:16]   <= pkt_data;
                            6'd38: dst_ipv6[15:8]    <= pkt_data;
                            6'd39: begin
                                dst_ipv6[7:0] <= pkt_data;
                                ipv6_valid <= 1'b1;
                                // Check if next header is TCP (6) or UDP (17)
                                if (ipv6_next_header == 8'd6 || ipv6_next_header == 8'd17) begin
                                    state    <= S_L4_HDR;
                                    byte_cnt <= 6'd0;
                                end else begin
                                    state        <= S_PAYLOAD;
                                    fields_valid <= 1'b1;
                                end
                            end
                            default: ;  // skip other IPv6 header bytes
                        endcase

                        if (byte_cnt != 6'd39) begin
                            byte_cnt <= byte_cnt + 6'd1;
                        end
                    end

                    S_PAYLOAD: begin
                        // Consume remaining bytes until EOF
                        if (pkt_eof) begin
                            state <= S_IDLE;
                        end
                    end

                    default: state <= S_IDLE;
                endcase
            end

            // Handle EOF in any state
            if (pkt_eof && pkt_valid && state != S_PAYLOAD) begin
                state <= S_IDLE;
            end
        end
    end

endmodule
