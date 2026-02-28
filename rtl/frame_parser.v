// frame_parser.v — Ethernet frame field extractor
// Extracts: dst_mac, src_mac, ethertype, vlan_id, vlan_pcp
//           src_ip, dst_ip, ip_protocol, ip_ttl, ip_checksum, src_port, dst_port (IPv4/TCP/UDP)
//           ip_dscp, ip_ecn (IPv4 TOS byte: DSCP[7:2] + ECN[1:0])
//           src_ipv6, dst_ipv6, ipv6_next_header (IPv6)
//           vxlan_vni (VXLAN Network Identifier)
//           gtp_teid (GTP-U Tunnel Endpoint ID, 5G)
//           mpls_label, mpls_tc, mpls_bos (MPLS label stack)
//           igmp_type (IGMP message type), mld_type (MLD message type)
// Handles 802.1Q VLAN-tagged frames (EtherType 0x8100)
// Handles IPv4 header parsing (20-byte fixed, IHL=5)
// Handles IPv6 header parsing (40-byte fixed)
// Handles TCP/UDP port extraction (first 4 bytes of L4 header)
// Handles VXLAN tunnel detection (UDP dst port 4789)
// Handles GTP-U tunnel detection (UDP dst port 2152)
// Handles MPLS label stack parsing (EtherType 0x8847/0x8848)
// Handles IGMP (IPv4 protocol 2) and MLD (ICMPv6 type 130-132)
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
    output reg  [7:0]  ip_ttl,       // IPv4 TTL field (byte 8 of IP header)
    output reg  [15:0] ip_checksum,  // IPv4 header checksum (bytes 10-11)
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

    // GTP-U fields (5G tunnel)
    output reg  [31:0] gtp_teid,
    output reg         gtp_valid,   // frame is GTP-U encapsulated

    // MPLS fields
    output reg  [19:0] mpls_label,
    output reg  [2:0]  mpls_tc,
    output reg         mpls_bos,
    output reg         mpls_valid,  // frame has MPLS label

    // IGMP/MLD fields
    output reg  [7:0]  igmp_type,
    output reg         igmp_valid,  // frame has IGMP message
    output reg  [7:0]  mld_type,
    output reg         mld_valid,   // frame has MLD message

    // QoS fields (IPv4 TOS byte)
    output reg  [5:0]  ip_dscp,       // IPv4 DSCP (TOS bits [7:2])
    output reg  [1:0]  ip_ecn,        // IPv4 ECN (TOS bits [1:0])

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
    localparam S_GTP_HDR   = 4'd11; // GTP-U header (8 bytes min)
    localparam S_MPLS_HDR  = 4'd12; // MPLS label stack
    localparam S_IGMP_HDR  = 4'd13; // IGMP message header

    reg [4:0] state;
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
            ip_ttl       <= 8'd0;
            ip_checksum  <= 16'd0;
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
            gtp_teid     <= 32'd0;
            gtp_valid    <= 1'b0;
            mpls_label   <= 20'd0;
            mpls_tc      <= 3'd0;
            mpls_bos     <= 1'b0;
            mpls_valid   <= 1'b0;
            igmp_type    <= 8'd0;
            igmp_valid   <= 1'b0;
            mld_type     <= 8'd0;
            mld_valid    <= 1'b0;
            ip_dscp      <= 6'd0;
            ip_ecn       <= 2'd0;
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
                ip_ttl      <= 8'd0;
                ip_checksum <= 16'd0;
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
                gtp_teid    <= 32'd0;
                gtp_valid   <= 1'b0;
                mpls_label  <= 20'd0;
                mpls_tc     <= 3'd0;
                mpls_bos    <= 1'b0;
                mpls_valid  <= 1'b0;
                igmp_type   <= 8'd0;
                igmp_valid  <= 1'b0;
                mld_type    <= 8'd0;
                mld_valid   <= 1'b0;
                ip_dscp     <= 6'd0;
                ip_ecn      <= 2'd0;
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
                            end
                            // Check for MPLS (0x8847 unicast or 0x8848 multicast)
                            else if (ethertype[15:8] == 8'h88 && (pkt_data == 8'h47 || pkt_data == 8'h48)) begin
                                state    <= S_MPLS_HDR;
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
                            end
                            // Check for MPLS after VLAN
                            else if (ethertype[15:8] == 8'h88 && (pkt_data == 8'h47 || pkt_data == 8'h48)) begin
                                state    <= S_MPLS_HDR;
                                byte_cnt <= 6'd0;
                            end else begin
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                        end
                    end

                    S_IP_HDR: begin
                        // Parse 20-byte IPv4 header (assuming IHL=5, standard header)
                        // Byte  8: TTL
                        // Byte  9: Protocol
                        // Bytes 10-11: Header checksum
                        // Bytes 12-15: Source IP
                        // Bytes 16-19: Destination IP
                        case (byte_cnt)
                            6'd1: begin
                                ip_dscp <= pkt_data[7:2];
                                ip_ecn  <= pkt_data[1:0];
                            end
                            6'd8:  ip_ttl <= pkt_data;
                            6'd9:  ip_protocol <= pkt_data;
                            6'd10: ip_checksum[15:8] <= pkt_data;
                            6'd11: ip_checksum[7:0]  <= pkt_data;
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
                                end
                                // Check for IGMP (protocol 2)
                                else if (ip_protocol == 8'd2) begin
                                    state    <= S_IGMP_HDR;
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
                                // Check for VXLAN: UDP + dst port 4789 (0x12B5)
                                if (ip_protocol == 8'd17 &&
                                    dst_port[15:8] == 8'h12 && pkt_data == 8'hB5) begin
                                    // Skip 4 bytes of remaining UDP header (length + checksum)
                                    // then parse 8-byte VXLAN header
                                    state    <= S_VXLAN_HDR;
                                    byte_cnt <= 6'd0;
                                end
                                // Check for GTP-U: UDP + dst port 2152 (0x0868)
                                else if (ip_protocol == 8'd17 &&
                                         dst_port[15:8] == 8'h08 && pkt_data == 8'h68) begin
                                    // Skip 4 bytes of remaining UDP header
                                    // then parse 8-byte GTP-U header
                                    state    <= S_GTP_HDR;
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
                                end
                                // Check for ICMPv6 (next header 58) — may contain MLD
                                else if (ipv6_next_header == 8'd58) begin
                                    state    <= S_IGMP_HDR;  // reuse for MLD (first byte = type)
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

                    S_GTP_HDR: begin
                        // GTP-U header: 4 bytes UDP remainder + 8 bytes GTP
                        // Bytes 0-3: UDP length + checksum (skip)
                        // Byte 4: GTP flags
                        // Byte 5: GTP message type
                        // Bytes 6-7: GTP length
                        // Bytes 8-11: TEID (32-bit Tunnel Endpoint ID)
                        case (byte_cnt)
                            6'd8:  gtp_teid[31:24] <= pkt_data;
                            6'd9:  gtp_teid[23:16] <= pkt_data;
                            6'd10: gtp_teid[15:8]  <= pkt_data;
                            6'd11: begin
                                gtp_teid[7:0] <= pkt_data;
                                gtp_valid    <= 1'b1;
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                            default: ;
                        endcase

                        if (byte_cnt != 6'd11) begin
                            byte_cnt <= byte_cnt + 6'd1;
                        end
                    end

                    S_MPLS_HDR: begin
                        // MPLS label entry: 4 bytes per label
                        // Bits 31-12: Label (20 bits)
                        // Bits 11-9: TC (Traffic Class, 3 bits)
                        // Bit 8: S (Bottom of Stack)
                        // Bits 7-0: TTL
                        // We parse only the first label entry
                        case (byte_cnt)
                            6'd0: mpls_label[19:12] <= pkt_data;
                            6'd1: begin
                                mpls_label[11:4] <= pkt_data;
                            end
                            6'd2: begin
                                mpls_label[3:0] <= pkt_data[7:4];
                                mpls_tc         <= pkt_data[3:1];
                                mpls_bos        <= pkt_data[0];
                            end
                            6'd3: begin
                                // TTL byte — done with first label
                                mpls_valid   <= 1'b1;
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                        endcase

                        if (byte_cnt != 6'd3) begin
                            byte_cnt <= byte_cnt + 6'd1;
                        end
                    end

                    S_IGMP_HDR: begin
                        // IGMP/MLD: first byte is the message type
                        if (byte_cnt == 6'd0) begin
                            // For IPv4 IGMP (protocol 2): igmp_type
                            // For IPv6 ICMPv6 (next_header 58): could be MLD
                            if (ipv6_valid) begin
                                // ICMPv6 type: MLD types are 130-132
                                mld_type  <= pkt_data;
                                mld_valid <= 1'b1;
                            end else begin
                                igmp_type  <= pkt_data;
                                igmp_valid <= 1'b1;
                            end
                            state        <= S_PAYLOAD;
                            fields_valid <= 1'b1;
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
