// frame_parser.v — Ethernet frame field extractor
// Extracts: dst_mac, src_mac, ethertype, vlan_id, vlan_pcp
//           outer_vlan_id, outer_vlan_pcp (QinQ 802.1ad)
//           src_ip, dst_ip, ip_protocol, ip_ttl, ip_checksum, src_port, dst_port (IPv4/TCP/UDP)
//           ip_dscp, ip_ecn (IPv4 TOS byte: DSCP[7:2] + ECN[1:0])
//           ip_dont_fragment, ip_more_fragments, ip_frag_offset (IPv4 flags+frag)
//           ipv6_dscp, ipv6_ecn (IPv6 Traffic Class: DSCP[7:2] + ECN[1:0])
//           src_ipv6, dst_ipv6, ipv6_next_header, ipv6_hop_limit, ipv6_flow_label (IPv6)
//           tcp_flags (TCP flags byte at offset 13 from TCP header)
//           icmp_type, icmp_code (ICMP type/code for IPv4 protocol 1)
//           icmpv6_type, icmpv6_code (ICMPv6 type/code for IPv6 next_header 58)
//           vxlan_vni (VXLAN Network Identifier)
//           gtp_teid (GTP-U Tunnel Endpoint ID, 5G)
//           mpls_label, mpls_tc, mpls_bos (MPLS label stack)
//           igmp_type (IGMP message type), mld_type (MLD message type)
//           arp_opcode, arp_spa, arp_tpa (ARP header fields)
//           oam_level, oam_opcode (IEEE 802.1ag CFM OAM fields)
//           nsh_spi, nsh_si, nsh_next_protocol (NSH RFC 8300)
//           geneve_vni (Geneve Virtual Network Identifier, RFC 8926)
//           ptp_message_type, ptp_version, ptp_domain (IEEE 1588 PTP)
//           l4_port_offset (absolute byte position of L4 src_port MSB)
// Handles 802.1Q VLAN-tagged frames (EtherType 0x8100)
// Handles 802.1ad QinQ double-tagged frames (EtherType 0x88A8 / 0x9100)
// Handles IPv4 header parsing (20-byte fixed, IHL=5)
// Handles IPv6 header parsing (40-byte fixed)
// Handles TCP/UDP port extraction (first 4 bytes of L4 header)
// Handles TCP flags extraction (byte 13 of TCP header)
// Handles ICMP type/code extraction (IPv4 protocol 1)
// Handles ICMPv6 type/code extraction (IPv6 next_header 58) with MLD backward compatibility
// Handles VXLAN tunnel detection (UDP dst port 4789)
// Handles GTP-U tunnel detection (UDP dst port 2152)
// Handles MPLS label stack parsing (EtherType 0x8847/0x8848)
// Handles IGMP (IPv4 protocol 2) and MLD (ICMPv6 type 130-132)
// Handles ARP header parsing (EtherType 0x0806)
// Handles OAM/CFM parsing (EtherType 0x8902, IEEE 802.1ag)
// Handles NSH parsing (EtherType 0x894F, RFC 8300)
// Handles Geneve tunnel detection (UDP dst port 6081, RFC 8926)
// Handles GRE tunnel detection (IP protocol 47) with optional key
// Handles PTP (IEEE 1588) detection: L2 (EtherType 0x88F7) and L4 (UDP dst port 319/320)
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

    // QinQ (802.1ad) outer tag
    output reg  [11:0] outer_vlan_id,
    output reg  [2:0]  outer_vlan_pcp,
    output reg         outer_vlan_valid, // frame had 802.1ad outer tag

    // L3 extracted fields (IPv4)
    output reg  [31:0] src_ip,
    output reg  [31:0] dst_ip,
    output reg  [7:0]  ip_protocol,
    output reg  [7:0]  ip_ttl,       // IPv4 TTL field (byte 8 of IP header)
    output reg  [15:0] ip_checksum,  // IPv4 header checksum (bytes 10-11)
    output reg         l3_valid,    // frame had IPv4 header

    // IPv4 fragmentation fields
    output reg         ip_dont_fragment,   // DF flag (byte 6 bit 6)
    output reg         ip_more_fragments,  // MF flag (byte 6 bit 5)
    output reg  [12:0] ip_frag_offset,     // 13-bit fragment offset
    output reg         ip_frag_valid,      // frag fields extracted

    // L3 extracted fields (IPv6)
    output reg  [127:0] src_ipv6,
    output reg  [127:0] dst_ipv6,
    output reg  [7:0]   ipv6_next_header,
    output reg          ipv6_valid,  // frame had IPv6 header

    // L4 extracted fields (TCP/UDP)
    output reg  [15:0] src_port,
    output reg  [15:0] dst_port,
    output reg         l4_valid,    // frame had TCP/UDP header

    // L4 port offset (absolute byte position of src_port MSB in frame)
    output reg  [10:0] l4_port_offset,
    output reg         l4_port_offset_valid,

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

    // IPv6 Traffic Class (TC byte spread across bytes 0-1 of IPv6 header)
    output reg  [5:0]  ipv6_dscp,     // IPv6 DSCP (TC bits [7:2])
    output reg  [1:0]  ipv6_ecn,      // IPv6 ECN (TC bits [1:0])

    // TCP flags (byte 13 of TCP header)
    output reg  [7:0]  tcp_flags,     // CWR|ECE|URG|ACK|PSH|RST|SYN|FIN
    output reg         tcp_flags_valid,

    // ICMP type/code (IPv4 protocol 1)
    output reg  [7:0]  icmp_type_field,  // ICMP message type
    output reg  [7:0]  icmp_code,     // ICMP code
    output reg         icmp_valid,    // frame has ICMP header

    // ICMPv6 type/code (IPv6 next_header 58)
    output reg  [7:0]  icmpv6_type,     // ICMPv6 type
    output reg  [7:0]  icmpv6_code,     // ICMPv6 code
    output reg         icmpv6_valid,    // ICMPv6 fields valid

    // ARP fields (EtherType 0x0806)
    output reg  [15:0] arp_opcode,      // ARP opcode (1=request, 2=reply)
    output reg  [31:0] arp_spa,         // ARP sender protocol address
    output reg  [31:0] arp_tpa,         // ARP target protocol address
    output reg         arp_valid,       // ARP fields valid

    // IPv6 extension fields
    output reg  [7:0]  ipv6_hop_limit,  // IPv6 hop limit (byte 7)
    output reg  [19:0] ipv6_flow_label, // IPv6 flow label (bytes 1-3, lower 20 bits)

    // OAM/CFM fields (IEEE 802.1ag, EtherType 0x8902)
    output reg  [2:0]  oam_level,       // Maintenance Domain Level (MEL, 0-7)
    output reg  [7:0]  oam_opcode,      // CFM OpCode (1=CCM, 3=LBR, 47=DMM, 48=DMR)
    output reg         oam_valid,       // OAM fields extracted

    // GRE tunnel fields (IP protocol 47)
    output reg  [15:0] gre_protocol,    // GRE Protocol Type (bytes 2-3)
    output reg  [31:0] gre_key,         // GRE Key (bytes 4-7, if K flag set)
    output reg         gre_valid,       // frame has GRE header

    // NSH fields (RFC 8300, EtherType 0x894F)
    output reg  [23:0] nsh_spi,          // Service Path Identifier (bytes 4-6)
    output reg  [7:0]  nsh_si,           // Service Index (byte 7)
    output reg  [7:0]  nsh_next_protocol, // Next Protocol (byte 2: 1=IPv4, 2=IPv6, 3=Ethernet)
    output reg         nsh_valid,        // NSH fields extracted

    // Geneve fields (RFC 8926, UDP dst port 6081)
    output reg  [23:0] geneve_vni,       // Virtual Network Identifier (bytes 4-6)
    output reg         geneve_valid,     // Geneve fields extracted

    // PTP fields (IEEE 1588, EtherType 0x88F7 or UDP 319/320)
    output reg  [3:0]  ptp_message_type, // PTP messageType (4-bit: 0=Sync, 1=Delay_Req, 8=Follow_Up)
    output reg  [3:0]  ptp_version,      // PTP versionPTP (4-bit, typically 2 for PTPv2)
    output reg  [7:0]  ptp_domain,       // PTP domainNumber (byte 4 of PTP header)
    output reg         ptp_valid,        // PTP fields extracted

    output reg         fields_valid // pulse: all header fields extracted
);

    // Parser states
    localparam S_IDLE       = 5'd0;
    localparam S_DST_MAC    = 5'd1;
    localparam S_SRC_MAC    = 5'd2;
    localparam S_ETYPE      = 5'd3;
    localparam S_VLAN_TAG   = 5'd4;
    localparam S_ETYPE2     = 5'd5;  // real ethertype after VLAN
    localparam S_IP_HDR     = 5'd6;  // IPv4 header (20 bytes)
    localparam S_L4_HDR     = 5'd7;  // TCP/UDP first 4 bytes
    localparam S_VXLAN_HDR  = 5'd8;  // VXLAN header (8 bytes)
    localparam S_PAYLOAD    = 5'd9;
    localparam S_IPV6_HDR   = 5'd10; // IPv6 header (40 bytes)
    localparam S_GTP_HDR    = 5'd11; // GTP-U header (8 bytes min)
    localparam S_MPLS_HDR   = 5'd12; // MPLS label stack
    localparam S_IGMP_HDR   = 5'd13; // IGMP message header
    localparam S_ICMP_HDR   = 5'd14; // ICMP message header (type + code)
    localparam S_ICMPV6_HDR = 5'd15; // ICMPv6 type + code (MLD backward compat)
    localparam S_ARP_HDR    = 5'd16; // ARP header (28 bytes)
    localparam S_OUTER_VLAN = 5'd17; // QinQ outer VLAN (802.1ad)
    localparam S_GRE_HDR    = 5'd18; // GRE header (4-8 bytes)
    localparam S_OAM_HDR    = 5'd19; // OAM/CFM header (EtherType 0x8902)
    localparam S_NSH_HDR    = 5'd20; // NSH header (EtherType 0x894F, RFC 8300)
    localparam S_GENEVE_HDR = 5'd21; // Geneve header (UDP dst port 6081, RFC 8926)
    localparam S_PTP_HDR    = 5'd22; // PTP header (EtherType 0x88F7 or UDP 319/320)

    reg [4:0] state;
    reg [5:0] byte_cnt;  // counts bytes within current state (up to 39 for IPv6)
    reg [3:0] ipv6_tc_hi; // stores upper 4 bits of IPv6 Traffic Class (from byte 0)
    reg [10:0] frame_byte_cnt;  // absolute byte counter from SOF
    reg        gre_key_present; // GRE K flag (bit 2 of flags byte 0)

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state        <= S_IDLE;
            byte_cnt     <= 6'd0;
            frame_byte_cnt <= 11'd0;
            dst_mac      <= 48'd0;
            src_mac      <= 48'd0;
            ethertype    <= 16'd0;
            vlan_id      <= 12'd0;
            vlan_pcp     <= 3'd0;
            vlan_valid   <= 1'b0;
            outer_vlan_id  <= 12'd0;
            outer_vlan_pcp <= 3'd0;
            outer_vlan_valid <= 1'b0;
            src_ip       <= 32'd0;
            dst_ip       <= 32'd0;
            ip_protocol  <= 8'd0;
            ip_ttl       <= 8'd0;
            ip_checksum  <= 16'd0;
            l3_valid     <= 1'b0;
            ip_dont_fragment  <= 1'b0;
            ip_more_fragments <= 1'b0;
            ip_frag_offset    <= 13'd0;
            ip_frag_valid     <= 1'b0;
            src_ipv6     <= 128'd0;
            dst_ipv6     <= 128'd0;
            ipv6_next_header <= 8'd0;
            ipv6_valid   <= 1'b0;
            src_port     <= 16'd0;
            dst_port     <= 16'd0;
            l4_valid     <= 1'b0;
            l4_port_offset       <= 11'd0;
            l4_port_offset_valid <= 1'b0;
            vxlan_vni    <= 24'd0;
            vxlan_valid  <= 1'b0;
            gtp_teid     <= 32'd0;
            gtp_valid    <= 1'b0;
            oam_level    <= 3'd0;
            oam_opcode   <= 8'd0;
            oam_valid    <= 1'b0;
            gre_protocol <= 16'd0;
            gre_key      <= 32'd0;
            gre_valid    <= 1'b0;
            gre_key_present <= 1'b0;
            nsh_spi          <= 24'd0;
            nsh_si           <= 8'd0;
            nsh_next_protocol <= 8'd0;
            nsh_valid        <= 1'b0;
            geneve_vni       <= 24'd0;
            geneve_valid     <= 1'b0;
            ptp_message_type <= 4'd0;
            ptp_version      <= 4'd0;
            ptp_domain       <= 8'd0;
            ptp_valid        <= 1'b0;
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
            ipv6_dscp    <= 6'd0;
            ipv6_ecn     <= 2'd0;
            ipv6_tc_hi   <= 4'd0;
            tcp_flags    <= 8'd0;
            tcp_flags_valid <= 1'b0;
            icmp_type_field <= 8'd0;
            icmp_code    <= 8'd0;
            icmp_valid   <= 1'b0;
            icmpv6_type  <= 8'd0;
            icmpv6_code  <= 8'd0;
            icmpv6_valid <= 1'b0;
            arp_opcode   <= 16'd0;
            arp_spa      <= 32'd0;
            arp_tpa      <= 32'd0;
            arp_valid    <= 1'b0;
            ipv6_hop_limit  <= 8'd0;
            ipv6_flow_label <= 20'd0;
            fields_valid <= 1'b0;
        end else begin
            fields_valid <= 1'b0;  // default: deassert

            if (pkt_sof && pkt_valid) begin
                // Start of new frame — reset and capture first byte of dst_mac
                state    <= S_DST_MAC;
                byte_cnt <= 6'd1;
                frame_byte_cnt <= 11'd1;
                dst_mac  <= {pkt_data, 40'd0};
                src_mac  <= 48'd0;
                ethertype <= 16'd0;
                vlan_id  <= 12'd0;
                vlan_pcp <= 3'd0;
                vlan_valid <= 1'b0;
                outer_vlan_id  <= 12'd0;
                outer_vlan_pcp <= 3'd0;
                outer_vlan_valid <= 1'b0;
                src_ip   <= 32'd0;
                dst_ip   <= 32'd0;
                ip_protocol <= 8'd0;
                ip_ttl      <= 8'd0;
                ip_checksum <= 16'd0;
                l3_valid <= 1'b0;
                ip_dont_fragment  <= 1'b0;
                ip_more_fragments <= 1'b0;
                ip_frag_offset    <= 13'd0;
                ip_frag_valid     <= 1'b0;
                src_ipv6 <= 128'd0;
                dst_ipv6 <= 128'd0;
                ipv6_next_header <= 8'd0;
                ipv6_valid <= 1'b0;
                src_port <= 16'd0;
                dst_port <= 16'd0;
                l4_valid <= 1'b0;
                l4_port_offset       <= 11'd0;
                l4_port_offset_valid <= 1'b0;
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
                ipv6_dscp   <= 6'd0;
                ipv6_ecn    <= 2'd0;
                ipv6_tc_hi  <= 4'd0;
                tcp_flags   <= 8'd0;
                tcp_flags_valid <= 1'b0;
                icmp_type_field <= 8'd0;
                icmp_code   <= 8'd0;
                icmp_valid  <= 1'b0;
                icmpv6_type <= 8'd0;
                icmpv6_code <= 8'd0;
                icmpv6_valid <= 1'b0;
                arp_opcode  <= 16'd0;
                arp_spa     <= 32'd0;
                arp_tpa     <= 32'd0;
                arp_valid   <= 1'b0;
                ipv6_hop_limit  <= 8'd0;
                ipv6_flow_label <= 20'd0;
                oam_level       <= 3'd0;
                oam_opcode      <= 8'd0;
                oam_valid       <= 1'b0;
                gre_protocol    <= 16'd0;
                gre_key         <= 32'd0;
                gre_valid       <= 1'b0;
                gre_key_present <= 1'b0;
                nsh_spi          <= 24'd0;
                nsh_si           <= 8'd0;
                nsh_next_protocol <= 8'd0;
                nsh_valid        <= 1'b0;
                geneve_vni       <= 24'd0;
                geneve_valid     <= 1'b0;
                ptp_message_type <= 4'd0;
                ptp_version      <= 4'd0;
                ptp_domain       <= 8'd0;
                ptp_valid        <= 1'b0;
            end else if (pkt_valid) begin
                // Increment absolute byte counter
                frame_byte_cnt <= frame_byte_cnt + 11'd1;

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
                            // Check for VLAN tag (802.1Q)
                            if (ethertype[15:8] == 8'h81 && pkt_data == 8'h00) begin
                                state    <= S_VLAN_TAG;
                                byte_cnt <= 6'd0;
                                vlan_valid <= 1'b1;
                            end
                            // Check for QinQ (802.1ad = 0x88A8, legacy = 0x9100)
                            else if ((ethertype[15:8] == 8'h88 && pkt_data == 8'hA8) ||
                                     (ethertype[15:8] == 8'h91 && pkt_data == 8'h00)) begin
                                state    <= S_OUTER_VLAN;
                                byte_cnt <= 6'd0;
                                outer_vlan_valid <= 1'b1;
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
                            end
                            // Check for ARP (0x0806)
                            else if (ethertype[15:8] == 8'h08 && pkt_data == 8'h06) begin
                                state    <= S_ARP_HDR;
                                byte_cnt <= 6'd0;
                            end
                            // Check for OAM/CFM (0x8902)
                            else if (ethertype[15:8] == 8'h89 && pkt_data == 8'h02) begin
                                state    <= S_OAM_HDR;
                                byte_cnt <= 6'd0;
                            end
                            // Check for NSH (0x894F, RFC 8300)
                            else if (ethertype[15:8] == 8'h89 && pkt_data == 8'h4F) begin
                                state    <= S_NSH_HDR;
                                byte_cnt <= 6'd0;
                            end
                            // Check for PTP (0x88F7, IEEE 1588)
                            else if (ethertype[15:8] == 8'h88 && pkt_data == 8'hF7) begin
                                state    <= S_PTP_HDR;
                                byte_cnt <= 6'd0;
                            end else begin
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                        end
                    end

                    S_OUTER_VLAN: begin
                        // QinQ outer tag: 2 bytes PCP+VID, then 2 bytes inner ethertype
                        case (byte_cnt)
                            6'd0: begin
                                outer_vlan_pcp <= pkt_data[7:5];
                                outer_vlan_id[11:8] <= pkt_data[3:0];
                                byte_cnt <= 6'd1;
                            end
                            6'd1: begin
                                outer_vlan_id[7:0] <= pkt_data;
                                byte_cnt <= 6'd2;
                            end
                            6'd2: begin
                                // Inner ethertype MSB
                                ethertype[15:8] <= pkt_data;
                                byte_cnt <= 6'd3;
                            end
                            6'd3: begin
                                ethertype[7:0] <= pkt_data;
                                // Check if inner tag is 802.1Q (0x8100)
                                if (ethertype[15:8] == 8'h81 && pkt_data == 8'h00) begin
                                    state      <= S_VLAN_TAG;
                                    byte_cnt   <= 6'd0;
                                    vlan_valid <= 1'b1;
                                end
                                // Inner is IPv4
                                else if (ethertype[15:8] == 8'h08 && pkt_data == 8'h00) begin
                                    state    <= S_IP_HDR;
                                    byte_cnt <= 6'd0;
                                end
                                // Inner is IPv6
                                else if (ethertype[15:8] == 8'h86 && pkt_data == 8'hDD) begin
                                    state    <= S_IPV6_HDR;
                                    byte_cnt <= 6'd0;
                                end
                                // Inner is MPLS
                                else if (ethertype[15:8] == 8'h88 && (pkt_data == 8'h47 || pkt_data == 8'h48)) begin
                                    state    <= S_MPLS_HDR;
                                    byte_cnt <= 6'd0;
                                end
                                // Inner is ARP
                                else if (ethertype[15:8] == 8'h08 && pkt_data == 8'h06) begin
                                    state    <= S_ARP_HDR;
                                    byte_cnt <= 6'd0;
                                end
                                // Inner is OAM/CFM (0x8902)
                                else if (ethertype[15:8] == 8'h89 && pkt_data == 8'h02) begin
                                    state    <= S_OAM_HDR;
                                    byte_cnt <= 6'd0;
                                end
                                // Inner is NSH (0x894F, RFC 8300)
                                else if (ethertype[15:8] == 8'h89 && pkt_data == 8'h4F) begin
                                    state    <= S_NSH_HDR;
                                    byte_cnt <= 6'd0;
                                end
                                // Inner is PTP (0x88F7, IEEE 1588)
                                else if (ethertype[15:8] == 8'h88 && pkt_data == 8'hF7) begin
                                    state    <= S_PTP_HDR;
                                    byte_cnt <= 6'd0;
                                end else begin
                                    state        <= S_PAYLOAD;
                                    fields_valid <= 1'b1;
                                end
                            end
                        endcase
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
                            end
                            // Check for ARP after VLAN (0x0806)
                            else if (ethertype[15:8] == 8'h08 && pkt_data == 8'h06) begin
                                state    <= S_ARP_HDR;
                                byte_cnt <= 6'd0;
                            end
                            // Check for OAM/CFM after VLAN (0x8902)
                            else if (ethertype[15:8] == 8'h89 && pkt_data == 8'h02) begin
                                state    <= S_OAM_HDR;
                                byte_cnt <= 6'd0;
                            end
                            // Check for NSH after VLAN (0x894F)
                            else if (ethertype[15:8] == 8'h89 && pkt_data == 8'h4F) begin
                                state    <= S_NSH_HDR;
                                byte_cnt <= 6'd0;
                            end
                            // Check for PTP after VLAN (0x88F7, IEEE 1588)
                            else if (ethertype[15:8] == 8'h88 && pkt_data == 8'hF7) begin
                                state    <= S_PTP_HDR;
                                byte_cnt <= 6'd0;
                            end else begin
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                        end
                    end

                    S_IP_HDR: begin
                        // Parse 20-byte IPv4 header (assuming IHL=5, standard header)
                        // Byte  1: TOS (DSCP + ECN)
                        // Byte  6: Flags[7:5] + Fragment Offset[12:8]
                        // Byte  7: Fragment Offset[7:0]
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
                            6'd6: begin
                                // Flags: bit 6 = DF, bit 5 = MF, bits 4:0 = frag_offset[12:8]
                                ip_dont_fragment  <= pkt_data[6];
                                ip_more_fragments <= pkt_data[5];
                                ip_frag_offset[12:8] <= pkt_data[4:0];
                            end
                            6'd7: begin
                                ip_frag_offset[7:0] <= pkt_data;
                                ip_frag_valid <= 1'b1;
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
                                    // Latch L4 port offset (next byte = src_port MSB)
                                    l4_port_offset <= frame_byte_cnt + 11'd1;
                                    l4_port_offset_valid <= 1'b1;
                                end
                                // Check for ICMP (protocol 1)
                                else if (ip_protocol == 8'd1) begin
                                    state    <= S_ICMP_HDR;
                                    byte_cnt <= 6'd0;
                                end
                                // Check for IGMP (protocol 2)
                                else if (ip_protocol == 8'd2) begin
                                    state    <= S_IGMP_HDR;
                                    byte_cnt <= 6'd0;
                                end
                                // Check for GRE (protocol 47)
                                else if (ip_protocol == 8'd47) begin
                                    state    <= S_GRE_HDR;
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
                        // Parse TCP/UDP header
                        // Bytes 0-1: Source port
                        // Bytes 2-3: Destination port
                        // TCP only: Byte 13: Flags (CWR|ECE|URG|ACK|PSH|RST|SYN|FIN)
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
                                    state    <= S_VXLAN_HDR;
                                    byte_cnt <= 6'd0;
                                end
                                // Check for GTP-U: UDP + dst port 2152 (0x0868)
                                else if (ip_protocol == 8'd17 &&
                                         dst_port[15:8] == 8'h08 && pkt_data == 8'h68) begin
                                    state    <= S_GTP_HDR;
                                    byte_cnt <= 6'd0;
                                end
                                // Check for Geneve: UDP + dst port 6081 (0x17C1)
                                else if (ip_protocol == 8'd17 &&
                                         dst_port[15:8] == 8'h17 && pkt_data == 8'hC1) begin
                                    state    <= S_GENEVE_HDR;
                                    byte_cnt <= 6'd0;
                                end
                                // Check for PTP: UDP dst port 319 (0x013F) or 320 (0x0140)
                                else if (ip_protocol == 8'd17 &&
                                         dst_port[15:8] == 8'h01 &&
                                         (pkt_data == 8'h3F || pkt_data == 8'h40)) begin
                                    state    <= S_PTP_HDR;
                                    byte_cnt <= 6'd0;
                                end
                                // UDP (not VXLAN/GTP/Geneve/PTP): done
                                else if (ip_protocol == 8'd17) begin
                                    state        <= S_PAYLOAD;
                                    fields_valid <= 1'b1;
                                end
                                // TCP: continue to byte 13 for flags
                                // (ip_protocol == 6 falls through to keep parsing)
                            end
                            6'd13: begin
                                // TCP flags byte (only reached for TCP, protocol 6)
                                tcp_flags       <= pkt_data;
                                tcp_flags_valid <= 1'b1;
                                state           <= S_PAYLOAD;
                                fields_valid    <= 1'b1;
                            end
                            default: ;  // skip bytes 4-12 of TCP header
                        endcase

                        if (byte_cnt != 6'd3 || ip_protocol == 8'd6) begin
                            if (byte_cnt != 6'd13) begin
                                byte_cnt <= byte_cnt + 6'd1;
                            end
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
                        // Bytes 0-1: Version(4) + Traffic Class(8) + Flow Label(20)
                        //   Byte 0: version[7:4], TC[7:4] = pkt_data[3:0]
                        //   Byte 1: TC[3:0] = pkt_data[7:4], flow_label[19:16] = pkt_data[3:0]
                        //   TC[7:2] = DSCP, TC[1:0] = ECN
                        // Byte  6: Next Header
                        // Bytes 8-23: Source IPv6 (16 bytes)
                        // Bytes 24-39: Destination IPv6 (16 bytes)
                        case (byte_cnt)
                            6'd0: ipv6_tc_hi <= pkt_data[3:0];  // TC bits [7:4]
                            6'd1: begin
                                // TC = {ipv6_tc_hi, pkt_data[7:4]}
                                // DSCP = TC[7:2] = {ipv6_tc_hi[3:0], pkt_data[7:6]}
                                // ECN  = TC[1:0] = pkt_data[5:4]
                                ipv6_dscp <= {ipv6_tc_hi[3:0], pkt_data[7:6]};
                                ipv6_ecn  <= pkt_data[5:4];
                                // Flow label [19:16] from lower nibble of byte 1
                                ipv6_flow_label[19:16] <= pkt_data[3:0];
                            end
                            6'd2: ipv6_flow_label[15:8] <= pkt_data;
                            6'd3: ipv6_flow_label[7:0]  <= pkt_data;
                            6'd6: ipv6_next_header <= pkt_data;
                            6'd7: ipv6_hop_limit <= pkt_data;
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
                                    // Latch L4 port offset (next byte = src_port MSB)
                                    l4_port_offset <= frame_byte_cnt + 11'd1;
                                    l4_port_offset_valid <= 1'b1;
                                end
                                // Check for ICMPv6 (next header 58) — type/code + MLD backward compat
                                else if (ipv6_next_header == 8'd58) begin
                                    state    <= S_ICMPV6_HDR;
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

                    S_ICMP_HDR: begin
                        // ICMP header: byte 0 = type, byte 1 = code
                        case (byte_cnt)
                            6'd0: begin
                                icmp_type_field <= pkt_data;
                                byte_cnt <= 6'd1;
                            end
                            6'd1: begin
                                icmp_code    <= pkt_data;
                                icmp_valid   <= 1'b1;
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                        endcase
                        // byte_cnt is advanced in case 0, case 1 transitions to PAYLOAD
                    end

                    S_ICMPV6_HDR: begin
                        // ICMPv6 header: byte 0 = type, byte 1 = code
                        case (byte_cnt)
                            6'd0: begin
                                icmpv6_type <= pkt_data;
                                byte_cnt <= 6'd1;
                            end
                            6'd1: begin
                                icmpv6_code  <= pkt_data;
                                icmpv6_valid <= 1'b1;
                                // MLD backward compatibility: types 130-132
                                if (icmpv6_type == 8'd130 || icmpv6_type == 8'd131 || icmpv6_type == 8'd132) begin
                                    mld_type  <= icmpv6_type;
                                    mld_valid <= 1'b1;
                                end
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                        endcase
                        // byte_cnt is advanced in case 0, case 1 transitions to PAYLOAD
                    end

                    S_ARP_HDR: begin
                        // ARP header (28 bytes):
                        // Bytes 0-1: Hardware type (skip)
                        // Bytes 2-3: Protocol type (skip)
                        // Byte 4: Hardware address length (skip)
                        // Byte 5: Protocol address length (skip)
                        // Bytes 6-7: Opcode
                        // Bytes 8-13: Sender hardware address (skip)
                        // Bytes 14-17: Sender protocol address (SPA)
                        // Bytes 18-23: Target hardware address (skip)
                        // Bytes 24-27: Target protocol address (TPA)
                        case (byte_cnt)
                            6'd6:  arp_opcode[15:8] <= pkt_data;
                            6'd7:  arp_opcode[7:0]  <= pkt_data;
                            6'd14: arp_spa[31:24] <= pkt_data;
                            6'd15: arp_spa[23:16] <= pkt_data;
                            6'd16: arp_spa[15:8]  <= pkt_data;
                            6'd17: arp_spa[7:0]   <= pkt_data;
                            6'd24: arp_tpa[31:24] <= pkt_data;
                            6'd25: arp_tpa[23:16] <= pkt_data;
                            6'd26: arp_tpa[15:8]  <= pkt_data;
                            6'd27: begin
                                arp_tpa[7:0] <= pkt_data;
                                arp_valid    <= 1'b1;
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                            default: ;
                        endcase

                        if (byte_cnt != 6'd27) begin
                            byte_cnt <= byte_cnt + 6'd1;
                        end
                    end

                    S_GRE_HDR: begin
                        // GRE header: minimum 4 bytes (flags + protocol type)
                        // If K flag set (bit 2 of byte 0): 4 more bytes for key
                        // Byte 0: flags [C|R|K|S|s|Recur|A|Flags]
                        // Byte 1: flags continued [Ver]
                        // Bytes 2-3: Protocol Type
                        // Bytes 4-7: Key (if K flag set)
                        case (byte_cnt)
                            6'd0: begin
                                gre_key_present <= pkt_data[5]; // K flag is bit 2 of GRE flags (bit 5 in byte 0 of RFC 2784 encoding: C=7,R=6,K=5,S=4)
                                byte_cnt <= 6'd1;
                            end
                            6'd1: begin
                                byte_cnt <= 6'd2;
                            end
                            6'd2: begin
                                gre_protocol[15:8] <= pkt_data;
                                byte_cnt <= 6'd3;
                            end
                            6'd3: begin
                                gre_protocol[7:0] <= pkt_data;
                                gre_valid <= 1'b1;
                                if (gre_key_present) begin
                                    byte_cnt <= 6'd4;
                                end else begin
                                    state        <= S_PAYLOAD;
                                    fields_valid <= 1'b1;
                                end
                            end
                            6'd4: begin
                                gre_key[31:24] <= pkt_data;
                                byte_cnt <= 6'd5;
                            end
                            6'd5: begin
                                gre_key[23:16] <= pkt_data;
                                byte_cnt <= 6'd6;
                            end
                            6'd6: begin
                                gre_key[15:8] <= pkt_data;
                                byte_cnt <= 6'd7;
                            end
                            6'd7: begin
                                gre_key[7:0] <= pkt_data;
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                            default: ;
                        endcase

                        if (byte_cnt != 6'd3 && byte_cnt != 6'd7 && !gre_key_present) begin
                            // handled in case above
                        end
                    end

                    S_OAM_HDR: begin
                        // OAM/CFM header (IEEE 802.1ag):
                        // Byte 0: MEL[7:5] (3-bit level) + Version[4:0]
                        // Byte 1: OpCode
                        // Bytes 2-3: Flags + First TLV Offset
                        case (byte_cnt)
                            6'd0: begin
                                oam_level <= pkt_data[7:5];
                                byte_cnt  <= 6'd1;
                            end
                            6'd1: begin
                                oam_opcode   <= pkt_data;
                                oam_valid    <= 1'b1;
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                            default: ;
                        endcase
                    end

                    S_NSH_HDR: begin
                        // NSH header (RFC 8300, EtherType 0x894F):
                        // Base header (4 bytes):
                        //   Byte 0: Version[7:6] + OAM[5] + unused[4:0]
                        //   Byte 1: Reserved
                        //   Byte 2: Next Protocol (1=IPv4, 2=IPv6, 3=Ethernet)
                        //   Byte 3: Reserved
                        // Service Path Header (4 bytes):
                        //   Byte 4: SPI[23:16]
                        //   Byte 5: SPI[15:8]
                        //   Byte 6: SPI[7:0]
                        //   Byte 7: SI
                        case (byte_cnt)
                            6'd0: begin
                                // Skip version/flags byte
                                byte_cnt <= 6'd1;
                            end
                            6'd1: begin
                                // Skip reserved byte
                                byte_cnt <= 6'd2;
                            end
                            6'd2: begin
                                nsh_next_protocol <= pkt_data;
                                byte_cnt <= 6'd3;
                            end
                            6'd3: begin
                                // Skip reserved byte
                                byte_cnt <= 6'd4;
                            end
                            6'd4: begin
                                nsh_spi[23:16] <= pkt_data;
                                byte_cnt <= 6'd5;
                            end
                            6'd5: begin
                                nsh_spi[15:8] <= pkt_data;
                                byte_cnt <= 6'd6;
                            end
                            6'd6: begin
                                nsh_spi[7:0] <= pkt_data;
                                byte_cnt <= 6'd7;
                            end
                            6'd7: begin
                                nsh_si       <= pkt_data;
                                nsh_valid    <= 1'b1;
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                            default: ;
                        endcase
                    end

                    S_GENEVE_HDR: begin
                        // Geneve header (RFC 8926, UDP dst port 6081):
                        // 8-byte fixed header:
                        //   Byte 0: Version[7:6] + OptLen[5:0]
                        //   Byte 1: O[7] + C[6] + Reserved[5:0]
                        //   Byte 2: Protocol Type[15:8]
                        //   Byte 3: Protocol Type[7:0]
                        //   Byte 4: VNI[23:16]
                        //   Byte 5: VNI[15:8]
                        //   Byte 6: VNI[7:0]
                        //   Byte 7: Reserved
                        case (byte_cnt)
                            6'd4: begin
                                geneve_vni[23:16] <= pkt_data;
                                byte_cnt <= 6'd5;
                            end
                            6'd5: begin
                                geneve_vni[15:8] <= pkt_data;
                                byte_cnt <= 6'd6;
                            end
                            6'd6: begin
                                geneve_vni[7:0] <= pkt_data;
                                byte_cnt <= 6'd7;
                            end
                            6'd7: begin
                                geneve_valid <= 1'b1;
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                            default: byte_cnt <= byte_cnt + 6'd1;
                        endcase
                    end

                    S_PTP_HDR: begin
                        // PTP common header (IEEE 1588):
                        //   Byte 0: transportSpecific[7:4] + messageType[3:0]
                        //   Byte 1: reserved[7:4] + versionPTP[3:0]
                        //   Bytes 2-3: messageLength
                        //   Byte 4: domainNumber
                        // For L4 PTP (UDP 319/320): skip 4 bytes UDP length+checksum first
                        // byte_cnt starts at 0 after UDP port detection or L2 EtherType
                        case (byte_cnt)
                            6'd0: begin
                                // For L4 PTP, bytes 0-3 are UDP length+checksum — skip
                                // For L2 PTP, byte 0 is PTP header byte 0
                                if (l4_valid) begin
                                    // L4 path: skip UDP remainder (length+checksum)
                                    byte_cnt <= 6'd1;
                                end else begin
                                    // L2 path: this is PTP header byte 0
                                    ptp_message_type <= pkt_data[3:0];
                                    ptp_version      <= pkt_data[7:4]; // transportSpecific, but PTPv1 puts version here
                                    byte_cnt <= 6'd1;
                                end
                            end
                            6'd1: begin
                                if (l4_valid) begin
                                    byte_cnt <= 6'd2; // skip
                                end else begin
                                    // L2 path: byte 1 = versionPTP
                                    ptp_version <= pkt_data[3:0];
                                    byte_cnt <= 6'd2;
                                end
                            end
                            6'd2: begin
                                if (l4_valid) begin
                                    byte_cnt <= 6'd3; // skip
                                end else begin
                                    byte_cnt <= 6'd3; // messageLength MSB, skip
                                end
                            end
                            6'd3: begin
                                if (l4_valid) begin
                                    byte_cnt <= 6'd4; // last UDP skip byte
                                end else begin
                                    byte_cnt <= 6'd4; // messageLength LSB, skip
                                end
                            end
                            6'd4: begin
                                if (l4_valid) begin
                                    // L4 path: now at PTP header byte 0
                                    ptp_message_type <= pkt_data[3:0];
                                    byte_cnt <= 6'd5;
                                end else begin
                                    // L2 path: byte 4 = domainNumber
                                    ptp_domain <= pkt_data;
                                    ptp_valid    <= 1'b1;
                                    state        <= S_PAYLOAD;
                                    fields_valid <= 1'b1;
                                end
                            end
                            6'd5: begin
                                // L4 path: PTP header byte 1 = versionPTP
                                ptp_version <= pkt_data[3:0];
                                byte_cnt <= 6'd6;
                            end
                            6'd6: begin
                                byte_cnt <= 6'd7; // messageLength MSB, skip
                            end
                            6'd7: begin
                                byte_cnt <= 6'd8; // messageLength LSB, skip
                            end
                            6'd8: begin
                                // L4 path: PTP header byte 4 = domainNumber
                                ptp_domain <= pkt_data;
                                ptp_valid    <= 1'b1;
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                            default: byte_cnt <= byte_cnt + 6'd1;
                        endcase

                        if (byte_cnt < 6'd4 || (l4_valid && byte_cnt < 6'd8)) begin
                            // byte_cnt is already incremented in the case blocks above
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
