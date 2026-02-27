// frame_parser.v — Ethernet frame field extractor
// Extracts: dst_mac, src_mac, ethertype, vlan_id, vlan_pcp
//           src_ip, dst_ip, ip_protocol, src_port, dst_port (IPv4/TCP/UDP)
// Handles 802.1Q VLAN-tagged frames (EtherType 0x8100)
// Handles IPv4 header parsing (20-byte fixed, IHL=5)
// Handles TCP/UDP port extraction (first 4 bytes of L4 header)
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

    // L4 extracted fields (TCP/UDP)
    output reg  [15:0] src_port,
    output reg  [15:0] dst_port,
    output reg         l4_valid,    // frame had TCP/UDP header

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
    localparam S_PAYLOAD   = 4'd8;

    reg [3:0] state;
    reg [4:0] byte_cnt;  // counts bytes within current state (up to 20 for IPv4)

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state        <= S_IDLE;
            byte_cnt     <= 5'd0;
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
            src_port     <= 16'd0;
            dst_port     <= 16'd0;
            l4_valid     <= 1'b0;
            fields_valid <= 1'b0;
        end else begin
            fields_valid <= 1'b0;  // default: deassert

            if (pkt_sof && pkt_valid) begin
                // Start of new frame — reset and capture first byte of dst_mac
                state    <= S_DST_MAC;
                byte_cnt <= 5'd1;
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
                src_port <= 16'd0;
                dst_port <= 16'd0;
                l4_valid <= 1'b0;
            end else if (pkt_valid) begin
                case (state)
                    S_DST_MAC: begin
                        dst_mac <= dst_mac | ({48'd0, pkt_data} << ((5 - byte_cnt) * 8));
                        if (byte_cnt == 5'd5) begin
                            state    <= S_SRC_MAC;
                            byte_cnt <= 5'd0;
                        end else begin
                            byte_cnt <= byte_cnt + 5'd1;
                        end
                    end

                    S_SRC_MAC: begin
                        src_mac <= src_mac | ({48'd0, pkt_data} << ((5 - byte_cnt) * 8));
                        if (byte_cnt == 5'd5) begin
                            state    <= S_ETYPE;
                            byte_cnt <= 5'd0;
                        end else begin
                            byte_cnt <= byte_cnt + 5'd1;
                        end
                    end

                    S_ETYPE: begin
                        if (byte_cnt == 5'd0) begin
                            ethertype[15:8] <= pkt_data;
                            byte_cnt <= 5'd1;
                        end else begin
                            ethertype[7:0] <= pkt_data;
                            // Check for VLAN tag
                            if (ethertype[15:8] == 8'h81 && pkt_data == 8'h00) begin
                                state    <= S_VLAN_TAG;
                                byte_cnt <= 5'd0;
                                vlan_valid <= 1'b1;
                            end
                            // Check for IPv4
                            else if (ethertype[15:8] == 8'h08 && pkt_data == 8'h00) begin
                                state    <= S_IP_HDR;
                                byte_cnt <= 5'd0;
                            end else begin
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                        end
                    end

                    S_VLAN_TAG: begin
                        // 2 bytes: PCP(3) + DEI(1) + VID(12)
                        if (byte_cnt == 5'd0) begin
                            vlan_pcp <= pkt_data[7:5];
                            vlan_id[11:8] <= pkt_data[3:0];
                            byte_cnt <= 5'd1;
                        end else begin
                            vlan_id[7:0] <= pkt_data;
                            state    <= S_ETYPE2;
                            byte_cnt <= 5'd0;
                        end
                    end

                    S_ETYPE2: begin
                        // Real ethertype after VLAN tag
                        if (byte_cnt == 5'd0) begin
                            ethertype[15:8] <= pkt_data;
                            byte_cnt <= 5'd1;
                        end else begin
                            ethertype[7:0] <= pkt_data;
                            // Check for IPv4 after VLAN
                            if (ethertype[15:8] == 8'h08 && pkt_data == 8'h00) begin
                                state    <= S_IP_HDR;
                                byte_cnt <= 5'd0;
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
                            5'd9:  ip_protocol <= pkt_data;
                            5'd12: src_ip[31:24] <= pkt_data;
                            5'd13: src_ip[23:16] <= pkt_data;
                            5'd14: src_ip[15:8]  <= pkt_data;
                            5'd15: src_ip[7:0]   <= pkt_data;
                            5'd16: dst_ip[31:24] <= pkt_data;
                            5'd17: dst_ip[23:16] <= pkt_data;
                            5'd18: dst_ip[15:8]  <= pkt_data;
                            5'd19: begin
                                dst_ip[7:0] <= pkt_data;
                                l3_valid <= 1'b1;
                                // Check if protocol is TCP (6) or UDP (17)
                                if (ip_protocol == 8'd6 || ip_protocol == 8'd17) begin
                                    state    <= S_L4_HDR;
                                    byte_cnt <= 5'd0;
                                end else begin
                                    state        <= S_PAYLOAD;
                                    fields_valid <= 1'b1;
                                end
                            end
                            default: ;  // skip other IPv4 header bytes
                        endcase

                        if (byte_cnt != 5'd19) begin
                            byte_cnt <= byte_cnt + 5'd1;
                        end
                    end

                    S_L4_HDR: begin
                        // Parse first 4 bytes of TCP/UDP header
                        // Bytes 0-1: Source port
                        // Bytes 2-3: Destination port
                        case (byte_cnt)
                            5'd0: src_port[15:8] <= pkt_data;
                            5'd1: src_port[7:0]  <= pkt_data;
                            5'd2: dst_port[15:8] <= pkt_data;
                            5'd3: begin
                                dst_port[7:0] <= pkt_data;
                                l4_valid     <= 1'b1;
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                        endcase

                        if (byte_cnt != 5'd3) begin
                            byte_cnt <= byte_cnt + 5'd1;
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
