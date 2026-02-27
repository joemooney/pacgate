// frame_parser.v — Ethernet frame field extractor
// Extracts: dst_mac, src_mac, ethertype, vlan_id, vlan_pcp
// Handles 802.1Q VLAN-tagged frames (EtherType 0x8100)
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

    // Extracted fields
    output reg  [47:0] dst_mac,
    output reg  [47:0] src_mac,
    output reg  [15:0] ethertype,
    output reg  [11:0] vlan_id,
    output reg  [2:0]  vlan_pcp,
    output reg         vlan_valid,  // frame had 802.1Q tag
    output reg         fields_valid // pulse: all header fields extracted
);

    // Parser states
    localparam S_IDLE      = 3'd0;
    localparam S_DST_MAC   = 3'd1;
    localparam S_SRC_MAC   = 3'd2;
    localparam S_ETYPE     = 3'd3;
    localparam S_VLAN_TAG  = 3'd4;
    localparam S_ETYPE2    = 3'd5;  // real ethertype after VLAN
    localparam S_PAYLOAD   = 3'd6;

    reg [2:0] state;
    reg [3:0] byte_cnt;  // counts bytes within current state

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state        <= S_IDLE;
            byte_cnt     <= 4'd0;
            dst_mac      <= 48'd0;
            src_mac      <= 48'd0;
            ethertype    <= 16'd0;
            vlan_id      <= 12'd0;
            vlan_pcp     <= 3'd0;
            vlan_valid   <= 1'b0;
            fields_valid <= 1'b0;
        end else begin
            fields_valid <= 1'b0;  // default: deassert

            if (pkt_sof && pkt_valid) begin
                // Start of new frame — reset and capture first byte of dst_mac
                state    <= S_DST_MAC;
                byte_cnt <= 4'd1;
                dst_mac  <= {pkt_data, 40'd0};
                src_mac  <= 48'd0;
                ethertype <= 16'd0;
                vlan_id  <= 12'd0;
                vlan_pcp <= 3'd0;
                vlan_valid <= 1'b0;
            end else if (pkt_valid) begin
                case (state)
                    S_DST_MAC: begin
                        dst_mac <= dst_mac | ({48'd0, pkt_data} << ((5 - byte_cnt) * 8));
                        if (byte_cnt == 4'd5) begin
                            state    <= S_SRC_MAC;
                            byte_cnt <= 4'd0;
                        end else begin
                            byte_cnt <= byte_cnt + 4'd1;
                        end
                    end

                    S_SRC_MAC: begin
                        src_mac <= src_mac | ({48'd0, pkt_data} << ((5 - byte_cnt) * 8));
                        if (byte_cnt == 4'd5) begin
                            state    <= S_ETYPE;
                            byte_cnt <= 4'd0;
                        end else begin
                            byte_cnt <= byte_cnt + 4'd1;
                        end
                    end

                    S_ETYPE: begin
                        if (byte_cnt == 4'd0) begin
                            ethertype[15:8] <= pkt_data;
                            byte_cnt <= 4'd1;
                        end else begin
                            ethertype[7:0] <= pkt_data;
                            // Check for VLAN tag
                            if (ethertype[15:8] == 8'h81 && pkt_data == 8'h00) begin
                                state    <= S_VLAN_TAG;
                                byte_cnt <= 4'd0;
                                vlan_valid <= 1'b1;
                            end else begin
                                state        <= S_PAYLOAD;
                                fields_valid <= 1'b1;
                            end
                        end
                    end

                    S_VLAN_TAG: begin
                        // 2 bytes: PCP(3) + DEI(1) + VID(12)
                        if (byte_cnt == 4'd0) begin
                            vlan_pcp <= pkt_data[7:5];
                            vlan_id[11:8] <= pkt_data[3:0];
                            byte_cnt <= 4'd1;
                        end else begin
                            vlan_id[7:0] <= pkt_data;
                            state    <= S_ETYPE2;
                            byte_cnt <= 4'd0;
                        end
                    end

                    S_ETYPE2: begin
                        // Real ethertype after VLAN tag
                        if (byte_cnt == 4'd0) begin
                            ethertype[15:8] <= pkt_data;
                            byte_cnt <= 4'd1;
                        end else begin
                            ethertype[7:0] <= pkt_data;
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
