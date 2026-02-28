// packet_rewrite.v — In-place packet header rewrite engine
// Hand-written infrastructure module (not generated from rules)
//
// Sits between store-forward FIFO output and AXI-Stream master output.
// Applies byte substitutions at known header offsets based on rewrite
// parameters from the rewrite_lut.
//
// Supported rewrites (all in-place, no frame length change):
//   set_dst_mac  — bytes 0-5
//   set_src_mac  — bytes 6-11
//   set_vlan_id  — bytes 14-15 (TCI, VLAN-tagged frames only)
//   set_ttl      — IP header byte 8 (offset 22 or 26 with VLAN, or 26 with QinQ)
//   dec_ttl      — decrement TTL by 1
//   set_src_ip   — IP header bytes 12-15 (offset 26-29 or 30-33 with VLAN)
//   set_dst_ip   — IP header bytes 16-19 (offset 30-33 or 34-37 with VLAN)
//   set_dscp     — IP header byte 1 TOS[7:2] (DSCP remarking, preserves ECN)
//   set_src_port — L4 source port (2 bytes at l4_port_offset)
//   set_dst_port — L4 destination port (2 bytes at l4_port_offset + 2)
//
// IP checksum is incrementally updated (RFC 1624) when TTL, IP
// addresses, or DSCP are modified.
//
// L4 (TCP/UDP) checksum is incrementally updated (RFC 1624) when
// ports are modified. UDP checksum == 0x0000 is left as-is.
//
// rewrite_flags encoding:
//   [0]=set_dst_mac [1]=set_src_mac [2]=set_vlan_id
//   [3]=set_ttl [4]=dec_ttl [5]=set_src_ip [6]=set_dst_ip [7]=set_dscp
//   [8]=set_src_port [9]=set_dst_port

module packet_rewrite (
    input  wire        clk,
    input  wire        rst_n,

    // AXI-Stream input (from store-forward FIFO)
    input  wire [7:0]  s_axis_tdata,
    input  wire        s_axis_tvalid,
    output wire        s_axis_tready,
    input  wire        s_axis_tlast,

    // AXI-Stream output (to external master)
    output reg  [7:0]  m_axis_tdata,
    output reg         m_axis_tvalid,
    input  wire        m_axis_tready,
    output reg         m_axis_tlast,

    // Rewrite parameters (latched on decision_valid by top-level)
    input  wire        rewrite_en,
    input  wire [15:0] rewrite_flags,
    input  wire [47:0] rewrite_dst_mac,
    input  wire [47:0] rewrite_src_mac,
    input  wire [11:0] rewrite_vlan_id,
    input  wire [7:0]  rewrite_ttl,
    input  wire [31:0] rewrite_src_ip,
    input  wire [31:0] rewrite_dst_ip,
    input  wire [5:0]  rewrite_dscp,
    input  wire [15:0] rewrite_src_port,
    input  wire [15:0] rewrite_dst_port,

    // Parsed fields from frame_parser (for incremental checksum)
    input  wire        has_vlan,
    input  wire        has_outer_vlan,
    input  wire [7:0]  orig_ip_ttl,
    input  wire [15:0] orig_ip_checksum,
    input  wire [31:0] orig_src_ip,
    input  wire [31:0] orig_dst_ip,
    input  wire [5:0]  orig_ip_dscp,
    input  wire [1:0]  orig_ip_ecn,
    input  wire [15:0] orig_src_port,
    input  wire [15:0] orig_dst_port,
    input  wire [10:0] l4_port_offset,
    input  wire        l4_port_offset_valid,
    input  wire [7:0]  ip_protocol
);

    // Flag decode
    wire flag_dst_mac  = rewrite_en & rewrite_flags[0];
    wire flag_src_mac  = rewrite_en & rewrite_flags[1];
    wire flag_vlan_id  = rewrite_en & rewrite_flags[2];
    wire flag_set_ttl  = rewrite_en & rewrite_flags[3];
    wire flag_dec_ttl  = rewrite_en & rewrite_flags[4];
    wire flag_src_ip   = rewrite_en & rewrite_flags[5];
    wire flag_dst_ip   = rewrite_en & rewrite_flags[6];
    wire flag_dscp     = rewrite_en & rewrite_flags[7];
    wire flag_src_port = rewrite_en & rewrite_flags[8];
    wire flag_dst_port = rewrite_en & rewrite_flags[9];

    // IP header base offset: 14 (no VLAN), 18 (with VLAN), 22 (with QinQ outer+inner)
    wire [10:0] ip_base = has_outer_vlan ? 11'd22 : (has_vlan ? 11'd18 : 11'd14);

    // Compute new TTL value
    wire [7:0] new_ttl = flag_set_ttl ? rewrite_ttl :
                         flag_dec_ttl ? (orig_ip_ttl - 8'd1) :
                         orig_ip_ttl;

    // --- Incremental IP checksum update (RFC 1624) ---
    // HC' = ~(~HC + ~m + m') in ones-complement arithmetic
    // We compute a 32-bit delta accumulator, then fold to 16 bits.
    //
    // For each modified field, delta += (~old + new)
    // Final: new_checksum = ~(~old_checksum + delta)

    reg [31:0] cksum_delta;

    always @(*) begin
        cksum_delta = 32'd0;

        // TTL change (byte field, but in 16-bit word with protocol)
        // Original word: {ip_ttl, ip_protocol} at IP+8..9
        // We only change the TTL byte; protocol stays the same.
        if (flag_set_ttl || flag_dec_ttl) begin
            cksum_delta = cksum_delta + {16'd0, ~{orig_ip_ttl, 8'h00}} + {16'd0, new_ttl, 8'h00};
        end

        // Source IP change (32-bit: two 16-bit words)
        if (flag_src_ip) begin
            cksum_delta = cksum_delta
                + {16'd0, ~orig_src_ip[31:16]} + {16'd0, rewrite_src_ip[31:16]}
                + {16'd0, ~orig_src_ip[15:0]}  + {16'd0, rewrite_src_ip[15:0]};
        end

        // Destination IP change (32-bit: two 16-bit words)
        if (flag_dst_ip) begin
            cksum_delta = cksum_delta
                + {16'd0, ~orig_dst_ip[31:16]} + {16'd0, rewrite_dst_ip[31:16]}
                + {16'd0, ~orig_dst_ip[15:0]}  + {16'd0, rewrite_dst_ip[15:0]};
        end

        // DSCP change (TOS byte: DSCP[7:2] + ECN[1:0], in 16-bit word {ver_ihl, tos} at IP+0..1)
        // Only DSCP changes; ECN is preserved from original
        if (flag_dscp) begin
            cksum_delta = cksum_delta
                + {16'd0, ~{8'h00, {orig_ip_dscp, orig_ip_ecn}}}
                + {16'd0,  {8'h00, {rewrite_dscp, orig_ip_ecn}}};
        end
    end

    // Fold 32-bit delta into 16 bits (ones-complement)
    wire [16:0] fold1 = {1'b0, cksum_delta[15:0]} + {1'b0, cksum_delta[31:16]};
    wire [15:0] fold2 = fold1[15:0] + {15'd0, fold1[16]};

    // Apply delta to original checksum
    wire [16:0] new_cksum_raw = {1'b0, ~orig_ip_checksum} + {1'b0, fold2};
    wire [15:0] new_cksum_fold = new_cksum_raw[15:0] + {15'd0, new_cksum_raw[16]};
    wire [15:0] new_checksum = ~new_cksum_fold;

    // --- L4 (TCP/UDP) incremental checksum update for port rewrite ---
    // TCP/UDP pseudo-header checksum includes src_port and dst_port.
    // We compute a delta the same way as IP checksum.
    reg [31:0] l4_cksum_delta;

    always @(*) begin
        l4_cksum_delta = 32'd0;
        if (flag_src_port) begin
            l4_cksum_delta = l4_cksum_delta + {16'd0, ~orig_src_port} + {16'd0, rewrite_src_port};
        end
        if (flag_dst_port) begin
            l4_cksum_delta = l4_cksum_delta + {16'd0, ~orig_dst_port} + {16'd0, rewrite_dst_port};
        end
    end

    wire [16:0] l4_fold1 = {1'b0, l4_cksum_delta[15:0]} + {1'b0, l4_cksum_delta[31:16]};
    wire [15:0] l4_fold2 = l4_fold1[15:0] + {15'd0, l4_fold1[16]};

    // L4 checksum positions relative to L4 header start (l4_port_offset)
    // TCP checksum: offset 16-17 from TCP header start
    // UDP checksum: offset 6-7 from UDP header start
    wire [10:0] l4_cksum_offset = (ip_protocol == 8'd6) ?
                                   (l4_port_offset + 11'd16) :
                                   (l4_port_offset + 11'd6);

    // --- Capture original L4 checksum on-the-fly ---
    reg [15:0] captured_l4_cksum;
    reg        l4_cksum_captured;

    // Compute new L4 checksum
    wire [16:0] new_l4_cksum_raw = {1'b0, ~captured_l4_cksum} + {1'b0, l4_fold2};
    wire [15:0] new_l4_cksum_fold = new_l4_cksum_raw[15:0] + {15'd0, new_l4_cksum_raw[16]};
    wire [15:0] new_l4_checksum = ~new_l4_cksum_fold;

    // Guard: UDP checksum == 0 means "no checksum", leave unchanged
    wire l4_port_rewrite_active = (flag_src_port || flag_dst_port) && l4_port_offset_valid;
    wire l4_cksum_update_ok = l4_cksum_captured &&
                               !(ip_protocol == 8'd17 && captured_l4_cksum == 16'h0000);

    // --- Byte counter and substitution ---
    reg [10:0] byte_pos;
    wire xfer = s_axis_tvalid & s_axis_tready;

    // Pass-through ready signal
    assign s_axis_tready = m_axis_tready;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            m_axis_tdata  <= 8'd0;
            m_axis_tvalid <= 1'b0;
            m_axis_tlast  <= 1'b0;
            byte_pos      <= 11'd0;
            captured_l4_cksum <= 16'd0;
            l4_cksum_captured <= 1'b0;
        end else begin
            if (m_axis_tready) begin
                m_axis_tvalid <= 1'b0;
                m_axis_tlast  <= 1'b0;
            end

            if (xfer) begin
                // Default: pass through unmodified
                m_axis_tdata  <= s_axis_tdata;
                m_axis_tvalid <= 1'b1;
                m_axis_tlast  <= s_axis_tlast;

                // --- Capture L4 checksum bytes on-the-fly ---
                if (l4_port_rewrite_active) begin
                    if (byte_pos == l4_cksum_offset) begin
                        captured_l4_cksum[15:8] <= s_axis_tdata;
                    end
                    if (byte_pos == l4_cksum_offset + 11'd1) begin
                        captured_l4_cksum[7:0] <= s_axis_tdata;
                        l4_cksum_captured <= 1'b1;
                    end
                end

                // --- Apply substitutions at known offsets ---

                // dst_mac: bytes 0-5
                if (flag_dst_mac) begin
                    case (byte_pos)
                        11'd0: m_axis_tdata <= rewrite_dst_mac[47:40];
                        11'd1: m_axis_tdata <= rewrite_dst_mac[39:32];
                        11'd2: m_axis_tdata <= rewrite_dst_mac[31:24];
                        11'd3: m_axis_tdata <= rewrite_dst_mac[23:16];
                        11'd4: m_axis_tdata <= rewrite_dst_mac[15:8];
                        11'd5: m_axis_tdata <= rewrite_dst_mac[7:0];
                        default: ;
                    endcase
                end

                // src_mac: bytes 6-11
                if (flag_src_mac) begin
                    case (byte_pos)
                        11'd6:  m_axis_tdata <= rewrite_src_mac[47:40];
                        11'd7:  m_axis_tdata <= rewrite_src_mac[39:32];
                        11'd8:  m_axis_tdata <= rewrite_src_mac[31:24];
                        11'd9:  m_axis_tdata <= rewrite_src_mac[23:16];
                        11'd10: m_axis_tdata <= rewrite_src_mac[15:8];
                        11'd11: m_axis_tdata <= rewrite_src_mac[7:0];
                        default: ;
                    endcase
                end

                // vlan_id: bytes 14-15 (TCI field, only if VLAN-tagged)
                // TCI = {PCP[2:0], DEI, VID[11:0]}
                // We only replace VID, preserving PCP and DEI
                if (flag_vlan_id && has_vlan) begin
                    if (byte_pos == 11'd14) begin
                        // Preserve PCP[2:0] and DEI, replace VID[11:8]
                        m_axis_tdata <= {s_axis_tdata[7:4], rewrite_vlan_id[11:8]};
                    end
                    if (byte_pos == 11'd15) begin
                        m_axis_tdata <= rewrite_vlan_id[7:0];
                    end
                end

                // TTL: IP header byte 8
                if (flag_set_ttl || flag_dec_ttl) begin
                    if (byte_pos == ip_base + 11'd8) begin
                        m_axis_tdata <= new_ttl;
                    end
                end

                // IP checksum: IP header bytes 10-11
                if (flag_set_ttl || flag_dec_ttl || flag_src_ip || flag_dst_ip || flag_dscp) begin
                    if (byte_pos == ip_base + 11'd10) begin
                        m_axis_tdata <= new_checksum[15:8];
                    end
                    if (byte_pos == ip_base + 11'd11) begin
                        m_axis_tdata <= new_checksum[7:0];
                    end
                end

                // Source IP: IP header bytes 12-15
                if (flag_src_ip) begin
                    if (byte_pos == ip_base + 11'd12) m_axis_tdata <= rewrite_src_ip[31:24];
                    if (byte_pos == ip_base + 11'd13) m_axis_tdata <= rewrite_src_ip[23:16];
                    if (byte_pos == ip_base + 11'd14) m_axis_tdata <= rewrite_src_ip[15:8];
                    if (byte_pos == ip_base + 11'd15) m_axis_tdata <= rewrite_src_ip[7:0];
                end

                // DSCP: IP header byte 1 (TOS) — replace DSCP[7:2], preserve ECN[1:0]
                if (flag_dscp) begin
                    if (byte_pos == ip_base + 11'd1) begin
                        m_axis_tdata <= {rewrite_dscp, s_axis_tdata[1:0]};
                    end
                end

                // Destination IP: IP header bytes 16-19
                if (flag_dst_ip) begin
                    if (byte_pos == ip_base + 11'd16) m_axis_tdata <= rewrite_dst_ip[31:24];
                    if (byte_pos == ip_base + 11'd17) m_axis_tdata <= rewrite_dst_ip[23:16];
                    if (byte_pos == ip_base + 11'd18) m_axis_tdata <= rewrite_dst_ip[15:8];
                    if (byte_pos == ip_base + 11'd19) m_axis_tdata <= rewrite_dst_ip[7:0];
                end

                // L4 source port: 2 bytes at l4_port_offset
                if (flag_src_port && l4_port_offset_valid) begin
                    if (byte_pos == l4_port_offset)        m_axis_tdata <= rewrite_src_port[15:8];
                    if (byte_pos == l4_port_offset + 11'd1) m_axis_tdata <= rewrite_src_port[7:0];
                end

                // L4 destination port: 2 bytes at l4_port_offset + 2
                if (flag_dst_port && l4_port_offset_valid) begin
                    if (byte_pos == l4_port_offset + 11'd2) m_axis_tdata <= rewrite_dst_port[15:8];
                    if (byte_pos == l4_port_offset + 11'd3) m_axis_tdata <= rewrite_dst_port[7:0];
                end

                // L4 checksum update (after port rewrite)
                if (l4_port_rewrite_active && l4_cksum_update_ok) begin
                    if (byte_pos == l4_cksum_offset)        m_axis_tdata <= new_l4_checksum[15:8];
                    if (byte_pos == l4_cksum_offset + 11'd1) m_axis_tdata <= new_l4_checksum[7:0];
                end

                // Update byte position
                if (s_axis_tlast) begin
                    byte_pos <= 11'd0;
                    l4_cksum_captured <= 1'b0;
                end else begin
                    byte_pos <= byte_pos + 11'd1;
                end
            end
        end
    end

endmodule
