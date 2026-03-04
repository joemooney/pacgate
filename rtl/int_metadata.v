// int_metadata.v — In-band Network Telemetry metadata capture
//
// Captures per-packet telemetry metadata as sideband output:
//   - switch_id          (16-bit, configurable via AXI-Lite)
//   - ingress_timestamp  (64-bit, from PTP clock or free-running counter)
//   - egress_timestamp   (64-bit, latched on pkt_eof)
//   - queue_id           (4-bit, from RSS queue assignment)
//   - hop_latency        (32-bit, egress - ingress delta)
//   - rule_idx           (8-bit, which rule matched)
//
// Metadata is valid for one cycle after int_meta_valid goes high.
// AXI-Lite registers:
//   0x00: switch_id[15:0]     (R/W)
//   0x04: hop_count_max[7:0]  (R/W, max metadata stack depth)
//   0x08: int_enable           (R/W, global enable)
//   0x0C: pkt_count[31:0]     (R, total INT-tagged packets)

module int_metadata #(
    parameter SWITCH_ID_DEFAULT = 16'd0,
    parameter MAX_HOP_DEFAULT   = 8'd8
)(
    input  wire        clk,
    input  wire        rst,

    // Packet interface signals
    input  wire        pkt_sof,
    input  wire        pkt_eof,
    input  wire        pkt_valid,

    // Decision interface
    input  wire        decision_valid,
    input  wire        decision_pass,
    input  wire [7:0]  decision_rule_idx,

    // INT enable for this packet (from int_lut)
    input  wire        int_enable_pkt,

    // RSS queue (from RSS module or override)
    input  wire [3:0]  rss_queue_id,
    input  wire        rss_queue_valid,

    // Timestamp source (PTP clock or free-running)
    input  wire [63:0] timestamp,

    // AXI-Lite configuration interface
    input  wire        axi_awvalid,
    output reg         axi_awready,
    input  wire [3:0]  axi_awaddr,
    input  wire [31:0] axi_wdata,
    input  wire        axi_wvalid,
    output reg         axi_wready,
    input  wire [3:0]  axi_araddr,
    input  wire        axi_arvalid,
    output reg         axi_arready,
    output reg  [31:0] axi_rdata,
    output reg         axi_rvalid,

    // INT metadata output (sideband)
    output reg         int_meta_valid,
    output reg  [15:0] int_switch_id,
    output reg  [63:0] int_ingress_ts,
    output reg  [63:0] int_egress_ts,
    output reg  [31:0] int_hop_latency,
    output reg  [3:0]  int_queue_id,
    output reg  [7:0]  int_rule_idx
);

    // Configuration registers
    reg [15:0] cfg_switch_id;
    reg [7:0]  cfg_hop_count_max;
    reg        cfg_int_enable;
    reg [31:0] pkt_count;

    // Per-packet state
    reg [63:0] ingress_ts;
    reg        pkt_active;
    reg        pkt_int_enabled;
    reg [3:0]  pkt_queue_id;
    reg [7:0]  pkt_rule_idx;

    // Initialize
    initial begin
        cfg_switch_id     = SWITCH_ID_DEFAULT;
        cfg_hop_count_max = MAX_HOP_DEFAULT;
        cfg_int_enable    = 1'b1;
        pkt_count         = 32'd0;
        pkt_active        = 1'b0;
        pkt_int_enabled   = 1'b0;
        int_meta_valid    = 1'b0;
    end

    // Packet tracking
    always @(posedge clk) begin
        if (rst) begin
            pkt_active      <= 1'b0;
            pkt_int_enabled <= 1'b0;
            int_meta_valid  <= 1'b0;
            pkt_count       <= 32'd0;
        end else begin
            int_meta_valid <= 1'b0;

            if (pkt_sof && pkt_valid) begin
                // Latch ingress timestamp at start of frame
                ingress_ts      <= timestamp;
                pkt_active      <= 1'b1;
                pkt_int_enabled <= 1'b0;
                pkt_queue_id    <= 4'd0;
                pkt_rule_idx    <= 8'd0;
            end

            // Capture decision info when available
            if (decision_valid && pkt_active) begin
                pkt_int_enabled <= int_enable_pkt && cfg_int_enable && decision_pass;
                pkt_rule_idx    <= decision_rule_idx;
            end

            // Capture RSS queue when available
            if (rss_queue_valid && pkt_active) begin
                pkt_queue_id <= rss_queue_id;
            end

            if (pkt_eof && pkt_valid && pkt_active) begin
                pkt_active <= 1'b0;

                if (pkt_int_enabled) begin
                    // Output metadata
                    int_meta_valid  <= 1'b1;
                    int_switch_id   <= cfg_switch_id;
                    int_ingress_ts  <= ingress_ts;
                    int_egress_ts   <= timestamp;
                    int_hop_latency <= timestamp[31:0] - ingress_ts[31:0];
                    int_queue_id    <= pkt_queue_id;
                    int_rule_idx    <= pkt_rule_idx;
                    pkt_count       <= pkt_count + 1;
                end
            end
        end
    end

    // AXI-Lite write interface
    always @(posedge clk) begin
        if (rst) begin
            axi_awready   <= 1'b0;
            axi_wready    <= 1'b0;
            cfg_switch_id <= SWITCH_ID_DEFAULT;
            cfg_hop_count_max <= MAX_HOP_DEFAULT;
            cfg_int_enable <= 1'b1;
        end else begin
            axi_awready <= 1'b0;
            axi_wready  <= 1'b0;

            if (axi_awvalid && axi_wvalid) begin
                axi_awready <= 1'b1;
                axi_wready  <= 1'b1;
                case (axi_awaddr)
                    4'h0: cfg_switch_id     <= axi_wdata[15:0];
                    4'h4: cfg_hop_count_max <= axi_wdata[7:0];
                    4'h8: cfg_int_enable    <= axi_wdata[0];
                    default: ;
                endcase
            end
        end
    end

    // AXI-Lite read interface
    always @(posedge clk) begin
        if (rst) begin
            axi_arready <= 1'b0;
            axi_rvalid  <= 1'b0;
            axi_rdata   <= 32'd0;
        end else begin
            axi_arready <= 1'b0;
            axi_rvalid  <= 1'b0;

            if (axi_arvalid) begin
                axi_arready <= 1'b1;
                axi_rvalid  <= 1'b1;
                case (axi_araddr)
                    4'h0: axi_rdata <= {16'd0, cfg_switch_id};
                    4'h4: axi_rdata <= {24'd0, cfg_hop_count_max};
                    4'h8: axi_rdata <= {31'd0, cfg_int_enable};
                    4'hC: axi_rdata <= pkt_count;
                    default: axi_rdata <= 32'd0;
                endcase
            end
        end
    end

endmodule
