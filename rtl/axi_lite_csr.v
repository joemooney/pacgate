// axi_lite_csr.v — AXI4-Lite register interface for PacGate counters
//
// Register Map (32-bit aligned, all 64-bit counters split into LO/HI):
//   0x000: TOTAL_PKT_LO      — total packets processed (low 32 bits)
//   0x004: TOTAL_PKT_HI      — total packets processed (high 32 bits)
//   0x008: TOTAL_PASS_LO     — total packets passed
//   0x00C: TOTAL_PASS_HI
//   0x010: TOTAL_DROP_LO     — total packets dropped
//   0x014: TOTAL_DROP_HI
//   0x018: TOTAL_BYTE_LO     — total bytes processed
//   0x01C: TOTAL_BYTE_HI
//   0x020: RULE_SEL           — write rule index to select per-rule counters
//   0x024: RULE_PKT_LO       — packets matching selected rule
//   0x028: RULE_PKT_HI
//   0x02C: RULE_BYTE_LO      — bytes matching selected rule
//   0x030: RULE_BYTE_HI
//   0x034: NUM_RULES          — number of rules (read-only)
//   0x038: CONTROL            — write 1 to clear all counters
//
// Parameters:
//   NUM_RULES — passed through to rule_counters
//   ADDR_WIDTH — AXI-Lite address width (default 8 = 256 bytes)

module axi_lite_csr #(
    parameter NUM_RULES  = 8,
    parameter ADDR_WIDTH = 8,
    parameter IDX_BITS   = $clog2(NUM_RULES) > 0 ? $clog2(NUM_RULES) : 1
)(
    input  wire                     clk,
    input  wire                     rst_n,

    // AXI4-Lite Slave Interface
    input  wire [ADDR_WIDTH-1:0]    s_axi_awaddr,
    input  wire                     s_axi_awvalid,
    output reg                      s_axi_awready,

    input  wire [31:0]              s_axi_wdata,
    input  wire [3:0]               s_axi_wstrb,
    input  wire                     s_axi_wvalid,
    output reg                      s_axi_wready,

    output reg  [1:0]               s_axi_bresp,
    output reg                      s_axi_bvalid,
    input  wire                     s_axi_bready,

    input  wire [ADDR_WIDTH-1:0]    s_axi_araddr,
    input  wire                     s_axi_arvalid,
    output reg                      s_axi_arready,

    output reg  [31:0]              s_axi_rdata,
    output reg  [1:0]               s_axi_rresp,
    output reg                      s_axi_rvalid,
    input  wire                     s_axi_rready,

    // Counter interface (directly from rule_counters)
    output reg  [IDX_BITS-1:0]      counter_sel,
    input  wire [63:0]              counter_pkt_count,
    input  wire [63:0]              counter_byte_count,
    input  wire [63:0]              total_pkt_count,
    input  wire [63:0]              total_pass_count,
    input  wire [63:0]              total_drop_count,
    input  wire [63:0]              total_byte_count,
    output reg                      counter_clear
);

    // Write state machine
    reg [ADDR_WIDTH-1:0] wr_addr;
    reg                  aw_done, w_done;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            s_axi_awready <= 1'b0;
            s_axi_wready  <= 1'b0;
            s_axi_bvalid  <= 1'b0;
            s_axi_bresp   <= 2'b00;
            aw_done       <= 1'b0;
            w_done        <= 1'b0;
            wr_addr       <= {ADDR_WIDTH{1'b0}};
            counter_sel   <= {IDX_BITS{1'b0}};
            counter_clear <= 1'b0;
        end else begin
            counter_clear <= 1'b0;

            // Address write channel
            if (s_axi_awvalid && !aw_done) begin
                s_axi_awready <= 1'b1;
                wr_addr       <= s_axi_awaddr;
                aw_done       <= 1'b1;
            end else begin
                s_axi_awready <= 1'b0;
            end

            // Data write channel
            if (s_axi_wvalid && !w_done) begin
                s_axi_wready <= 1'b1;
                w_done       <= 1'b1;
            end else begin
                s_axi_wready <= 1'b0;
            end

            // Both address and data received — process write
            if (aw_done && w_done) begin
                case (wr_addr[7:0])
                    8'h20: counter_sel   <= s_axi_wdata[IDX_BITS-1:0]; // RULE_SEL
                    8'h38: counter_clear <= 1'b1;                        // CONTROL
                    default: ;
                endcase
                s_axi_bvalid <= 1'b1;
                s_axi_bresp  <= 2'b00; // OKAY
                aw_done      <= 1'b0;
                w_done       <= 1'b0;
            end

            // Write response handshake
            if (s_axi_bvalid && s_axi_bready) begin
                s_axi_bvalid <= 1'b0;
            end
        end
    end

    // Read state machine
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            s_axi_arready <= 1'b0;
            s_axi_rvalid  <= 1'b0;
            s_axi_rdata   <= 32'd0;
            s_axi_rresp   <= 2'b00;
        end else begin
            if (s_axi_arvalid && !s_axi_rvalid) begin
                s_axi_arready <= 1'b1;
                s_axi_rvalid  <= 1'b1;
                s_axi_rresp   <= 2'b00;

                case (s_axi_araddr[7:0])
                    8'h00: s_axi_rdata <= total_pkt_count[31:0];
                    8'h04: s_axi_rdata <= total_pkt_count[63:32];
                    8'h08: s_axi_rdata <= total_pass_count[31:0];
                    8'h0C: s_axi_rdata <= total_pass_count[63:32];
                    8'h10: s_axi_rdata <= total_drop_count[31:0];
                    8'h14: s_axi_rdata <= total_drop_count[63:32];
                    8'h18: s_axi_rdata <= total_byte_count[31:0];
                    8'h1C: s_axi_rdata <= total_byte_count[63:32];
                    8'h20: s_axi_rdata <= {{(32-IDX_BITS){1'b0}}, counter_sel};
                    8'h24: s_axi_rdata <= counter_pkt_count[31:0];
                    8'h28: s_axi_rdata <= counter_pkt_count[63:32];
                    8'h2C: s_axi_rdata <= counter_byte_count[31:0];
                    8'h30: s_axi_rdata <= counter_byte_count[63:32];
                    8'h34: s_axi_rdata <= NUM_RULES;
                    default: s_axi_rdata <= 32'hDEAD_BEEF;
                endcase
            end else begin
                s_axi_arready <= 1'b0;
            end

            if (s_axi_rvalid && s_axi_rready) begin
                s_axi_rvalid <= 1'b0;
            end
        end
    end

endmodule
