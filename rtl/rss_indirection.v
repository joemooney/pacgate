// rss_indirection.v — RSS indirection table + key storage
// 128-entry table mapping hash_value[6:0] → queue_id[3:0]
// AXI-Lite interface for runtime table and key updates.
//
// Address map (32-bit word addresses):
//   0x000 - 0x07F : Indirection table entries (128 x 4-bit queue_id, read/write)
//   0x080 - 0x089 : Hash key registers (10 x 32-bit = 40 bytes, read/write)
//   0x090         : Control register (bit 0 = commit, self-clearing)
//
// Default initialization: round-robin across NUM_QUEUES.

module rss_indirection #(
    parameter NUM_QUEUES = 4,     // 1-16
    parameter ADDR_WIDTH = 12     // AXI-Lite address width
)(
    input  wire                   clk,
    input  wire                   rst,

    // Hash input from rss_toeplitz
    input  wire [31:0]            hash_value,
    input  wire                   hash_valid,

    // Per-rule queue override (from rss_queue_lut)
    input  wire  [3:0]            override_queue,
    input  wire                   override_valid,

    // Queue output
    output reg   [3:0]            rss_queue_id,
    output reg                    rss_queue_valid,

    // Hash key output (active key, feeds rss_toeplitz)
    output wire [319:0]           hash_key,

    // AXI-Lite write interface (simplified)
    input  wire [ADDR_WIDTH-1:0]  axi_awaddr,
    input  wire                   axi_awvalid,
    output wire                   axi_awready,
    input  wire [31:0]            axi_wdata,
    input  wire                   axi_wvalid,
    output wire                   axi_wready,
    // AXI-Lite read interface (simplified)
    input  wire [ADDR_WIDTH-1:0]  axi_araddr,
    input  wire                   axi_arvalid,
    output wire                   axi_arready,
    output reg  [31:0]            axi_rdata,
    output reg                    axi_rvalid
);

    // Indirection table: 128 entries x 4 bits
    reg [3:0] itable [0:127];

    // Hash key: 10 x 32-bit registers = 320 bits
    // Default: Microsoft RSS key
    reg [31:0] key_regs [0:9];

    // Build 320-bit key output from registers
    assign hash_key = {key_regs[0], key_regs[1], key_regs[2], key_regs[3], key_regs[4],
                       key_regs[5], key_regs[6], key_regs[7], key_regs[8], key_regs[9]};

    // Initialize indirection table with round-robin and default key
    integer k;
    initial begin
        for (k = 0; k < 128; k = k + 1)
            itable[k] = k % NUM_QUEUES;
        // Microsoft RSS default key
        key_regs[0] = 32'h6d5a56da;
        key_regs[1] = 32'h255b0ec2;
        key_regs[2] = 32'h4167253d;
        key_regs[3] = 32'h43a38fb0;
        key_regs[4] = 32'hd0ca2bcb;
        key_regs[5] = 32'hae7b30b4;
        key_regs[6] = 32'h77cb2da3;
        key_regs[7] = 32'h8030f20c;
        key_regs[8] = 32'h6a42b73b;
        key_regs[9] = 32'hbeac01fa;
    end

    // Queue lookup: override takes priority over hash-based assignment
    always @(posedge clk) begin
        if (rst) begin
            rss_queue_id  <= 4'h0;
            rss_queue_valid <= 1'b0;
        end else if (override_valid) begin
            rss_queue_id  <= override_queue;
            rss_queue_valid <= 1'b1;
        end else if (hash_valid) begin
            rss_queue_id  <= itable[hash_value[6:0]];
            rss_queue_valid <= 1'b1;
        end else begin
            rss_queue_valid <= 1'b0;
        end
    end

    // AXI-Lite write logic
    assign axi_awready = 1'b1;
    assign axi_wready  = 1'b1;

    wire [ADDR_WIDTH-1:0] waddr = axi_awaddr;

    always @(posedge clk) begin
        if (!rst && axi_awvalid && axi_wvalid) begin
            if (waddr[ADDR_WIDTH-1:2] < 128) begin
                // Indirection table write
                itable[waddr[8:2]] <= axi_wdata[3:0];
            end else if (waddr[ADDR_WIDTH-1:2] >= 128 && waddr[ADDR_WIDTH-1:2] < 138) begin
                // Key register write
                key_regs[waddr[ADDR_WIDTH-1:2] - 128] <= axi_wdata;
            end
        end
    end

    // AXI-Lite read logic
    assign axi_arready = 1'b1;

    always @(posedge clk) begin
        if (rst) begin
            axi_rdata  <= 32'h0;
            axi_rvalid <= 1'b0;
        end else if (axi_arvalid) begin
            axi_rvalid <= 1'b1;
            if (axi_araddr[ADDR_WIDTH-1:2] < 128) begin
                axi_rdata <= {28'h0, itable[axi_araddr[8:2]]};
            end else if (axi_araddr[ADDR_WIDTH-1:2] >= 128 && axi_araddr[ADDR_WIDTH-1:2] < 138) begin
                axi_rdata <= key_regs[axi_araddr[ADDR_WIDTH-1:2] - 128];
            end else begin
                axi_rdata <= 32'h0;
            end
        end else begin
            axi_rvalid <= 1'b0;
        end
    end

endmodule
