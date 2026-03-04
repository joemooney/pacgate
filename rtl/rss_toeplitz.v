// rss_toeplitz.v — Toeplitz hash engine for Receive Side Scaling (RSS)
// Computes 32-bit hash from 5-tuple (src_ip, dst_ip, src_port, dst_port, ip_protocol)
// using Microsoft RSS-compatible Toeplitz hash algorithm.
//
// Combinational design: hash output valid same cycle as input.
// Key is a 40-byte (320-bit) secret key stored in registers.

module rss_toeplitz #(
    parameter INPUT_WIDTH = 104  // 32+32+16+16+8 = 104 bits for 5-tuple
)(
    input  wire        clk,
    input  wire        rst,

    // 5-tuple input
    input  wire [31:0] src_ip,
    input  wire [31:0] dst_ip,
    input  wire [15:0] src_port,
    input  wire [15:0] dst_port,
    input  wire  [7:0] ip_protocol,
    input  wire        hash_en,       // Pulse high to compute hash

    // Hash key (40 bytes = 320 bits, configurable via AXI-Lite)
    input  wire [319:0] hash_key,

    // Hash output
    output reg  [31:0] hash_value,
    output reg         hash_valid
);

    // Pack 5-tuple into a flat input vector: src_ip || dst_ip || src_port || dst_port || ip_protocol
    wire [INPUT_WIDTH-1:0] input_data = {src_ip, dst_ip, src_port, dst_port, ip_protocol};

    // Combinational Toeplitz hash computation
    // For each set bit in input_data, XOR the 32-bit key window starting at that bit position.
    // Key window at bit position i = hash_key[319-i : 288-i]
    integer i;
    reg [31:0] hash_comb;

    always @(*) begin
        hash_comb = 32'h0;
        for (i = 0; i < INPUT_WIDTH; i = i + 1) begin
            if (input_data[INPUT_WIDTH - 1 - i]) begin
                // Key window: 32 bits starting at bit position i from the MSB of the key
                hash_comb = hash_comb ^ hash_key[319 - i -: 32];
            end
        end
    end

    // Register output
    always @(posedge clk) begin
        if (rst) begin
            hash_value <= 32'h0;
            hash_valid <= 1'b0;
        end else begin
            hash_valid <= hash_en;
            if (hash_en)
                hash_value <= hash_comb;
        end
    end

endmodule
