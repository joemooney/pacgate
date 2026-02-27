// rule_counters.v — Per-rule packet and byte counters
// Each rule gets a 64-bit packet counter and 64-bit byte counter.
// Counters increment when a rule match occurs.
// Read interface: select rule index, get {pkt_count, byte_count}.
//
// Parameters:
//   NUM_RULES — number of rules (determines counter array size)
//
// Write interface:
//   match_hit[NUM_RULES-1:0]    — one-hot match indicators (pulse per frame)
//   byte_count_in[15:0]         — frame size in bytes (valid when decision_valid)
//   decision_valid              — frame decision is final (latch counters)
//   decision_rule_idx           — index of the matching rule (valid when decision_valid)
//
// Read interface:
//   counter_sel[$clog2(NUM_RULES)-1:0] — rule index to read
//   counter_pkt_count[63:0]            — packet count for selected rule
//   counter_byte_count[63:0]           — byte count for selected rule
//   counter_clear                      — pulse: clear all counters

module rule_counters #(
    parameter NUM_RULES = 8,
    parameter IDX_BITS  = $clog2(NUM_RULES) > 0 ? $clog2(NUM_RULES) : 1
)(
    input  wire                    clk,
    input  wire                    rst_n,

    // Increment interface
    input  wire                    decision_valid,
    input  wire [IDX_BITS-1:0]     decision_rule_idx,
    input  wire                    decision_pass,
    input  wire                    decision_default, // 1 if default action (no rule matched)
    input  wire [15:0]             frame_byte_count,

    // Read interface
    input  wire [IDX_BITS-1:0]     counter_sel,
    output wire [63:0]             counter_pkt_count,
    output wire [63:0]             counter_byte_count,

    // Global counters
    output reg  [63:0]             total_pkt_count,
    output reg  [63:0]             total_pass_count,
    output reg  [63:0]             total_drop_count,
    output reg  [63:0]             total_byte_count,

    // Control
    input  wire                    counter_clear
);

    // Per-rule counters
    reg [63:0] pkt_counters  [0:NUM_RULES-1];
    reg [63:0] byte_counters [0:NUM_RULES-1];

    integer i;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n || counter_clear) begin
            for (i = 0; i < NUM_RULES; i = i + 1) begin
                pkt_counters[i]  <= 64'd0;
                byte_counters[i] <= 64'd0;
            end
            total_pkt_count  <= 64'd0;
            total_pass_count <= 64'd0;
            total_drop_count <= 64'd0;
            total_byte_count <= 64'd0;
        end else if (decision_valid) begin
            // Update global counters
            total_pkt_count  <= total_pkt_count + 64'd1;
            total_byte_count <= total_byte_count + {48'd0, frame_byte_count};

            if (decision_pass)
                total_pass_count <= total_pass_count + 64'd1;
            else
                total_drop_count <= total_drop_count + 64'd1;

            // Update per-rule counters (only if a rule matched, not default)
            if (!decision_default) begin
                pkt_counters[decision_rule_idx]  <= pkt_counters[decision_rule_idx] + 64'd1;
                byte_counters[decision_rule_idx] <= byte_counters[decision_rule_idx] + {48'd0, frame_byte_count};
            end
        end
    end

    // Read mux
    assign counter_pkt_count  = pkt_counters[counter_sel];
    assign counter_byte_count = byte_counters[counter_sel];

endmodule
