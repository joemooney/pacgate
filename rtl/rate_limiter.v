// rate_limiter.v — Token-bucket rate limiter for per-rule rate control
// Parameters: CLOCK_FREQ (Hz), PPS (packets per second), BURST (max tokens)
//
// Operation:
//   - Tokens are added at rate PPS per second (1 token per CLOCK_FREQ/PPS cycles)
//   - Token count capped at BURST
//   - On packet arrival (pkt_valid pulse): if tokens > 0 and pass_in, consume token -> pass
//   - Otherwise -> rate_drop (packet dropped due to rate limit)

module rate_limiter #(
    parameter CLOCK_FREQ = 125_000_000,  // 125 MHz default
    parameter PPS        = 1000,          // packets per second
    parameter BURST      = 64             // max burst tokens
) (
    input  wire clk,
    input  wire rst_n,

    input  wire pass_in,     // upstream pass decision
    input  wire pkt_arrive,  // packet decision pulse

    output reg  pass_out,    // rate-limited pass
    output reg  rate_drop    // dropped by rate limiter
);

    // Calculate refill interval: cycles between token additions
    localparam REFILL_INTERVAL = CLOCK_FREQ / PPS;

    reg [15:0] tokens;
    reg [31:0] refill_counter;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            tokens         <= BURST[15:0]; // start full
            refill_counter <= 32'd0;
            pass_out       <= 1'b0;
            rate_drop      <= 1'b0;
        end else begin
            pass_out  <= 1'b0;
            rate_drop <= 1'b0;

            // Token refill
            if (refill_counter >= REFILL_INTERVAL - 1) begin
                refill_counter <= 32'd0;
                if (tokens < BURST[15:0]) begin
                    tokens <= tokens + 16'd1;
                end
            end else begin
                refill_counter <= refill_counter + 32'd1;
            end

            // Packet arrival: consume token if available
            if (pkt_arrive) begin
                if (pass_in && tokens > 16'd0) begin
                    tokens   <= tokens - 16'd1;
                    pass_out <= 1'b1;
                end else if (pass_in) begin
                    // Pass decision but no tokens — rate drop
                    pass_out  <= 1'b0;
                    rate_drop <= 1'b1;
                end else begin
                    // Drop decision from upstream — pass through
                    pass_out <= 1'b0;
                end
            end
        end
    end

endmodule
