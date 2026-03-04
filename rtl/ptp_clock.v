// ptp_clock.v — IEEE 1588 PTP Hardware Clock
// Free-running 64-bit nanosecond counter (32-bit seconds + 32-bit nanoseconds)
// Latches timestamp at pkt_sof and pkt_eof for ingress timestamping
// Optional PPS input for external synchronization
//
// Parameters:
//   CLK_PERIOD_NS — clock period in nanoseconds (default 4 for 250MHz)
//
// Interface:
//   clk, rst_n          — clock and active-low reset
//   pkt_sof, pkt_eof    — packet start/end of frame pulses
//   pps_in              — optional 1PPS input (not used in basic version)
//   timestamp_sof[63:0] — latched at pkt_sof [63:32]=seconds, [31:0]=nanoseconds
//   timestamp_eof[63:0] — latched at pkt_eof
//   current_time[63:0]  — free-running time

module ptp_clock #(
    parameter CLK_PERIOD_NS = 4  // 250MHz default
)(
    input  wire        clk,
    input  wire        rst_n,

    // Packet timing
    input  wire        pkt_sof,
    input  wire        pkt_eof,

    // External sync (optional)
    input  wire        pps_in,

    // Timestamp outputs
    output reg  [63:0] timestamp_sof,  // latched at SOF
    output reg  [63:0] timestamp_eof,  // latched at EOF
    output wire [63:0] current_time    // free-running
);

    reg [31:0] seconds;
    reg [31:0] nanoseconds;

    assign current_time = {seconds, nanoseconds};

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            seconds     <= 32'd0;
            nanoseconds <= 32'd0;
            timestamp_sof <= 64'd0;
            timestamp_eof <= 64'd0;
        end else begin
            // Increment nanosecond counter
            if (nanoseconds + CLK_PERIOD_NS >= 32'd1_000_000_000) begin
                nanoseconds <= nanoseconds + CLK_PERIOD_NS - 32'd1_000_000_000;
                seconds     <= seconds + 32'd1;
            end else begin
                nanoseconds <= nanoseconds + CLK_PERIOD_NS;
            end

            // Latch timestamp at start of frame
            if (pkt_sof) begin
                timestamp_sof <= {seconds, nanoseconds};
            end

            // Latch timestamp at end of frame
            if (pkt_eof) begin
                timestamp_eof <= {seconds, nanoseconds};
            end
        end
    end

endmodule
