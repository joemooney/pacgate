// axi_stream_adapter.v — AXI-Stream to simple pkt_* interface adapter
// Hand-written infrastructure module (not generated from rules)
//
// Converts AXI-Stream input (tdata/tvalid/tready/tlast) to the simple
// byte-stream interface expected by packet_filter_top:
//   pkt_data[7:0], pkt_valid, pkt_sof, pkt_eof
//
// Also provides AXI-Stream output from decision signals.

module axi_stream_adapter (
    input  wire        clk,
    input  wire        rst_n,

    // AXI-Stream slave (input packets)
    input  wire [7:0]  s_axis_tdata,
    input  wire        s_axis_tvalid,
    output wire        s_axis_tready,
    input  wire        s_axis_tlast,

    // Simple pkt interface (to packet_filter_top)
    output reg  [7:0]  pkt_data,
    output reg         pkt_valid,
    output reg         pkt_sof,
    output reg         pkt_eof
);

    // Track whether the next valid byte is start-of-frame
    reg expecting_sof;

    // Always ready to accept data (no backpressure to filter path)
    assign s_axis_tready = 1'b1;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            pkt_data      <= 8'd0;
            pkt_valid     <= 1'b0;
            pkt_sof       <= 1'b0;
            pkt_eof       <= 1'b0;
            expecting_sof <= 1'b1;
        end else begin
            // Default: deassert pulse signals
            pkt_valid <= 1'b0;
            pkt_sof   <= 1'b0;
            pkt_eof   <= 1'b0;

            if (s_axis_tvalid && s_axis_tready) begin
                pkt_data  <= s_axis_tdata;
                pkt_valid <= 1'b1;
                pkt_sof   <= expecting_sof;
                pkt_eof   <= s_axis_tlast;

                if (s_axis_tlast)
                    expecting_sof <= 1'b1;
                else
                    expecting_sof <= 1'b0;
            end
        end
    end

endmodule
