// packet_filter_axi_top.v — AXI-Stream top-level packet filter
// Hand-written infrastructure module (not generated from rules)
//
// Integrates:
//   AXI-Stream in -> adapter -> packet_filter_top -> FIFO -> AXI-Stream out
//
// Parameters:
//   FIFO_DEPTH     - store-and-forward FIFO depth in bytes (default 2048)
//   MAX_FRAME_SIZE - maximum expected Ethernet frame size (default 1522)

module packet_filter_axi_top #(
    parameter FIFO_DEPTH     = 2048,
    parameter MAX_FRAME_SIZE = 1522
)(
    input  wire        clk,
    input  wire        rst_n,

    // AXI-Stream slave input (incoming packets)
    input  wire [7:0]  s_axis_tdata,
    input  wire        s_axis_tvalid,
    output wire        s_axis_tready,
    input  wire        s_axis_tlast,

    // AXI-Stream master output (filtered packets — only passed frames)
    output wire [7:0]  m_axis_tdata,
    output wire        m_axis_tvalid,
    input  wire        m_axis_tready,
    output wire        m_axis_tlast,

    // Status signals
    output wire        decision_valid,
    output wire        decision_pass,
    output wire        fifo_overflow,
    output wire        fifo_empty
);

    // Internal signals: adapter -> filter
    wire [7:0] pkt_data;
    wire       pkt_valid;
    wire       pkt_sof;
    wire       pkt_eof;

    // AXI-Stream to simple interface adapter
    axi_stream_adapter u_adapter (
        .clk            (clk),
        .rst_n          (rst_n),
        .s_axis_tdata   (s_axis_tdata),
        .s_axis_tvalid  (s_axis_tvalid),
        .s_axis_tready  (s_axis_tready),
        .s_axis_tlast   (s_axis_tlast),
        .pkt_data       (pkt_data),
        .pkt_valid      (pkt_valid),
        .pkt_sof        (pkt_sof),
        .pkt_eof        (pkt_eof)
    );

    // Packet filter core (generated from rules)
    packet_filter_top u_filter (
        .clk            (clk),
        .rst_n          (rst_n),
        .pkt_data       (pkt_data),
        .pkt_valid      (pkt_valid),
        .pkt_sof        (pkt_sof),
        .pkt_eof        (pkt_eof),
        .decision_valid (decision_valid),
        .decision_pass  (decision_pass)
    );

    // Store-and-forward FIFO: buffers frame, forwards or discards based on decision
    store_forward_fifo #(
        .FIFO_DEPTH     (FIFO_DEPTH),
        .MAX_FRAME_SIZE (MAX_FRAME_SIZE)
    ) u_fifo (
        .clk            (clk),
        .rst_n          (rst_n),
        .wr_data        (pkt_data),
        .wr_valid       (pkt_valid),
        .wr_sof         (pkt_sof),
        .wr_eof         (pkt_eof),
        .decision_valid (decision_valid),
        .decision_pass  (decision_pass),
        .m_axis_tdata   (m_axis_tdata),
        .m_axis_tvalid  (m_axis_tvalid),
        .m_axis_tready  (m_axis_tready),
        .m_axis_tlast   (m_axis_tlast),
        .fifo_overflow  (fifo_overflow),
        .fifo_empty     (fifo_empty)
    );

endmodule
