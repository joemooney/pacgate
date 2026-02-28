// axis_8_to_512.v — AXI-Stream width converter: 8-bit to 512-bit
// Hand-written RTL — do not regenerate
//
// Serializes 8-bit AXI-Stream bytes into 512-bit beats.
// Accumulates bytes in 512-bit register with 6-bit counter.
// Outputs when 64 bytes collected or s_axis_tlast received.
// Generates tkeep mask from byte count.

module axis_8_to_512 (
    input  wire         clk,
    input  wire         rst_n,

    // AXI-Stream slave input (8-bit)
    input  wire [7:0]   s_axis_tdata,
    input  wire         s_axis_tvalid,
    output wire         s_axis_tready,
    input  wire         s_axis_tlast,

    // AXI-Stream master output (512-bit)
    output reg  [511:0] m_axis_tdata,
    output reg  [63:0]  m_axis_tkeep,
    output reg          m_axis_tvalid,
    input  wire         m_axis_tready,
    output reg          m_axis_tlast
);

    reg [511:0] accum;
    reg [6:0]   count;      // 0-64 bytes accumulated
    reg         output_pending;

    // Accept input when not holding a pending output
    assign s_axis_tready = !output_pending && rst_n;

    // Generate tkeep mask: bits 0..count-1 set
    function [63:0] make_tkeep;
        input [6:0] cnt;
        integer i;
        begin
            make_tkeep = 64'd0;
            for (i = 0; i < 64; i = i + 1) begin
                if (i < cnt)
                    make_tkeep[i] = 1'b1;
            end
        end
    endfunction

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            accum          <= 512'd0;
            count          <= 7'd0;
            output_pending <= 1'b0;
            m_axis_tdata   <= 512'd0;
            m_axis_tkeep   <= 64'd0;
            m_axis_tvalid  <= 1'b0;
            m_axis_tlast   <= 1'b0;
        end else begin
            // Clear output when downstream accepts
            if (m_axis_tvalid && m_axis_tready) begin
                m_axis_tvalid  <= 1'b0;
                m_axis_tlast   <= 1'b0;
                output_pending <= 1'b0;
            end

            // Accumulate input bytes
            if (s_axis_tvalid && s_axis_tready) begin
                accum[count[5:0]*8 +: 8] <= s_axis_tdata;

                if (s_axis_tlast || count == 7'd63) begin
                    // Output the accumulated beat
                    m_axis_tdata  <= accum;
                    m_axis_tdata[count[5:0]*8 +: 8] <= s_axis_tdata;  // include current byte
                    m_axis_tkeep  <= make_tkeep(count + 1);
                    m_axis_tvalid <= 1'b1;
                    m_axis_tlast  <= s_axis_tlast;
                    output_pending <= 1'b1;
                    count         <= 7'd0;
                    accum         <= 512'd0;
                end else begin
                    count <= count + 1;
                end
            end
        end
    end

endmodule
