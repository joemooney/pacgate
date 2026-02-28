// axis_512_to_8.v — AXI-Stream width converter: 512-bit to 8-bit
// Hand-written RTL — do not regenerate
//
// Deserializes 512-bit AXI-Stream beats into sequential 8-bit bytes.
// Latches 512-bit data + 64-bit tkeep, outputs bytes 0..N-1.
// Deasserts s_axis_tready while draining.
// tkeep must be contiguous from bit 0.

module axis_512_to_8 (
    input  wire         clk,
    input  wire         rst_n,

    // AXI-Stream slave input (512-bit)
    input  wire [511:0] s_axis_tdata,
    input  wire [63:0]  s_axis_tkeep,
    input  wire         s_axis_tvalid,
    output wire         s_axis_tready,
    input  wire         s_axis_tlast,

    // AXI-Stream master output (8-bit)
    output wire [7:0]   m_axis_tdata,
    output wire         m_axis_tvalid,
    input  wire         m_axis_tready,
    output wire         m_axis_tlast
);

    localparam S_IDLE  = 1'b0;
    localparam S_DRAIN = 1'b1;

    reg         state;
    reg [511:0] data_reg;
    reg [6:0]   byte_count;   // number of valid bytes (1-64)
    reg [6:0]   byte_idx;     // current output index (0-63)
    reg         last_reg;

    // Count valid bytes from contiguous tkeep
    function [6:0] count_tkeep;
        input [63:0] tkeep;
        integer i;
        begin
            count_tkeep = 0;
            for (i = 0; i < 64; i = i + 1) begin
                if (tkeep[i])
                    count_tkeep = count_tkeep + 1;
            end
        end
    endfunction

    // Accept new beat only in IDLE state
    assign s_axis_tready = (state == S_IDLE) && rst_n;

    // Output current byte from data register
    wire [5:0] byte_sel = byte_idx[5:0];
    assign m_axis_tdata  = data_reg[byte_sel*8 +: 8];
    assign m_axis_tvalid = (state == S_DRAIN);
    assign m_axis_tlast  = (state == S_DRAIN) && last_reg && (byte_idx == byte_count - 1);

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state      <= S_IDLE;
            data_reg   <= 512'd0;
            byte_count <= 7'd0;
            byte_idx   <= 7'd0;
            last_reg   <= 1'b0;
        end else begin
            case (state)
                S_IDLE: begin
                    if (s_axis_tvalid && s_axis_tready) begin
                        data_reg   <= s_axis_tdata;
                        byte_count <= count_tkeep(s_axis_tkeep);
                        byte_idx   <= 7'd0;
                        last_reg   <= s_axis_tlast;
                        state      <= S_DRAIN;
                    end
                end

                S_DRAIN: begin
                    if (m_axis_tready) begin
                        if (byte_idx == byte_count - 1) begin
                            // Last byte of this beat
                            state    <= S_IDLE;
                            byte_idx <= 7'd0;
                        end else begin
                            byte_idx <= byte_idx + 1;
                        end
                    end
                end
            endcase
        end
    end

endmodule
