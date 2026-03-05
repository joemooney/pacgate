// conntrack_table.v — Connection tracking hash table with TCP state tracking
// Hand-written infrastructure module for PacGate
//
// CRC-based hash with open-addressing linear probing.
// Stores 5-tuple flow keys (src_ip, dst_ip, ip_protocol, src_port, dst_port)
// with per-entry timeout via timestamp comparison.
// Tracks TCP connection state per flow (NEW → ESTABLISHED → CLOSING → CLOSED).
//
// Parameters:
//   TABLE_SIZE  — Number of entries (must be power of 2)
//   KEY_WIDTH   — Width of lookup key in bits
//   TIMEOUT     — Entry expiry timeout in clock cycles

module conntrack_table #(
    parameter TABLE_SIZE  = 1024,
    parameter KEY_WIDTH   = 104,   // 32+32+8+16+16 = 104 bits (5-tuple)
    parameter TIMEOUT     = 1000000,
    parameter INDEX_BITS  = $clog2(TABLE_SIZE)
) (
    input  wire                   clk,
    input  wire                   rst_n,

    // Global timestamp (free-running counter)
    input  wire [31:0]            timestamp,

    // TCP flags for state tracking (from frame_parser)
    input  wire [7:0]             tcp_flags_in,

    // Packet length for per-flow byte counting
    input  wire [15:0]            pkt_len_in,

    // Lookup interface
    input  wire [KEY_WIDTH-1:0]   key_in,
    input  wire                   lookup_valid,
    output reg                    lookup_hit,
    output reg                    lookup_done,
    output reg  [2:0]             flow_state,     // TCP state of matched flow
    output reg                    flow_state_valid, // flow_state output is valid

    // Insert interface (first packet of flow)
    input  wire                   insert_en,
    input  wire [KEY_WIDTH-1:0]   insert_key,
    output reg                    insert_done,
    output reg                    insert_ok,

    // Flow read-back interface (for flow export)
    input  wire [INDEX_BITS-1:0]  flow_read_idx,
    input  wire                   flow_read_en,
    output reg  [KEY_WIDTH-1:0]   flow_read_key,
    output reg                    flow_read_valid,
    output reg  [63:0]            flow_read_pkt_count,
    output reg  [63:0]            flow_read_byte_count,
    output reg  [2:0]             flow_read_tcp_state,
    output reg                    flow_read_done
);

    // TCP state encoding
    localparam TCP_NONE        = 3'd0;  // No flow entry
    localparam TCP_NEW         = 3'd1;  // SYN seen (first packet)
    localparam TCP_ESTABLISHED = 3'd2;  // Bidirectional traffic (SYN-ACK or return)
    localparam TCP_FIN_WAIT    = 3'd3;  // FIN seen
    localparam TCP_CLOSED      = 3'd4;  // RST or both FINs seen

    // TCP flag bit positions
    wire flag_fin = tcp_flags_in[0];
    wire flag_syn = tcp_flags_in[1];
    wire flag_rst = tcp_flags_in[2];
    wire flag_ack = tcp_flags_in[4];

    // Table storage
    reg [KEY_WIDTH-1:0]  table_key       [0:TABLE_SIZE-1];
    reg                  table_valid     [0:TABLE_SIZE-1];
    reg [31:0]           table_ts        [0:TABLE_SIZE-1];
    reg [2:0]            table_tcp_state [0:TABLE_SIZE-1];

    // Per-flow counters
    reg [63:0]           table_pkt_count  [0:TABLE_SIZE-1];
    reg [63:0]           table_byte_count [0:TABLE_SIZE-1];

    // Hash function: simple CRC-like XOR folding
    function [INDEX_BITS-1:0] hash_key;
        input [KEY_WIDTH-1:0] key;
        reg [31:0] h;
        integer i;
        begin
            h = 32'hDEADBEEF;
            for (i = 0; i < KEY_WIDTH; i = i + 1) begin
                if (key[i])
                    h = h ^ (32'h04C11DB7 >> (i % 16));
                h = {h[30:0], h[31]};  // rotate left
            end
            hash_key = h[INDEX_BITS-1:0];
        end
    endfunction

    // Next-state function for TCP state machine
    function [2:0] tcp_next_state;
        input [2:0] current;
        input       syn, ack, fin, rst;
        begin
            if (rst)
                tcp_next_state = TCP_CLOSED;
            else case (current)
                TCP_NEW: begin
                    if (syn && ack)
                        tcp_next_state = TCP_ESTABLISHED;
                    else if (ack)
                        tcp_next_state = TCP_ESTABLISHED;
                    else
                        tcp_next_state = TCP_NEW;
                end
                TCP_ESTABLISHED: begin
                    if (fin)
                        tcp_next_state = TCP_FIN_WAIT;
                    else
                        tcp_next_state = TCP_ESTABLISHED;
                end
                TCP_FIN_WAIT: begin
                    if (fin || ack)
                        tcp_next_state = TCP_CLOSED;
                    else
                        tcp_next_state = TCP_FIN_WAIT;
                end
                default: tcp_next_state = current;
            endcase
        end
    endfunction

    // FSM states
    localparam S_IDLE      = 3'd0;
    localparam S_LOOKUP    = 3'd1;
    localparam S_PROBE     = 3'd2;
    localparam S_INSERT    = 3'd3;
    localparam S_INS_PROBE = 3'd4;
    localparam S_DONE      = 3'd5;

    reg [2:0]              state;
    reg [INDEX_BITS-1:0]   probe_idx;
    reg [3:0]              probe_count;  // Max 16 probes
    reg [KEY_WIDTH-1:0]    op_key;
    reg [7:0]              op_tcp_flags;  // Captured TCP flags for state update
    reg [15:0]             op_pkt_len;   // Captured packet length for byte counting

    localparam MAX_PROBES = 4'd8;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state            <= S_IDLE;
            lookup_hit       <= 1'b0;
            lookup_done      <= 1'b0;
            insert_done      <= 1'b0;
            insert_ok        <= 1'b0;
            flow_state       <= TCP_NONE;
            flow_state_valid <= 1'b0;
            probe_idx        <= {INDEX_BITS{1'b0}};
            probe_count      <= 4'd0;
            op_pkt_len       <= 16'd0;
        end else begin
            // Default: clear done signals after one cycle
            lookup_done      <= 1'b0;
            insert_done      <= 1'b0;
            flow_state_valid <= 1'b0;

            case (state)
                S_IDLE: begin
                    lookup_hit <= 1'b0;
                    insert_ok  <= 1'b0;
                    if (lookup_valid) begin
                        op_key       <= key_in;
                        op_tcp_flags <= tcp_flags_in;
                        op_pkt_len   <= pkt_len_in;
                        probe_idx    <= hash_key(key_in);
                        probe_count  <= 4'd0;
                        state        <= S_LOOKUP;
                    end else if (insert_en) begin
                        op_key       <= insert_key;
                        op_tcp_flags <= tcp_flags_in;
                        op_pkt_len   <= pkt_len_in;
                        probe_idx    <= hash_key(insert_key);
                        probe_count  <= 4'd0;
                        state        <= S_INSERT;
                    end
                end

                S_LOOKUP: begin
                    if (table_valid[probe_idx] &&
                        table_key[probe_idx] == op_key &&
                        (timestamp - table_ts[probe_idx]) < TIMEOUT) begin
                        // Hit: update timestamp + advance TCP state + increment counters
                        lookup_hit       <= 1'b1;
                        lookup_done      <= 1'b1;
                        flow_state       <= table_tcp_state[probe_idx];
                        flow_state_valid <= 1'b1;
                        table_ts[probe_idx] <= timestamp;
                        // Advance TCP state based on flags
                        table_tcp_state[probe_idx] <= tcp_next_state(
                            table_tcp_state[probe_idx],
                            op_tcp_flags[1], op_tcp_flags[4],
                            op_tcp_flags[0], op_tcp_flags[2]
                        );
                        // Increment per-flow counters
                        table_pkt_count[probe_idx]  <= table_pkt_count[probe_idx] + 64'd1;
                        table_byte_count[probe_idx] <= table_byte_count[probe_idx] + {48'd0, op_pkt_len};
                        state <= S_IDLE;
                    end else if (!table_valid[probe_idx] || probe_count >= MAX_PROBES) begin
                        // Miss
                        lookup_hit       <= 1'b0;
                        lookup_done      <= 1'b1;
                        flow_state       <= TCP_NONE;
                        flow_state_valid <= 1'b1;
                        state            <= S_IDLE;
                    end else begin
                        // Expired entry or collision: probe next
                        if (table_valid[probe_idx] &&
                            (timestamp - table_ts[probe_idx]) >= TIMEOUT) begin
                            table_valid[probe_idx] <= 1'b0;  // Evict expired
                        end
                        probe_idx   <= probe_idx + 1'b1;
                        probe_count <= probe_count + 4'd1;
                    end
                end

                S_INSERT: begin
                    if (!table_valid[probe_idx] ||
                        (timestamp - table_ts[probe_idx]) >= TIMEOUT) begin
                        // Empty or expired slot: insert with initial TCP state + counters
                        table_key[probe_idx]       <= op_key;
                        table_valid[probe_idx]     <= 1'b1;
                        table_ts[probe_idx]        <= timestamp;
                        table_tcp_state[probe_idx] <= (op_tcp_flags[1]) ? TCP_NEW : TCP_ESTABLISHED;
                        table_pkt_count[probe_idx]  <= 64'd1;
                        table_byte_count[probe_idx] <= {48'd0, op_pkt_len};
                        insert_ok   <= 1'b1;
                        insert_done <= 1'b1;
                        state       <= S_IDLE;
                    end else if (table_key[probe_idx] == op_key) begin
                        // Already exists: update timestamp + advance state + increment counters
                        table_ts[probe_idx] <= timestamp;
                        table_tcp_state[probe_idx] <= tcp_next_state(
                            table_tcp_state[probe_idx],
                            op_tcp_flags[1], op_tcp_flags[4],
                            op_tcp_flags[0], op_tcp_flags[2]
                        );
                        table_pkt_count[probe_idx]  <= table_pkt_count[probe_idx] + 64'd1;
                        table_byte_count[probe_idx] <= table_byte_count[probe_idx] + {48'd0, op_pkt_len};
                        insert_ok   <= 1'b1;
                        insert_done <= 1'b1;
                        state       <= S_IDLE;
                    end else if (probe_count >= MAX_PROBES) begin
                        // Table full in this neighborhood
                        insert_ok   <= 1'b0;
                        insert_done <= 1'b1;
                        state       <= S_IDLE;
                    end else begin
                        // Collision: linear probe
                        probe_idx   <= probe_idx + 1'b1;
                        probe_count <= probe_count + 4'd1;
                    end
                end

                default: state <= S_IDLE;
            endcase
        end
    end

    // Initialize table on reset
    integer j;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (j = 0; j < TABLE_SIZE; j = j + 1) begin
                table_valid[j]      <= 1'b0;
                table_ts[j]         <= 32'd0;
                table_tcp_state[j]  <= TCP_NONE;
                table_pkt_count[j]  <= 64'd0;
                table_byte_count[j] <= 64'd0;
            end
        end
    end

    // Flow read-back interface (registered, 1-cycle latency)
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            flow_read_key       <= {KEY_WIDTH{1'b0}};
            flow_read_valid     <= 1'b0;
            flow_read_pkt_count <= 64'd0;
            flow_read_byte_count<= 64'd0;
            flow_read_tcp_state <= TCP_NONE;
            flow_read_done      <= 1'b0;
        end else begin
            flow_read_done <= 1'b0;  // Default: clear done after one cycle
            if (flow_read_en) begin
                flow_read_key        <= table_key[flow_read_idx];
                flow_read_valid      <= table_valid[flow_read_idx];
                flow_read_pkt_count  <= table_pkt_count[flow_read_idx];
                flow_read_byte_count <= table_byte_count[flow_read_idx];
                flow_read_tcp_state  <= table_tcp_state[flow_read_idx];
                flow_read_done       <= 1'b1;
            end
        end
    end

endmodule
