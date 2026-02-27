// conntrack_table.v — Connection tracking hash table
// Hand-written infrastructure module for PacGate
//
// CRC-based hash with open-addressing linear probing.
// Stores 5-tuple flow keys (src_ip, dst_ip, ip_protocol, src_port, dst_port)
// with per-entry timeout via timestamp comparison.
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

    // Lookup interface
    input  wire [KEY_WIDTH-1:0]   key_in,
    input  wire                   lookup_valid,
    output reg                    lookup_hit,
    output reg                    lookup_done,

    // Insert interface (first packet of flow)
    input  wire                   insert_en,
    input  wire [KEY_WIDTH-1:0]   insert_key,
    output reg                    insert_done,
    output reg                    insert_ok
);

    // Table storage
    reg [KEY_WIDTH-1:0]  table_key   [0:TABLE_SIZE-1];
    reg                  table_valid [0:TABLE_SIZE-1];
    reg [31:0]           table_ts    [0:TABLE_SIZE-1];

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

    localparam MAX_PROBES = 4'd8;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state        <= S_IDLE;
            lookup_hit   <= 1'b0;
            lookup_done  <= 1'b0;
            insert_done  <= 1'b0;
            insert_ok    <= 1'b0;
            probe_idx    <= {INDEX_BITS{1'b0}};
            probe_count  <= 4'd0;
        end else begin
            // Default: clear done signals after one cycle
            lookup_done <= 1'b0;
            insert_done <= 1'b0;

            case (state)
                S_IDLE: begin
                    lookup_hit <= 1'b0;
                    insert_ok  <= 1'b0;
                    if (lookup_valid) begin
                        op_key      <= key_in;
                        probe_idx   <= hash_key(key_in);
                        probe_count <= 4'd0;
                        state       <= S_LOOKUP;
                    end else if (insert_en) begin
                        op_key      <= insert_key;
                        probe_idx   <= hash_key(insert_key);
                        probe_count <= 4'd0;
                        state       <= S_INSERT;
                    end
                end

                S_LOOKUP: begin
                    if (table_valid[probe_idx] &&
                        table_key[probe_idx] == op_key &&
                        (timestamp - table_ts[probe_idx]) < TIMEOUT) begin
                        // Hit: update timestamp
                        lookup_hit  <= 1'b1;
                        lookup_done <= 1'b1;
                        table_ts[probe_idx] <= timestamp;
                        state       <= S_IDLE;
                    end else if (!table_valid[probe_idx] || probe_count >= MAX_PROBES) begin
                        // Miss
                        lookup_hit  <= 1'b0;
                        lookup_done <= 1'b1;
                        state       <= S_IDLE;
                    end else begin
                        // Expired entry or collision: probe next
                        if (table_valid[probe_idx] &&
                            (timestamp - table_ts[probe_idx]) >= TIMEOUT) begin
                            table_valid[probe_idx] <= 1'b0;  // Evict expired
                        end
                        probe_idx   <= probe_idx + {{INDEX_BITS}}'d1;
                        probe_count <= probe_count + 4'd1;
                    end
                end

                S_INSERT: begin
                    if (!table_valid[probe_idx] ||
                        (timestamp - table_ts[probe_idx]) >= TIMEOUT) begin
                        // Empty or expired slot: insert
                        table_key[probe_idx]   <= op_key;
                        table_valid[probe_idx] <= 1'b1;
                        table_ts[probe_idx]    <= timestamp;
                        insert_ok   <= 1'b1;
                        insert_done <= 1'b1;
                        state       <= S_IDLE;
                    end else if (table_key[probe_idx] == op_key) begin
                        // Already exists: update timestamp
                        table_ts[probe_idx] <= timestamp;
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
                        probe_idx   <= probe_idx + {{INDEX_BITS}}'d1;
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
                table_valid[j] <= 1'b0;
                table_ts[j]    <= 32'd0;
            end
        end
    end

endmodule
