module replay_buffer #(
  parameter DEPTH = 64
) (
  input  logic               clk,
  input  logic               rst_n,
  input  logic [11:0]        seq_num,
  input  logic [DATA_WIDTH-1:0] tlp_data,
  input  logic               store_tlp,
  input  logic [11:0]        replay_seq,
  input  logic               replay_req,
  output logic [DATA_WIDTH-1:0] replay_data,
  output logic               replay_valid
);

  logic [DATA_WIDTH-1:0] buffer [DEPTH-1:0];
  logic [11:0]           stored_seq [DEPTH-1:0];

  always_ff @(posedge clk) begin
    if (store_tlp) begin
      buffer[seq_num % DEPTH] <= tlp_data;
      stored_seq[seq_num % DEPTH] <= seq_num;
    end
  end

  assign replay_data  = buffer[replay_seq % DEPTH];
  assign replay_valid = replay_req;

endmodule