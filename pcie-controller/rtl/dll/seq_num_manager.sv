module seq_num_manager (
  input  logic clk,
  input  logic rst_n,
  input  logic send_tlp,
  output logic [11:0] current_seq_num,
  output logic        seq_valid
);

  logic [11:0] seq_counter;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      seq_counter <= 0;
    end else if (send_tlp) begin
      seq_counter <= seq_counter + 1;
    end
  end

  assign current_seq_num = seq_counter;
  assign seq_valid = 1'b1;

endmodule