module credit_manager #(
  parameter int NUM_VC = 2
) (
  input  logic clk,
  input  logic rst_n,
  input  credit_type_t credit_type,
  input  logic [11:0]  credits_consumed,
  output logic [11:0]  credits_available [NUM_VC-1:0],
  input  logic         update_credits
);

  logic [11:0] credit_reg [NUM_VC-1:0];

  initial begin
    credit_reg = '{default: 12'h100}; // Initial credits
  end

  always_ff @(posedge clk) begin
    if (update_credits) begin
      credit_reg[0] <= credit_reg[0] - credits_consumed;
    end
  end

  assign credits_available = credit_reg;

endmodule