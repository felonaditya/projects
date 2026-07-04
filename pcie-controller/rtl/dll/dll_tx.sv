module dll_tx (
  input  logic clk, rst_n,
  input  logic [DATA_WIDTH-1:0] tlp_in,
  output logic [DATA_WIDTH-1:0] dll_out,
  output logic dll_valid
);
  assign dll_out = tlp_in;
  assign dll_valid = 1'b1;
endmodule