module dll_rx (
  input  logic clk, rst_n,
  input  logic [DATA_WIDTH-1:0] dll_in,
  output logic [DATA_WIDTH-1:0] tlp_out,
  output logic tlp_valid
);
  assign tlp_out = dll_in;
  assign tlp_valid = 1'b1;
endmodule