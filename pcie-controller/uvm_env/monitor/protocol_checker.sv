module protocol_checker (
  input logic clk,
  input logic rst_n,
  input logic tx_valid,
  input logic [DATA_WIDTH-1:0] tx_data
);
  // Add more assertions here later
  assert property (@(posedge clk) disable iff (!rst_n) tx_valid |-> tx_data !== 'x)
  else $error("X-propagation on TX data");
endmodule