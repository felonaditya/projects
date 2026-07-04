interface pcie_pipe_if #(parameter DATA_WIDTH = 512) (input logic clk, rst_n);
  logic [DATA_WIDTH-1:0] tx_data, rx_data;
  logic tx_valid, rx_valid;
  // Add all PIPE signals per spec...
  
  modport dut (output tx_data, input rx_data, ...);
  modport tb  (input tx_data, output rx_data, ...);
endinterface