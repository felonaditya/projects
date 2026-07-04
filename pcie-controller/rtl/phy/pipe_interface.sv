interface pcie_pipe_if #(parameter DATA_WIDTH = 512) (input logic clk, rst_n);
  logic [DATA_WIDTH-1:0] tx_data;
  logic [DATA_WIDTH-1:0] rx_data;
  logic tx_valid;
  logic rx_valid;
  logic phy_status;
  logic [1:0] power_state;

  modport dut (output tx_data, tx_valid, input rx_data, rx_valid);
  modport tb  (input tx_data, tx_valid, output rx_data, rx_valid);
endinterface