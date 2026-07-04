`include "uvm_macros.svh"
import uvm_pkg::*;
import pcie_uvm_pkg::*;

module tb_top;
  logic clk = 0;
  logic rst_n = 0;

  pcie_pipe_if pipe_if (clk, rst_n);
  axi_if axi_if (clk, rst_n);   // assume axi_if exists

  pcie_ep_top dut (
    .clk      (clk),
    .rst_n    (rst_n),
    .tx_data  (pipe_if.tx_data),
    .rx_data  (pipe_if.rx_data),
    .tx_valid (pipe_if.tx_valid),
    .rx_valid (pipe_if.rx_valid),
    .axi_s    (axi_if)
  );

  initial begin
    uvm_config_db#(virtual pcie_pipe_if)::set(null, "*", "pipe_vif", pipe_if);
    run_test("base_test");
  end

  always #5 clk = ~clk;

  initial begin
    rst_n = 0; #50; rst_n = 1;
  end
endmodule