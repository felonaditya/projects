`include "pcie_params.svh"
`include "pcie_assertions.svh"
import pcie_pkg::*;

module pcie_ep_top (
  input  logic         clk,
  input  logic         rst_n,
  
  // PIPE
  output logic [DATA_WIDTH-1:0] tx_data,
  input  logic [DATA_WIDTH-1:0] rx_data,
  output logic                  tx_valid,
  input  logic                  rx_valid,
  
  // AXI
  axi_if.slave axi_s
);

  // TLP
  logic tlp_to_dll_valid;
  logic [DATA_WIDTH-1:0] tlp_to_dll_data;

  tlp_tx_rx tlp_layer (
    .clk            (clk),
    .rst_n          (rst_n),
    .tlp_req_valid  (1'b1),
    .tlp_type       (MRD64),
    .tlp_out_valid  (tlp_to_dll_valid),
    .tlp_out_data   (tlp_to_dll_data),
    .tlp_in_data    (rx_data),
    .tlp_in_valid   (rx_valid)
  );

  // DLL
  dll_top dll_layer (
    .clk            (clk),
    .rst_n          (rst_n),
    .tlp_valid_in   (tlp_to_dll_valid),
    .tlp_data_in    (tlp_to_dll_data),
    .dll_tlp_valid  (tx_valid),
    .dll_tlp_out    (tx_data),
    .rx_data        (rx_data),
    .rx_valid       (rx_valid)
  );

  // Config + DMA (basic)
  config_space cfg_inst (.*);
  dma_engine dma_inst (.*);

endmodule