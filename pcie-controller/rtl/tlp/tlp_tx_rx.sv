`include "pcie_params.svh"
import pcie_pkg::*;

module tlp_tx_rx (
  input  logic               clk,
  input  logic               rst_n,
  
  // From upper layers
  input  logic               tlp_req_valid,
  input  tlp_type_t          tlp_type,
  
  // To DLL / PIPE
  output logic               tlp_out_valid,
  output logic [DATA_WIDTH-1:0] tlp_out_data,
  
  // From DLL / PIPE
  input  logic [DATA_WIDTH-1:0] tlp_in_data,
  input  logic               tlp_in_valid,
  
  // Status
  output logic               credits_ok
);

  tlp_formatter formatter_inst (
    .clk           (clk),
    .rst_n         (rst_n),
    .tlp_req_valid (tlp_req_valid),
    .tlp_type      (tlp_type),
    .addr          (64'h0000_0000_1000_0000), // example
    .length        (10'd64),
    .requester_id  (16'h0001),
    .tag           (8'h00),
    .tlp_valid     (tlp_out_valid),
    .tlp_data      (tlp_out_data),
    .ready         (1'b1)
  );

  tlp_parser parser_inst (
    .clk            (clk),
    .rst_n          (rst_n),
    .rx_tlp_data    (tlp_in_data),
    .rx_tlp_valid   (tlp_in_valid)
  );

  credit_manager #(.NUM_VC(VC_COUNT)) credit_inst (
    .clk              (clk),
    .rst_n            (rst_n)
  );

  assign credits_ok = 1'b1; // placeholder

endmodule