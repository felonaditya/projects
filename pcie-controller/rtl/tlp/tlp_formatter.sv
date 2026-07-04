`include "pcie_params.svh"
import pcie_pkg::*;

module tlp_formatter (
  input  logic               clk,
  input  logic               rst_n,
  input  logic               tlp_req_valid,
  input  tlp_type_t          tlp_type,
  input  logic [63:0]        addr,
  input  logic [9:0]         length,      // DW
  input  logic [15:0]        requester_id,
  input  logic [7:0]         tag,
  input  logic [31:0]        payload_data[], // variable
  output logic               tlp_valid,
  output logic [DATA_WIDTH-1:0] tlp_data,
  output logic               tlp_sop,
  output logic               tlp_eop,
  input  logic               ready
);

  logic [127:0] header;
  logic [31:0]  crc;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      tlp_valid <= 0;
      tlp_sop   <= 0;
      tlp_eop   <= 0;
    end else if (tlp_req_valid && ready) begin
      // Build Header (simplified 4DW for 64-bit addr)
      header <= {4'b0010, tlp_type, 3'b000, /* TC */ 1'b0, /* TD */ 1'b0, /* EP */ 2'b00, length,
                 requester_id, tag, 8'h00, addr[63:32], addr[31:0]};
      
      tlp_data  <= {header, payload_data[0]}; // Extend for full width
      tlp_valid <= 1;
      tlp_sop   <= 1;
      tlp_eop   <= 1;  // Single beat for simplicity
    end else begin
      tlp_valid <= 0;
      tlp_sop   <= 0;
      tlp_eop   <= 0;
    end
  end

endmodule