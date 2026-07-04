module tlp_parser (
  input  logic               clk,
  input  logic               rst_n,
  input  logic [DATA_WIDTH-1:0] rx_tlp_data,
  input  logic               rx_tlp_valid,
  output tlp_type_t          decoded_type,
  output logic [63:0]        decoded_addr,
  output logic [9:0]         decoded_length,
  output logic [31:0]        payload_out[],
  output logic               tlp_valid_out,
  output logic               is_completion
);

  always_comb begin
    decoded_type = UNKNOWN;
    if (rx_tlp_valid) begin
      // Simplified decode
      decoded_type = tlp_type_t'(rx_tlp_data[28:24]);
      decoded_addr = {rx_tlp_data[95:64], rx_tlp_data[63:32]};
      decoded_length = rx_tlp_data[9:0];
      is_completion = (decoded_type == CPL || decoded_type == CPLD);
    end
  end

  assign tlp_valid_out = rx_tlp_valid;

endmodule