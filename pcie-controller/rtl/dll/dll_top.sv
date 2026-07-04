module dll_top (
  input  logic clk, rst_n,
  input  logic tlp_valid_in,
  input  logic [DATA_WIDTH-1:0] tlp_data_in,
  output logic dll_tlp_valid,
  output logic [DATA_WIDTH-1:0] dll_tlp_out,
  input  logic [DATA_WIDTH-1:0] rx_data,
  input  logic rx_valid
);

  ack_nak_protocol ack_nak (.*);
  lcrc_generator lcrc (.*);
  replay_buffer replay (.*);

  assign dll_tlp_valid = tlp_valid_in;
  assign dll_tlp_out   = tlp_data_in; // Extend with seq num + LCRC in full version

endmodule