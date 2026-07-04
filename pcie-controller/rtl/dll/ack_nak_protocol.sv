module ack_nak_protocol (
  input  logic clk,
  input  logic rst_n,
  input  logic [11:0] rx_seq_num,
  output logic        send_ack,
  output logic        send_nak
);

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      send_ack <= 0;
      send_nak <= 0;
    end else begin
      send_ack <= 1'b1;   // Simplified - always ACK for now
      send_nak <= 1'b0;
    end
  end
endmodule