module ltssm (
  input logic clk,
  input logic rst_n,
  output logic link_up
);
  typedef enum logic [3:0] { DETECT, POLLING, CONFIG, L0 } state_t;
  state_t state = DETECT;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) state <= DETECT;
    else if (state == DETECT) state <= POLLING;
    else if (state == POLLING) state <= CONFIG;
    else if (state == CONFIG) state <= L0;
  end

  assign link_up = (state == L0);
endmodule