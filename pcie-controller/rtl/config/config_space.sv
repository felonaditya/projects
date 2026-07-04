module config_space (
  input  logic         clk,
  input  logic         rst_n,
  input  logic [11:0]  addr,
  input  logic         we,
  input  logic [31:0]  wdata,
  output logic [31:0]  rdata
);

  logic [31:0] cfg_regs [256];  // Simplified

  always_ff @(posedge clk) begin
    if (we) begin
      cfg_regs[addr] <= wdata;
    end
  end

  assign rdata = cfg_regs[addr];

endmodule