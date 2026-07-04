module dma_descriptor (
  input  logic clk, rst_n,
  input  logic load_desc,
  output logic [63:0] src_addr,
  output logic [63:0] dst_addr,
  output logic [15:0] length
);
  // Placeholder
  assign src_addr = 64'h1000_0000;
  assign dst_addr = 64'h2000_0000;
  assign length   = 16'h100;
endmodule