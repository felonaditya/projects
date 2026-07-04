module dma_engine (
  input  logic         clk,
  input  logic         rst_n,
  axi_if.master        axi_m,
  input  logic         dma_start,
  output logic         dma_done
);

  logic [31:0] src_addr, dst_addr;
  logic [9:0]  transfer_size;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      dma_done <= 0;
    end else if (dma_start) begin
      `uvm_info("DMA", "DMA Transfer Started", UVM_LOW) // Note: This will be visible in sim log
      #100; // Simulate work
      dma_done <= 1;
    end
  end

endmodule