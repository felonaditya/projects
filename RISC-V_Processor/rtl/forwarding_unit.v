`timescale 1ns / 1ps

module forwarding_unit(

    input  wire [4:0] ex_rs1,
    input  wire [4:0] ex_rs2,

    input  wire [4:0] mem_rd,
    input  wire       mem_reg_write,

    input  wire [4:0] wb_rd,
    input  wire       wb_reg_write,

    output reg  [1:0] forward_a,
    output reg  [1:0] forward_b

);

always @(*)
begin

    // Default: no forwarding
    forward_a = 2'b00;
    forward_b = 2'b00;

    // EX hazard (MEM stage)
    if (mem_reg_write && (mem_rd != 0) && (mem_rd == ex_rs1))
        forward_a = 2'b10;

    if (mem_reg_write && (mem_rd != 0) && (mem_rd == ex_rs2))
        forward_b = 2'b10;

    // WB hazard
    if (wb_reg_write && (wb_rd != 0) && (wb_rd == ex_rs1))
        forward_a = 2'b01;

    if (wb_reg_write && (wb_rd != 0) && (wb_rd == ex_rs2))
        forward_b = 2'b01;

end

endmodule