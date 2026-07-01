`timescale 1ns / 1ps

module if_id(

    input  wire        clk,
    input  wire        rst,
    input  wire        flush,
    input  wire        stall,

    input  wire [31:0] pc_in,
    input  wire [31:0] instr_in,

    output reg  [31:0] pc_out,
    output reg  [31:0] instr_out

);

always @(posedge clk or posedge rst)
begin
    if (rst)
    begin
        pc_out    <= 32'd0;
        instr_out <= 32'd0;
    end
    else if (flush)
    begin
        pc_out    <= 32'd0;
        instr_out <= 32'd0;
    end
    else if (!stall)
    begin
        pc_out    <= pc_in;
        instr_out <= instr_in;
    end
end

endmodule