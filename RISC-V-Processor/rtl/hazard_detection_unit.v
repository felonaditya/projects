`timescale 1ns / 1ps

module hazard_detection_unit(

    input  wire       id_ex_mem_read,
    input  wire [4:0] id_ex_rd,

    input  wire [4:0] if_id_rs1,
    input  wire [4:0] if_id_rs2,

    output reg        pc_stall,
    output reg        if_id_stall,
    output reg        id_ex_flush

);

always @(*)
begin

    pc_stall   = 0;
    if_id_stall = 0;
    id_ex_flush = 0;

    // Load-use hazard detection
    if (id_ex_mem_read &&
       ((id_ex_rd == if_id_rs1) || (id_ex_rd == if_id_rs2)) &&
       (id_ex_rd != 0))
    begin
        pc_stall    = 1;
        if_id_stall = 1;
        id_ex_flush = 1;
    end

end

endmodule