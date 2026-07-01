`timescale 1ns / 1ps

module control_unit(

    input  wire [6:0] opcode,

    output reg        reg_write,
    output reg        mem_read,
    output reg        mem_write,
    output reg        mem_to_reg,
    output reg        alu_src,
    output reg        branch,
    output reg        jump,
    output reg [1:0]  alu_op

);

always @(*)
begin

    // Default values

    reg_write = 0;
    mem_read  = 0;
    mem_write = 0;
    mem_to_reg = 0;
    alu_src   = 0;
    branch    = 0;
    jump      = 0;
    alu_op    = 2'b00;

    case(opcode)

        //---------------------------------------------------
        // R-Type
        //---------------------------------------------------

        7'b0110011:
        begin
            reg_write = 1;
            alu_src   = 0;
            alu_op    = 2'b10;
        end

        //---------------------------------------------------
        // I-Type Arithmetic (ADDI, ANDI, ORI, ...)
        //---------------------------------------------------

        7'b0010011:
        begin
            reg_write = 1;
            alu_src   = 1;
            alu_op    = 2'b10;
        end

        //---------------------------------------------------
        // LOAD (LW)
        //---------------------------------------------------

        7'b0000011:
        begin
            reg_write = 1;
            mem_read  = 1;
            mem_to_reg = 1;
            alu_src   = 1;
            alu_op    = 2'b00;
        end

        //---------------------------------------------------
        // STORE (SW)
        //---------------------------------------------------

        7'b0100011:
        begin
            mem_write = 1;
            alu_src   = 1;
            alu_op    = 2'b00;
        end

        //---------------------------------------------------
        // BRANCH (BEQ)
        //---------------------------------------------------

        7'b1100011:
        begin
            branch = 1;
            alu_op = 2'b01;
        end

        //---------------------------------------------------
        // JAL
        //---------------------------------------------------

        7'b1101111:
        begin
            jump = 1;
            reg_write = 1;
        end

        //---------------------------------------------------
        // JALR
        //---------------------------------------------------

        7'b1100111:
        begin
            jump = 1;
            reg_write = 1;
            alu_src = 1;
        end

        //---------------------------------------------------
        // LUI
        //---------------------------------------------------

        7'b0110111:
        begin
            reg_write = 1;
            alu_src = 1;
        end

        //---------------------------------------------------
        // AUIPC
        //---------------------------------------------------

        7'b0010111:
        begin
            reg_write = 1;
            alu_src = 1;
        end

        default:
        begin
            // Keep default values
        end

    endcase

end

endmodule