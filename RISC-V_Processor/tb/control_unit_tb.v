`timescale 1ns / 1ps

module control_unit_tb;

reg [6:0] opcode;

wire reg_write;
wire mem_read;
wire mem_write;
wire mem_to_reg;
wire alu_src;
wire branch;
wire jump;
wire [1:0] alu_op;

integer errors = 0;

control_unit DUT(

    .opcode(opcode),

    .reg_write(reg_write),
    .mem_read(mem_read),
    .mem_write(mem_write),
    .mem_to_reg(mem_to_reg),
    .alu_src(alu_src),
    .branch(branch),
    .jump(jump),
    .alu_op(alu_op)

);

task check;

input exp_reg_write;
input exp_mem_read;
input exp_mem_write;
input exp_mem_to_reg;
input exp_alu_src;
input exp_branch;
input exp_jump;
input [1:0] exp_alu_op;

begin

    #5;

    if(
        reg_write  !== exp_reg_write ||
        mem_read   !== exp_mem_read ||
        mem_write  !== exp_mem_write ||
        mem_to_reg !== exp_mem_to_reg ||
        alu_src    !== exp_alu_src ||
        branch     !== exp_branch ||
        jump       !== exp_jump ||
        alu_op     !== exp_alu_op
      )
    begin
        $display("FAILED opcode = %b", opcode);
        errors = errors + 1;
    end
    else
        $display("PASS");

end

endtask

initial
begin

    //--------------------
    // R-Type
    //--------------------

    opcode = 7'b0110011;
    check(1,0,0,0,0,0,0,2'b10);

    //--------------------
    // LW
    //--------------------

    opcode = 7'b0000011;
    check(1,1,0,1,1,0,0,2'b00);

    //--------------------
    // SW
    //--------------------

    opcode = 7'b0100011;
    check(0,0,1,0,1,0,0,2'b00);

    //--------------------
    // BEQ
    //--------------------

    opcode = 7'b1100011;
    check(0,0,0,0,0,1,0,2'b01);

    //--------------------
    // ADDI
    //--------------------

    opcode = 7'b0010011;
    check(1,0,0,0,1,0,0,2'b10);

    //--------------------
    // JAL
    //--------------------

    opcode = 7'b1101111;
    check(1,0,0,0,0,0,1,2'b00);

    if(errors==0)
        $display("\nCONTROL UNIT TEST PASSED\n");
    else
        $display("\nTOTAL ERRORS = %d\n",errors);

    $finish;

end

endmodule