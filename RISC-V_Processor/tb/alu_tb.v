`timescale 1ns / 1ps

module alu_tb;

reg  [31:0] a;
reg  [31:0] b;
reg  [3:0]  alu_ctrl;

wire [31:0] result;
wire zero;

alu DUT (
    .a(a),
    .b(b),
    .alu_ctrl(alu_ctrl),
    .result(result),
    .zero(zero)
);

integer errors = 0;

task check;

input [31:0] expected;

begin
    #10;

    if(result !== expected) begin
        $display("-----------------------------------");
        $display("FAILED");
        $display("A=%d",a);
        $display("B=%d",b);
        $display("CTRL=%b",alu_ctrl);
        $display("Expected=%d",expected);
        $display("Got=%d",result);
        errors = errors + 1;
    end

    else begin
        $display("PASS");
    end

end

endtask

initial begin

    //--------------------
    // ADD
    //--------------------

    a=20;
    b=15;
    alu_ctrl=4'b0000;
    check(35);

    //--------------------
    // SUB
    //--------------------

    a=20;
    b=10;
    alu_ctrl=4'b0001;
    check(10);

    //--------------------
    // AND
    //--------------------

    a=32'hAA55AA55;
    b=32'hFFFF0000;
    alu_ctrl=4'b0010;
    check(32'hAA550000);

    //--------------------
    // OR
    //--------------------

    a=32'hAA550000;
    b=32'h00005555;
    alu_ctrl=4'b0011;
    check(32'hAA555555);

    //--------------------
    // XOR
    //--------------------

    a=32'hFFFFFFFF;
    b=32'h0000FFFF;
    alu_ctrl=4'b0100;
    check(32'hFFFF0000);

    //--------------------
    // Shift Left
    //--------------------

    a=1;
    b=5;
    alu_ctrl=4'b0101;
    check(32);

    //--------------------
    // Shift Right
    //--------------------

    a=64;
    b=3;
    alu_ctrl=4'b0110;
    check(8);

    //--------------------
    // Arithmetic Shift
    //--------------------

    a=32'hFFFFFFF0;
    b=2;
    alu_ctrl=4'b0111;
    check(32'hFFFFFFFC);

    //--------------------
    // SLT
    //--------------------

    a=-5;
    b=2;
    alu_ctrl=4'b1000;
    check(1);

    //--------------------
    // SLTU
    //--------------------

    a=5;
    b=7;
    alu_ctrl=4'b1001;
    check(1);

    //--------------------
    // PASS B
    //--------------------

    a=111;
    b=222;
    alu_ctrl=4'b1010;
    check(222);

    //--------------------------------

    if(errors==0)
        $display("\nALL TESTS PASSED\n");
    else
        $display("\nTOTAL ERRORS = %d\n",errors);

    $finish;

end

endmodule