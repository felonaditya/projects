`timescale 1ns / 1ps

module pc_tb;

reg clk;
reg rst;
reg pc_write;

reg [31:0] pc_next;

wire [31:0] pc_current;

integer errors = 0;

pc DUT (

    .clk(clk),
    .rst(rst),
    .pc_write(pc_write),
    .pc_next(pc_next),
    .pc_current(pc_current)

);

always #5 clk = ~clk;

task expect;

input [31:0] expected;

begin

    #1;

    if (pc_current !== expected)
    begin
        $display("--------------------------------");
        $display("FAILED");
        $display("Expected PC = %h", expected);
        $display("Actual PC   = %h", pc_current);
        errors = errors + 1;
    end
    else
    begin
        $display("PASS : PC = %h", pc_current);
    end

end

endtask

initial
begin

    clk = 0;
    rst = 1;
    pc_write = 0;
    pc_next = 0;

    //-------------------------
    // Reset
    //-------------------------

    #20;

    rst = 0;

    expect(32'h00000000);

    //-------------------------
    // PC = 4
    //-------------------------

    @(posedge clk);

    pc_write = 1;
    pc_next = 32'h00000004;

    @(posedge clk);

    expect(32'h00000004);

    //-------------------------
    // PC = 8
    //-------------------------

    pc_next = 32'h00000008;

    @(posedge clk);

    expect(32'h00000008);

    //-------------------------
    // Stall PC
    //-------------------------

    pc_write = 0;
    pc_next = 32'h0000000C;

    @(posedge clk);

    expect(32'h00000008);

    //-------------------------
    // Resume
    //-------------------------

    pc_write = 1;

    @(posedge clk);

    expect(32'h0000000C);

    //-------------------------

    if(errors == 0)
        $display("\nPROGRAM COUNTER TEST PASSED\n");
    else
        $display("\nTOTAL ERRORS = %d\n", errors);

    $finish;

end

endmodule