`timescale 1ns / 1ps

module register_file_tb;

reg clk;
reg rst;

reg reg_write;

reg [4:0] rs1;
reg [4:0] rs2;
reg [4:0] rd;

reg [31:0] write_data;

wire [31:0] read_data1;
wire [31:0] read_data2;

integer errors = 0;

register_file DUT(

    .clk(clk),
    .rst(rst),

    .reg_write(reg_write),

    .rs1(rs1),
    .rs2(rs2),
    .rd(rd),

    .write_data(write_data),

    .read_data1(read_data1),
    .read_data2(read_data2)

);

always #5 clk = ~clk;

task expect;

input [31:0] actual;
input [31:0] expected;

begin

    #1;

    if(actual !== expected)
    begin
        $display("--------------------------------");
        $display("FAILED");
        $display("Expected = %h", expected);
        $display("Actual   = %h", actual);
        errors = errors + 1;
    end
    else
    begin
        $display("PASS");
    end

end

endtask

initial
begin

    clk = 0;
    rst = 1;

    reg_write = 0;

    rs1 = 0;
    rs2 = 0;
    rd  = 0;

    write_data = 0;

    #20;

    rst = 0;

    //-------------------------
    // Write x1
    //-------------------------

    @(posedge clk);

    reg_write = 1;
    rd = 5'd1;
    write_data = 32'h12345678;

    @(posedge clk);

    reg_write = 0;

    rs1 = 5'd1;

    expect(read_data1,32'h12345678);

    //-------------------------
    // Write x5
    //-------------------------

    @(posedge clk);

    reg_write = 1;
    rd = 5'd5;
    write_data = 32'h87654321;

    @(posedge clk);

    reg_write = 0;

    rs2 = 5'd5;

    expect(read_data2,32'h87654321);

    //-------------------------
    // x0 should remain zero
    //-------------------------

    @(posedge clk);

    reg_write = 1;
    rd = 5'd0;
    write_data = 32'hFFFFFFFF;

    @(posedge clk);

    reg_write = 0;

    rs1 = 0;

    expect(read_data1,32'd0);

    //-------------------------
    // Read both ports
    //-------------------------

    rs1 = 5'd1;
    rs2 = 5'd5;

    expect(read_data1,32'h12345678);
    expect(read_data2,32'h87654321);

    //-------------------------

    if(errors==0)
        $display("\nREGISTER FILE TEST PASSED\n");
    else
        $display("\nTOTAL ERRORS = %d\n",errors);

    $finish;

end

endmodule