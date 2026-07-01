`timescale 1ns / 1ps

module data_memory_tb;

reg clk;

reg mem_write;
reg mem_read;

reg [31:0] address;
reg [31:0] write_data;

wire [31:0] read_data;

integer errors = 0;

data_memory DUT(

    .clk(clk),
    .mem_write(mem_write),
    .mem_read(mem_read),
    .address(address),
    .write_data(write_data),
    .read_data(read_data)

);

always #5 clk = ~clk;

task expect;

input [31:0] expected;

begin

    #2;

    if(read_data !== expected)
    begin
        $display("--------------------------------");
        $display("FAILED");
        $display("Address  = %h", address);
        $display("Expected = %h", expected);
        $display("Actual   = %h", read_data);
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

    mem_write = 0;
    mem_read  = 0;

    address = 0;
    write_data = 0;

    //-------------------------
    // Write memory[0]
    //-------------------------

    @(posedge clk);

    mem_write = 1;
    address = 32'h00000000;
    write_data = 32'h12345678;

    @(posedge clk);

    mem_write = 0;

    //-------------------------
    // Read memory[0]
    //-------------------------

    mem_read = 1;
    address = 32'h00000000;

    expect(32'h12345678);

    //-------------------------
    // Write memory[4]
    //-------------------------

    @(posedge clk);

    mem_read = 0;
    mem_write = 1;

    address = 32'h00000004;
    write_data = 32'hABCDEF01;

    @(posedge clk);

    mem_write = 0;

    //-------------------------
    // Read memory[4]
    //-------------------------

    mem_read = 1;
    address = 32'h00000004;

    expect(32'hABCDEF01);

    //-------------------------
    // Read disabled
    //-------------------------

    mem_read = 0;

    #2;

    if(read_data !== 32'd0)
    begin
        $display("FAILED : Read Disable");
        errors = errors + 1;
    end

    //-------------------------

    if(errors == 0)
        $display("\nDATA MEMORY TEST PASSED\n");
    else
        $display("\nTOTAL ERRORS = %d\n", errors);

    $finish;

end

endmodule