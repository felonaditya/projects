`timescale 1ns / 1ps

module instruction_memory_tb;

reg  [31:0] address;
wire [31:0] instruction;

integer errors = 0;

instruction_memory DUT (

    .address(address),
    .instruction(instruction)

);

task expect;

input [31:0] expected;

begin

    #5;

    if(instruction !== expected)
    begin
        $display("--------------------------------");
        $display("FAILED");
        $display("Address   = %h", address);
        $display("Expected  = %h", expected);
        $display("Received  = %h", instruction);
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

    address = 32'h00000000;
    expect(32'h00500093);

    address = 32'h00000004;
    expect(32'h00A00113);

    address = 32'h00000008;
    expect(32'h002081B3);

    address = 32'h0000000C;
    expect(32'h00302023);

    address = 32'h00000010;
    expect(32'h0000006F);

    if(errors == 0)
        $display("\nINSTRUCTION MEMORY TEST PASSED\n");
    else
        $display("\nTOTAL ERRORS = %d\n", errors);

    $finish;

end

endmodule