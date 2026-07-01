`timescale 1ns / 1ps

module cpu_tb;

reg clk;
reg rst;

// DUT
wire [31:0] x1, x2, x3, mem0;

cpu_top DUT (
    .clk(clk),
    .rst(rst),

    .debug_x1(x1),
    .debug_x2(x2),
    .debug_x3(x3),
    .debug_mem0(mem0)
);

//======================================================
// Clock generation
//======================================================

always #5 clk = ~clk;

//======================================================
// Simulation control
//======================================================

integer cycle_count = 0;
integer max_cycles = 200;

//======================================================
// Optional waveform dump
//======================================================

initial begin
    $dumpfile("cpu_wave.vcd");
    $dumpvars(0, cpu_tb);
end

//======================================================
// Monitor
//======================================================

always @(posedge clk) begin

    cycle_count = cycle_count + 1;

    $display("------------------------------------------------");
    $display("Cycle : %0d", cycle_count);
    $display("PC    : %h", DUT.pc_current);
    $display("Instr : %h", DUT.instruction);

    $display("x1    : %h", x1);
    $display("x2    : %h", x2);
    $display("x3    : %h", x3);
    $display("mem[0]: %h", mem0);

    // Safety stop
    if (cycle_count >= max_cycles) begin
        $display("Simulation stopped (timeout).");
        $finish;
    end

end

//======================================================
// Reset + run
//======================================================

initial begin

    clk = 0;
    rst = 1;

    #20;
    rst = 0;

    $display("CPU Simulation Started...");

    #2000;

    $display("------------------------------------------------");
    $display("FINAL STATE:");
    $display("x1     = %h", x1);
    $display("x2     = %h", x2);
    $display("x3     = %h", x3);
    $display("mem[0] = %h", mem0);

    $display("Simulation Finished.");

    $finish;

end

endmodule