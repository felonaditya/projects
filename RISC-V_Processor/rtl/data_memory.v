`timescale 1ns / 1ps

module data_memory (

    input  wire        clk,
    input  wire        mem_write,
    input  wire        mem_read,

    input  wire [31:0] address,
    input  wire [31:0] write_data,

    output wire [31:0] read_data

);

    // 256 x 32-bit data memory
    reg [31:0] memory [0:255];

    integer i;

    // Initialize memory to zero (simulation)
    initial begin
        for(i = 0; i < 256; i = i + 1)
            memory[i] = 32'd0;
    end

    // Synchronous write
    always @(posedge clk)
    begin
        if(mem_write)
            memory[address[31:2]] <= write_data;
    end

    // Asynchronous read
    assign read_data = (mem_read) ? memory[address[31:2]] : 32'd0;

endmodule