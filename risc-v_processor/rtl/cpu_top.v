`timescale 1ns / 1ps

module cpu_top(

    input wire clk,
    input wire rst,

    // DEBUG OUTPUTS
    output wire [31:0] debug_x1,
    output wire [31:0] debug_x2,
    output wire [31:0] debug_x3,
    output wire [31:0] debug_mem0

);

`include "rtl/cpu_defines.vh"

//======================================================
// PC
//======================================================

wire [31:0] pc_current;
wire [31:0] pc_next;
wire [31:0] pc_plus_4 = pc_current + 4;

//======================================================
// Instruction
//======================================================

wire [31:0] instruction;

//======================================================
// IF/ID
//======================================================

wire [31:0] if_id_pc;
wire [31:0] if_id_instr;

//======================================================
// Decode fields
//======================================================

wire [4:0] rs1 = if_id_instr[19:15];
wire [4:0] rs2 = if_id_instr[24:20];
wire [4:0] rd  = if_id_instr[11:7];

wire [2:0] funct3 = if_id_instr[14:12];
wire       funct7_5 = if_id_instr[30];

//======================================================
// Control signals
//======================================================

wire reg_write, mem_read, mem_write, mem_to_reg;
wire alu_src, branch, jump;
wire [1:0] alu_op;

//======================================================
// ID/EX signals
//======================================================

wire ex_reg_write, ex_mem_read, ex_mem_write, ex_mem_to_reg;
wire ex_alu_src, ex_branch, ex_jump;
wire [1:0] ex_alu_op;

wire [31:0] ex_pc;
wire [31:0] ex_rs1_data, ex_rs2_data, ex_imm;

wire [4:0] ex_rs1, ex_rs2, ex_rd;

//======================================================
// ALU
//======================================================

wire [3:0] alu_ctrl;
wire [31:0] alu_result;

//======================================================
// MEM stage
//======================================================

wire mem_reg_write, mem_mem_read, mem_mem_write, mem_mem_to_reg;
wire [31:0] mem_alu_result, mem_rs2_data;
wire [4:0] mem_rd;

wire [31:0] mem_read_data;

//======================================================
// WB stage
//======================================================

wire wb_reg_write, wb_mem_to_reg;
wire [31:0] wb_mem_data, wb_alu_result;
wire [4:0] wb_rd;

wire [31:0] wb_data;

//======================================================
// Register file outputs
//======================================================

wire [31:0] rs1_data;
wire [31:0] rs2_data;

//======================================================
// Immediate
//======================================================

wire [31:0] imm;

//======================================================
// Branch
//======================================================

wire branch_taken;

//======================================================
// HAZARD (disabled for now safe run)
//======================================================

wire pc_stall = 0;
wire if_id_stall = 0;
wire id_ex_flush = 0;

//======================================================
// PC
//======================================================

pc PC (
    .clk(clk),
    .rst(rst),
    .pc_write(~pc_stall),
    .pc_next(pc_next),
    .pc_current(pc_current)
);

//======================================================
// Instruction memory
//======================================================

instruction_memory IMEM (
    .address(pc_current),
    .instruction(instruction)
);

//======================================================
// IF/ID
//======================================================

if_id IF_ID (
    .clk(clk),
    .rst(rst),
    .flush(id_ex_flush),
    .stall(if_id_stall),

    .pc_in(pc_current),
    .instr_in(instruction),

    .pc_out(if_id_pc),
    .instr_out(if_id_instr)
);

//======================================================
// Register file
//======================================================

register_file RF (
    .clk(clk),
    .rst(rst),

    .reg_write(wb_reg_write),
    .rs1(rs1),
    .rs2(rs2),
    .rd(wb_rd),
    .write_data(wb_data),

    .read_data1(rs1_data),
    .read_data2(rs2_data)
);

//======================================================
// Control unit
//======================================================

control_unit CU (
    .opcode(if_id_instr[6:0]),

    .reg_write(reg_write),
    .mem_read(mem_read),
    .mem_write(mem_write),
    .mem_to_reg(mem_to_reg),
    .alu_src(alu_src),
    .branch(branch),
    .jump(jump),
    .alu_op(alu_op)
);

//======================================================
// Immediate generator
//======================================================

immediate_generator IMM (
    .instruction(if_id_instr),
    .immediate(imm)
);

//======================================================
// ID/EX pipeline
//======================================================

id_ex ID_EX (
    .clk(clk),
    .rst(rst),

    .reg_write_in(reg_write),
    .mem_read_in(mem_read),
    .mem_write_in(mem_write),
    .mem_to_reg_in(mem_to_reg),
    .alu_src_in(alu_src),
    .branch_in(branch),
    .jump_in(jump),
    .alu_op_in(alu_op),

    .pc_in(if_id_pc),
    .rs1_data_in(rs1_data),
    .rs2_data_in(rs2_data),
    .imm_in(imm),

    .rs1_in(rs1),
    .rs2_in(rs2),
    .rd_in(rd),

    .reg_write_out(ex_reg_write),
    .mem_read_out(ex_mem_read),
    .mem_write_out(ex_mem_write),
    .mem_to_reg_out(ex_mem_to_reg),
    .alu_src_out(ex_alu_src),
    .branch_out(ex_branch),
    .jump_out(ex_jump),
    .alu_op_out(ex_alu_op),

    .pc_out(ex_pc),
    .rs1_data_out(ex_rs1_data),
    .rs2_data_out(ex_rs2_data),
    .imm_out(ex_imm),

    .rs1_out(ex_rs1),
    .rs2_out(ex_rs2),
    .rd_out(ex_rd)
);

//======================================================
// ALU control
//======================================================

alu_control ALUCTRL (
    .alu_op(ex_alu_op),
    .funct3(funct3),
    .funct7_5(funct7_5),
    .alu_control(alu_ctrl)
);

//======================================================
// Branch unit
//======================================================

branch_unit BU (
    .rs1(ex_rs1_data),
    .rs2(ex_rs2_data),
    .funct3(funct3),
    .branch_taken(branch_taken)
);

//======================================================
// PC next
//======================================================

assign pc_next =
    branch_taken ? (ex_pc + imm) :
    pc_plus_4;

//======================================================
// ALU
//======================================================

alu ALU (
    .a(ex_rs1_data),
    .b(ex_alu_src ? ex_imm : ex_rs2_data),
    .alu_ctrl(alu_ctrl),
    .result(alu_result),
    .zero()
);

//======================================================
// EX/MEM
//======================================================

ex_mem EX_MEM (
    .clk(clk),
    .rst(rst),

    .reg_write_in(ex_reg_write),
    .mem_read_in(ex_mem_read),
    .mem_write_in(ex_mem_write),
    .mem_to_reg_in(ex_mem_to_reg),

    .alu_result_in(alu_result),
    .rs2_data_in(ex_rs2_data),
    .rd_in(ex_rd),

    .reg_write_out(mem_reg_write),
    .mem_read_out(mem_mem_read),
    .mem_write_out(mem_mem_write),
    .mem_to_reg_out(mem_mem_to_reg),

    .alu_result_out(mem_alu_result),
    .rs2_data_out(mem_rs2_data),
    .rd_out(mem_rd)
);

//======================================================
// Data memory
//======================================================

data_memory DMEM (
    .clk(clk),
    .mem_write(mem_mem_write),
    .mem_read(mem_mem_read),
    .address(mem_alu_result),
    .write_data(mem_rs2_data),
    .read_data(mem_read_data)
);

//======================================================
// MEM/WB
//======================================================

mem_wb MEM_WB (
    .clk(clk),
    .rst(rst),

    .reg_write_in(mem_reg_write),
    .mem_to_reg_in(mem_mem_to_reg),

    .mem_data_in(mem_read_data),
    .alu_result_in(mem_alu_result),
    .rd_in(mem_rd),

    .reg_write_out(wb_reg_write),
    .mem_to_reg_out(wb_mem_to_reg),

    .mem_data_out(wb_mem_data),
    .alu_result_out(wb_alu_result),
    .rd_out(wb_rd)
);

//======================================================
// Writeback
//======================================================

assign wb_data =
    wb_mem_to_reg ? wb_mem_data : wb_alu_result;

//======================================================
// DEBUG OUTPUTS
//======================================================

assign debug_x1 = RF.registers[1];
assign debug_x2 = RF.registers[2];
assign debug_x3 = RF.registers[3];
assign debug_mem0 = DMEM.memory[0];

endmodule