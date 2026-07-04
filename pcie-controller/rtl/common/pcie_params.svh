```systemverilog
`ifndef PCIE_PARAMS_SVH
`define PCIE_PARAMS_SVH

// Global Parameters
parameter int PCIE_GEN = 5;           // 3,4,5,6
parameter int NUM_LANES = 16;
parameter int DATA_WIDTH = 512;       // 64/128/256/512/1024
parameter int MAX_PAYLOAD_SIZE = 512; // bytes
parameter int MAX_READ_REQ_SIZE = 512;

parameter int VC_COUNT = 2;           // Virtual Channels
parameter int REPLAY_BUFFER_DEPTH = 64;

`endif