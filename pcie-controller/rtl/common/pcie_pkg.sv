`ifndef PCIE_PKG_SV
`define PCIE_PKG_SV

package pcie_pkg;

  // TLP Types
  typedef enum logic [4:0] {
    MRD32 = 5'b00000, MRD64 = 5'b01000,
    MWR32 = 5'b00001, MWR64 = 5'b01001,
    CPL  = 5'b01010,  CPLD = 5'b01011,
    MSG  = 5'b10000,  // etc.
    // Add more as needed
    UNKNOWN = 5'b11111
  } tlp_type_t;

  // TLP Header Structure (simplified 4DW)
  typedef struct packed {
    logic [2:0]  fmt;
    logic [4:0]  type_;
    logic [2:0]  tc;
    logic        td;
    logic        ep;
    logic [1:0]  attr;
    logic [9:0]  length;
    logic [15:0] requester_id;
    logic [7:0]  tag;
    logic [15:0] completer_id;
    // ... extend for full spec
  } tlp_header_t;

  // DLLP Types
  typedef enum logic [3:0] {
    ACK  = 4'b0000,
    NAK  = 4'b0001,
    FC   = 4'b1100,
    // ...
    DLLP_PM = 4'b1000
  } dllp_type_t;

  // Credit types
  typedef enum logic [1:0] {
    CREDIT_PH, CREDIT_PD, CREDIT_NPH, CREDIT_NPD
  } credit_type_t;

  // Add more structs, functions, etc.

endpackage : pcie_pkg