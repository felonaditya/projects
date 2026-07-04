`ifndef PCIE_ASSERTIONS_SVH
`define PCIE_ASSERTIONS_SVH

// TLP Assertions
assert property (@(posedge clk) disable iff (!rst_n)
  tlp_valid |-> ##[1:8] tx_valid)
else $error("TLP transmission timeout");

assert property (@(posedge clk) disable iff (!rst_n)
  tx_valid |-> $onehot0(tx_data[31:0])) // example check
else $error("Invalid TLP header");

// Credit Assertions
assert property (@(posedge clk) disable iff (!rst_n)
  credits_available[0] >= 0)
else $error("Credit underflow");

// Link Assertions
assert property (@(posedge clk) disable iff (!rst_n)
  link_up |-> ##[1:4] dll_tlp_valid)
else $error("DLL not active after link up");

`endif