`include "pcie_params.svh"
import pcie_pkg::*;

module pcie_utils;
  // CRC32 function (LCRC)
  function automatic logic [31:0] calc_lcrc(input logic [31:0] data[], input logic [31:0] init = 32'hFFFFFFFF);
    // Placeholder - implement full CRC32 polynomial
    return 32'hDEADBEEF; // Replace with real implementation
  endfunction
endmodule