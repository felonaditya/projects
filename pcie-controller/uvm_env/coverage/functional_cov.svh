covergroup pcie_functional_cg;
  option.per_instance = 1;
  tlp_types: coverpoint tlp_type;
  vc_usage: coverpoint vc_id;
  credit_levels: coverpoint credit_level bins {low, medium, high};
  error_types: coverpoint error_type;
endgroup