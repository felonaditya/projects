class pcie_env_cfg extends uvm_object;
  `uvm_object_utils(pcie_env_cfg)

  rand bit enable_scoreboard;
  rand bit enable_coverage;
  rand int num_transactions;

  constraint default_c {
    num_transactions inside {[100:1000]};
    enable_scoreboard == 1;
    enable_coverage == 1;
  }

  function new(string name = "pcie_env_cfg");
    super.new(name);
  endfunction
endclass