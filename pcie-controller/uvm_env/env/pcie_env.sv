class pcie_env extends uvm_env;
  `uvm_component_utils(pcie_env)

  pcie_agent      pcie_agt;
  pcie_scoreboard scb;
  pcie_coverage   cov;
  pcie_env_cfg    cfg;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction

  virtual function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    cfg = pcie_env_cfg::type_id::create("cfg", this);
    pcie_agt = pcie_agent::type_id::create("pcie_agt", this);
    scb = pcie_scoreboard::type_id::create("scb", this);
    cov = pcie_coverage::type_id::create("cov", this);
  endfunction
endclass