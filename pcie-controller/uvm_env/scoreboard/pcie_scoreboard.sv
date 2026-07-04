class pcie_scoreboard extends uvm_scoreboard;
  `uvm_component_utils(pcie_scoreboard)

  uvm_analysis_port #(uvm_sequence_item) exp_port;
  uvm_analysis_port #(uvm_sequence_item) act_port;

  function new(string name, uvm_component parent);
    super.new(name, parent);
    exp_port = new("exp_port", this);
    act_port = new("act_port", this);
  endfunction

  virtual function void write_exp(uvm_sequence_item item);
    `uvm_info("SCB", "Expected TLP received", UVM_HIGH)
  endfunction

  virtual function void write_act(uvm_sequence_item item);
    `uvm_info("SCB", "Actual TLP received", UVM_HIGH)
    // TODO: Real comparison later
  endfunction

  virtual function void connect_phase(uvm_phase phase);
    // Connect from monitors later
  endfunction
endclass