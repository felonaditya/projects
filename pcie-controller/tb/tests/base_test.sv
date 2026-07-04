class base_test extends uvm_test;
  `uvm_component_utils(base_test)

  pcie_env env;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction

  virtual function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    env = pcie_env::type_id::create("env", this);
  endfunction

  virtual task run_phase(uvm_phase phase);
    pcie_random_seq seq;
    phase.raise_objection(this);
    
    `uvm_info("TEST", "=== PCIe UVM Test Started ===", UVM_LOW)
    
    seq = pcie_random_seq::type_id::create("seq");
    seq.start(env.pcie_agt.sequencer);
    
    #2000;
    `uvm_info("TEST", "=== PCIe UVM Test Finished ===", UVM_LOW)
    phase.drop_objection(this);
  endtask
endclass