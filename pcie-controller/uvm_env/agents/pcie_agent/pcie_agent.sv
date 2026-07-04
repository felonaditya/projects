class pcie_agent extends uvm_agent;
  `uvm_component_utils(pcie_agent)

  pcie_driver    driver;
  pcie_monitor   monitor;
  pcie_sequencer sequencer;

  virtual pcie_pipe_if pipe_vif;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction

  virtual function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    monitor = pcie_monitor::type_id::create("monitor", this);
    if (get_is_active() == UVM_ACTIVE) begin
      driver = pcie_driver::type_id::create("driver", this);
      sequencer = pcie_sequencer::type_id::create("sequencer", this);
    end
  endfunction

  virtual function void connect_phase(uvm_phase phase);
    if (get_is_active() == UVM_ACTIVE)
      driver.seq_item_port.connect(sequencer.seq_item_export);
  endfunction
endclass