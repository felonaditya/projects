class pcie_monitor extends uvm_monitor;
  `uvm_component_utils(pcie_monitor)

  virtual pcie_pipe_if vif;
  uvm_analysis_port #(uvm_sequence_item) ap;

  function new(string name, uvm_component parent);
    super.new(name, parent);
    ap = new("ap", this);
  endfunction

  virtual task run_phase(uvm_phase phase);
    forever begin
      @(posedge vif.clk);
      if (vif.tx_valid) begin
        `uvm_info("MONITOR", "Detected TLP transmission", UVM_HIGH)
      end
    end
  endtask
endclass