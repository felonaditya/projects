class pcie_driver extends uvm_driver #(uvm_sequence_item);
  `uvm_component_utils(pcie_driver)

  virtual pcie_pipe_if vif;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction

  virtual task run_phase(uvm_phase phase);
    forever begin
      seq_item_port.get_next_item(req);
      // Drive TLP on interface (simplified)
      @(posedge vif.clk);
      `uvm_info("DRIVER", "Driving TLP", UVM_MEDIUM)
      seq_item_port.item_done();
    end
  endtask
endclass