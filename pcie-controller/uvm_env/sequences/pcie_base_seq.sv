class pcie_base_seq extends uvm_sequence #(uvm_sequence_item);
  `uvm_object_utils(pcie_base_seq)

  function new(string name = "pcie_base_seq");
    super.new(name);
  endfunction

  virtual task body();
    `uvm_info("SEQ", "Base sequence running", UVM_LOW)
    repeat(10) begin
      #50;
    end
  endtask
endclass