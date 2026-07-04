class regress_seq extends pcie_base_seq;
  `uvm_object_utils(regress_seq)

  virtual task body();
    repeat(50) begin
      `uvm_do(req)
    end
  endtask
endclass