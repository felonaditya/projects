class pcie_random_seq extends pcie_base_seq;
  `uvm_object_utils(pcie_random_seq)

  rand bit inject_crc_error;

  virtual task body();
    repeat(20) begin
      `uvm_do_with(req, {inject_crc_error dist {0:=90, 1:=10};})
      if (inject_crc_error) 
        `uvm_info("ERROR_INJ", "CRC Error Injected!", UVM_LOW)
    end
  endtask
endclass