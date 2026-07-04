class pcie_coverage extends uvm_subscriber #(uvm_sequence_item);
  `uvm_component_utils(pcie_coverage)

  covergroup tlp_cg;
    coverpoint tlp_type {
      bins mrd = {MRD32, MRD64};
      bins mwr = {MWR32, MWR64};
      bins cpl = {CPL, CPLD};
    }
    coverpoint length { bins short = {[1:32]}; bins long = {[33:512]}; }
  endgroup

  function new(string name, uvm_component parent);
    super.new(name, parent);
    tlp_cg = new();
  endfunction

  virtual function void write(uvm_sequence_item t);
    // Sample coverage
    tlp_cg.sample();
  endfunction
endclass