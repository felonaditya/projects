# PCIe Gen5/Gen6 Controller - Advanced Project

Advanced PCIe Gen5/Gen6 Endpoint Controller (Transaction Layer + Data Link Layer) designed and verified in SystemVerilog with a complete UVM testbench, including TLP handling, credit flow control, replay buffer, LCRC, and constrained-random coverage-driven verification.

**Status**: Basic framework complete (TL + DLL + UVM)

**Run**:
- `make sim` → Basic UVM test
- `make regress` → Multiple seeds
- `make cov` → Coverage report
