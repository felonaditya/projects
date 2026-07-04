# PCIe Gen5/Gen6 Controller - Advanced Project

**Status**: Basic framework complete (TL + DLL + UVM)

**Next Steps for Full Beast Mode**:
- Implement full PIPE + LTSSM
- Add comprehensive SVA assertions
- Expand Scoreboard with real predictor
- Add error injection framework
- Achieve >95% coverage

**Run**:
- `make sim` → Basic UVM test
- `make regress` → Multiple seeds
- `make cov` → Coverage report