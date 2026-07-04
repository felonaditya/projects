# PCIe Controller Project Makefile
SIM = vcs
TEST = base_test
SEED = 1

all: sim

sim:
	$(SIM) -full64 -sverilog +define+UVM \
		+incdir+rtl/common +incdir+uvm_env \
		rtl/common/*.sv \
		rtl/tlp/*.sv \
		rtl/dll/*.sv \
		rtl/config/*.sv \
		rtl/dma/*.sv \
		rtl/top/*.sv \
		tb/*.sv tb/interfaces/*.sv \
		uvm_env/**/*.sv \
		-R +UVM_TESTNAME=$(TEST) +ntb_random_seed=$(SEED) \
		-l sim.log

wave:
	dve -full64 -vpd simv.vpd &

cov:
	urg -dir simv.vdb -report coverage_report -format both

clean:
	rm -rf simv* csrc* *.log *.vpd *.fsdb waves/* coverage_report

regress:
	./scripts/regression/run_regress.sh