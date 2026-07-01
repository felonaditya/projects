# sim/run.do

vlib work
vlog ../rtl/*.v
vlog ../tb/*.v
vsim cpu_tb
add wave -r /*
run -all