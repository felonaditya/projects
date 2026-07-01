# sim/Makefile

TOP = cpu_tb
SRC = ../rtl/*.v ../tb/*.v
OUT = cpu_sim

run:
	iverilog -I ../rtl -o $(OUT) $(SRC)
	vvp $(OUT)
	gtkwave cpu_wave.vcd

clean:
	rm -f cpu_sim cpu_wave.vcd