#!/bin/bash

echo "Fillisr_regs.sv << 'EOT'
module csr_regs (input clk, rst_n);
  // Configuration registers
endmodule
EOT

# UVM Placeholders
touch uvm_env/sequences/virtual_seq.sv
cat > uvm_env/sequences/virtual_seq.sv << 'EOT'
class virtual_seq extends uvm_sequence;
  `uvm_object_utils(virtual_seq)
endclass
EOT

touch uvm_env/scoreboard/predictor.sv
cat > uvm_env/scoreboard/predictor.sv << 'EOT'
class predictor extends uvm_component;
  `uvm_component_utils(predictor)
endclass
EOT

# Scripts
touch scripts/utils/parse_log.py
cat > scripts/utils/parse_log.py << 'EOT'
print("Log parser placeholder")
EOT

echo "All placeholder files created successfully!"
