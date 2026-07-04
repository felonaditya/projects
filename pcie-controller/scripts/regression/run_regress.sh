#!/bin/bash
echo "=== PCIe Controller Regression Started ==="

for i in {1..5}; do
  echo "Running test with seed $i"
  make sim SEED=$i TEST=base_test
done

echo "=== Regression Completed ==="