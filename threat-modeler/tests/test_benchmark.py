"""Regression gate: run the precision benchmark and require all labelled
assertions to hold. Keeps the evidenced-tier accuracy from silently drifting.
See benchmark/run_benchmark.py and issue #32.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from benchmark.run_benchmark import main as run_benchmark  # noqa: E402

rc = run_benchmark()
assert rc == 0, "precision benchmark: one or more labelled assertions failed"
print("\nbenchmark gate: PASS")
