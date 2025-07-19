# eBPF Process Monitor Performance Test Summary

**Test Date:** 2025-07-19 22:33:58
**Host:** ccnochch
**Kernel:** 5.15.167.4-microsoft-standard-WSL2+
**Architecture:** x86_64

## Test Results Overview

- **Tests Passed:** 6/7
- **Success Rate:** 85.7%
- **Performance Improvement:** -8.32%
- **Stability Score:** 0.00

## Key Findings

⚠ MIXED RESULTS: Both implementations have trade-offs
   - Tracepoint better in 0 out of 4 categories
   - Consider workload-specific testing

=== Detailed Metrics Summary ===
Performance Improvement: -8.32%
Stability Score: 0.00
Memory Efficiency: GOOD vs GOOD
CPU Efficiency: GOOD vs GOOD

## Detailed Metrics

### Kprobe Implementation
  Average latency: 433.10 ns
  Events per second: 2308936
  Memory usage: 1096 KB
  CPU usage: 0.00%
  Allocation failures: 0
  Processing errors: 0

### Tracepoint Implementation
  Average latency: 469.14 ns
  Events per second: 2131573
  Memory usage: 1332 KB
  CPU usage: 5.23%
  Allocation failures: 0
  Processing errors: 0

## Test Categories

### 1. Basic Performance Comparison
✗ Performance comparison: FAILED

### 2. High Load Stability Tests
✓ Kprobe stability test: PASSED
✓ Tracepoint stability test: PASSED

=== Phase 3: Memory Usage Tests ===

### 3. Memory Usage Tests
✓ Kprobe memory test: PASSED
✓ Tracepoint memory test: PASSED

=== Phase 4: CPU Usage Tests ===

### 4. CPU Usage Tests
✓ Kprobe CPU test: PASSED
✓ Tracepoint CPU test: PASSED

=== Final Test Summary ===

## Recommendations

⚠ MIXED RESULTS: Both implementations have trade-offs

---

*For complete test output, see: performance_test_report.txt*
