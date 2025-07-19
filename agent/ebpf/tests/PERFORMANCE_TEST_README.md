# eBPF Process Monitor Performance Test Suite

This directory contains comprehensive performance tests that compare kprobe-based and tracepoint-based eBPF process monitoring implementations. The tests evaluate performance, stability, memory usage, and CPU overhead under various conditions.

## Overview

The performance test suite addresses the following requirements:
- **Requirement 1.1**: Performance comparison between kprobe and tracepoint implementations
- **Requirement 2.1**: Helper function performance validation
- **Requirement 5.1**: Error handling and statistics performance impact

## Test Categories

### 1. Basic Performance Comparison
- **Latency Measurement**: Average, minimum, and maximum event processing latency
- **Throughput Testing**: Events processed per second under normal load
- **Resource Usage**: Memory and CPU consumption during operation
- **Error Rate Analysis**: Allocation failures and processing errors

### 2. High Load Stability Tests
- **Stress Testing**: Performance under high process creation/termination load
- **Error Rate Monitoring**: Error increase under stress conditions
- **Stability Rating**: Classification of implementation stability (EXCELLENT/GOOD/FAIR/POOR)

### 3. Memory Usage Tests
- **Memory Growth Analysis**: Memory consumption over multiple test iterations
- **Peak Memory Tracking**: Maximum memory usage during stress tests
- **Memory Efficiency Rating**: Classification of memory efficiency
- **Leak Detection**: Memory growth patterns over time

### 4. CPU Usage Tests
- **CPU Overhead Measurement**: Average CPU usage during event processing
- **Processing Rate Analysis**: Events processed per second per CPU usage
- **CPU Efficiency Rating**: Classification of CPU efficiency
- **Scalability Assessment**: Performance under CPU-intensive workloads

## Test Implementation

### Mock Framework
The tests use a comprehensive mock framework that simulates the eBPF environment:

- **Mock eBPF Helpers**: Simulated versions of all eBPF helper functions
- **Mock Maps**: Simulated configuration and statistics maps
- **Mock Ring Buffer**: Simulated event ring buffer operations
- **Mock Tracepoint Contexts**: Test versions of kernel tracepoint structures

### Performance Metrics
The following metrics are collected and analyzed:

```c
struct performance_metrics {
    double avg_latency_ns;          // Average event processing latency
    double max_latency_ns;          // Maximum latency observed
    double min_latency_ns;          // Minimum latency observed
    uint64_t total_events;          // Total events processed
    uint64_t events_per_second;     // Throughput measurement
    uint64_t memory_usage_kb;       // Average memory usage
    double cpu_usage_percent;       // Average CPU usage
    uint64_t allocation_failures;   // Ring buffer allocation failures
    uint64_t processing_errors;     // Processing errors encountered
};
```

### Comparison Analysis
The test suite provides detailed comparison between implementations:

```c
struct comparison_results {
    struct performance_metrics kprobe_metrics;
    struct performance_metrics tracepoint_metrics;
    double performance_improvement_percent;
    double stability_score;
    int reliability_rating;         // 1-10 scale
};
```

## Building and Running Tests

### Prerequisites
- GCC compiler with C99 support
- pthread library
- Make build system
- Linux system with /proc filesystem access

### Quick Start

```bash
# Build and run performance tests
make performance-test

# Or use the automated test script
./run_performance_tests.sh

# Build only (without running)
make performance_test

# Clean build artifacts
make clean
```

### Advanced Usage

```bash
# Run with verbose output
./run_performance_tests.sh --verbose

# Run with minimal output
./run_performance_tests.sh --quiet

# Run specific test phases manually
./performance_test
```

## Test Configuration

### Performance Test Parameters
```c
#define MAX_TEST_DURATION_SEC 60        // Maximum test duration
#define HIGH_LOAD_PROCESSES 1000        // Processes for stress testing
#define STRESS_TEST_ITERATIONS 10000    // Iterations for stress tests
#define MEMORY_SAMPLE_INTERVAL_MS 100   // Memory sampling interval
#define CPU_SAMPLE_INTERVAL_MS 50       // CPU sampling interval
```

### Mock Configuration
```c
struct config mock_config = {
    .enable_process_monitoring = 1,     // Enable process monitoring
    .enable_network_monitoring = 0,     // Disable other monitors
    .enable_file_monitoring = 0,
    .enable_syscall_monitoring = 0,
    .sampling_rate = 100                // 100% sampling rate
};
```

## Test Output and Reports

### Console Output
The test suite provides real-time progress updates and results:

```
eBPF Process Monitor Performance Test Suite
==========================================

=== Phase 1: Basic Performance Comparison ===
Running kprobe performance test...
✓ kprobe test completed
  Average latency: 457.88 ns
  Events per second: 2183988
  Memory usage: 1100 KB
  CPU usage: 0.00%

=== Performance Optimization Recommendations ===
🎯 STRONG RECOMMENDATION: Use tracepoint-based implementation
   - Better performance in 3 out of 4 categories
   - Performance improvement: 15.2%
   - Reliability rating: 8/10
```

### Generated Reports
The test script generates several report files:

1. **performance_test_report.txt**: Complete test output
2. **performance_summary.md**: Markdown summary with key findings
3. **performance_test.log**: Detailed execution log

### Report Structure
```markdown
# eBPF Process Monitor Performance Test Summary

**Test Date:** 2024-01-15 14:30:00
**Host:** test-server
**Kernel:** 5.15.0-generic
**Architecture:** x86_64

## Test Results Overview
- **Tests Passed:** 6/7
- **Success Rate:** 85.7%
- **Performance Improvement:** 15.2%
- **Stability Score:** 8.5

## Key Findings
- Tracepoint implementation shows significant performance improvement
- Both implementations demonstrate excellent stability
- Memory efficiency is comparable between implementations
- CPU overhead is lower for tracepoint implementation

## Recommendations
✓ Strongly recommend tracepoint implementation
```

## Performance Analysis

### Kprobe Implementation Characteristics
- **Advantages**: Lower memory overhead, simpler implementation
- **Disadvantages**: Higher CPU overhead, less accurate parent PID information
- **Use Cases**: Older kernels, simple monitoring requirements

### Tracepoint Implementation Characteristics
- **Advantages**: Better performance, accurate context information, enhanced error handling
- **Disadvantages**: Requires newer kernel versions, more complex implementation
- **Use Cases**: Modern kernels, comprehensive monitoring requirements

### Decision Matrix
| Criteria | Kprobe | Tracepoint | Winner |
|----------|--------|------------|---------|
| Performance | Good | Excellent | Tracepoint |
| Stability | Good | Excellent | Tracepoint |
| Memory Usage | Excellent | Good | Kprobe |
| CPU Efficiency | Good | Excellent | Tracepoint |
| Accuracy | Fair | Excellent | Tracepoint |
| Compatibility | Excellent | Good | Kprobe |

## Troubleshooting

### Common Issues

1. **Compilation Errors**
   ```bash
   # Ensure all dependencies are installed
   sudo apt-get install build-essential pthread-dev
   
   # Check GCC version
   gcc --version
   ```

2. **Permission Issues**
   ```bash
   # Ensure execute permissions
   chmod +x run_performance_tests.sh
   chmod +x performance_test
   ```

3. **Memory Issues**
   ```bash
   # Run with memory debugging
   valgrind --leak-check=full ./performance_test
   ```

### Performance Tuning

1. **Test Duration**: Adjust `MAX_TEST_DURATION_SEC` for longer tests
2. **Stress Load**: Modify `HIGH_LOAD_PROCESSES` for different stress levels
3. **Sampling Rate**: Change `STRESS_TEST_ITERATIONS` for different test intensities

## Integration with CI/CD

### Example GitHub Actions
```yaml
name: eBPF Performance Tests
on: [push, pull_request]
jobs:
  performance-test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Install dependencies
      run: sudo apt-get install build-essential
    - name: Run performance tests
      run: |
        cd agent/ebpf/tests
        ./run_performance_tests.sh
    - name: Upload results
      uses: actions/upload-artifact@v2
      with:
        name: performance-results
        path: agent/ebpf/tests/performance_*.txt
```

### Example Jenkins Pipeline
```groovy
pipeline {
    agent any
    stages {
        stage('Performance Test') {
            steps {
                dir('agent/ebpf/tests') {
                    sh './run_performance_tests.sh'
                    archiveArtifacts artifacts: 'performance_*.txt'
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.',
                        reportFiles: 'performance_summary.md',
                        reportName: 'Performance Test Report'
                    ])
                }
            }
        }
    }
}
```

## Contributing

When contributing to the performance test suite:

1. **Follow Existing Patterns**: Use the established mock framework and test structure
2. **Add Comprehensive Coverage**: Include edge cases and error conditions
3. **Update Documentation**: Update this README with new test descriptions
4. **Validate Results**: Ensure tests produce consistent and meaningful results
5. **Performance Impact**: Consider the performance impact of test additions

### Adding New Tests

1. **Create Test Function**:
```c
static int test_new_performance_aspect(void) {
    // Test setup
    reset_mock_state();
    
    // Performance measurement
    uint64_t start_time = get_timestamp_ns();
    // ... test execution ...
    uint64_t end_time = get_timestamp_ns();
    
    // Analysis and reporting
    double latency = (end_time - start_time) / iterations;
    printf("New test latency: %.2f ns\n", latency);
    
    return latency < threshold ? 1 : 0;
}
```

2. **Integrate with Main Test Suite**:
```c
// Add to main() function
int new_test_result = test_new_performance_aspect();
test_total++;
if (new_test_result) {
    test_passed++;
    printf("✓ New performance test: PASSED\n");
} else {
    printf("✗ New performance test: FAILED\n");
}
```

## Requirements Mapping

This performance test suite addresses the following specification requirements:

- **Requirement 1.1**: Performance comparison between implementations ✅
- **Requirement 2.1**: Helper function performance validation ✅
- **Requirement 5.1**: Error handling performance impact ✅
- **Requirement 6.3**: Comprehensive performance testing ✅

## Future Enhancements

1. **Real eBPF Integration**: Test with actual eBPF programs on live systems
2. **Multi-Architecture Support**: Test on ARM64, RISC-V architectures
3. **Kernel Version Matrix**: Test across different kernel versions
4. **Network Performance**: Add network event performance testing
5. **File System Performance**: Add file system event performance testing
6. **Automated Regression Detection**: Detect performance regressions automatically
7. **Benchmark Database**: Store and compare results over time
8. **Visual Reports**: Generate charts and graphs for performance trends