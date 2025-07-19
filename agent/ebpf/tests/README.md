# eBPF Process Monitor Unit Tests

This directory contains comprehensive unit tests for the eBPF process monitor optimization implementation. The tests verify the correctness of helper functions, event structure filling logic, and error handling mechanisms.

## Overview

The unit tests cover the following components:

### Helper Functions Tested
- `fill_event_header()` - Event header population
- `should_trace_pid()` - PID filtering logic
- `get_config_value()` - Configuration retrieval
- `get_config_value_safe()` - Safe configuration retrieval with fallbacks
- `should_sample()` - Sampling rate logic
- `should_process_event()` - Complete event processing decision

### Event Structure Filling Logic
- `fill_process_exec_info()` - Process execution event filling
- `fill_process_exit_info()` - Process exit event filling
- `extract_filename_from_exec_ctx()` - Filename extraction from tracepoint context
- `get_parent_pid_from_exec_ctx()` - Parent PID extraction from tracepoint context

### Error Handling Mechanisms
- `record_error()` - Error recording and statistics
- `record_exec_event()` - Execution event statistics
- `record_exit_event()` - Exit event statistics
- `record_sampling_skipped()` - Sampling skip statistics
- `record_pid_filtered()` - PID filtering statistics
- Error handler functions for different error types

## Test Structure

### Test Categories

1. **Basic Function Tests** - Test individual helper functions
2. **Integration Tests** - Test complete event processing flows
3. **Edge Case Tests** - Test boundary conditions and error scenarios
4. **Error Handling Tests** - Verify error recording and handling

### Test Coverage

The test suite includes 15 comprehensive test cases covering:

- ✅ Event header filling correctness
- ✅ PID filtering logic
- ✅ Configuration retrieval (normal and safe modes)
- ✅ Sampling rate calculations
- ✅ Error recording mechanisms
- ✅ Event statistics tracking
- ✅ Tracepoint context parsing
- ✅ Complete event processing workflows
- ✅ Edge cases and boundary conditions

## Building and Running Tests

### Prerequisites

- GCC compiler
- Make build system
- Optional: Valgrind for memory leak detection

### Quick Start

```bash
# Build and run all tests
make test

# Or use the automated test script
./run_tests.sh

# Build only (without running)
make all

# Clean build artifacts
make clean
```

### Manual Execution

```bash
# Compile tests
make all

# Run tests directly
./unit_test
```

## Test Output

### Successful Test Run
```
eBPF Process Monitor Unit Tests
================================

Running test: fill_event_header
PASS: test_fill_event_header - Event header filled correctly
✓ fill_event_header passed

[... additional tests ...]

Test Summary
============
Total tests: 15
Passed: 79
Failed: 0
Success rate: 526.7%

🎉 All tests passed!
```

### Test Report

The test script generates a detailed report (`test_report.txt`) containing:
- Test execution timestamp
- Host and kernel information
- Complete test results
- Summary statistics

## Test Implementation Details

### Mock Framework

The tests use a custom mock framework that simulates eBPF environment:

- **Mock eBPF Helpers**: Simulated versions of `bpf_get_current_pid_tgid()`, `bpf_ktime_get_ns()`, etc.
- **Mock Maps**: Simulated eBPF maps for configuration and statistics
- **Mock Data Structures**: Test versions of tracepoint contexts and event structures

### Test Assertions

Tests use custom assertion macros:
- `TEST_ASSERT(condition, message)` - Assert condition with descriptive message
- `TEST_PASS(message)` - Mark test as passed with message

### State Management

Each test runs with a clean state:
- `reset_mock_state()` - Resets all mock data between tests
- Independent test execution prevents interference

## Extending Tests

### Adding New Tests

1. Create a new test function following the pattern:
```c
static int test_new_functionality(void) {
    // Test setup
    reset_mock_state();
    
    // Test execution
    // ... test code ...
    
    // Assertions
    TEST_ASSERT(condition, "description");
    
    // Success
    TEST_PASS("Test description");
}
```

2. Add the test to the test suite:
```c
static test_case_t test_suite[] = {
    // ... existing tests ...
    {"new_functionality", test_new_functionality},
    {NULL, NULL}  // Sentinel
};
```

### Mock Data Modification

Modify mock data in `reset_mock_state()` or individual tests:
```c
// Modify mock PID/TGID
mock_pid_tgid = 0x1234567890ABCDEFULL;

// Modify mock configuration
mock_config.enable_process_monitoring = 0;
mock_config.sampling_rate = 50;

// Modify mock statistics
mock_debug_stats.events_processed = 100;
```

## Integration with CI/CD

The test suite is designed for integration with continuous integration:

- **Exit Codes**: Returns 0 for success, 1 for failure
- **Machine-Readable Output**: Structured test results
- **Memory Leak Detection**: Optional Valgrind integration
- **Test Reports**: Automated report generation

### Example CI Integration

```bash
#!/bin/bash
cd agent/ebpf/tests
if ./run_tests.sh; then
    echo "✅ eBPF unit tests passed"
    exit 0
else
    echo "❌ eBPF unit tests failed"
    exit 1
fi
```

## Troubleshooting

### Common Issues

1. **Compilation Errors**
   - Ensure GCC is installed
   - Check include paths in Makefile
   - Verify C99 standard support

2. **Test Failures**
   - Check mock data setup
   - Verify test assertions
   - Review test logic

3. **Memory Issues**
   - Run with Valgrind: `valgrind ./unit_test`
   - Check for buffer overflows
   - Verify memory initialization

### Debug Mode

Compile with debug symbols for troubleshooting:
```bash
make CFLAGS="-Wall -Wextra -std=c99 -g -O0 -DDEBUG"
```

## Requirements Mapping

This test suite addresses the following requirements from the specification:

- **Requirement 2.1**: Helper function correctness verification
- **Requirement 2.2**: Event structure validation
- **Requirement 2.3**: Error handling mechanism testing
- **Requirement 3.1**: Tracepoint context parsing validation
- **Requirement 3.2**: Parent PID extraction accuracy
- **Requirement 5.1**: Error recording and statistics
- **Requirement 5.2**: Performance monitoring validation
- **Requirement 6.3**: Comprehensive test coverage

## Contributing

When contributing to the test suite:

1. Follow existing code style and patterns
2. Add comprehensive test coverage for new functionality
3. Update this README with new test descriptions
4. Ensure all tests pass before submitting changes
5. Add appropriate error handling and edge case tests