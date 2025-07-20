# eBPF Process Monitor Production Validation

This directory contains comprehensive production validation tests for the eBPF process monitor system.

## Quick Start

### Basic Validation (Recommended)
```bash
# Run quick validation tests
./scripts/run-production-validation.sh --quick

# Or run C tests directly
cd agent/ebpf/tests
make production-validation-test
```

### Comprehensive Validation
```bash
# Run all validation tests (requires root for Go tests)
sudo ./scripts/run-production-validation.sh

# Run long-term stability test (2+ hours)
sudo ./scripts/run-production-validation.sh --long-term
```

## Test Components

### 1. C-based eBPF Validation (`production_validation_test.c`)
- **Purpose**: Validates eBPF kernel-level functionality
- **Features**: Long-term stability, workload testing, monitoring, logging
- **Execution**: `./production_validation_test [--quick|--long-term]`

### 2. Go-based Integration Tests (`production_validation_test.go`)
- **Purpose**: Validates user-space integration and monitoring
- **Features**: Health monitoring, debug statistics, performance benchmarks
- **Execution**: `go test -v ./internal/collector/ -run TestProductionValidation*`

### 3. Automated Test Runner (`run-production-validation.sh`)
- **Purpose**: Orchestrates all validation tests
- **Features**: Prerequisites checking, result aggregation, reporting
- **Execution**: `./scripts/run-production-validation.sh [options]`

## Test Options

### Command Line Options
- `--quick`: Run quick validation tests only (~2 minutes)
- `--long-term`: Run extended stability tests (2+ hours)
- `--skip-go`: Skip Go integration tests
- `--help`: Show help information

### Environment Variables
- `LONG_TERM_DURATION`: Override long-term test duration (e.g., "1h30m")

## Requirements

### System Requirements
- Linux kernel 5.15+ with eBPF support
- GCC compiler and Make build system
- Go 1.19+ compiler
- Root privileges (for full eBPF functionality)

### Build Dependencies
```bash
# Ubuntu/Debian
sudo apt-get install build-essential golang-go

# RHEL/CentOS
sudo yum install gcc make golang
```

## Test Results

### Success Criteria
- **Memory Usage**: < 500MB peak (excellent), < 1GB (acceptable)
- **CPU Usage**: < 20% peak (excellent), < 50% (acceptable)
- **Error Rate**: < 5% overall
- **Health Checks**: > 90% pass rate
- **Event Processing**: Consistent collection rates

### Output Interpretation
```
✓ PASS: Test completed successfully
✗ FAIL: Test failed, review logs for details
⚠ WARN: Test passed with warnings
```

## Integration with CI/CD

### GitHub Actions Example
```yaml
name: Production Validation
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Production Validation
        run: ./scripts/run-production-validation.sh --quick
```

### Jenkins Pipeline Example
```groovy
pipeline {
    agent any
    stages {
        stage('Production Validation') {
            steps {
                sh './scripts/run-production-validation.sh --quick'
            }
        }
    }
}
```

## Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Solution: Run with root privileges
sudo ./scripts/run-production-validation.sh --quick
```

#### Kernel Compatibility
```bash
# Check eBPF support
ls /sys/kernel/debug/tracing/events/sched/
```

#### Build Failures
```bash
# Install dependencies
sudo apt-get install build-essential

# Clean and rebuild
make clean && make all
```

### Debug Information
```bash
# Enable verbose output
./production_validation_test --quick 2>&1 | tee debug.log

# Check system resources
free -h
top -p $(pgrep production_validation_test)
```

## Performance Monitoring

### Real-time Monitoring
```bash
# Monitor during test execution
watch -n 1 'ps aux | grep production_validation_test'
watch -n 1 'free -h'
```

### Log Analysis
```bash
# Analyze test logs
grep -E "(PASS|FAIL|ERROR)" test_output.log
grep "Memory usage" test_output.log
```

## Production Deployment

### Pre-deployment Checklist
1. ✅ All validation tests pass
2. ✅ Performance metrics within acceptable ranges
3. ✅ No memory leaks detected
4. ✅ Error rates below thresholds
5. ✅ Monitoring and alerting configured

### Deployment Steps
```bash
# 1. Run comprehensive validation
sudo ./scripts/run-production-validation.sh

# 2. Review results and metrics
cat agent/ebpf/PRODUCTION_VALIDATION_SUMMARY.md

# 3. Deploy with monitoring
# (Follow your organization's deployment procedures)
```

## Support

### Getting Help
- Review test logs for specific error messages
- Check system requirements and dependencies
- Verify kernel eBPF support and permissions
- Consult the troubleshooting section above

### Reporting Issues
When reporting issues, include:
- Test command executed
- Complete error output
- System information (`uname -a`)
- Kernel version and eBPF support status

## Contributing

### Adding New Tests
1. Add test functions to appropriate test files
2. Update Makefile build targets
3. Update documentation and help text
4. Test with both quick and long-term modes

### Test Guidelines
- Follow existing code style and patterns
- Include comprehensive error handling
- Add appropriate logging and metrics
- Ensure tests are deterministic and repeatable