#!/bin/bash

# Production Validation Test Runner
# This script runs comprehensive production validation tests for the eBPF process monitor

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

error() {
    echo -e "${RED}✗${NC} $1"
}

# Parse command line arguments
QUICK_MODE=false
LONG_TERM_MODE=false
SKIP_GO_TESTS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            QUICK_MODE=true
            shift
            ;;
        --long-term)
            LONG_TERM_MODE=true
            shift
            ;;
        --skip-go)
            SKIP_GO_TESTS=true
            shift
            ;;
        --help)
            echo "Production Validation Test Runner"
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --quick      Run quick validation tests only"
            echo "  --long-term  Run long-term stability tests"
            echo "  --skip-go    Skip Go integration tests"
            echo "  --help       Show this help message"
            echo ""
            echo "Default: Run comprehensive validation (C + Go tests)"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check prerequisites
log "Checking prerequisites..."

if ! command -v gcc &> /dev/null; then
    error "GCC compiler not found. Please install gcc."
    exit 1
fi

if ! command -v make &> /dev/null; then
    error "Make build system not found. Please install make."
    exit 1
fi

if ! command -v go &> /dev/null; then
    error "Go compiler not found. Please install Go."
    exit 1
fi

# Check if running as root for eBPF tests
if [[ $EUID -ne 0 ]]; then
    warning "Not running as root. Some eBPF integration tests may be skipped."
fi

success "Prerequisites check passed"

# Initialize results tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run test and track results
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    log "Running $test_name..."
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if eval "$test_command"; then
        success "$test_name passed"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        error "$test_name failed"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Main validation execution
log "Starting production environment validation..."

# 1. C-based eBPF validation tests
log "=== C-based eBPF Validation Tests ==="

cd agent/ebpf/tests

# Build tests
log "Building C validation tests..."
if ! make clean > /dev/null 2>&1; then
    warning "Clean failed, continuing..."
fi

if ! make production-validation-test > /dev/null 2>&1; then
    error "Failed to build C validation tests"
    exit 1
fi

success "C validation tests built successfully"

# Run C tests
if [[ "$LONG_TERM_MODE" == "true" ]]; then
    run_test "C Long-term Stability Test" "./production_validation_test --long-term"
elif [[ "$QUICK_MODE" == "true" ]]; then
    run_test "C Quick Validation Test" "./production_validation_test --quick"
else
    # Run comprehensive C tests (excluding long-term by default)
    run_test "C Comprehensive Validation Test" "./production_validation_test --quick"
fi

cd ../../..

# 2. Go-based integration tests
if [[ "$SKIP_GO_TESTS" != "true" ]]; then
    log "=== Go-based Integration Tests ==="
    
    cd agent
    
    # Run Go tests (only if running as root, since eBPF requires privileges)
    if [[ $EUID -eq 0 ]]; then
        if [[ "$LONG_TERM_MODE" == "true" ]]; then
            run_test "Go Long-term Stability Test" "go test -v ./internal/collector/ -run TestProductionValidationLongTerm -timeout 2h"
        elif [[ "$QUICK_MODE" == "true" ]]; then
            run_test "Go Quick Validation Test" "go test -v ./internal/collector/ -run TestProductionValidationQuick -timeout 10m"
        else
            # Run comprehensive Go tests
            run_test "Go Quick Validation Test" "go test -v ./internal/collector/ -run TestProductionValidationQuick -timeout 10m"
            
            # Run benchmarks
            run_test "Go Performance Benchmarks" "go test -v ./internal/collector/ -bench BenchmarkProcessCollectorPerformance -timeout 5m"
        fi
        
        # Integration tests
        run_test "Go Integration Test" "go test -v ./internal/collector/ -run TestProductionValidationIntegration -timeout 10m"
    else
        warning "Skipping Go tests (requires root privileges for eBPF)"
        log "To run Go tests, execute: sudo ./scripts/run-production-validation.sh --quick"
    fi
    
    cd ..
else
    log "Skipping Go-based integration tests"
fi

# 3. Additional validation tests
log "=== Additional Validation Tests ==="

# Run existing performance tests if available
if [[ -f "agent/ebpf/tests/performance_test" ]]; then
    cd agent/ebpf/tests
    run_test "Performance Regression Test" "./performance_test"
    cd ../../..
fi

# Generate final report
log "=== Production Validation Summary ==="

echo ""
echo "=================================================="
echo "Production Environment Validation Results"
echo "=================================================="
echo "Test Date: $(date)"
echo "Host: $(hostname)"
echo "Kernel: $(uname -r)"
echo "Architecture: $(uname -m)"
echo ""
echo "Test Results:"
echo "  Total tests: $TOTAL_TESTS"
echo "  Passed: $PASSED_TESTS"
echo "  Failed: $FAILED_TESTS"
echo "  Success rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%"
echo ""

if [[ $FAILED_TESTS -eq 0 ]]; then
    success "🎉 All production validation tests PASSED!"
    echo "The system is ready for production deployment."
    echo ""
    echo "Next steps:"
    echo "  1. Deploy monitoring and alerting in production"
    echo "  2. Set up continuous validation in CI/CD pipeline"
    echo "  3. Monitor system performance in production"
    exit 0
else
    error "❌ Some production validation tests FAILED!"
    echo "Please review the test results and address any issues before production deployment."
    echo ""
    echo "Troubleshooting:"
    echo "  1. Check system resources (memory, CPU)"
    echo "  2. Verify kernel eBPF support"
    echo "  3. Ensure proper permissions for eBPF operations"
    echo "  4. Review test logs for specific error details"
    exit 1
fi