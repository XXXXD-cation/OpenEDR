#!/bin/bash

# eBPF Process Monitor Performance Test Runner
# This script runs comprehensive performance tests comparing kprobe vs tracepoint implementations

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_REPORT="performance_test_report.txt"
LOG_FILE="performance_test.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}✓${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}✗${NC} $1" | tee -a "$LOG_FILE"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if gcc is available
    if ! command -v gcc &> /dev/null; then
        error "GCC compiler not found. Please install gcc."
        exit 1
    fi
    
    # Check if make is available
    if ! command -v make &> /dev/null; then
        error "Make build system not found. Please install make."
        exit 1
    fi
    
    # Check if we have sufficient permissions
    if [[ $EUID -eq 0 ]]; then
        warning "Running as root. This may affect performance measurements."
    fi
    
    success "Prerequisites check passed"
}

# Build performance tests
build_tests() {
    log "Building performance tests..."
    
    cd "$SCRIPT_DIR"
    
    # Clean previous builds
    make clean > /dev/null 2>&1 || true
    
    # Build performance tests
    if make performance-test > build.log 2>&1; then
        success "Performance tests built successfully"
    else
        error "Failed to build performance tests"
        cat build.log
        exit 1
    fi
}

# Run performance tests
run_tests() {
    log "Running comprehensive performance tests..."
    log "This may take several minutes..."
    
    cd "$SCRIPT_DIR"
    
    # Run the performance test suite
    if ./performance_test > "$TEST_REPORT" 2>&1; then
        success "Performance tests completed successfully"
        return 0
    else
        warning "Some performance tests may have failed"
        return 1
    fi
}

# Generate summary report
generate_summary() {
    log "Generating performance test summary..."
    
    local report_file="$SCRIPT_DIR/$TEST_REPORT"
    local summary_file="$SCRIPT_DIR/performance_summary.md"
    
    if [[ ! -f "$report_file" ]]; then
        error "Test report not found: $report_file"
        return 1
    fi
    
    # Extract key metrics from the report
    local performance_improvement=$(grep "Performance improvement:" "$report_file" | tail -1 | awk '{print $3}')
    local stability_score=$(grep "Stability Score:" "$report_file" | tail -1 | awk '{print $3}')
    local tests_passed=$(grep "Tests passed:" "$report_file" | awk '{print $3}')
    local success_rate=$(grep "Success rate:" "$report_file" | awk '{print $3}')
    
    # Create markdown summary
    cat > "$summary_file" << EOF
# eBPF Process Monitor Performance Test Summary

**Test Date:** $(date '+%Y-%m-%d %H:%M:%S')
**Host:** $(hostname)
**Kernel:** $(uname -r)
**Architecture:** $(uname -m)

## Test Results Overview

- **Tests Passed:** $tests_passed
- **Success Rate:** $success_rate
- **Performance Improvement:** $performance_improvement
- **Stability Score:** $stability_score

## Key Findings

$(grep -A 10 "=== Performance Optimization Recommendations ===" "$report_file" | tail -n +2)

## Detailed Metrics

### Kprobe Implementation
$(grep -A 6 "Kprobe Implementation:" "$report_file" | tail -n +2)

### Tracepoint Implementation
$(grep -A 6 "Tracepoint Implementation:" "$report_file" | tail -n +2)

## Test Categories

### 1. Basic Performance Comparison
$(grep -A 1 "Performance comparison:" "$report_file")

### 2. High Load Stability Tests
$(grep -A 2 "stability test:" "$report_file")

### 3. Memory Usage Tests
$(grep -A 2 "memory test:" "$report_file")

### 4. CPU Usage Tests
$(grep -A 2 "CPU test:" "$report_file")

## Recommendations

$(grep -A 20 "=== Performance Optimization Recommendations ===" "$report_file" | grep -E "^(🎯|✓|⚠)" | head -10)

---

*For complete test output, see: $TEST_REPORT*
EOF
    
    success "Performance summary generated: $summary_file"
}

# Display results
display_results() {
    log "Performance Test Results Summary"
    echo "================================"
    
    if [[ -f "$SCRIPT_DIR/$TEST_REPORT" ]]; then
        # Show key results
        echo
        grep -E "(Tests passed:|Success rate:|Performance improvement:|Reliability rating:)" "$SCRIPT_DIR/$TEST_REPORT" || true
        echo
        
        # Show recommendations
        echo "Key Recommendations:"
        grep -A 5 "RECOMMENDATION:" "$SCRIPT_DIR/$TEST_REPORT" | head -10 || true
        echo
        
        success "Full report available at: $SCRIPT_DIR/$TEST_REPORT"
        
        if [[ -f "$SCRIPT_DIR/performance_summary.md" ]]; then
            success "Summary report available at: $SCRIPT_DIR/performance_summary.md"
        fi
    else
        error "Test report not found"
        return 1
    fi
}

# Cleanup function
cleanup() {
    log "Cleaning up temporary files..."
    rm -f "$SCRIPT_DIR/build.log"
}

# Main execution
main() {
    echo "eBPF Process Monitor Performance Test Suite"
    echo "==========================================="
    echo
    
    # Initialize log file
    echo "Performance test run started at $(date)" > "$LOG_FILE"
    
    # Set trap for cleanup
    trap cleanup EXIT
    
    # Run test sequence
    check_prerequisites
    build_tests
    
    local test_result=0
    run_tests || test_result=$?
    
    generate_summary
    display_results
    
    echo
    if [[ $test_result -eq 0 ]]; then
        success "All performance tests completed successfully!"
    else
        warning "Performance tests completed with some issues. Check the report for details."
    fi
    
    return $test_result
}

# Script usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -v, --verbose  Enable verbose output"
    echo "  -q, --quiet    Suppress non-essential output"
    echo
    echo "Examples:"
    echo "  $0              # Run all performance tests"
    echo "  $0 --verbose    # Run with detailed output"
    echo "  $0 --quiet      # Run with minimal output"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -v|--verbose)
            set -x
            shift
            ;;
        -q|--quiet)
            exec > /dev/null 2>&1
            shift
            ;;
        *)
            error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Run main function
main "$@"