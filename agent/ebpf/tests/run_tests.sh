#!/bin/bash

# eBPF Process Monitor Test Runner
# This script compiles and runs both unit tests and integration tests for the eBPF process monitor optimization

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Parse command line arguments
TEST_TYPE="all"
VALGRIND_CHECK=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --unit-only)
            TEST_TYPE="unit"
            shift
            ;;
        --integration-only)
            TEST_TYPE="integration"
            shift
            ;;
        --valgrind)
            VALGRIND_CHECK=true
            shift
            ;;
        --help)
            echo "eBPF Process Monitor Test Runner"
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --unit-only        Run only unit tests"
            echo "  --integration-only Run only integration tests"
            echo "  --valgrind         Run memory leak detection with valgrind"
            echo "  --help             Show this help message"
            echo ""
            echo "Default: Run both unit and integration tests"
            exit 0
            ;;
        *)
            print_warning "Unknown option: $1"
            shift
            ;;
    esac
done

# Check if we're in the right directory
if [ ! -f "unit_test.c" ] || [ ! -f "integration_test.c" ]; then
    print_error "Test source files not found. Please run this script from the tests directory."
    exit 1
fi

print_status "Starting eBPF Process Monitor Test Suite"
echo "=========================================="

# Check for required tools
print_status "Checking build dependencies..."

if ! command -v gcc &> /dev/null; then
    print_error "gcc not found. Please install gcc to compile the tests."
    exit 1
fi

print_success "Build dependencies found"

# Clean previous builds
print_status "Cleaning previous builds..."
make clean > /dev/null 2>&1 || true

# Compile tests
print_status "Compiling tests..."
if make all; then
    print_success "All tests compiled successfully"
else
    print_error "Failed to compile tests"
    exit 1
fi

# Initialize test results
UNIT_TEST_RESULT=0
INTEGRATION_TEST_RESULT=0
OVERALL_RESULT=0

# Run unit tests
if [ "$TEST_TYPE" = "all" ] || [ "$TEST_TYPE" = "unit" ]; then
    print_status "Running unit tests..."
    echo ""
    
    if ./unit_test; then
        echo ""
        print_success "Unit tests completed successfully!"
        UNIT_TEST_RESULT=0
    else
        echo ""
        print_error "Some unit tests failed!"
        UNIT_TEST_RESULT=1
        OVERALL_RESULT=1
    fi
fi

# Run integration tests
if [ "$TEST_TYPE" = "all" ] || [ "$TEST_TYPE" = "integration" ]; then
    print_status "Running integration tests..."
    echo ""
    
    if ./integration_test --integration; then
        echo ""
        print_success "Integration tests completed successfully!"
        INTEGRATION_TEST_RESULT=0
    else
        echo ""
        print_error "Some integration tests failed!"
        INTEGRATION_TEST_RESULT=1
        OVERALL_RESULT=1
    fi
fi

# Generate comprehensive test report
print_status "Generating test report..."

cat > test_report.txt << EOF
eBPF Process Monitor Test Report
===============================
Date: $(date)
Host: $(hostname)
Kernel: $(uname -r)
Test Type: $TEST_TYPE

Test Results Summary:
EOF

if [ "$TEST_TYPE" = "all" ] || [ "$TEST_TYPE" = "unit" ]; then
    if [ $UNIT_TEST_RESULT -eq 0 ]; then
        echo "Unit Tests: PASSED" >> test_report.txt
    else
        echo "Unit Tests: FAILED" >> test_report.txt
    fi
fi

if [ "$TEST_TYPE" = "all" ] || [ "$TEST_TYPE" = "integration" ]; then
    if [ $INTEGRATION_TEST_RESULT -eq 0 ]; then
        echo "Integration Tests: PASSED" >> test_report.txt
    else
        echo "Integration Tests: FAILED" >> test_report.txt
    fi
fi

echo "" >> test_report.txt
echo "Detailed Results:" >> test_report.txt
echo "=================" >> test_report.txt

# Add unit test results to report
if [ "$TEST_TYPE" = "all" ] || [ "$TEST_TYPE" = "unit" ]; then
    echo "" >> test_report.txt
    echo "Unit Test Output:" >> test_report.txt
    echo "-----------------" >> test_report.txt
    ./unit_test >> test_report.txt 2>&1 || true
fi

# Add integration test results to report
if [ "$TEST_TYPE" = "all" ] || [ "$TEST_TYPE" = "integration" ]; then
    echo "" >> test_report.txt
    echo "Integration Test Output:" >> test_report.txt
    echo "------------------------" >> test_report.txt
    ./integration_test --integration >> test_report.txt 2>&1 || true
fi

print_success "Test report generated: test_report.txt"

# Optional: Run with valgrind if requested and available
if [ "$VALGRIND_CHECK" = true ]; then
    if command -v valgrind &> /dev/null; then
        print_status "Running memory leak detection with valgrind..."
        
        # Check unit tests with valgrind
        if [ "$TEST_TYPE" = "all" ] || [ "$TEST_TYPE" = "unit" ]; then
            print_status "Checking unit tests for memory leaks..."
            if valgrind --leak-check=full --error-exitcode=1 ./unit_test > /dev/null 2>&1; then
                print_success "No memory leaks detected in unit tests"
            else
                print_warning "Memory issues detected in unit tests. Run 'valgrind --leak-check=full ./unit_test' for details."
            fi
        fi
        
        # Check integration tests with valgrind
        if [ "$TEST_TYPE" = "all" ] || [ "$TEST_TYPE" = "integration" ]; then
            print_status "Checking integration tests for memory leaks..."
            if valgrind --leak-check=full --error-exitcode=1 ./integration_test --integration > /dev/null 2>&1; then
                print_success "No memory leaks detected in integration tests"
            else
                print_warning "Memory issues detected in integration tests. Run 'valgrind --leak-check=full ./integration_test --integration' for details."
            fi
        fi
    else
        print_warning "Valgrind not found. Skipping memory leak detection."
    fi
fi

# Print final results
echo ""
echo "=========================================="
if [ $OVERALL_RESULT -eq 0 ]; then
    print_success "All tests completed successfully!"
else
    print_error "Some tests failed! Check test_report.txt for details."
fi

print_status "Test execution completed!"
exit $OVERALL_RESULT