# eBPF Tests Makefile

CC := gcc
CFLAGS := -Wall -Wextra -std=c99 -g -O0
INCLUDES := -I../include
LIBS := -lpthread
UNIT_TARGET := unit_test
INTEGRATION_TARGET := integration_test
PERFORMANCE_TARGET := performance_test
COMPATIBILITY_TARGET := compatibility_test
PRODUCTION_TARGET := production_validation_test
FILE_TYPE_FILTERING_TARGET := file_type_filtering_test
UNIT_SOURCE := unit_test.c
INTEGRATION_SOURCE := integration_test.c
PERFORMANCE_SOURCE := performance_test.c
COMPATIBILITY_SOURCE := compatibility_test.c
PRODUCTION_SOURCE := production_validation_test.c
FILE_TYPE_FILTERING_SOURCE := file_type_filtering_test.c

.PHONY: all clean test unit-test integration-test performance-test compatibility-test production-validation-test run help

all: $(UNIT_TARGET) $(INTEGRATION_TARGET) $(PERFORMANCE_TARGET) $(COMPATIBILITY_TARGET) $(PRODUCTION_TARGET) $(FILE_TYPE_FILTERING_TARGET)

$(UNIT_TARGET): $(UNIT_SOURCE)
	@echo "Compiling unit tests..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $(UNIT_TARGET) $(UNIT_SOURCE)
	@echo "Unit tests compiled successfully"

$(INTEGRATION_TARGET): $(INTEGRATION_SOURCE)
	@echo "Compiling integration tests..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $(INTEGRATION_TARGET) $(INTEGRATION_SOURCE)
	@echo "Integration tests compiled successfully"

$(PERFORMANCE_TARGET): $(PERFORMANCE_SOURCE)
	@echo "Compiling performance tests..."
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBS) -o $(PERFORMANCE_TARGET) $(PERFORMANCE_SOURCE)
	@echo "Performance tests compiled successfully"

$(COMPATIBILITY_TARGET): $(COMPATIBILITY_SOURCE)
	@echo "Compiling compatibility tests..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $(COMPATIBILITY_TARGET) $(COMPATIBILITY_SOURCE)
	@echo "Compatibility tests compiled successfully"

$(PRODUCTION_TARGET): $(PRODUCTION_SOURCE)
	@echo "Compiling production validation tests..."
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBS) -o $(PRODUCTION_TARGET) $(PRODUCTION_SOURCE)
	@echo "Production validation tests compiled successfully"

$(FILE_TYPE_FILTERING_TARGET): $(FILE_TYPE_FILTERING_SOURCE)
	@echo "Compiling file type filtering tests..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $(FILE_TYPE_FILTERING_TARGET) $(FILE_TYPE_FILTERING_SOURCE)
	@echo "File type filtering tests compiled successfully"

unit-test: $(UNIT_TARGET)
	@echo "Running eBPF unit tests..."
	@echo "=========================="
	./$(UNIT_TARGET)

integration-test: $(INTEGRATION_TARGET)
	@echo "Running eBPF integration tests..."
	@echo "================================="
	./$(INTEGRATION_TARGET) --integration

performance-test: $(PERFORMANCE_TARGET)
	@echo "Running eBPF performance tests..."
	@echo "================================="
	./$(PERFORMANCE_TARGET)

compatibility-test: $(COMPATIBILITY_TARGET)
	@echo "Running eBPF compatibility tests..."
	@echo "==================================="
	./$(COMPATIBILITY_TARGET)

production-validation-test: $(PRODUCTION_TARGET)
	@echo "Running eBPF production validation tests..."
	@echo "==========================================="
	./$(PRODUCTION_TARGET) --quick

production-validation-long: $(PRODUCTION_TARGET)
	@echo "Running eBPF long-term production validation tests..."
	@echo "===================================================="
	./$(PRODUCTION_TARGET) --long-term

file-type-filtering-test: $(FILE_TYPE_FILTERING_TARGET)
	@echo "Running file type filtering tests..."
	@echo "===================================="
	./$(FILE_TYPE_FILTERING_TARGET)

test: unit-test integration-test performance-test compatibility-test production-validation-test file-type-filtering-test

run: test

clean:
	@echo "Cleaning up..."
	rm -f $(UNIT_TARGET) $(INTEGRATION_TARGET) $(PERFORMANCE_TARGET) $(COMPATIBILITY_TARGET) $(PRODUCTION_TARGET) $(FILE_TYPE_FILTERING_TARGET)
	@echo "Clean complete"

help:
	@echo "eBPF Tests Build System"
	@echo "======================="
	@echo ""
	@echo "Targets:"
	@echo "  all                        - Build all tests (default)"
	@echo "  unit-test                  - Build and run unit tests"
	@echo "  integration-test           - Build and run integration tests"
	@echo "  performance-test           - Build and run performance tests"
	@echo "  compatibility-test         - Build and run compatibility tests"
	@echo "  production-validation-test - Build and run production validation tests (quick)"
	@echo "  production-validation-long - Build and run long-term production validation tests"
	@echo "  file-type-filtering-test   - Build and run file type filtering tests"
	@echo "  test                       - Build and run all tests"
	@echo "  run                        - Alias for test"
	@echo "  clean                      - Remove build artifacts"
	@echo "  help                       - Show this help"
	@echo ""
	@echo "Usage:"
	@echo "  make                              # Build all tests"
	@echo "  make unit-test                    # Run unit tests only"
	@echo "  make integration-test             # Run integration tests only"
	@echo "  make performance-test             # Run performance tests only"
	@echo "  make compatibility-test           # Run compatibility tests only"
	@echo "  make production-validation-test   # Run production validation tests (quick)"
	@echo "  make production-validation-long   # Run long-term production validation tests"
	@echo "  make test                         # Run all tests"
	@echo "  make clean                        # Clean up"

# Default target
.DEFAULT_GOAL := all