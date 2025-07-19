# eBPF Makefile for OpenEDR Agent

# Compiler and flags
CLANG := clang
LLC := llc
BPFTOOL := bpftool

# Directories
SRC_DIR := src
INCLUDE_DIR := include
BUILD_DIR := build
VMLINUX_DIR := vmlinux

# Version selection for process monitor
PROCESS_MONITOR_VERSION ?= v2
ifeq ($(PROCESS_MONITOR_VERSION),v1)
    PROCESS_MONITOR_SRC := $(SRC_DIR)/process_monitor.c
else
    PROCESS_MONITOR_SRC := $(SRC_DIR)/process_monitor_v2.c
endif

# Source files - exclude both process monitor versions, then add the selected one
SOURCES := $(filter-out $(SRC_DIR)/process_monitor.c $(SRC_DIR)/process_monitor_v2.c, $(wildcard $(SRC_DIR)/*.c))
SOURCES += $(PROCESS_MONITOR_SRC)

OBJECTS := $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
SKELETONS := $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.skel.h)

# Compiler flags
CFLAGS := -O2 -g -Wall -Werror
CFLAGS += -I$(INCLUDE_DIR)
CFLAGS += -I/usr/include/x86_64-linux-gnu
CFLAGS += -target bpf
CFLAGS += -D__TARGET_ARCH_x86
CFLAGS += -mcpu=v3

# Check if we have vmlinux.h
VMLINUX_H := $(VMLINUX_DIR)/vmlinux.h
ifeq ($(wildcard $(VMLINUX_H)),)
    # Use system headers if vmlinux.h is not available
    CFLAGS += -I/usr/include
    CFLAGS += -I/usr/include/linux
else
    CFLAGS += -I$(VMLINUX_DIR)
endif

.PHONY: all clean install generate-vmlinux help build-v1 build-v2 show-version test test-unit

all: $(BUILD_DIR) $(OBJECTS) $(SKELETONS)

# Build specific versions
build-v1:
	@$(MAKE) PROCESS_MONITOR_VERSION=v1 all

build-v2:
	@$(MAKE) PROCESS_MONITOR_VERSION=v2 all

# Show current version selection
show-version:
	@echo "Current process monitor version: $(PROCESS_MONITOR_VERSION)"
	@echo "Selected source file: $(PROCESS_MONITOR_SRC)"

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(VMLINUX_DIR)

# Compile eBPF programs
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(INCLUDE_DIR)/common.h | $(BUILD_DIR)
	@echo "Compiling $< -> $@"
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "Compilation successful for $@"
ifdef VERIFY
	@echo "Verifying $@"
	@sudo $(BPFTOOL) prog load $@ /sys/fs/bpf/verify_$(basename $(notdir $@)) 2>/dev/null && \
	 sudo rm -f /sys/fs/bpf/verify_$(basename $(notdir $@)) || \
	 (echo "eBPF verification failed for $@" && exit 1)
endif

# Generate skeleton headers
$(BUILD_DIR)/%.skel.h: $(BUILD_DIR)/%.o
	@echo "Generating skeleton for $< -> $@"
	$(BPFTOOL) gen skeleton $< > $@

# Generate vmlinux.h (requires root privileges)
generate-vmlinux:
	@echo "Generating vmlinux.h..."
	@if [ ! -f $(VMLINUX_H) ]; then \
		echo "Attempting to generate vmlinux.h (may require sudo)..."; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H) 2>/dev/null || \
		echo "Warning: Could not generate vmlinux.h. Using system headers instead."; \
	else \
		echo "vmlinux.h already exists"; \
	fi

# Install compiled programs (copy to a system location)
install: all
	@echo "Installing eBPF programs..."
	@sudo mkdir -p /opt/openedr/ebpf
	@sudo cp $(BUILD_DIR)/*.o /opt/openedr/ebpf/
	@sudo chmod 644 /opt/openedr/ebpf/*.o
	@echo "eBPF programs installed to /opt/openedr/ebpf/"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)

# Verify eBPF programs
verify: $(OBJECTS)
	@echo "Verifying all eBPF programs..."
	@for obj in $(OBJECTS); do \
		echo "Verifying $$obj..."; \
		sudo $(BPFTOOL) prog load $$obj /sys/fs/bpf/verify_$$(basename $$obj .o) 2>/dev/null && \
		sudo rm -f /sys/fs/bpf/verify_$$(basename $$obj .o) && \
		echo "$$obj verified successfully" || \
		(echo "eBPF verification failed for $$obj" && exit 1); \
	done
	@echo "All eBPF programs verified successfully"

# Show program information
info: $(OBJECTS)
	@echo "eBPF Program Information:"
	@for obj in $(OBJECTS); do \
		echo "=== $$obj ==="; \
		$(BPFTOOL) prog show pinned $$obj 2>/dev/null || echo "Program not loaded"; \
		echo; \
	done

# Load programs (for testing)
load: $(OBJECTS)
	@echo "Loading eBPF programs..."
	@for obj in $(OBJECTS); do \
		echo "Loading $$obj..."; \
		sudo $(BPFTOOL) prog load $$obj /sys/fs/bpf/$$(basename $$obj .o) || echo "Failed to load $$obj"; \
	done

# Unload programs
unload:
	@echo "Unloading eBPF programs..."
	@sudo rm -f /sys/fs/bpf/process_monitor
	@sudo rm -f /sys/fs/bpf/network_monitor
	@sudo rm -f /sys/fs/bpf/file_monitor

# Check dependencies
check-deps:
	@echo "Checking eBPF development dependencies..."
	@which $(CLANG) >/dev/null || (echo "Error: clang not found" && exit 1)
	@which $(LLC) >/dev/null || (echo "Error: llc not found" && exit 1)
	@which $(BPFTOOL) >/dev/null || (echo "Error: bpftool not found" && exit 1)
	@pkg-config --exists libbpf || (echo "Error: libbpf not found" && exit 1)
	@echo "All dependencies found"

# Show kernel version and eBPF support
kernel-info:
	@echo "Kernel Information:"
	@echo "Version: $$(uname -r)"
	@echo "eBPF Support:"
	@echo "  CONFIG_BPF: $$(grep -q 'CONFIG_BPF=y' /boot/config-$$(uname -r) 2>/dev/null && echo 'YES' || echo 'UNKNOWN')"
	@echo "  CONFIG_BPF_SYSCALL: $$(grep -q 'CONFIG_BPF_SYSCALL=y' /boot/config-$$(uname -r) 2>/dev/null && echo 'YES' || echo 'UNKNOWN')"
	@echo "  BTF Support: $$([ -f /sys/kernel/btf/vmlinux ] && echo 'YES' || echo 'NO')"
	@echo "  Ring Buffer: $$([ -d /sys/fs/bpf ] && echo 'YES' || echo 'NO')"

# Run unit tests
test-unit:
	@echo "Running eBPF unit tests..."
	@$(MAKE) -C tests test

test: test-unit

# Help
help:
	@echo "OpenEDR eBPF Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all              - Build all eBPF programs (default: v2)"
	@echo "  build-v1         - Build with process monitor v1 (kprobe-based)"
	@echo "  build-v2         - Build with process monitor v2 (tracepoint-based)"
	@echo "  show-version     - Show current process monitor version selection"
	@echo "  clean            - Clean build artifacts"
	@echo "  verify           - Verify eBPF programs"
	@echo "  install          - Install programs to system location"
	@echo "  load             - Load programs for testing"
	@echo "  unload           - Unload programs"
	@echo "  generate-vmlinux - Generate vmlinux.h header"
	@echo "  check-deps       - Check build dependencies"
	@echo "  kernel-info      - Show kernel eBPF support info"
	@echo "  info             - Show loaded program information"
	@echo "  test-unit        - Run unit tests"
	@echo "  test             - Alias for test-unit"
	@echo "  help             - Show this help"
	@echo ""
	@echo "Version Selection:"
	@echo "  PROCESS_MONITOR_VERSION=v1  - Use original kprobe-based implementation"
	@echo "  PROCESS_MONITOR_VERSION=v2  - Use optimized tracepoint-based implementation (default)"
	@echo ""
	@echo "Examples:"
	@echo "  make                         - Build with v2 (default)"
	@echo "  make PROCESS_MONITOR_VERSION=v1  - Build with v1"
	@echo "  make build-v1                - Build with v1"
	@echo "  make build-v2                - Build with v2"
	@echo ""
	@echo "Files built:"
	@echo "  $(OBJECTS)"
	@echo "  $(SKELETONS)"
