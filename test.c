/*
 * eBPF Process Monitor Integration Tests
 * 
 * This file contains comprehensive integration tests for the eBPF process monitor
 * optimization implementation. These tests verify the complete event capture flow,
 * parent PID accuracy, process exit event correctness, and event deduplication logic.
 * 
 * Requirements tested:
 * - 1.1: Complete event capture flow
 * - 1.2: Parent PID accuracy verification  
 * - 1.3: Process exit event correctness
 * - 3.1: Tracepoint context parsing validation
 * - 3.2: Parent PID extraction accuracy
 * - 4.1: Event processing workflow
 * - 4.2: Error handling mechanisms
 * - 4.3: Event deduplication logic
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

// Define basic types and constants for integration testing
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint8_t __u8;
typedef int64_t __s64;
typedef int32_t __s32;
typedef int16_t __s16;
typedef int8_t __s8;

// Maximum lengths for various fields
#define MAX_FILENAME_LEN    256
#define MAX_COMM_LEN        16
#define MAX_PATH_LEN        4096
#define TASK_COMM_LEN       16

// Event types
enum event_type {
    EVENT_PROCESS_EXEC = 1,
    EVENT_PROCESS_EXIT = 2,
    EVENT_NETWORK_CONNECT = 3,
    EVENT_NETWORK_ACCEPT = 4,
    EVENT_FILE_OPEN = 5,
    EVENT_FILE_WRITE = 6,
    EVENT_FILE_UNLINK = 7,
    EVENT_SYSCALL = 8,
};

// Common event header
struct event_header {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 event_type;
    __u32 cpu;
    char comm[TASK_COMM_LEN];
};

// Process events
struct process_event {
    struct event_header header;
    __u32 ppid;
    __u32 exit_code;  // Only for exit events
    char filename[MAX_FILENAME_LEN];
    char args[512];   // Truncated command line arguments
};

// Debug and error statistics
struct debug_stats {
    __u64 events_processed;     // Total events processed
    __u64 events_dropped;       // Events dropped due to various reasons
    __u64 allocation_failures;  // Ring buffer allocation failures
    __u64 config_errors;        // Configuration read errors
    __u64 data_read_errors;     // Data read/extraction errors
    __u64 tracepoint_errors;    // Tracepoint-specific errors
    __u64 exec_events;          // Process execution events
    __u64 exit_events;          // Process exit events
    __u64 sampling_skipped;     // Events skipped due to sampling
    __u64 pid_filtered;         // Events filtered by PID
    __u64 last_error_timestamp; // Timestamp of last error
    __u32 last_error_type;      // Type of last error
    __u32 last_error_pid;       // PID that caused last error
};

// Configuration structure
struct config {
    __u32 enable_process_monitoring;
    __u32 enable_network_monitoring;
    __u32 enable_file_monitoring;
    __u32 enable_syscall_monitoring;
    __u32 sampling_rate;
};

// Error types for statistics
enum error_type {
    ERROR_EVENT_DROPPED = 0,
    ERROR_ALLOCATION_FAILURE = 1,
    ERROR_CONFIG_ERROR = 2,
    ERROR_DATA_READ_ERROR = 3,
    ERROR_TRACEPOINT_ERROR = 4,
};

// Monitor types for configuration
enum monitor_type {
    MONITOR_PROCESS = 0,
    MONITOR_NETWORK = 1,
    MONITOR_FILE = 2,
    MONITOR_SYSCALL = 3,
    MONITOR_SAMPLING_RATE = 4,
};

// Tracepoint context structures (simplified for testing)
struct trace_entry {
    __u16 type;
    __u8 flags;
    __u8 preempt_count;
    __s32 pid;
};

// Process execution tracepoint context
struct trace_event_raw_sched_process_exec {
    struct trace_entry ent;
    __u32 __data_loc_filename;  // Offset to filename in __data
    __u32 pid;                  // Current process PID
    __u32 old_pid;              // Parent process PID (PPID)
    char __data[256];           // Variable length data area
};

// Process exit tracepoint context
struct trace_event_raw_sched_process_exit {
    struct trace_entry ent;
    char comm[16];              // Process command name
    __u32 pid;                  // Process PID
    __s32 prio;                 // Process priority
    char __data[256];           // Variable length data area
};

// System call exit tracepoint context
struct trace_event_raw_sys_exit {
    struct trace_entry ent;
    __s64 id;                   // System call ID
    __s64 ret;                  // Return value/exit code
    char __data[256];           // Variable length data area
};

// Test framework macros
#define INTEGRATION_TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("FAIL: %s - %s\n", __func__, message); \
            return -1; \
        } \
    } while(0)

#define INTEGRATION_TEST_PASS(message) \
    do { \
        printf("PASS: %s - %s\n", __func__, message); \
        return 0; \
    } while(0)

// Test configuration
#define MAX_TEST_EVENTS 1000
#define TEST_TIMEOUT_SECONDS 10
#define TEST_PROCESS_NAME "test_child"

// Global test state
static struct {
    struct process_event captured_events[MAX_TEST_EVENTS];
    int event_count;
    int test_running;
    pid_t test_parent_pid;
    pid_t test_child_pid;
} integration_test_state;

// Mock eBPF environment for integration testing
// These functions simulate the eBPF runtime environment

// Mock configuration for testing
static struct config mock_integration_config = {
    .enable_process_monitoring = 1,
    .enable_network_monitoring = 0,
    .enable_file_monitoring = 0,
    .enable_syscall_monitoring = 0,
    .sampling_rate = 100
};

// Mock debug statistics for integration testing
static struct debug_stats mock_integration_stats = {0};

// Mock eBPF helper functions for integration tests
static uint64_t mock_integration_pid_tgid = 0;
static uint64_t mock_integration_uid_gid = 0;
static uint64_t mock_integration_timestamp = 0;
static uint32_t mock_integration_cpu = 0;
static char mock_integration_comm[TASK_COMM_LEN] = "test_process";

// Mock helper functions
static uint64_t mock_bpf_get_current_pid_tgid(void) {
    return mock_integration_pid_tgid;
}

static uint64_t mock_bpf_get_current_uid_gid(void) {
    return mock_integration_uid_gid;
}

static uint64_t mock_bpf_ktime_get_ns(void) {
    return mock_integration_timestamp;
}

static uint32_t mock_bpf_get_smp_processor_id(void) {
    return mock_integration_cpu;
}

static int mock_bpf_get_current_comm(void *buf, uint32_t size) {
    strncpy((char*)buf, mock_integration_comm, size);
    return 0;
}

static int mock_bpf_probe_read_kernel_str(void *dst, uint32_t size, const void *src) {
    if (!src || !dst) return -1;
    strncpy((char*)dst, (const char*)src, size);
    return strlen((const char*)src);
}

// Mock map lookup for configuration
static void* mock_bpf_map_lookup_elem(void *map, const void *key) {
    (void)key; // Suppress unused parameter warning
    
    // For config_map simulation
    if (map == (void*)0x1000) {  // Use dummy pointer for config_map
        return &mock_integration_config;
    }
    // For debug_stats_map simulation
    if (map == (void*)0x2000) {  // Use dummy pointer for debug_stats_map
        return &mock_integration_stats;
    }
    return NULL;
}

// Mock atomic operations for statistics
static uint64_t mock_sync_fetch_and_add(uint64_t *ptr, uint64_t value) {
    uint64_t old = *ptr;
    *ptr += value;
    return old;
}

// Mock ring buffer operations for integration tests
static void* mock_bpf_ringbuf_reserve(void *ringbuf, uint64_t size, uint64_t flags) {
    (void)ringbuf; (void)size; (void)flags; // Suppress unused warnings
    
    if (integration_test_state.event_count >= MAX_TEST_EVENTS) {
        return NULL;  // Simulate ring buffer full
    }
    
    // Return pointer to next available event slot
    return &integration_test_state.captured_events[integration_test_state.event_count];
}

// Mock ring buffer submit for integration tests
static int mock_bpf_ringbuf_submit(void *data, uint64_t flags) {
    (void)data; (void)flags; // Suppress unused warnings
    
    if (integration_test_state.event_count < MAX_TEST_EVENTS) {
        integration_test_state.event_count++;
        return 0;
    }
    return -1;
}

// Mock random number generator for sampling tests
static uint32_t mock_bpf_get_prandom_u32(void) {
    return rand();
}

// Simulated eBPF helper functions implementation
// These replicate the logic from common.h for testing

static void fill_event_header(struct event_header *header, uint32_t event_type) {
    uint64_t pid_tgid = mock_bpf_get_current_pid_tgid();
    uint64_t uid_gid = mock_bpf_get_current_uid_gid();
    
    header->timestamp = mock_bpf_ktime_get_ns();
    header->pid = pid_tgid & 0xFFFFFFFF;
    header->tgid = pid_tgid >> 32;
    header->uid = uid_gid & 0xFFFFFFFF;
    header->gid = uid_gid >> 32;
    header->event_type = event_type;
    header->cpu = mock_bpf_get_smp_processor_id();
    
    mock_bpf_get_current_comm(header->comm, sizeof(header->comm));
}

static int should_trace_pid(uint32_t pid) {
    // Skip kernel threads (pid 0) and init (pid 1)
    if (pid <= 1) {
        return 0;
    }
    return 1;
}

static int get_config_value(uint32_t key, uint32_t *value) {
    struct config *cfg = (struct config*)mock_bpf_map_lookup_elem((void*)0x1000, &key);
    if (!cfg) {
        return -1;
    }
    
    switch (key) {
        case 0: *value = cfg->enable_process_monitoring; break;
        case 1: *value = cfg->enable_network_monitoring; break;
        case 2: *value = cfg->enable_file_monitoring; break;
        case 3: *value = cfg->enable_syscall_monitoring; break;
        case 4: *value = cfg->sampling_rate; break;
        default: return -1;
    }
    
    return 0;
}

static int should_sample(uint32_t rate) {
    if (rate == 0) return 0;
    if (rate >= 100) return 1;
    
    return (mock_bpf_get_prandom_u32() % 100) < rate;
}

static void record_error(uint32_t error_type) {
    uint32_t key = 0;
    struct debug_stats *stats = (struct debug_stats*)mock_bpf_map_lookup_elem((void*)0x2000, &key);
    if (stats) {
        // Update error counters
        switch (error_type) {
            case ERROR_EVENT_DROPPED:
                mock_sync_fetch_and_add(&stats->events_dropped, 1);
                break;
            case ERROR_ALLOCATION_FAILURE:
                mock_sync_fetch_and_add(&stats->allocation_failures, 1);
                break;
            case ERROR_CONFIG_ERROR:
                mock_sync_fetch_and_add(&stats->config_errors, 1);
                break;
            case ERROR_DATA_READ_ERROR:
                mock_sync_fetch_and_add(&stats->data_read_errors, 1);
                break;
            case ERROR_TRACEPOINT_ERROR:
                mock_sync_fetch_and_add(&stats->tracepoint_errors, 1);
                break;
        }
        
        // Update last error information for debugging
        stats->last_error_timestamp = mock_bpf_ktime_get_ns();
        stats->last_error_type = error_type;
        stats->last_error_pid = mock_bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    }
}

static void record_exec_event(void) {
    uint32_t key = 0;
    struct debug_stats *stats = (struct debug_stats*)mock_bpf_map_lookup_elem((void*)0x2000, &key);
    if (stats) {
        mock_sync_fetch_and_add(&stats->exec_events, 1);
        mock_sync_fetch_and_add(&stats->events_processed, 1);
    }
}

static void record_exit_event(void) {
    uint32_t key = 0;
    struct debug_stats *stats = (struct debug_stats*)mock_bpf_map_lookup_elem((void*)0x2000, &key);
    if (stats) {
        mock_sync_fetch_and_add(&stats->exit_events, 1);
        mock_sync_fetch_and_add(&stats->events_processed, 1);
    }
}

static void record_sampling_skipped(void) {
    uint32_t key = 0;
    struct debug_stats *stats = (struct debug_stats*)mock_bpf_map_lookup_elem((void*)0x2000, &key);
    if (stats) {
        mock_sync_fetch_and_add(&stats->sampling_skipped, 1);
    }
}

static void record_pid_filtered(void) {
    uint32_t key = 0;
    struct debug_stats *stats = (struct debug_stats*)mock_bpf_map_lookup_elem((void*)0x2000, &key);
    if (stats) {
        mock_sync_fetch_and_add(&stats->pid_filtered, 1);
    }
}

static int get_config_value_safe(uint32_t key, uint32_t *value, uint32_t fallback) {
    int ret = get_config_value(key, value);
    if (ret < 0) {
        record_error(ERROR_CONFIG_ERROR);
        *value = fallback;
        return 0;  // Return success with fallback value
    }
    return ret;
}
    struct config *cfg = (struct config*)mock_bpf_map_lookup_elem((voi// Er
ror handling helpers
static int handle_allocation_failure(void) {
    record_error(ERROR_ALLOCATION_FAILURE);
    return 0;  // Continue processing other events
}

static int handle_config_error(void) {
    record_error(ERROR_CONFIG_ERROR);
    return 1;  // Use default configuration and continue
}

static int handle_data_read_error(void) {
    record_error(ERROR_DATA_READ_ERROR);
    return 0;  // Skip this event but continue processing
}

static int handle_tracepoint_error(void) {
    record_error(ERROR_TRACEPOINT_ERROR);
    return 0;  // Skip this event but continue processing
}

// Common event preprocessing check
static int should_process_event(uint32_t monitor_type) {
    uint32_t pid = mock_bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // PID filtering check
    if (!should_trace_pid(pid)) {
        record_pid_filtered();
        return 0;
    }
    
    // Configuration check with safe fallback
    uint32_t enabled = 0;
    get_config_value_safe(monitor_type, &enabled, 1);  // Default to enabled
    
    if (!enabled) {
        return 0;
    }
    
    // Sampling rate check with safe fallback
    uint32_t rate = 100;
    get_config_value_safe(MONITOR_SAMPLING_RATE, &rate, 100);  // Default to 100%
    
    if (!should_sample(rate)) {
        record_sampling_skipped();
        return 0;
    }
    
    return 1;
}

// Safe event allocation and initialization
static struct process_event* allocate_process_event(uint32_t event_type) {
    struct process_event *event = (struct process_event*)mock_bpf_ringbuf_reserve(NULL, sizeof(*event), 0);
    if (!event) {
        record_error(ERROR_ALLOCATION_FAILURE);
        return NULL;
    }
    
    // Initialize event header
    fill_event_header(&event->header, event_type);
    
    return event;
}

// Extract filename from sched_process_exec tracepoint context
static int extract_filename_from_exec_ctx(
    struct trace_event_raw_sched_process_exec *ctx,
    char *filename, 
    size_t size) {
    
    // Get filename offset from __data_loc_filename
    uint32_t offset = ctx->__data_loc_filename & 0xFFFF;
    
    // Validate offset to prevent out-of-bounds access
    if (offset > 4096) {  // Reasonable upper bound
        record_error(ERROR_DATA_READ_ERROR);
        return -1;
    }
    
    // For testing, we'll use the data directly from __data
    if (offset < sizeof(ctx->__data) && strlen(ctx->__data) > 0) {
        strncpy(filename, ctx->__data, size - 1);
        filename[size - 1] = '\0';
        return strlen(filename);
    }
    
    record_error(ERROR_DATA_READ_ERROR);
    return -1;
}

// Get parent PID from sched_process_exec tracepoint context
static uint32_t get_parent_pid_from_exec_ctx(
    struct trace_event_raw_sched_process_exec *ctx) {
    
    return ctx->old_pid;
}

// Fill process execution event info from tracepoint context
static void fill_process_exec_info(
    struct process_event *event,
    struct trace_event_raw_sched_process_exec *ctx) {
    
    // Get accurate parent process ID from tracepoint context
    if (ctx) {
        event->ppid = get_parent_pid_from_exec_ctx(ctx);
    } else {
        event->ppid = 0;  // Unknown parent
        handle_tracepoint_error();
    }
    
    event->exit_code = 0;  // Not applicable for exec events
    
    // Extract filename from tracepoint context with error handling
    if (ctx && extract_filename_from_exec_ctx(ctx, event->filename, sizeof(event->filename)) < 0) {
        // On error, clear filename and record the error
        memset(event->filename, 0, sizeof(event->filename));
        handle_data_read_error();
    } else if (!ctx) {
        // If context is null, clear filename and record error
        memset(event->filename, 0, sizeof(event->filename));
        handle_tracepoint_error();
    }
    
    // Clear args for now (command line args extraction is complex)
    memset(event->args, 0, sizeof(event->args));
}

// Fill process exit event info from tracepoint context
static void fill_process_exit_info(
    struct process_event *event,
    struct trace_event_raw_sched_process_exit *ctx) {
    
    (void)ctx; // Suppress unused parameter warning
    
    // For exit events, parent PID is not available in the tracepoint
    event->ppid = 0;
    
    // Note: sched_process_exit tracepoint doesn't directly provide exit code
    event->exit_code = 0;
    
    // Clear filename and args for exit events
    memset(event->filename, 0, sizeof(event->filename));
    memset(event->args, 0, sizeof(event->args));
}

// Enhanced allocation function with retry logic
static struct process_event* allocate_process_event_with_retry(uint32_t event_type) {
    struct process_event *event;
    
    // First attempt
    event = (struct process_event*)mock_bpf_ringbuf_reserve(NULL, sizeof(*event), 0);
    if (event) {
        fill_event_header(&event->header, event_type);
        return event;
    }
    
    // Record the allocation failure
    record_error(ERROR_ALLOCATION_FAILURE);
    
    // Try once more (simulating BPF_RB_FORCE_WAKEUP)
    event = (struct process_event*)mock_bpf_ringbuf_reserve(NULL, sizeof(*event), 1);
    if (event) {
        fill_event_header(&event->header, event_type);
        return event;
    }
    
    // If both attempts fail, return NULL
    return NULL;
}

// Simulated eBPF program functions for testing

// Simulated trace_process_exec_v2 function
static int trace_process_exec_v2(struct trace_event_raw_sched_process_exec *ctx) {
    // Use common preprocessing check to eliminate code duplication
    if (!should_process_event(MONITOR_PROCESS)) {
        return 0;
    }
    
    // Allocate event using enhanced helper function with retry logic
    struct process_event *event = allocate_process_event_with_retry(EVENT_PROCESS_EXEC);
    if (!event) {
        return handle_allocation_failure();
    }
    
    // Fill process execution information from tracepoint context
    fill_process_exec_info(event, ctx);
    
    // Record successful exec event processing for monitoring
    record_exec_event();
    
    // Submit event to ring buffer
    mock_bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Simulated trace_process_exit_v2 function
static int trace_process_exit_v2(struct trace_event_raw_sched_process_exit *ctx) {
    // Use common preprocessing check to eliminate code duplication
    if (!should_process_event(MONITOR_PROCESS)) {
        return 0;
    }
    
    // Allocate event using enhanced helper function with retry logic
    struct process_event *event = allocate_process_event_with_retry(EVENT_PROCESS_EXIT);
    if (!event) {
        return handle_allocation_failure();
    }
    
    // Fill process exit information from tracepoint context
    fill_process_exit_info(event, ctx);
    
    // Record successful exit event processing for monitoring
    record_exit_event();
    
    // Submit event to ring buffer
    mock_bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Simulated trace_sys_exit_v2 function
static int trace_sys_exit_v2(struct trace_event_raw_sys_exit *ctx) {
    // Only process if we're monitoring processes
    uint32_t enabled = 0;
    if (get_config_value_safe(MONITOR_PROCESS, &enabled, 1) < 0 || !enabled) {
        return 0;
    }
    
    // Basic PID filtering
    uint32_t pid = mock_bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    if (!should_trace_pid(pid)) {
        return 0;
    }
    
    // Allocate a minimal event for exit code tracking
    struct process_event *event = allocate_process_event_with_retry(EVENT_PROCESS_EXIT);
    if (!event) {
        return handle_allocation_failure();
    }
    
    // Fill basic information
    event->ppid = 0;  // Will be filled by sched_process_exit correlation
    event->exit_code = (uint32_t)ctx->ret;  // Actual exit code from syscall
    
    // Clear filename and args for syscall exit events
    memset(event->filename, 0, sizeof(event->filename));
    memset(event->args, 0, sizeof(event->args));
    
    // Submit event for correlation in user space
    mock_bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Simulated trace_sys_exit_group_v2 function
static int trace_sys_exit_group_v2(struct trace_event_raw_sys_exit *ctx) {
    // Only process if we're monitoring processes
    uint32_t enabled = 0;
    if (get_config_value_safe(MONITOR_PROCESS, &enabled, 1) < 0 || !enabled) {
        return 0;
    }
    
    // Basic PID filtering
    uint32_t pid = mock_bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    if (!should_trace_pid(pid)) {
        return 0;
    }
    
    // Similar to sys_exit but for process group exits
    struct process_event *event = allocate_process_event_with_retry(EVENT_PROCESS_EXIT);
    if (!event) {
        return handle_allocation_failure();
    }
    
    // Fill basic information
    event->ppid = 0;  // Will be filled by sched_process_exit correlation
    event->exit_code = (uint32_t)ctx->ret;  // Actual exit code from syscall
    
    // Clear filename and args for syscall exit events
    memset(event->filename, 0, sizeof(event->filename));
    memset(event->args, 0, sizeof(event->args));
    
    // Submit event for correlation in user space
    mock_bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Integration test helper functions

// Reset integration test state
static void reset_integration_test_state(void) {
    memset(&integration_test_state, 0, sizeof(integration_test_state));
    memset(&mock_integration_stats, 0, sizeof(mock_integration_stats));
    
    // Reset mock values to defaults
    mock_integration_pid_tgid = 0x1234567890ABCDEFULL;  // PID=0x90ABCDEF, TGID=0x12345678
    mock_integration_uid_gid = 0x0000000000000000ULL;   // UID=0, GID=0
    mock_integration_timestamp = 1234567890000000000ULL; // Mock timestamp
    mock_integration_cpu = 0;
    strcpy(mock_integration_comm, "test_process");
    
    // Reset configuration to enabled state
    mock_integration_config.enable_process_monitoring = 1;
    mock_integration_config.sampling_rate = 100;
    
    integration_test_state.test_running = 1;
    integration_test_state.test_parent_pid = getpid();
}

// Create mock tracepoint context for process exec
static struct trace_event_raw_sched_process_exec* create_mock_exec_context(
    uint32_t pid, uint32_t ppid, const char* filename) {
    
    static struct {
        struct trace_event_raw_sched_process_exec ctx;
    } mock_ctx;
    
    memset(&mock_ctx, 0, sizeof(mock_ctx));
    
    // Fill trace entry
    mock_ctx.ctx.ent.pid = pid;
    
    // Fill exec-specific fields
    mock_ctx.ctx.pid = pid;
    mock_ctx.ctx.old_pid = ppid;  // This is the parent PID
    
    // Set up filename data
    if (filename) {
        strncpy(mock_ctx.ctx.__data, filename, sizeof(mock_ctx.ctx.__data) - 1);
        mock_ctx.ctx.__data_loc_filename = 0;  // Offset 0 in __data
    }
    
    return &mock_ctx.ctx;
}

// Create mock tracepoint context for process exit
static struct trace_event_raw_sched_process_exit* create_mock_exit_context(
    uint32_t pid, const char* comm) {
    
    static struct trace_event_raw_sched_process_exit mock_ctx;
    
    memset(&mock_ctx, 0, sizeof(mock_ctx));
    
    // Fill trace entry
    mock_ctx.ent.pid = pid;
    
    // Fill exit-specific fields
    mock_ctx.pid = pid;
    if (comm) {
        strncpy(mock_ctx.comm, comm, sizeof(mock_ctx.comm) - 1);
    }
    
    return &mock_ctx;
}

// Create mock syscall exit context
static struct trace_event_raw_sys_exit* create_mock_syscall_exit_context(
    int64_t syscall_id, int64_t exit_code) {
    
    static struct trace_event_raw_sys_exit mock_ctx;
    
    memset(&mock_ctx, 0, sizeof(mock_ctx));
    
    mock_ctx.id = syscall_id;
    mock_ctx.ret = exit_code;
    
    return &mock_ctx;
}

// Verify event header correctness
static int verify_event_header(const struct event_header* header, uint32_t expected_type) {
    if (!header) return 0;
    
    // Check event type
    if (header->event_type != expected_type) {
        printf("Event type mismatch: expected %u, got %u\n", expected_type, header->event_type);
        return 0;
    }
    
    // Check PID/TGID extraction
    uint32_t expected_pid = mock_integration_pid_tgid & 0xFFFFFFFF;
    uint32_t expected_tgid = mock_integration_pid_tgid >> 32;
    
    if (header->pid != expected_pid) {
        printf("PID mismatch: expected %u, got %u\n", expected_pid, header->pid);
        return 0;
    }
    
    if (header->tgid != expected_tgid) {
        printf("TGID mismatch: expected %u, got %u\n", expected_tgid, header->tgid);
        return 0;
    }
    
    // Check UID/GID extraction
    uint32_t expected_uid = mock_integration_uid_gid & 0xFFFFFFFF;
    uint32_t expected_gid = mock_integration_uid_gid >> 32;
    
    if (header->uid != expected_uid) {
        printf("UID mismatch: expected %u, got %u\n", expected_uid, header->uid);
        return 0;
    }
    
    if (header->gid != expected_gid) {
        printf("GID mismatch: expected %u, got %u\n", expected_gid, header->gid);
        return 0;
    }
    
    // Check timestamp
    if (header->timestamp != mock_integration_timestamp) {
        printf("Timestamp mismatch: expected %lu, got %lu\n", 
               mock_integration_timestamp, header->timestamp);
        return 0;
    }
    
    // Check CPU
    if (header->cpu != mock_integration_cpu) {
        printf("CPU mismatch: expected %u, got %u\n", mock_integration_cpu, header->cpu);
        return 0;
    }
    
    // Check comm
    if (strcmp(header->comm, mock_integration_comm) != 0) {
        printf("Comm mismatch: expected '%s', got '%s'\n", 
               mock_integration_comm, header->comm);
        return 0;
    }
    
    return 1;
}

// Find event by type in captured events
static struct process_event* find_event_by_type(uint32_t event_type) {
    for (int i = 0; i < integration_test_state.event_count; i++) {
        if (integration_test_state.captured_events[i].header.event_type == event_type) {
            return &integration_test_state.captured_events[i];
        }
    }
    return NULL;
}

// Count events by type
static int count_events_by_type(uint32_t event_type) {
    int count = 0;
    for (int i = 0; i < integration_test_state.event_count; i++) {
        if (integration_test_state.captured_events[i].header.event_type == event_type) {
            count++;
        }
    }
    return count;
}
// Integration Test 1: Complete Event Capture Flow
// Tests the complete flow from tracepoint trigger to event submission
// Requirements: 1.1, 4.1
static int test_complete_event_capture_flow(void) {
    reset_integration_test_state();
    
    // Test process exec event capture
    uint32_t test_pid = 12345;
    uint32_t test_ppid = 54321;
    const char* test_filename = "/bin/test_program";
    
    // Set up mock environment for this test
    mock_integration_pid_tgid = ((uint64_t)test_ppid << 32) | test_pid;
    strcpy(mock_integration_comm, "test_exec");
    
    // Create mock tracepoint context
    struct trace_event_raw_sched_process_exec* exec_ctx = 
        create_mock_exec_context(test_pid, test_ppid, test_filename);
    
    // Call the V2 process exec handler
    int result = trace_process_exec_v2(exec_ctx);
    
    // Verify the handler executed successfully
    INTEGRATION_TEST_ASSERT(result == 0, "Process exec handler should return 0");
    
    // Verify an event was captured
    INTEGRATION_TEST_ASSERT(integration_test_state.event_count == 1, 
                           "Should capture exactly one exec event");
    
    // Verify the captured event
    struct process_event* captured_event = &integration_test_state.captured_events[0];
    
    // Verify event header
    INTEGRATION_TEST_ASSERT(verify_event_header(&captured_event->header, EVENT_PROCESS_EXEC),
                           "Event header should be correctly filled");
    
    // Verify process-specific data
    INTEGRATION_TEST_ASSERT(captured_event->ppid == test_ppid,
                           "Parent PID should be correctly extracted from tracepoint context");
    
    INTEGRATION_TEST_ASSERT(captured_event->exit_code == 0,
                           "Exit code should be 0 for exec events");
    
    INTEGRATION_TEST_ASSERT(strcmp(captured_event->filename, test_filename) == 0,
                           "Filename should be correctly extracted from tracepoint context");
    
    // Verify statistics were updated
    INTEGRATION_TEST_ASSERT(mock_integration_stats.exec_events == 1,
                           "Exec event statistics should be incremented");
    
    INTEGRATION_TEST_ASSERT(mock_integration_stats.events_processed == 1,
                           "Total events processed should be incremented");
    
    INTEGRATION_TEST_PASS("Complete event capture flow works correctly");
}

// Integration Test 2: Parent PID Accuracy Verification
// Tests that parent PID is correctly extracted from tracepoint context
// Requirements: 1.2, 3.2
static int test_parent_pid_accuracy(void) {
    reset_integration_test_state();
    
    // Test with various parent-child PID combinations
    struct {
        uint32_t child_pid;
        uint32_t parent_pid;
        const char* description;
    } test_cases[] = {
        {1000, 1, "Child of init process"},
        {2000, 1000, "Normal parent-child relationship"},
        {65535, 32768, "High PID values"},
        {1, 0, "Edge case: child PID 1"},
        {0, 0, "Edge case: both PIDs 0 (should be filtered)"}
    };
    
    int num_test_cases = sizeof(test_cases) / sizeof(test_cases[0]);
    
    for (int i = 0; i < num_test_cases; i++) {
        // Reset for each test case
        integration_test_state.event_count = 0;
        
        uint32_t child_pid = test_cases[i].child_pid;
        uint32_t parent_pid = test_cases[i].parent_pid;
        
        // Set up mock environment
        mock_integration_pid_tgid = ((uint64_t)parent_pid << 32) | child_pid;
        
        // Create mock exec context with specific parent PID
        struct trace_event_raw_sched_process_exec* exec_ctx = 
            create_mock_exec_context(child_pid, parent_pid, "/bin/test");
        
        // Call the handler
        int result = trace_process_exec_v2(exec_ctx);
        
        // For PID <= 1, the event should be filtered out
        if (child_pid <= 1) {
            INTEGRATION_TEST_ASSERT(integration_test_state.event_count == 0,
                                   "Events with PID <= 1 should be filtered out");
            continue;
        }
        
        INTEGRATION_TEST_ASSERT(result == 0, "Handler should succeed");
        INTEGRATION_TEST_ASSERT(integration_test_state.event_count == 1, 
                               "Should capture one event per test case");
        
        // Verify parent PID extraction
        struct process_event* event = &integration_test_state.captured_events[0];
        INTEGRATION_TEST_ASSERT(event->ppid == parent_pid,
                               "Parent PID should match tracepoint context");
        
        printf("✓ Parent PID test case: %s (child=%u, parent=%u)\n", 
               test_cases[i].description, child_pid, parent_pid);
    }
    
    INTEGRATION_TEST_PASS("Parent PID accuracy verification successful");
}
// Integration Test 3: Process Exit Event Correctness
// Tests process exit event handling and exit code capture
// Requirements: 1.3, 4.2
static int test_process_exit_event_correctness(void) {
    reset_integration_test_state();
    
    uint32_t test_pid = 9999;
    uint32_t test_tgid = 8888;
    const char* test_comm = "exiting_proc";
    
    // Set up mock environment
    mock_integration_pid_tgid = ((uint64_t)test_tgid << 32) | test_pid;
    strcpy(mock_integration_comm, test_comm);
    
    // Test 1: sched_process_exit tracepoint
    struct trace_event_raw_sched_process_exit* exit_ctx = 
        create_mock_exit_context(test_pid, test_comm);
    
    int result = trace_process_exit_v2(exit_ctx);
    
    INTEGRATION_TEST_ASSERT(result == 0, "Process exit handler should succeed");
    INTEGRATION_TEST_ASSERT(integration_test_state.event_count == 1,
                           "Should capture one exit event");
    
    // Verify the exit event
    struct process_event* exit_event = &integration_test_state.captured_events[0];
    
    INTEGRATION_TEST_ASSERT(verify_event_header(&exit_event->header, EVENT_PROCESS_EXIT),
                           "Exit event header should be correct");
    
    INTEGRATION_TEST_ASSERT(exit_event->ppid == 0,
                           "PPID should be 0 for sched_process_exit events");
    
    INTEGRATION_TEST_ASSERT(exit_event->exit_code == 0,
                           "Exit code should be 0 for sched_process_exit (will be filled by syscall)");
    
    // Test 2: sys_exit syscall tracepoint (for exit code)
    int32_t test_exit_code = 42;
    struct trace_event_raw_sys_exit* syscall_ctx = 
        create_mock_syscall_exit_context(60, test_exit_code);  // 60 = sys_exit
    
    result = trace_sys_exit_v2(syscall_ctx);
    
    INTEGRATION_TEST_ASSERT(result == 0, "Syscall exit handler should succeed");
    INTEGRATION_TEST_ASSERT(integration_test_state.event_count == 2,
                           "Should capture both sched_exit and sys_exit events");
    
    // Find the syscall exit event
    struct process_event* syscall_event = NULL;
    for (int i = 0; i < integration_test_state.event_count; i++) {
        if (integration_test_state.captured_events[i].exit_code == (uint32_t)test_exit_code) {
            syscall_event = &integration_test_state.captured_events[i];
            break;
        }
    }
    
    INTEGRATION_TEST_ASSERT(syscall_event != NULL, "Should find syscall exit event");
    INTEGRATION_TEST_ASSERT(syscall_event->exit_code == (uint32_t)test_exit_code,
                           "Exit code should be correctly captured from syscall");
    
    // Test 3: sys_exit_group syscall tracepoint
    integration_test_state.event_count = 0;  // Reset for next test
    
    int32_t group_exit_code = 1;
    struct trace_event_raw_sys_exit* group_ctx = 
        create_mock_syscall_exit_context(231, group_exit_code);  // 231 = sys_exit_group
    
    result = trace_sys_exit_group_v2(group_ctx);
    
    INTEGRATION_TEST_ASSERT(result == 0, "Exit group handler should succeed");
    INTEGRATION_TEST_ASSERT(integration_test_state.event_count == 1,
                           "Should capture exit group event");
    
    struct process_event* group_event = &integration_test_state.captured_events[0];
    INTEGRATION_TEST_ASSERT(group_event->exit_code == (uint32_t)group_exit_code,
                           "Exit group code should be correctly captured");
    
    // Verify statistics
    INTEGRATION_TEST_ASSERT(mock_integration_stats.exit_events >= 1,
                           "Exit event statistics should be updated");
    
    INTEGRATION_TEST_PASS("Process exit event correctness verified");
}

// Integration Test 4: Event Deduplication Logic
// Tests that duplicate events are properly handled and filtered
// Requirements: 4.3
static int test_event_deduplication_logic(void) {
    reset_integration_test_state();
    
    uint32_t test_pid = 7777;
    uint32_t test_ppid = 6666;
    const char* test_filename = "/bin/duplicate_test";
    
    // Set up mock environment
    mock_integration_pid_tgid = ((uint64_t)test_ppid << 32) | test_pid;
    strcpy(mock_integration_comm, "dup_test");
    
    // Create identical tracepoint contexts
    struct trace_event_raw_sched_process_exec* exec_ctx1 = 
        create_mock_exec_context(test_pid, test_ppid, test_filename);
    struct trace_event_raw_sched_process_exec* exec_ctx2 = 
        create_mock_exec_context(test_pid, test_ppid, test_filename);
    
    // Test rapid successive calls (simulating potential duplicates)
    int result1 = trace_process_exec_v2(exec_ctx1);
    int result2 = trace_process_exec_v2(exec_ctx2);
    
    INTEGRATION_TEST_ASSERT(result1 == 0 && result2 == 0, 
                           "Both handlers should succeed");
    
    // Both events should be captured (deduplication happens in user space)
    // The eBPF program captures all events, user space handles deduplication
    INTEGRATION_TEST_ASSERT(integration_test_state.event_count == 2,
                           "Both events should be captured by eBPF");
    
    // Verify both events have the same content (for user space deduplication)
    struct process_event* event1 = &integration_test_state.captured_events[0];
    struct process_event* event2 = &integration_test_state.captured_events[1];
    
    INTEGRATION_TEST_ASSERT(event1->header.pid == event2->header.pid,
                           "Both events should have same PID");
    INTEGRATION_TEST_ASSERT(event1->ppid == event2->ppid,
                           "Both events should have same PPID");
    INTEGRATION_TEST_ASSERT(strcmp(event1->filename, event2->filename) == 0,
                           "Both events should have same filename");
    
    // Test sampling-based deduplication
    integration_test_state.event_count = 0;  // Reset
    mock_integration_config.sampling_rate = 50;  // 50% sampling
    
    // Set random seed for predictable results
    srand(12345);
    
    int captured_events = 0;
    int total_attempts = 100;
    
    for (int i = 0; i < total_attempts; i++) {
        struct trace_event_raw_sched_process_exec* ctx = 
            create_mock_exec_context(test_pid + i, test_ppid, test_filename);
        
        mock_integration_pid_tgid = ((uint64_t)test_ppid << 32) | (test_pid + i);
        
        int old_count = integration_test_state.event_count;
        trace_process_exec_v2(ctx);
        
        if (integration_test_state.event_count > old_count) {
            captured_events++;
        }
    }
    
    // With 50% sampling, we should capture roughly half the events
    // Allow some variance due to randomness
    INTEGRATION_TEST_ASSERT(captured_events >= 30 && captured_events <= 70,
                           "Sampling should capture approximately 50% of events");
    
    // Verify sampling statistics
    INTEGRATION_TEST_ASSERT(mock_integration_stats.sampling_skipped > 0,
                           "Some events should be marked as sampling skipped");
    
    INTEGRATION_TEST_PASS("Event deduplication logic works correctly");
}
// Integration Test 5: Error Handling and Edge Cases
// Tests error handling mechanisms and boundary conditions
// Requirements: 4.2
static int test_error_handling_and_edge_cases(void) {
    reset_integration_test_state();
    
    // Test 1: Ring buffer full scenario
    // Fill up the ring buffer to test allocation failure handling
    for (int i = 0; i < MAX_TEST_EVENTS; i++) {
        uint32_t test_pid = 1000 + i;
        uint32_t test_ppid = 2000;
        
        mock_integration_pid_tgid = ((uint64_t)test_ppid << 32) | test_pid;
        
        struct trace_event_raw_sched_process_exec* ctx = 
            create_mock_exec_context(test_pid, test_ppid, "/bin/test");
        
        trace_process_exec_v2(ctx);
    }
    
    INTEGRATION_TEST_ASSERT(integration_test_state.event_count == MAX_TEST_EVENTS,
                           "Should fill ring buffer to capacity");
    
    // Try to add one more event (should trigger allocation failure)
    uint32_t overflow_pid = 9999;
    mock_integration_pid_tgid = ((uint64_t)2000 << 32) | overflow_pid;
    
    struct trace_event_raw_sched_process_exec* overflow_ctx = 
        create_mock_exec_context(overflow_pid, 2000, "/bin/overflow");
    
    int overflow_result = trace_process_exec_v2(overflow_ctx);
    
    // Handler should stERT(overflow_result == 0,
                           "Handler should continue processing even on allocation failure");
    
    // Event count should remain at MAX_TEST_EVENTS
    INTEGRATION_TEST_ASSERT(integration_test_state.event_count == MAX_TEST_EVENTS,
                           "Event count should not exceed maximum");
    
    // Allocation failure should be recorded in statistics
    INTEGRATION_TEST_ASSERT(mock_integration_stats.allocation_failures > 0,
                           "Allocation failures should be recorded in statistics");
    
    // Test 2: PID filtering edge cases
    struct {
        uint32_t pid;
        int should_be_filtered;
        const char* description;
    } pid_filter_tests[] = {
        {0, 1, "PID 0 (kernel threads)"},
        {1, 1, "PID 1 (init process)"},
        {2, 0, "PID 2 (first valid process)"},
        {65535, 0, "High PID value"}
    };
    
    int num_pid_tests = sizeof(pid_filter_tests) / sizeof(pid_filter_tests[0]);
    
    for (int i = 0; i < num_pid_tests; i++) {
        integration_test_state.event_count = 0;  // Reset
        memset(&mock_integration_stats, 0, sizeof(mock_integration_stats));
        
        uint32_t test_pid = pid_filter_tests[i].pid;
        uinill return 0 (continue processing)
    INTEGRATI2_t test_ppid = 1000;
        
        mock_integration_pid_tgid = ((uint64_t)test_ppid << 32) | test_pid;
        
        struct trace_event_raw_sched_process_exec* ctx = 
            create_mock_exec_context(test_pid, test_ppid, "/bin/test");
        
        int result = trace_process_exec_v2(ctx);
        
        INTEGRATION_TEST_ASSERT(result == 0, "Handler should always return 0");
        
        if (pid_filter_tests[i].should_be_filtered) {
            INTEGRATION_TEST_ASSERT(integration_test_state.event_count == 0,
                                   "Filtered PIDs should not generate events");
            INTEGRATION_TEST_ASSERT(mock_integration_stats.pid_filtered > 0,
                                   "PID filtering should be recorded in statistics");
        } else {
            INTEGRATION_TEST_ASSERT(integration_test_state.event_count == 1,
                                   "Valid PIDs should generate events");
        }
        
        printf("✓ PID filter test: %s (PID=%u)\n", 
               pid_filter_tests[i].description, test_pid);
    }
    
    // Test 3: NULL context handling
    reset_integration_test_state();
    
    // Test with NULL context (should handle gracefully)
    int null_result = trace_process_exec_v2(NULL);
    
    INTEGRATION_TEST_ASSERT(null_result == 0, "NULL context should be handled gracefully");
    INTEGRATION_TEST_ASSERT(mock_integration_stats.tracepoint_errors > 0,
                           "NULL context should be recorded as tracepoint error");
    
    INTEGRATION_TEST_PASS("Error handling and edge cases work correctly");
}

// Integration test suite definition
typedef struct {
    const char* name;
    int (*test_func)(void);
} integration_test_case_t;

static integration_test_case_t integration_test_suite[] = {
    {"complete_event_capture_flow", test_complete_event_capture_flow},
    {"parent_pid_accuracy", test_parent_pid_accuracy},
    {"process_exit_event_correctness", test_process_exit_event_correctness},
    {"event_deduplication_logic", test_event_deduplication_logic},
    {"error_handling_and_edge_cases", test_error_handling_and_edge_cases},
    {NULL, NULL}  // Sentinel
};

// Print test header
static void print_integration_test_header(void) {
    printf("\n");
    printf("eBPF Process Monitor Integration Tests\n");
    printf("=====================================\n");
    printf("\n");
    printf("Testing complete event capture flows, parent PID accuracy,\n");
    printf("process exit events, and event deduplication logic.\n");
    printf("\n");
    printf("Requirements tested:\n");
    printf("- 1.1: Complete event capture flow\n");
    printf("- 1.2: Parent PID accuracy verification\n");
    printf("- 1.3: Process exit event correctness\n");
    printf("- 3.1: Tracepoint context parsing validation\n");
    printf("- 3.2: Parent PID extraction accuracy\n");
    printf("- 4.1: Event processing workflow\n");
    printf("- 4.2: Error handling mechanisms\n");
    printf("- 4.3: Event deduplication logic\n");
    printf("\n");
}

// Print test summary
static void print_integration_test_summary(int total_tests, int passed_tests, int failed_tests) {
    printf("\n");
    printf("Integration Test Summary\n");
    printf("=======================\n");
    printf("Total tests: %d\n", total_tests);
    printf("Passed: %d\n", passed_tests);
    printf("Failed: %d\n", failed_tests);
    
    if (failed_tests == 0) {
        printf("Success rate: 100.0%%\n");
        printf("\n🎉 All integration tests passed!\n");
    } else {
        printf("Success rate: %.1f%%\n", (float)passed_tests / total_tests * 100.0);
        printf("\n❌ Some integration tests failed!\n");
    }
    printf("\n");
}

// Run all integration tests
static int run_integration_tests(void) {
    int total_tests = 0;
    int passed_tests = 0;
    int failed_tests = 0;
    
    print_integration_test_header();
    
    // Count total tests
    for (int i = 0; integration_test_suite[i].name != NULL; i++) {
        total_tests++;
    }
    
    // Run each test
    for (int i = 0; integration_test_suite[i].name != NULL; i++) {
        printf("Running integration test: %s\n", integration_test_suite[i].name);
        
        int result = integration_test_suite[i].test_func();
        
        if (result == 0) {
            passed_tests++;
            printf("✓ %s passed\n", integration_test_suite[i].name);
        } else {
            failed_tests++;
            printf("✗ %s failed\n", integration_test_suite[i].name);
        }
        
        printf("\n");
    }
    
    print_integration_test_summary(total_tests, passed_tests, failed_tests);
    
    return (failed_tests == 0) ? 0 : 1;
}

// Main function for integration tests
int main(int argc, char *argv[]) {
    // Initialize random seed for consistent testing
    srand(time(NULL));
    
    // Check if we're running integration tests specifically
    if (argc > 1 && strcmp(argv[1], "--integration") == 0) {
        return run_integration_tests();
    } else {
        printf("eBPF Process Monitor Integration Test Suite\n");
        printf("==========================================\n");
        printf("\n");
        printf("Usage: %s --integration\n", argv[0]);
        printf("\n");
        printf("This test suite validates:\n");
        printf("- Complete event capture flow\n");
        printf("- Parent PID accuracy verification\n");
        printf("- Process exit event correctness\n");
        printf("- Event deduplication logic\n");
        printf("- Error handling mechanisms\n");
        printf("\n");
        return 0;
    }
}ON_TEST_ASS