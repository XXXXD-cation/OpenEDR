/*
 * eBPF Process Monitor Unit Tests
 * 
 * This file contains comprehensive unit tests for the eBPF process monitor
 * optimization, covering helper functions, event structure filling logic,
 * and error handling mechanisms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

// Mock eBPF types and constants for testing
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int32_t __s32;
typedef int64_t __s64;

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_PATH_LEN 4096

// Mock eBPF helper return values for testing
static __u64 mock_pid_tgid = 0x0000123400005678ULL;  // TGID=0x1234, PID=0x5678
static __u64 mock_uid_gid = 0x0000ABCD0000EF12ULL;   // GID=0xABCD, UID=0xEF12
static __u64 mock_timestamp = 1234567890123456789ULL;
static __u32 mock_cpu = 2;
static char mock_comm[TASK_COMM_LEN] = "test_process";

// Test configuration
static int test_failures = 0;
static int test_successes = 0;

// Test result macros
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("FAIL: %s - %s\n", __func__, message); \
            test_failures++; \
            return 0; \
        } else { \
            test_successes++; \
        } \
    } while(0)

#define TEST_PASS(message) \
    do { \
        printf("PASS: %s - %s\n", __func__, message); \
        return 1; \
    } while(0)

// Event types (from common.h)
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

// Error types (from common.h)
enum error_type {
    ERROR_EVENT_DROPPED = 0,
    ERROR_ALLOCATION_FAILURE = 1,
    ERROR_CONFIG_ERROR = 2,
    ERROR_DATA_READ_ERROR = 3,
    ERROR_TRACEPOINT_ERROR = 4,
};

// Monitor types (from common.h)
enum monitor_type {
    MONITOR_PROCESS = 0,
    MONITOR_NETWORK = 1,
    MONITOR_FILE = 2,
    MONITOR_SYSCALL = 3,
    MONITOR_SAMPLING_RATE = 4,
};

// Event structures (from common.h)
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

struct process_event {
    struct event_header header;
    __u32 ppid;
    __u32 exit_code;
    char filename[MAX_FILENAME_LEN];
    char args[512];
};

// Debug statistics structure
struct debug_stats {
    __u64 events_processed;
    __u64 events_dropped;
    __u64 allocation_failures;
    __u64 config_errors;
    __u64 data_read_errors;
    __u64 tracepoint_errors;
    __u64 exec_events;
    __u64 exit_events;
    __u64 sampling_skipped;
    __u64 pid_filtered;
    __u64 last_error_timestamp;
    __u32 last_error_type;
    __u32 last_error_pid;
};

// Configuration structure
struct config {
    __u32 enable_process_monitoring;
    __u32 enable_network_monitoring;
    __u32 enable_file_monitoring;
    __u32 enable_syscall_monitoring;
    __u32 sampling_rate;
};

// Tracepoint context structures for testing
struct trace_entry {
    __u16 type;
    __u8 flags;
    __u8 preempt_count;
    __s32 pid;
};

struct trace_event_raw_sched_process_exec {
    struct trace_entry ent;
    __u32 __data_loc_filename;
    __u32 pid;
    __u32 old_pid;
    char __data[256];  // Mock data area
};

struct trace_event_raw_sched_process_exit {
    struct trace_entry ent;
    char comm[16];
    __u32 pid;
    __s32 prio;
    char __data[0];
};

struct trace_event_raw_sys_exit {
    struct trace_entry ent;
    __s64 id;
    __s64 ret;
    char __data[0];
};

// Mock global variables for testing
static struct debug_stats mock_debug_stats = {0};
static struct config mock_config = {
    .enable_process_monitoring = 1,
    .enable_network_monitoring = 1,
    .enable_file_monitoring = 1,
    .enable_syscall_monitoring = 1,
    .sampling_rate = 100
};

// Mock random number for sampling tests
static __u32 mock_random = 50;

// Mock eBPF helper functions for testing
static __u64 bpf_get_current_pid_tgid(void) {
    return mock_pid_tgid;
}

static __u64 bpf_get_current_uid_gid(void) {
    return mock_uid_gid;
}

static __u64 bpf_ktime_get_ns(void) {
    return mock_timestamp;
}

static __u32 bpf_get_smp_processor_id(void) {
    return mock_cpu;
}

static int bpf_get_current_comm(void *buf, __u32 size) {
    if (size > sizeof(mock_comm)) {
        size = sizeof(mock_comm);
    }
    memcpy(buf, mock_comm, size);
    return 0;
}

static __u32 bpf_get_prandom_u32(void) {
    return mock_random;
}

static int bpf_probe_read_kernel_str(void *dst, __u32 size, const void *unsafe_ptr) {
    // Mock implementation - copy from a test string
    const char *test_filename = "/usr/bin/test_program";
    size_t len = strlen(test_filename);
    if (len >= size) len = size - 1;
    memcpy(dst, test_filename, len);
    ((char*)dst)[len] = '\0';
    return len;
}

// Mock map lookup function
static void* bpf_map_lookup_elem(void *map, const void *key) {
    // For debug_stats_map
    if (map == (void*)0x1000) {
        return &mock_debug_stats;
    }
    // For config_map
    if (map == (void*)0x2000) {
        return &mock_config;
    }
    return NULL;
}

// Mock atomic operations
static void __sync_fetch_and_add(__u64 *ptr, __u64 value) {
    *ptr += value;
}

// Mock memory operations
static void* __builtin_memset(void *s, int c, size_t n) {
    return memset(s, c, n);
}

// Mock map pointers for testing
static void *debug_stats_map = (void*)0x1000;
static void *config_map = (void*)0x2000;

// Helper functions to test (copied from common.h with modifications for testing)

static void fill_event_header(struct event_header *header, __u32 event_type) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    
    header->timestamp = bpf_ktime_get_ns();
    header->pid = pid_tgid & 0xFFFFFFFF;
    header->tgid = pid_tgid >> 32;
    header->uid = uid_gid & 0xFFFFFFFF;
    header->gid = uid_gid >> 32;
    header->event_type = event_type;
    header->cpu = bpf_get_smp_processor_id();
    
    bpf_get_current_comm(header->comm, sizeof(header->comm));
}

static int should_trace_pid(__u32 pid) {
    // Skip kernel threads (pid 0) and init (pid 1)
    if (pid <= 1) {
        return 0;
    }
    return 1;
}

static int get_config_value(__u32 key, __u32 *value) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(config_map, &config_key);
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

static int should_sample(__u32 rate) {
    if (rate == 0) return 0;
    if (rate >= 100) return 1;
    
    return (bpf_get_prandom_u32() % 100) < rate;
}

static void record_error(__u32 error_type) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        switch (error_type) {
            case ERROR_EVENT_DROPPED:
                __sync_fetch_and_add(&stats->events_dropped, 1);
                break;
            case ERROR_ALLOCATION_FAILURE:
                __sync_fetch_and_add(&stats->allocation_failures, 1);
                break;
            case ERROR_CONFIG_ERROR:
                __sync_fetch_and_add(&stats->config_errors, 1);
                break;
            case ERROR_DATA_READ_ERROR:
                __sync_fetch_and_add(&stats->data_read_errors, 1);
                break;
            case ERROR_TRACEPOINT_ERROR:
                __sync_fetch_and_add(&stats->tracepoint_errors, 1);
                break;
        }
        
        stats->last_error_timestamp = bpf_ktime_get_ns();
        stats->last_error_type = error_type;
        stats->last_error_pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    }
}

static void record_exec_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->exec_events, 1);
        __sync_fetch_and_add(&stats->events_processed, 1);
    }
}

static void record_exit_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->exit_events, 1);
        __sync_fetch_and_add(&stats->events_processed, 1);
    }
}

static void record_sampling_skipped(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->sampling_skipped, 1);
    }
}

static void record_pid_filtered(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->pid_filtered, 1);
    }
}

static int get_config_value_safe(__u32 key, __u32 *value, __u32 fallback) {
    int ret = get_config_value(key, value);
    if (ret < 0) {
        record_error(ERROR_CONFIG_ERROR);
        *value = fallback;
        return 0;
    }
    return ret;
}

static int should_process_event(__u32 monitor_type) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // PID filtering check
    if (!should_trace_pid(pid)) {
        record_pid_filtered();
        return 0;
    }
    
    // Configuration check with safe fallback
    __u32 enabled = 0;
    get_config_value_safe(monitor_type, &enabled, 1);
    
    if (!enabled) {
        return 0;
    }
    
    // Sampling rate check with safe fallback
    __u32 rate = 100;
    get_config_value_safe(MONITOR_SAMPLING_RATE, &rate, 100);
    
    if (!should_sample(rate)) {
        record_sampling_skipped();
        return 0;
    }
    
    return 1;
}

static int extract_filename_from_exec_ctx(
    struct trace_event_raw_sched_process_exec *ctx,
    char *filename, 
    size_t size) {
    
    // Get filename offset from __data_loc_filename
    __u32 offset = ctx->__data_loc_filename & 0xFFFF;
    
    // Validate offset to prevent out-of-bounds access
    if (offset > 4096) {
        record_error(ERROR_DATA_READ_ERROR);
        return -1;
    }
    
    // Read filename from __data area using kernel-safe read
    int ret = bpf_probe_read_kernel_str(filename, size, (char *)ctx + offset);
    if (ret < 0) {
        record_error(ERROR_DATA_READ_ERROR);
        return ret;
    }
    
    return 0;
}

static __u32 get_parent_pid_from_exec_ctx(
    struct trace_event_raw_sched_process_exec *ctx) {
    
    return ctx->old_pid;
}

static int handle_allocation_failure(void) {
    record_error(ERROR_ALLOCATION_FAILURE);
    return 0;
}

static int handle_config_error(void) {
    record_error(ERROR_CONFIG_ERROR);
    return 1;
}

static int handle_data_read_error(void) {
    record_error(ERROR_DATA_READ_ERROR);
    return 0;
}

static int handle_tracepoint_error(void) {
    record_error(ERROR_TRACEPOINT_ERROR);
    return 0;
}

static void fill_process_exec_info(
    struct process_event *event,
    struct trace_event_raw_sched_process_exec *ctx) {
    
    if (ctx) {
        event->ppid = get_parent_pid_from_exec_ctx(ctx);
    } else {
        event->ppid = 0;
        handle_tracepoint_error();
    }
    
    event->exit_code = 0;
    
    if (ctx && extract_filename_from_exec_ctx(ctx, event->filename, sizeof(event->filename)) < 0) {
        __builtin_memset(event->filename, 0, sizeof(event->filename));
        handle_data_read_error();
    } else if (!ctx) {
        __builtin_memset(event->filename, 0, sizeof(event->filename));
        handle_tracepoint_error();
    }
    
    __builtin_memset(event->args, 0, sizeof(event->args));
}

static void fill_process_exit_info(
    struct process_event *event,
    struct trace_event_raw_sched_process_exit *ctx) {
    
    event->ppid = 0;
    event->exit_code = 0;
    
    __builtin_memset(event->filename, 0, sizeof(event->filename));
    __builtin_memset(event->args, 0, sizeof(event->args));
}

// Test helper functions to reset state
static void reset_mock_state(void) {
    memset(&mock_debug_stats, 0, sizeof(mock_debug_stats));
    mock_config.enable_process_monitoring = 1;
    mock_config.enable_network_monitoring = 1;
    mock_config.enable_file_monitoring = 1;
    mock_config.enable_syscall_monitoring = 1;
    mock_config.sampling_rate = 100;
    mock_random = 50;
}

// Unit Tests

// Test 1: fill_event_header function
static int test_fill_event_header(void) {
    struct event_header header;
    memset(&header, 0, sizeof(header));
    
    fill_event_header(&header, EVENT_PROCESS_EXEC);
    
    TEST_ASSERT(header.timestamp == mock_timestamp, "Timestamp should match mock value");
    TEST_ASSERT(header.pid == (mock_pid_tgid & 0xFFFFFFFF), "PID should be extracted correctly");
    TEST_ASSERT(header.tgid == (mock_pid_tgid >> 32), "TGID should be extracted correctly");
    TEST_ASSERT(header.uid == (mock_uid_gid & 0xFFFFFFFF), "UID should be extracted correctly");
    TEST_ASSERT(header.gid == (mock_uid_gid >> 32), "GID should be extracted correctly");
    TEST_ASSERT(header.event_type == EVENT_PROCESS_EXEC, "Event type should match");
    TEST_ASSERT(header.cpu == mock_cpu, "CPU should match mock value");
    TEST_ASSERT(strcmp(header.comm, mock_comm) == 0, "Comm should match mock value");
    
    TEST_PASS("Event header filled correctly");
}

// Test 2: should_trace_pid function
static int test_should_trace_pid(void) {
    TEST_ASSERT(should_trace_pid(0) == 0, "Should not trace PID 0 (kernel)");
    TEST_ASSERT(should_trace_pid(1) == 0, "Should not trace PID 1 (init)");
    TEST_ASSERT(should_trace_pid(2) == 1, "Should trace PID 2");
    TEST_ASSERT(should_trace_pid(1000) == 1, "Should trace normal PIDs");
    
    TEST_PASS("PID filtering works correctly");
}

// Test 3: get_config_value function
static int test_get_config_value(void) {
    __u32 value;
    
    TEST_ASSERT(get_config_value(0, &value) == 0, "Should successfully get process monitoring config");
    TEST_ASSERT(value == 1, "Process monitoring should be enabled");
    
    TEST_ASSERT(get_config_value(4, &value) == 0, "Should successfully get sampling rate");
    TEST_ASSERT(value == 100, "Sampling rate should be 100");
    
    TEST_ASSERT(get_config_value(99, &value) == -1, "Should fail for invalid key");
    
    TEST_PASS("Configuration retrieval works correctly");
}

// Test 4: should_sample function
static int test_should_sample(void) {
    TEST_ASSERT(should_sample(0) == 0, "Should not sample with rate 0");
    TEST_ASSERT(should_sample(100) == 1, "Should always sample with rate 100");
    
    // Test with mock random value of 50
    mock_random = 30;
    TEST_ASSERT(should_sample(50) == 1, "Should sample when random < rate");
    
    mock_random = 70;
    TEST_ASSERT(should_sample(50) == 0, "Should not sample when random >= rate");
    
    TEST_PASS("Sampling logic works correctly");
}

// Test 5: Error recording functions
static int test_error_recording(void) {
    reset_mock_state();
    
    record_error(ERROR_ALLOCATION_FAILURE);
    TEST_ASSERT(mock_debug_stats.allocation_failures == 1, "Should record allocation failure");
    TEST_ASSERT(mock_debug_stats.last_error_type == ERROR_ALLOCATION_FAILURE, "Should record error type");
    
    record_error(ERROR_CONFIG_ERROR);
    TEST_ASSERT(mock_debug_stats.config_errors == 1, "Should record config error");
    
    record_error(ERROR_DATA_READ_ERROR);
    TEST_ASSERT(mock_debug_stats.data_read_errors == 1, "Should record data read error");
    
    record_error(ERROR_TRACEPOINT_ERROR);
    TEST_ASSERT(mock_debug_stats.tracepoint_errors == 1, "Should record tracepoint error");
    
    TEST_PASS("Error recording works correctly");
}

// Test 6: Event recording functions
static int test_event_recording(void) {
    reset_mock_state();
    
    record_exec_event();
    TEST_ASSERT(mock_debug_stats.exec_events == 1, "Should record exec event");
    TEST_ASSERT(mock_debug_stats.events_processed == 1, "Should increment processed events");
    
    record_exit_event();
    TEST_ASSERT(mock_debug_stats.exit_events == 1, "Should record exit event");
    TEST_ASSERT(mock_debug_stats.events_processed == 2, "Should increment processed events");
    
    record_sampling_skipped();
    TEST_ASSERT(mock_debug_stats.sampling_skipped == 1, "Should record sampling skip");
    
    record_pid_filtered();
    TEST_ASSERT(mock_debug_stats.pid_filtered == 1, "Should record PID filter");
    
    TEST_PASS("Event recording works correctly");
}

// Test 7: get_config_value_safe function
static int test_get_config_value_safe(void) {
    __u32 value;
    
    // Test normal case
    TEST_ASSERT(get_config_value_safe(0, &value, 0) == 0, "Should succeed with valid key");
    TEST_ASSERT(value == 1, "Should get correct value");
    
    // Test fallback case - simulate map lookup failure
    void *original_map = config_map;
    config_map = NULL;  // Force lookup failure
    
    TEST_ASSERT(get_config_value_safe(0, &value, 42) == 0, "Should succeed with fallback");
    TEST_ASSERT(value == 42, "Should use fallback value");
    TEST_ASSERT(mock_debug_stats.config_errors == 1, "Should record config error");
    
    config_map = original_map;  // Restore
    
    TEST_PASS("Safe config value retrieval works correctly");
}

// Test 8: should_process_event function
static int test_should_process_event(void) {
    reset_mock_state();
    
    // Set mock PID to a valid value
    mock_pid_tgid = 0x0000123400001000ULL;  // PID=4096, TGID=0x1234
    
    // Test normal case
    TEST_ASSERT(should_process_event(MONITOR_PROCESS) == 1, "Should process valid event");
    
    // Test PID filtering
    mock_pid_tgid = 0x0000123400000001ULL;  // PID=1 (init)
    TEST_ASSERT(should_process_event(MONITOR_PROCESS) == 0, "Should not process init PID");
    TEST_ASSERT(mock_debug_stats.pid_filtered == 1, "Should record PID filter");
    
    // Reset PID
    mock_pid_tgid = 0x0000123400001000ULL;
    
    // Test disabled monitoring
    mock_config.enable_process_monitoring = 0;
    TEST_ASSERT(should_process_event(MONITOR_PROCESS) == 0, "Should not process when disabled");
    
    // Reset config
    mock_config.enable_process_monitoring = 1;
    
    // Test sampling
    mock_config.sampling_rate = 50;
    mock_random = 75;  // Above threshold
    TEST_ASSERT(should_process_event(MONITOR_PROCESS) == 0, "Should not process when sampling skips");
    TEST_ASSERT(mock_debug_stats.sampling_skipped == 1, "Should record sampling skip");
    
    TEST_PASS("Event processing decision works correctly");
}

// Test 9: extract_filename_from_exec_ctx function
static int test_extract_filename_from_exec_ctx(void) {
    struct trace_event_raw_sched_process_exec ctx;
    char filename[MAX_FILENAME_LEN];
    
    // Setup mock context
    ctx.__data_loc_filename = 64;  // Valid offset
    strcpy(ctx.__data, "/usr/bin/test_program");
    
    TEST_ASSERT(extract_filename_from_exec_ctx(&ctx, filename, sizeof(filename)) == 0, 
                "Should successfully extract filename");
    
    // Test invalid offset
    ctx.__data_loc_filename = 5000;  // Invalid offset
    reset_mock_state();
    TEST_ASSERT(extract_filename_from_exec_ctx(&ctx, filename, sizeof(filename)) == -1, 
                "Should fail with invalid offset");
    TEST_ASSERT(mock_debug_stats.data_read_errors == 1, "Should record data read error");
    
    TEST_PASS("Filename extraction works correctly");
}

// Test 10: get_parent_pid_from_exec_ctx function
static int test_get_parent_pid_from_exec_ctx(void) {
    struct trace_event_raw_sched_process_exec ctx;
    ctx.old_pid = 1234;
    
    __u32 ppid = get_parent_pid_from_exec_ctx(&ctx);
    TEST_ASSERT(ppid == 1234, "Should return correct parent PID");
    
    TEST_PASS("Parent PID extraction works correctly");
}

// Test 11: Error handling functions
static int test_error_handlers(void) {
    reset_mock_state();
    
    TEST_ASSERT(handle_allocation_failure() == 0, "Should return 0 for allocation failure");
    TEST_ASSERT(mock_debug_stats.allocation_failures == 1, "Should record allocation failure");
    
    TEST_ASSERT(handle_config_error() == 1, "Should return 1 for config error");
    TEST_ASSERT(mock_debug_stats.config_errors == 1, "Should record config error");
    
    TEST_ASSERT(handle_data_read_error() == 0, "Should return 0 for data read error");
    TEST_ASSERT(mock_debug_stats.data_read_errors == 1, "Should record data read error");
    
    TEST_ASSERT(handle_tracepoint_error() == 0, "Should return 0 for tracepoint error");
    TEST_ASSERT(mock_debug_stats.tracepoint_errors == 1, "Should record tracepoint error");
    
    TEST_PASS("Error handlers work correctly");
}

// Test 12: fill_process_exec_info function
static int test_fill_process_exec_info(void) {
    struct process_event event;
    struct trace_event_raw_sched_process_exec ctx;
    
    // Setup mock context
    ctx.old_pid = 5678;
    ctx.__data_loc_filename = 64;
    strcpy(ctx.__data, "/usr/bin/test");
    
    memset(&event, 0, sizeof(event));
    fill_process_exec_info(&event, &ctx);
    
    TEST_ASSERT(event.ppid == 5678, "Should set correct parent PID");
    TEST_ASSERT(event.exit_code == 0, "Should set exit code to 0 for exec events");
    
    // Test with NULL context
    reset_mock_state();
    memset(&event, 0, sizeof(event));
    fill_process_exec_info(&event, NULL);
    
    TEST_ASSERT(event.ppid == 0, "Should set PPID to 0 with NULL context");
    TEST_ASSERT(mock_debug_stats.tracepoint_errors == 2, "Should record tracepoint errors");
    
    TEST_PASS("Process exec info filling works correctly");
}

// Test 13: fill_process_exit_info function
static int test_fill_process_exit_info(void) {
    struct process_event event;
    struct trace_event_raw_sched_process_exit ctx;
    
    // Fill with some data first
    memset(&event, 0xFF, sizeof(event));
    
    fill_process_exit_info(&event, &ctx);
    
    TEST_ASSERT(event.ppid == 0, "Should set PPID to 0 for exit events");
    TEST_ASSERT(event.exit_code == 0, "Should set exit code to 0");
    
    // Check that filename and args are cleared
    int filename_cleared = 1;
    for (int i = 0; i < MAX_FILENAME_LEN; i++) {
        if (event.filename[i] != 0) {
            filename_cleared = 0;
            break;
        }
    }
    TEST_ASSERT(filename_cleared, "Should clear filename");
    
    int args_cleared = 1;
    for (int i = 0; i < 512; i++) {
        if (event.args[i] != 0) {
            args_cleared = 0;
            break;
        }
    }
    TEST_ASSERT(args_cleared, "Should clear args");
    
    TEST_PASS("Process exit info filling works correctly");
}

// Test 14: Integration test for complete event processing flow
static int test_event_processing_flow(void) {
    reset_mock_state();
    
    // Set up for a successful event processing
    mock_pid_tgid = 0x0000123400001000ULL;  // Valid PID
    mock_config.enable_process_monitoring = 1;
    mock_config.sampling_rate = 100;  // Always sample
    mock_random = 50;
    
    // Test the complete flow
    TEST_ASSERT(should_process_event(MONITOR_PROCESS) == 1, "Should process event");
    
    // Simulate event creation and filling
    struct process_event event;
    struct trace_event_raw_sched_process_exec ctx;
    
    memset(&event, 0, sizeof(event));
    fill_event_header(&event.header, EVENT_PROCESS_EXEC);
    
    ctx.old_pid = 9999;
    ctx.__data_loc_filename = 64;
    strcpy(ctx.__data, "/bin/test_app");
    
    fill_process_exec_info(&event, &ctx);
    record_exec_event();
    
    // Verify the complete event
    TEST_ASSERT(event.header.event_type == EVENT_PROCESS_EXEC, "Should have correct event type");
    TEST_ASSERT(event.header.pid == 0x1000, "Should have correct PID");
    TEST_ASSERT(event.header.tgid == 0x1234, "Should have correct TGID");
    TEST_ASSERT(event.ppid == 9999, "Should have correct parent PID");
    TEST_ASSERT(mock_debug_stats.exec_events == 1, "Should record exec event");
    TEST_ASSERT(mock_debug_stats.events_processed == 1, "Should record processed event");
    
    TEST_PASS("Complete event processing flow works correctly");
}

// Test 15: Edge cases and error conditions
static int test_edge_cases(void) {
    reset_mock_state();
    
    // Test with all monitoring disabled
    mock_config.enable_process_monitoring = 0;
    mock_config.enable_network_monitoring = 0;
    mock_config.enable_file_monitoring = 0;
    mock_config.enable_syscall_monitoring = 0;
    
    TEST_ASSERT(should_process_event(MONITOR_PROCESS) == 0, "Should not process when disabled");
    TEST_ASSERT(should_process_event(MONITOR_NETWORK) == 0, "Should not process when disabled");
    TEST_ASSERT(should_process_event(MONITOR_FILE) == 0, "Should not process when disabled");
    TEST_ASSERT(should_process_event(MONITOR_SYSCALL) == 0, "Should not process when disabled");
    
    // Test with zero sampling rate
    mock_config.enable_process_monitoring = 1;
    mock_config.sampling_rate = 0;
    TEST_ASSERT(should_process_event(MONITOR_PROCESS) == 0, "Should not process with 0% sampling");
    TEST_ASSERT(mock_debug_stats.sampling_skipped == 1, "Should record sampling skip");
    
    // Test boundary PIDs
    mock_pid_tgid = 0x0000000000000000ULL;  // PID=0
    TEST_ASSERT(should_process_event(MONITOR_PROCESS) == 0, "Should not process PID 0");
    
    mock_pid_tgid = 0x0000000000000001ULL;  // PID=1
    TEST_ASSERT(should_process_event(MONITOR_PROCESS) == 0, "Should not process PID 1");
    
    mock_pid_tgid = 0x0000000000000002ULL;  // PID=2
    mock_config.sampling_rate = 100;
    TEST_ASSERT(should_process_event(MONITOR_PROCESS) == 1, "Should process PID 2");
    
    TEST_PASS("Edge cases handled correctly");
}

// Test runner structure
typedef struct {
    const char *name;
    int (*test_func)(void);
} test_case_t;

// Test suite definition
static test_case_t test_suite[] = {
    {"fill_event_header", test_fill_event_header},
    {"should_trace_pid", test_should_trace_pid},
    {"get_config_value", test_get_config_value},
    {"should_sample", test_should_sample},
    {"error_recording", test_error_recording},
    {"event_recording", test_event_recording},
    {"get_config_value_safe", test_get_config_value_safe},
    {"should_process_event", test_should_process_event},
    {"extract_filename_from_exec_ctx", test_extract_filename_from_exec_ctx},
    {"get_parent_pid_from_exec_ctx", test_get_parent_pid_from_exec_ctx},
    {"error_handlers", test_error_handlers},
    {"fill_process_exec_info", test_fill_process_exec_info},
    {"fill_process_exit_info", test_fill_process_exit_info},
    {"event_processing_flow", test_event_processing_flow},
    {"edge_cases", test_edge_cases},
    {NULL, NULL}  // Sentinel
};

// Main test runner
int main(int argc, char *argv[]) {
    printf("eBPF Process Monitor Unit Tests\n");
    printf("================================\n\n");
    
    int total_tests = 0;
    test_failures = 0;
    test_successes = 0;
    
    // Run all tests
    for (int i = 0; test_suite[i].name != NULL; i++) {
        printf("Running test: %s\n", test_suite[i].name);
        reset_mock_state();  // Reset state before each test
        
        if (test_suite[i].test_func()) {
            printf("✓ %s passed\n\n", test_suite[i].name);
        } else {
            printf("✗ %s failed\n\n", test_suite[i].name);
        }
        total_tests++;
    }
    
    // Print summary
    printf("Test Summary\n");
    printf("============\n");
    printf("Total tests: %d\n", total_tests);
    printf("Passed: %d\n", test_successes);
    printf("Failed: %d\n", test_failures);
    printf("Success rate: %.1f%%\n", 
           total_tests > 0 ? (float)test_successes / total_tests * 100 : 0);
    
    if (test_failures == 0) {
        printf("\n🎉 All tests passed!\n");
        return 0;
    } else {
        printf("\n❌ Some tests failed!\n");
        return 1;
    }
}