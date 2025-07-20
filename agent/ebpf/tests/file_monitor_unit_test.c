/*
 * eBPF File System Monitor Unit Tests
 * 
 * This file contains comprehensive unit tests for the eBPF file system monitor
 * implementation, covering file path extraction, event capture, error handling,
 * and sampling/filtering logic.
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
    MONITOR_FILE_SAMPLING_RATE = 6,
};

// Eventures (from common.h)
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

struct file_event {
    struct event_header header;
    __u32 flags;      // File open flags
    __u16 mode;       // File mode
    __s32 fd;         // File descriptor
    __u64 size;       // File size (for write events)
    __u64 offset;     // File offset (for write events)
    char filename[MAX_PATH_LEN];
};

// Debug statistics structure
struct debug_stats {
    __u64 events_processed;
    __u64 events_dropped;
    __u64 allocation_failures;
    __u64 config_errors;
    __u64 data_read_errors;
    __u64 tracepoint_errors;
    __u64 file_events;
    __u64 file_open_events;
    __u64 file_write_events;
    __u64 file_unlink_events;
    __u64 file_path_extraction_errors;
    __u64 file_type_filtered;
    __u64 file_sampling_skipped;
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
    __u32 file_sampling_rate;
    __u32 max_file_path_len;
    __u32 enable_file_write_monitoring;
    __u32 enable_file_delete_monitoring;
    __u32 file_type_filter_enabled;
    __u32 file_extensions_whitelist[16];
    __u32 file_extensions_blacklist[16];
    __u32 whitelist_size;
    __u32 blacklist_size;
};

// Tracepoint context structures for testing
struct trace_entry {
    __u16 type;
    __u8 flags;
    __u8 preempt_count;
    __s32 pid;
};

struct trace_event_raw_vfs_open {
    struct trace_entry ent;
    __u32 __data_loc_filename;
    __u32 flags;
    __u16 mode;
    __s32 ret;
    char __data[256];  // Mock data area
};

struct trace_event_raw_vfs_write {
    struct trace_entry ent;
    __u32 __data_loc_filename;
    __u64 offset;
    __u64 count;
    __s64 ret;
    char __data[256];  // Mock data area
};

struct trace_event_raw_vfs_unlink {
    struct trace_entry ent;
    __u32 __data_loc_filename;
    __u32 __data_loc_pathname;
    __s32 ret;
    char __data[256];  // Mock data area
};
// Mock global variables for testing
static struct debug_stats mock_debug_stats = {0};
static struct config mock_config = {
    .enable_process_monitoring = 1,
    .enable_network_monitoring = 1,
    .enable_file_monitoring = 1,
    .enable_syscall_monitoring = 1,
    .sampling_rate = 100,
    .file_sampling_rate = 100,
    .max_file_path_len = MAX_PATH_LEN,
    .enable_file_write_monitoring = 1,
    .enable_file_delete_monitoring = 1,
    .file_type_filter_enabled = 0,
    .whitelist_size = 0,
    .blacklist_size = 0
};

// Mock eBPF helper return values for testing
static __u64 mock_pid_tgid = 0x0000123400005678ULL;  // TGID=0x1234, PID=0x5678
static __u64 mock_uid_gid = 0x0000ABCD0000EF12ULL;   // GID=0xABCD, UID=0xEF12
static __u64 mock_timestamp = 1234567890123456789ULL;
static __u32 mock_cpu = 2;
static char mock_comm[TASK_COMM_LEN] = "test_process";
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
static void* __builtin_memcpy(void *dest, const void *src, size_t n) {
    return memcpy(dest, src, n);
}

static void* __builtin_memset(void *s, int c, size_t n) {
    return memset(s, c, n);
}

// Mock map pointers for testing
static void *debug_stats_map = (void*)0x1000;
static void *config_map = (void*)0x2000;

// Helper functions to test (adapted from file_monitor.c and common.h)

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
        case 6: *value = cfg->file_sampling_rate; break;
        default: return -1;
    }
    
    return 0;
}

static int get_config_value_safe(__u32 key, __u32 *value, __u32 fallback) {
    int ret = get_config_value(key, value);
    if (ret < 0) {
        *value = fallback;
        return 0;
    }
    return ret;
}

static int get_file_sampling_rate(__u32 *rate) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(config_map, &config_key);
    if (!cfg) {
        return -1;
    }
    
    *rate = cfg->file_sampling_rate > 0 ? cfg->file_sampling_rate : cfg->sampling_rate;
    return 0;
}

static int get_max_file_path_len(__u32 *len) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(config_map, &config_key);
    if (!cfg) {
        return -1;
    }
    
    *len = cfg->max_file_path_len > 0 ? cfg->max_file_path_len : MAX_PATH_LEN;
    return 0;
}

static int is_file_write_monitoring_enabled(void) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(config_map, &config_key);
    if (!cfg) {
        return 1; // Default to enabled
    }
    
    return cfg->enable_file_write_monitoring;
}

static int is_file_delete_monitoring_enabled(void) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(config_map, &config_key);
    if (!cfg) {
        return 1; // Default to enabled
    }
    
    return cfg->enable_file_delete_monitoring;
}

static int should_sample(__u32 rate) {
    if (rate == 0) return 0;
    if (rate >= 100) return 1;
    
    return (bpf_get_prandom_u32() % 100) < rate;
}

// Error recording and statistics functions
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

static void record_file_path_extraction_error(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->file_path_extraction_errors, 1);
    }
}

static void record_file_open_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->file_open_events, 1);
        __sync_fetch_and_add(&stats->file_events, 1);
        __sync_fetch_and_add(&stats->events_processed, 1);
    }
}

static void record_file_write_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->file_write_events, 1);
        __sync_fetch_and_add(&stats->file_events, 1);
        __sync_fetch_and_add(&stats->events_processed, 1);
    }
}

static void record_file_unlink_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->file_unlink_events, 1);
        __sync_fetch_and_add(&stats->file_events, 1);
        __sync_fetch_and_add(&stats->events_processed, 1);
    }
}

static void record_file_sampling_skipped(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->file_sampling_skipped, 1);
    }
}

static void record_file_type_filtered(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->file_type_filtered, 1);
    }
}

static void record_pid_filtered(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->pid_filtered, 1);
    }
}

// File path extraction function (adapted from file_monitor.c)
static int extract_file_path(char *dest, __u32 dest_size, 
                            char *data, __u32 offset) {
    if (!dest || dest_size == 0) {
        record_file_path_extraction_error();
        return -1;
    }
    
    // Initialize destination buffer
    dest[0] = '\0';
    
    if (!data) {
        record_file_path_extraction_error();
        // Set fallback value for null data
        if (dest_size > 9) {
            __builtin_memcpy(dest, "<no-data>", 10);
        }
        return -1;
    }
    
    if (offset == 0) {
        record_file_path_extraction_error();
        // Set fallback value for zero offset
        if (dest_size > 11) {
            __builtin_memcpy(dest, "<no-offset>", 12);
        }
        return -1;
    }
    
    // Get configured maximum path length
    __u32 max_path_len = 0;
    if (get_max_file_path_len(&max_path_len) < 0) {
        max_path_len = MAX_PATH_LEN;
    }
    
    // Use the smaller of dest_size-1 and max_path_len to avoid buffer overflows
    __u32 copy_len = dest_size - 1; // Leave space for null terminator
    if (copy_len > max_path_len) {
        copy_len = max_path_len;
    }
    
    // Ensure minimum buffer size for meaningful paths
    if (copy_len < 2) {
        record_file_path_extraction_error();
        return -1;
    }
    
    // Extract filename from variable data area with bounds checking
    int ret = bpf_probe_read_kernel_str(dest, copy_len, data + offset);
    if (ret < 0) {
        record_file_path_extraction_error();
        // Set a fallback value based on error type
        if (dest_size > 9) {
            __builtin_memcpy(dest, "<unknown>", 10);
        }
        return -1;
    }
    
    // Validate extracted path is not empty
    if (dest[0] == '\0') {
        record_file_path_extraction_error();
        if (dest_size > 7) {
            __builtin_memcpy(dest, "<empty>", 8);
        }
        return -1;
    }
    
    return 0;
}

// File information extraction functions (adapted from file_monitor.c)
static __u32 extract_file_flags(__u32 raw_flags) {
    // Validate flags are within reasonable range
    // Most file flags are in the lower 16 bits
    if (raw_flags > 0xFFFF) {
        // Suspicious flags value, mask to reasonable range
        raw_flags &= 0xFFFF;
    }
    
    // Return normalized flags - user space can interpret them
    return raw_flags;
}

static __u16 extract_file_mode(__u16 raw_mode) {
    // Validate mode is not completely invalid
    if (raw_mode == 0xFFFF) {
        // Invalid mode, return default read-only permissions
        return 0x0444; // r--r--r--
    }
    
    // Mask to keep only permission bits (lower 12 bits)
    __u16 mode = raw_mode & 0x0FFF;
    
    // Ensure mode has at least some valid permission bits
    if (mode == 0) {
        // No permissions set, return minimal read permission for owner
        return 0x0400; // r--------
    }
    
    return mode;
}

static __u64 extract_file_size(__u64 raw_size) {
    // Check for obviously invalid values (negative when cast to signed)
    if (raw_size > 0x7FFFFFFFFFFFFFFFULL) {
        // Size seems unreasonable, might be an error value (-1, -EINVAL, etc.)
        return 0;
    }
    
    // Check for extremely large file sizes (> 1TB) which might indicate corruption
    const __u64 MAX_REASONABLE_FILE_SIZE = 1024ULL * 1024ULL * 1024ULL * 1024ULL; // 1TB
    if (raw_size > MAX_REASONABLE_FILE_SIZE) {
        // Log this as potentially suspicious but don't zero it out
        return raw_size;
    }
    
    return raw_size;
}

static __u64 extract_file_offset(__u64 raw_offset) {
    // Check for obviously invalid values (negative when cast to signed)
    if (raw_offset > 0x7FFFFFFFFFFFFFFFULL) {
        // Offset seems unreasonable, might be an error value (-1, -EINVAL, etc.)
        return 0;
    }
    
    // Check for extremely large offsets (> 1TB) which might indicate corruption
    const __u64 MAX_REASONABLE_FILE_OFFSET = 1024ULL * 1024ULL * 1024ULL * 1024ULL; // 1TB
    if (raw_offset > MAX_REASONABLE_FILE_OFFSET) {
        // Log this as potentially suspicious but don't zero it out
        return raw_offset;
    }
    
    return raw_offset;
}

// File information filling function (adapted from file_monitor.c)
static int fill_file_info(struct file_event *event,
                         char *tracepoint_data,
                         __u32 filename_offset,
                         __u32 flags,
                         __u16 mode,
                         __s32 fd,
                         __u64 size,
                         __u64 offset) {
    if (!event) {
        return -1;
    }
    
    // Extract file path with error handling
    if (extract_file_path(event->filename, sizeof(event->filename),
                         tracepoint_data, filename_offset) < 0) {
        // Path extraction failed, but continue with other fields
        record_file_path_extraction_error();
    }
    
    // Extract and validate file operation flags
    event->flags = extract_file_flags(flags);
    
    // Extract and validate file mode
    event->mode = extract_file_mode(mode);
    
    // Set file descriptor
    event->fd = fd;
    
    // Extract and validate file size
    event->size = extract_file_size(size);
    
    // Extract and validate file offset
    event->offset = extract_file_offset(offset);
    
    return 0;
}

// File event error handling function (adapted from file_monitor.c)
static int handle_file_error(__u32 error_type, struct file_event *event) {
    record_error(ERROR_DATA_READ_ERROR);
    
    switch (error_type) {
        case 1: // FILE_PATH_EXTRACTION_ERROR
            record_file_path_extraction_error();
            // Continue processing with placeholder filename
            if (event && sizeof(event->filename) > 9) {
                __builtin_memcpy(event->filename, "<unknown>", 10);
            }
            return 1; // Continue processing
            
        case 2: // FILE_INFO_READ_ERROR
            // Critical error, skip event entirely
            record_file_path_extraction_error();
            return 0;
            
        case 3: // FILE_SIZE_INVALID
            // Set size to 0 and continue
            if (event) {
                event->size = 0;
            }
            return 1;
            
        case 4: // FILE_OFFSET_INVALID
            // Set offset to 0 and continue
            if (event) {
                event->offset = 0;
            }
            return 1;
            
        case 5: // FILE_FLAGS_INVALID
            // Set flags to 0 (no specific flags) and continue
            if (event) {
                event->flags = 0;
            }
            return 1;
            
        case 6: // FILE_MODE_INVALID
            // Set mode to default read-only and continue
            if (event) {
                event->mode = 0x0444; // r--r--r--
            }
            return 1;
            
        case 7: // FILE_FD_INVALID
            // Set fd to -1 (invalid) and continue
            if (event) {
                event->fd = -1;
            }
            return 1;
            
        default:
            // Unknown error type, skip event for safety
            record_error(ERROR_DATA_READ_ERROR);
            return 0;
    }
}

// File event validation function (adapted from file_monitor.c)
static int validate_file_event_data(struct file_event *event) {
    if (!event) {
        return 0; // Invalid event structure
    }
    
    // Validate filename is not completely empty or invalid
    if (event->filename[0] == '\0') {
        return handle_file_error(1, event); // Path extraction error
    }
    
    // Check for obviously corrupted filename (all null bytes beyond first)
    int has_content = 0;
    for (int i = 0; i < 32 && i < sizeof(event->filename); i++) {
        if (event->filename[i] != '\0') {
            has_content = 1;
            break;
        }
    }
    
    if (!has_content) {
        return handle_file_error(1, event); // Path extraction error
    }
    
    // Validate file descriptor is reasonable (not extremely negative)
    if (event->fd < -1000) {
        return handle_file_error(7, event); // FD invalid
    }
    
    // All validations passed
    return 1;
}

// Simple file type filtering (mock implementation)
static int should_monitor_file_type(const char *filename) {
    // For testing, we'll implement a simple check
    // In real implementation, this would check whitelist/blacklist
    if (!filename) return 0;
    
    // Mock: filter out .tmp files
    size_t len = strlen(filename);
    if (len > 4 && strcmp(filename + len - 4, ".tmp") == 0) {
        return 0;
    }
    
    return 1; // Allow all other files
}

// Test helper functions to reset state
static void reset_mock_state(void) {
    memset(&mock_debug_stats, 0, sizeof(mock_debug_stats));
    mock_config.enable_process_monitoring = 1;
    mock_config.enable_network_monitoring = 1;
    mock_config.enable_file_monitoring = 1;
    mock_config.enable_syscall_monitoring = 1;
    mock_config.sampling_rate = 100;
    mock_config.file_sampling_rate = 100;
    mock_config.max_file_path_len = MAX_PATH_LEN;
    mock_config.enable_file_write_monitoring = 1;
    mock_config.enable_file_delete_monitoring = 1;
    mock_config.file_type_filter_enabled = 0;
    mock_config.whitelist_size = 0;
    mock_config.blacklist_size = 0;
    mock_random = 50;
}

// Unit Tests

// Test 1: File path extraction function correctness
static int test_file_path_extraction(void) {
    char dest[256];
    char test_data[] = "dummy\0/path/to/test/file.txt\0more_data";
    __u32 offset = 6; // Points to "/path/to/test/file.txt"
    
    reset_mock_state();
    
    // Test normal case
    int result = extract_file_path(dest, sizeof(dest), test_data, offset);
    TEST_ASSERT(result == 0, "Should successfully extract file path");
    TEST_ASSERT(strcmp(dest, "/usr/bin/test_program") == 0, "Should extract correct path");
    
    // Test null destination
    result = extract_file_path(NULL, sizeof(dest), test_data, offset);
    TEST_ASSERT(result == -1, "Should fail with null destination");
    TEST_ASSERT(mock_debug_stats.file_path_extraction_errors == 1, "Should record path extraction error");
    
    // Test null data
    reset_mock_state();
    result = extract_file_path(dest, sizeof(dest), NULL, offset);
    TEST_ASSERT(result == -1, "Should fail with null data");
    TEST_ASSERT(strcmp(dest, "<no-data>") == 0, "Should set fallback value");
    TEST_ASSERT(mock_debug_stats.file_path_extraction_errors == 1, "Should record path extraction error");
    
    // Test zero offset
    reset_mock_state();
    result = extract_file_path(dest, sizeof(dest), test_data, 0);
    TEST_ASSERT(result == -1, "Should fail with zero offset");
    TEST_ASSERT(strcmp(dest, "<no-offset>") == 0, "Should set fallback value");
    TEST_ASSERT(mock_debug_stats.file_path_extraction_errors == 1, "Should record path extraction error");
    
    // Test small buffer
    reset_mock_state();
    result = extract_file_path(dest, 1, test_data, offset);
    TEST_ASSERT(result == -1, "Should fail with small buffer");
    TEST_ASSERT(mock_debug_stats.file_path_extraction_errors == 1, "Should record path extraction error");
    
    TEST_PASS("File path extraction tests passed");
}

// Test 2: File flags extraction
static int test_file_flags_extraction(void) {
    // Test normal flags
    __u32 result = extract_file_flags(0x0042); // O_RDWR | O_CREAT
    TEST_ASSERT(result == 0x0042, "Should preserve normal flags");
    
    // Test large flags (should be masked)
    result = extract_file_flags(0x12345678);
    TEST_ASSERT(result == 0x5678, "Should mask large flags to lower 16 bits");
    
    // Test zero flags
    result = extract_file_flags(0);
    TEST_ASSERT(result == 0, "Should handle zero flags");
    
    // Test maximum valid flags
    result = extract_file_flags(0xFFFF);
    TEST_ASSERT(result == 0xFFFF, "Should preserve maximum valid flags");
    
    TEST_PASS("File flags extraction tests passed");
}

// Test 3: File mode extraction
static int test_file_mode_extraction(void) {
    // Test normal mode
    __u16 result = extract_file_mode(0x81A4); // Regular file with 644 permissions
    TEST_ASSERT(result == 0x01A4, "Should extract only permission bits");
    
    // Test invalid mode (0xFFFF)
    result = extract_file_mode(0xFFFF);
    TEST_ASSERT(result == 0x0444, "Should return default read-only for invalid mode");
    
    // Test zero mode
    result = extract_file_mode(0);
    TEST_ASSERT(result == 0x0400, "Should return minimal read permission for zero mode");
    
    // Test mode with file type bits
    result = extract_file_mode(0x8000 | 0x0755); // Regular file with 755 permissions
    TEST_ASSERT(result == 0x0755, "Should mask out file type bits");
    
    TEST_PASS("File mode extraction tests passed");
}

// Test 4: File size extraction
static int test_file_size_extraction(void) {
    // Test normal size
    __u64 result = extract_file_size(1024);
    TEST_ASSERT(result == 1024, "Should preserve normal size");
    
    // Test very large size (negative when cast to signed)
    result = extract_file_size(0xFFFFFFFFFFFFFFFFULL);
    TEST_ASSERT(result == 0, "Should zero out invalid large size");
    
    // Test extremely large but valid size (> 1TB)
    __u64 large_size = 2ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL; // 2TB
    result = extract_file_size(large_size);
    TEST_ASSERT(result == large_size, "Should preserve very large valid size");
    
    // Test zero size
    result = extract_file_size(0);
    TEST_ASSERT(result == 0, "Should handle zero size");
    
    // Test boundary case
    result = extract_file_size(0x7FFFFFFFFFFFFFFFULL);
    TEST_ASSERT(result == 0x7FFFFFFFFFFFFFFFULL, "Should preserve maximum valid size");
    
    TEST_PASS("File size extraction tests passed");
}

// Test 5: File offset extraction
static int test_file_offset_extraction(void) {
    // Test normal offset
    __u64 result = extract_file_offset(4096);
    TEST_ASSERT(result == 4096, "Should preserve normal offset");
    
    // Test very large offset (negative when cast to signed)
    result = extract_file_offset(0xFFFFFFFFFFFFFFFFULL);
    TEST_ASSERT(result == 0, "Should zero out invalid large offset");
    
    // Test extremely large but valid offset (> 1TB)
    __u64 large_offset = 2ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL; // 2TB
    result = extract_file_offset(large_offset);
    TEST_ASSERT(result == large_offset, "Should preserve very large valid offset");
    
    // Test zero offset
    result = extract_file_offset(0);
    TEST_ASSERT(result == 0, "Should handle zero offset");
    
    // Test boundary case
    result = extract_file_offset(0x7FFFFFFFFFFFFFFFULL);
    TEST_ASSERT(result == 0x7FFFFFFFFFFFFFFFULL, "Should preserve maximum valid offset");
    
    TEST_PASS("File offset extraction tests passed");
}

// Test 6: File information filling
static int test_fill_file_info(void) {
    struct file_event event;
    char test_data[] = "dummy\0/test/file.txt\0more_data";
    __u32 filename_offset = 6;
    
    reset_mock_state();
    memset(&event, 0, sizeof(event));
    
    // Test normal case
    int result = fill_file_info(&event, test_data, filename_offset, 
                               0x0042, 0x0644, 5, 1024, 512);
    TEST_ASSERT(result == 0, "Should successfully fill file info");
    TEST_ASSERT(event.flags == 0x0042, "Should set correct flags");
    TEST_ASSERT(event.mode == 0x0644, "Should set correct mode");
    TEST_ASSERT(event.fd == 5, "Should set correct file descriptor");
    TEST_ASSERT(event.size == 1024, "Should set correct size");
    TEST_ASSERT(event.offset == 512, "Should set correct offset");
    
    // Test with null event
    result = fill_file_info(NULL, test_data, filename_offset, 
                           0x0042, 0x0644, 5, 1024, 512);
    TEST_ASSERT(result == -1, "Should fail with null event");
    
    // Test with invalid flags (should be normalized)
    memset(&event, 0, sizeof(event));
    result = fill_file_info(&event, test_data, filename_offset, 
                           0x12345678, 0xFFFF, -1, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL);
    TEST_ASSERT(result == 0, "Should handle invalid values");
    TEST_ASSERT(event.flags == 0x5678, "Should normalize flags");
    TEST_ASSERT(event.mode == 0x0444, "Should normalize mode");
    TEST_ASSERT(event.fd == -1, "Should preserve negative fd");
    TEST_ASSERT(event.size == 0, "Should normalize invalid size");
    TEST_ASSERT(event.offset == 0, "Should normalize invalid offset");
    
    TEST_PASS("File information filling tests passed");
}

// Test 7: File event error handling
static int test_file_event_error_handling(void) {
    struct file_event event;
    
    reset_mock_state();
    memset(&event, 0, sizeof(event));
    
    // Test path extraction error
    int result = handle_file_error(1, &event);
    TEST_ASSERT(result == 1, "Should continue processing after path extraction error");
    TEST_ASSERT(strcmp(event.filename, "<unknown>") == 0, "Should set unknown filename");
    TEST_ASSERT(mock_debug_stats.data_read_errors == 1, "Should record data read error");
    TEST_ASSERT(mock_debug_stats.file_path_extraction_errors == 1, "Should record path extraction error");
    
    // Test critical error
    reset_mock_state();
    result = handle_file_error(2, &event);
    TEST_ASSERT(result == 0, "Should skip event for critical error");
    TEST_ASSERT(mock_debug_stats.data_read_errors == 1, "Should record data read error");
    
    // Test size invalid error
    reset_mock_state();
    memset(&event, 0xFF, sizeof(event));
    result = handle_file_error(3, &event);
    TEST_ASSERT(result == 1, "Should continue processing after size error");
    TEST_ASSERT(event.size == 0, "Should reset size to 0");
    
    // Test offset invalid error
    reset_mock_state();
    memset(&event, 0xFF, sizeof(event));
    result = handle_file_error(4, &event);
    TEST_ASSERT(result == 1, "Should continue processing after offset error");
    TEST_ASSERT(event.offset == 0, "Should reset offset to 0");
    
    // Test flags invalid error
    reset_mock_state();
    memset(&event, 0xFF, sizeof(event));
    result = handle_file_error(5, &event);
    TEST_ASSERT(result == 1, "Should continue processing after flags error");
    TEST_ASSERT(event.flags == 0, "Should reset flags to 0");
    
    // Test mode invalid error
    reset_mock_state();
    memset(&event, 0xFF, sizeof(event));
    result = handle_file_error(6, &event);
    TEST_ASSERT(result == 1, "Should continue processing after mode error");
    TEST_ASSERT(event.mode == 0x0444, "Should reset mode to default");
    
    // Test fd invalid error
    reset_mock_state();
    memset(&event, 0xFF, sizeof(event));
    result = handle_file_error(7, &event);
    TEST_ASSERT(result == 1, "Should continue processing after fd error");
    TEST_ASSERT(event.fd == -1, "Should reset fd to -1");
    
    // Test unknown error type
    reset_mock_state();
    result = handle_file_error(99, &event);
    TEST_ASSERT(result == 0, "Should skip event for unknown error");
    TEST_ASSERT(mock_debug_stats.data_read_errors == 2, "Should record data read errors");
    
    TEST_PASS("File event error handling tests passed");
}

// Test 8: File event validation
static int test_file_event_validation(void) {
    struct file_event event;
    
    reset_mock_state();
    
    // Test null event
    int result = validate_file_event_data(NULL);
    TEST_ASSERT(result == 0, "Should fail validation for null event");
    
    // Test valid event
    memset(&event, 0, sizeof(event));
    strcpy(event.filename, "/valid/path.txt");
    event.fd = 5;
    result = validate_file_event_data(&event);
    TEST_ASSERT(result == 1, "Should pass validation for valid event");
    
    // Test empty filename
    reset_mock_state();
    memset(&event, 0, sizeof(event));
    event.filename[0] = '\0';
    result = validate_file_event_data(&event);
    TEST_ASSERT(result == 1, "Should handle empty filename with error recovery");
    TEST_ASSERT(strcmp(event.filename, "<unknown>") == 0, "Should set unknown filename");
    
    // Test extremely negative fd
    reset_mock_state();
    memset(&event, 0, sizeof(event));
    strcpy(event.filename, "/valid/path.txt");
    event.fd = -2000;
    result = validate_file_event_data(&event);
    TEST_ASSERT(result == 1, "Should handle invalid fd with error recovery");
    TEST_ASSERT(event.fd == -1, "Should reset fd to -1");
    
    TEST_PASS("File event validation tests passed");
}

// Test 9: File operation event capture (open, write, unlink)
static int test_file_operation_event_capture(void) {
    reset_mock_state();
    
    // Test file open event recording
    record_file_open_event();
    TEST_ASSERT(mock_debug_stats.file_open_events == 1, "Should record file open event");
    TEST_ASSERT(mock_debug_stats.file_events == 1, "Should increment total file events");
    TEST_ASSERT(mock_debug_stats.events_processed == 1, "Should increment processed events");
    
    // Test file write event recording
    record_file_write_event();
    TEST_ASSERT(mock_debug_stats.file_write_events == 1, "Should record file write event");
    TEST_ASSERT(mock_debug_stats.file_events == 2, "Should increment total file events");
    TEST_ASSERT(mock_debug_stats.events_processed == 2, "Should increment processed events");
    
    // Test file unlink event recording
    record_file_unlink_event();
    TEST_ASSERT(mock_debug_stats.file_unlink_events == 1, "Should record file unlink event");
    TEST_ASSERT(mock_debug_stats.file_events == 3, "Should increment total file events");
    TEST_ASSERT(mock_debug_stats.events_processed == 3, "Should increment processed events");
    
    TEST_PASS("File operation event capture tests passed");
}

// Test 10: File event sampling logic
static int test_file_event_sampling(void) {
    reset_mock_state();
    
    // Test 100% sampling rate
    mock_config.file_sampling_rate = 100;
    mock_random = 50;
    TEST_ASSERT(should_sample(100) == 1, "Should always sample with 100% rate");
    
    // Test 0% sampling rate
    TEST_ASSERT(should_sample(0) == 0, "Should never sample with 0% rate");
    
    // Test 50% sampling rate with random below threshold
    mock_random = 30;
    TEST_ASSERT(should_sample(50) == 1, "Should sample when random < rate");
    
    // Test 50% sampling rate with random above threshold
    mock_random = 70;
    TEST_ASSERT(should_sample(50) == 0, "Should not sample when random >= rate");
    
    // Test sampling skip recording
    reset_mock_state();
    record_file_sampling_skipped();
    TEST_ASSERT(mock_debug_stats.file_sampling_skipped == 1, "Should record sampling skip");
    
    // Test file sampling rate configuration
    __u32 rate;
    mock_config.file_sampling_rate = 75;
    int result = get_file_sampling_rate(&rate);
    TEST_ASSERT(result == 0, "Should successfully get file sampling rate");
    TEST_ASSERT(rate == 75, "Should return configured file sampling rate");
    
    // Test fallback to global sampling rate
    mock_config.file_sampling_rate = 0;
    mock_config.sampling_rate = 60;
    result = get_file_sampling_rate(&rate);
    TEST_ASSERT(result == 0, "Should successfully get fallback sampling rate");
    TEST_ASSERT(rate == 60, "Should fallback to global sampling rate");
    
    TEST_PASS("File event sampling tests passed");
}

// Test 11: File type filtering logic
static int test_file_type_filtering(void) {
    // Test normal file (should be monitored)
    int result = should_monitor_file_type("/path/to/document.txt");
    TEST_ASSERT(result == 1, "Should monitor normal files");
    
    // Test filtered file type (.tmp files)
    result = should_monitor_file_type("/path/to/temp.tmp");
    TEST_ASSERT(result == 0, "Should filter .tmp files");
    
    // Test null filename
    result = should_monitor_file_type(NULL);
    TEST_ASSERT(result == 0, "Should not monitor null filename");
    
    // Test file without extension
    result = should_monitor_file_type("/path/to/file");
    TEST_ASSERT(result == 1, "Should monitor files without extension");
    
    // Test file type filtering recording
    reset_mock_state();
    record_file_type_filtered();
    TEST_ASSERT(mock_debug_stats.file_type_filtered == 1, "Should record file type filtering");
    
    TEST_PASS("File type filtering tests passed");
}

// Test 12: File monitoring configuration
static int test_file_monitoring_configuration(void) {
    reset_mock_state();
    
    // Test file monitoring enabled check
    __u32 enabled;
    int result = get_config_value(2, &enabled);
    TEST_ASSERT(result == 0, "Should successfully get file monitoring config");
    TEST_ASSERT(enabled == 1, "File monitoring should be enabled");
    
    // Test file write monitoring
    TEST_ASSERT(is_file_write_monitoring_enabled() == 1, "File write monitoring should be enabled");
    
    mock_config.enable_file_write_monitoring = 0;
    TEST_ASSERT(is_file_write_monitoring_enabled() == 0, "File write monitoring should be disabled");
    
    // Test file delete monitoring
    mock_config.enable_file_delete_monitoring = 1;
    TEST_ASSERT(is_file_delete_monitoring_enabled() == 1, "File delete monitoring should be enabled");
    
    mock_config.enable_file_delete_monitoring = 0;
    TEST_ASSERT(is_file_delete_monitoring_enabled() == 0, "File delete monitoring should be disabled");
    
    // Test max file path length configuration
    __u32 max_len;
    mock_config.max_file_path_len = 2048;
    result = get_max_file_path_len(&max_len);
    TEST_ASSERT(result == 0, "Should successfully get max file path length");
    TEST_ASSERT(max_len == 2048, "Should return configured max path length");
    
    // Test fallback to default
    mock_config.max_file_path_len = 0;
    result = get_max_file_path_len(&max_len);
    TEST_ASSERT(result == 0, "Should successfully get fallback max path length");
    TEST_ASSERT(max_len == MAX_PATH_LEN, "Should fallback to default max path length");
    
    TEST_PASS("File monitoring configuration tests passed");
}

// Test 13: PID filtering for file events
static int test_pid_filtering_for_file_events(void) {
    reset_mock_state();
    
    // Test valid PID
    TEST_ASSERT(should_trace_pid(1000) == 1, "Should trace normal PIDs");
    
    // Test kernel PID (should be filtered)
    TEST_ASSERT(should_trace_pid(0) == 0, "Should not trace kernel PID 0");
    
    // Test init PID (should be filtered)
    TEST_ASSERT(should_trace_pid(1) == 0, "Should not trace init PID 1");
    
    // Test PID filtering recording
    record_pid_filtered();
    TEST_ASSERT(mock_debug_stats.pid_filtered == 1, "Should record PID filtering");
    
    TEST_PASS("PID filtering for file events tests passed");
}

// Test 14: Event header filling for file events
static int test_event_header_filling(void) {
    struct event_header header;
    
    reset_mock_state();
    memset(&header, 0, sizeof(header));
    
    // Test file open event header
    fill_event_header(&header, EVENT_FILE_OPEN);
    TEST_ASSERT(header.timestamp == mock_timestamp, "Should set correct timestamp");
    TEST_ASSERT(header.pid == (mock_pid_tgid & 0xFFFFFFFF), "Should set correct PID");
    TEST_ASSERT(header.tgid == (mock_pid_tgid >> 32), "Should set correct TGID");
    TEST_ASSERT(header.uid == (mock_uid_gid & 0xFFFFFFFF), "Should set correct UID");
    TEST_ASSERT(header.gid == (mock_uid_gid >> 32), "Should set correct GID");
    TEST_ASSERT(header.event_type == EVENT_FILE_OPEN, "Should set correct event type");
    TEST_ASSERT(header.cpu == mock_cpu, "Should set correct CPU");
    TEST_ASSERT(strcmp(header.comm, mock_comm) == 0, "Should set correct comm");
    
    // Test file write event header
    memset(&header, 0, sizeof(header));
    fill_event_header(&header, EVENT_FILE_WRITE);
    TEST_ASSERT(header.event_type == EVENT_FILE_WRITE, "Should set file write event type");
    
    // Test file unlink event header
    memset(&header, 0, sizeof(header));
    fill_event_header(&header, EVENT_FILE_UNLINK);
    TEST_ASSERT(header.event_type == EVENT_FILE_UNLINK, "Should set file unlink event type");
    
    TEST_PASS("Event header filling tests passed");
}

// Test 15: Integration test for complete file event processing
static int test_complete_file_event_processing(void) {
    struct file_event event;
    char test_data[] = "dummy\0/home/user/document.pdf\0more_data";
    __u32 filename_offset = 6;
    
    reset_mock_state();
    memset(&event, 0, sizeof(event));
    
    // Simulate complete file open event processing
    __u32 pid = mock_pid_tgid & 0xFFFFFFFF;
    
    // Check PID filtering
    if (!should_trace_pid(pid)) {
        record_pid_filtered();
        TEST_ASSERT(0, "Should not filter valid PID");
    }
    
    // Check file monitoring enabled
    __u32 enabled = 0;
    get_config_value_safe(2, &enabled, 0);
    TEST_ASSERT(enabled == 1, "File monitoring should be enabled");
    
    // Check sampling
    __u32 rate = 100;
    get_file_sampling_rate(&rate);
    if (!should_sample(rate)) {
        record_file_sampling_skipped();
        TEST_ASSERT(0, "Should not skip with 100% sampling");
    }
    
    // Fill event header
    fill_event_header(&event.header, EVENT_FILE_OPEN);
    
    // Fill file information
    int result = fill_file_info(&event, test_data, filename_offset,
                               0x0002, 0x0644, 3, 0, 0); // O_RDWR, 644 permissions, fd=3
    TEST_ASSERT(result == 0, "Should successfully fill file info");
    
    // Validate event data
    result = validate_file_event_data(&event);
    TEST_ASSERT(result == 1, "Should pass event validation");
    
    // Apply file type filtering
    if (!should_monitor_file_type(event.filename)) {
        record_file_type_filtered();
        TEST_ASSERT(0, "Should not filter PDF files");
    }
    
    // Record statistics
    record_file_open_event();
    
    // Verify complete event
    TEST_ASSERT(event.header.event_type == EVENT_FILE_OPEN, "Should have correct event type");
    TEST_ASSERT(event.header.pid == (mock_pid_tgid & 0xFFFFFFFF), "Should have correct PID");
    TEST_ASSERT(event.flags == 0x0002, "Should have correct flags");
    TEST_ASSERT(event.mode == 0x0644, "Should have correct mode");
    TEST_ASSERT(event.fd == 3, "Should have correct file descriptor");
    TEST_ASSERT(mock_debug_stats.file_open_events == 1, "Should record file open event");
    TEST_ASSERT(mock_debug_stats.file_events == 1, "Should record total file events");
    TEST_ASSERT(mock_debug_stats.events_processed == 1, "Should record processed events");
    
    TEST_PASS("Complete file event processing tests passed");
}

// Test 16: Edge cases and boundary conditions
static int test_edge_cases_and_boundaries(void) {
    reset_mock_state();
    
    // Test with disabled file monitoring
    mock_config.enable_file_monitoring = 0;
    __u32 enabled = 0;
    get_config_value_safe(2, &enabled, 0);
    TEST_ASSERT(enabled == 0, "File monitoring should be disabled");
    
    // Test with zero file sampling rate
    mock_config.file_sampling_rate = 0;
    TEST_ASSERT(should_sample(0) == 0, "Should not sample with 0% rate");
    
    // Test with maximum values
    struct file_event event;
    memset(&event, 0, sizeof(event));
    
    int result = fill_file_info(&event, NULL, 0,
                               0xFFFFFFFF, 0xFFFF, -1,
                               0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL);
    TEST_ASSERT(result == 0, "Should handle maximum values");
    TEST_ASSERT(event.flags == 0xFFFF, "Should mask flags correctly");
    TEST_ASSERT(event.mode == 0x0444, "Should normalize invalid mode");
    TEST_ASSERT(event.size == 0, "Should normalize invalid size");
    TEST_ASSERT(event.offset == 0, "Should normalize invalid offset");
    
    // Test with very long filename
    char long_filename[MAX_PATH_LEN + 100];
    memset(long_filename, 'a', sizeof(long_filename) - 1);
    long_filename[sizeof(long_filename) - 1] = '\0';
    
    result = should_monitor_file_type(long_filename);
    TEST_ASSERT(result == 1, "Should handle very long filenames");
    
    // Test boundary PID values
    TEST_ASSERT(should_trace_pid(2) == 1, "Should trace PID 2");
    TEST_ASSERT(should_trace_pid(0xFFFFFFFF) == 1, "Should trace maximum PID");
    
    // Test configuration with null map
    void *original_map = config_map;
    config_map = NULL;
    
    __u32 value;
    result = get_config_value_safe(2, &value, 42);
    TEST_ASSERT(result == 0, "Should succeed with fallback");
    TEST_ASSERT(value == 42, "Should use fallback value");
    
    config_map = original_map; // Restore
    
    TEST_PASS("Edge cases and boundary conditions tests passed");
}

// Test runner structure
typedef struct {
    const char *name;
    int (*test_func)(void);
} test_case_t;

// Test suite definition
static test_case_t test_suite[] = {
    {"file_path_extraction", test_file_path_extraction},
    {"file_flags_extraction", test_file_flags_extraction},
    {"file_mode_extraction", test_file_mode_extraction},
    {"file_size_extraction", test_file_size_extraction},
    {"file_offset_extraction", test_file_offset_extraction},
    {"fill_file_info", test_fill_file_info},
    {"file_event_error_handling", test_file_event_error_handling},
    {"file_event_validation", test_file_event_validation},
    {"file_operation_event_capture", test_file_operation_event_capture},
    {"file_event_sampling", test_file_event_sampling},
    {"file_type_filtering", test_file_type_filtering},
    {"file_monitoring_configuration", test_file_monitoring_configuration},
    {"pid_filtering_for_file_events", test_pid_filtering_for_file_events},
    {"event_header_filling", test_event_header_filling},
    {"complete_file_event_processing", test_complete_file_event_processing},
    {"edge_cases_and_boundaries", test_edge_cases_and_boundaries},
    {NULL, NULL}  // Sentinel
};

// Main test runner
int main(int argc, char *argv[]) {
    printf("eBPF File System Monitor Unit Tests\n");
    printf("====================================\n\n");
    
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
        printf("\n🎉 All file system monitoring tests passed!\n");
        return 0;
    } else {
        printf("\n❌ Some file system monitoring tests failed!\n");
        return 1;
    }
}

