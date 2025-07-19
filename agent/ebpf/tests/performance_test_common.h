#ifndef __PERFORMANCE_TEST_COMMON_H__
#define __PERFORMANCE_TEST_COMMON_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>

// Mock eBPF types and constants for testing
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint8_t __u8;
typedef int64_t __s64;
typedef int32_t __s32;
typedef int16_t __s16;
typedef int8_t __s8;

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

// Maximum lengths for various fields
#define MAX_FILENAME_LEN    256
#define MAX_COMM_LEN        16
#define MAX_PATH_LEN        4096
#define TASK_COMM_LEN       16

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

// Configuration structure
struct config {
    __u32 enable_process_monitoring;
    __u32 enable_network_monitoring;
    __u32 enable_file_monitoring;
    __u32 enable_syscall_monitoring;
    __u32 sampling_rate;
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

// Tracepoint context structures
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
    char __data[0];             // Variable length data area
};

// Process exit tracepoint context
struct trace_event_raw_sched_process_exit {
    struct trace_entry ent;
    char comm[16];              // Process command name
    __u32 pid;                  // Process PID
    __s32 prio;                 // Process priority
    char __data[0];             // Variable length data area
};

// System call exit tracepoint context
struct trace_event_raw_sys_exit {
    struct trace_entry ent;
    __s64 id;                   // System call ID
    __s64 ret;                  // Return value/exit code
    char __data[0];             // Variable length data area
};

// Mock map structures
extern struct config mock_config;
extern struct debug_stats mock_kprobe_stats;
extern struct debug_stats mock_tracepoint_stats;
extern char mock_events_buffer[4096];

// Mock eBPF helper function declarations
__u64 bpf_get_current_pid_tgid(void);
__u64 bpf_ktime_get_ns(void);
__u64 bpf_get_current_uid_gid(void);
__u32 bpf_get_smp_processor_id(void);
int bpf_get_current_comm(void *comm, __u32 size);
__u32 bpf_get_prandom_u32(void);
void* bpf_ringbuf_reserve(void *ringbuf, __u64 size, __u64 flags);
void bpf_ringbuf_submit(void *data, __u64 flags);
void* bpf_map_lookup_elem(void *map, const void *key);
long bpf_probe_read_user_str(void *dst, __u32 size, const void *unsafe_ptr);
long bpf_probe_read_kernel_str(void *dst, __u32 size, const void *unsafe_ptr);

// Helper function declarations
void fill_event_header(struct event_header *header, __u32 event_type);
int should_trace_pid(__u32 pid);
int get_config_value(__u32 key, __u32 *value);
int should_sample(__u32 rate);
void record_error(__u32 error_type);
void record_exec_event(void);
void record_exit_event(void);
void record_sampling_skipped(void);
void record_pid_filtered(void);
int get_config_value_safe(__u32 key, __u32 *value, __u32 fallback);
int should_process_event(__u32 monitor_type);
struct process_event* allocate_process_event(__u32 event_type);
int extract_filename_from_exec_ctx(struct trace_event_raw_sched_process_exec *ctx, char *filename, size_t size);
__u32 get_parent_pid_from_exec_ctx(struct trace_event_raw_sched_process_exec *ctx);
void fill_process_exec_info(struct process_event *event, struct trace_event_raw_sched_process_exec *ctx);
void fill_process_exit_info(struct process_event *event, struct trace_event_raw_sched_process_exit *ctx);
struct process_event* allocate_process_event_with_retry(__u32 event_type);
int handle_allocation_failure(void);
int handle_config_error(void);
int handle_data_read_error(void);
int handle_tracepoint_error(void);

#endif /* __PERFORMANCE_TEST_COMMON_H__ */