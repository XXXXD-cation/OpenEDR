#ifndef __COMMON_H__
#define __COMMON_H__

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Additional type definitions for eBPF compatibility
#ifndef size_t
typedef __u64 size_t;
#endif

// Network constants (define them if not available)
#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

// Basic socket address structure
struct sockaddr {
    __u16 sa_family;
    char sa_data[14];
};

// Maximum lengths for various fields
#define MAX_FILENAME_LEN    256
#define MAX_COMM_LEN        16
#define MAX_PATH_LEN        4096
#define TASK_COMM_LEN       16

// Kernel version compatibility
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
    #define USE_MODERN_TRACEPOINT 1
    #define USE_RINGBUF 1
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
    #define USE_BASIC_TRACEPOINT 1
    #define USE_PERF_EVENT 1
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
    #define USE_COMPAT_TRACEPOINT 1
    #define USE_PERF_EVENT 1
#else
    #define USE_KPROBE_FALLBACK 1
#endif

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

// Network events
struct network_event {
    struct event_header header;
    __u16 family;     // AF_INET or AF_INET6
    __u16 protocol;   // IPPROTO_TCP or IPPROTO_UDP
    __u16 sport;      // Source port
    __u16 dport;      // Destination port
    union {
        __u32 saddr_v4;
        __u8 saddr_v6[16];
    };
    union {
        __u32 daddr_v4;
        __u8 daddr_v6[16];
    };
};

// File system events
struct file_event {
    struct event_header header;
    __u32 flags;      // File open flags
    __u16 mode;       // File mode
    __s32 fd;         // File descriptor
    __u64 size;       // File size (for write events)
    __u64 offset;     // File offset (for write events)
    char filename[MAX_PATH_LEN];
};

// System call events
struct syscall_event {
    struct event_header header;
    __u64 syscall_nr;
    __u64 args[6];    // System call arguments
    __s64 ret;        // Return value
};

// Tracepoint context structures
#ifndef USE_KPROBE_FALLBACK

// Base trace entry structure (from kernel)
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

// System call exit tracepoint context (alternative for exit code)
struct trace_event_raw_sys_exit {
    struct trace_entry ent;
    __s64 id;                   // System call ID
    __s64 ret;                  // Return value/exit code
    char __data[0];             // Variable length data area
};

#endif /* USE_KPROBE_FALLBACK */

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

// Helper macros
#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
    struct { \
        __uint(type, _type); \
        __uint(max_entries, _max_entries); \
        __type(key, _key_type); \
        __type(value, _value_type); \
    } _name SEC(".maps")

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Configuration map
struct config {
    __u32 enable_process_monitoring;
    __u32 enable_network_monitoring;
    __u32 enable_file_monitoring;
    __u32 enable_syscall_monitoring;
    __u32 sampling_rate;
};

BPF_MAP(config_map, BPF_MAP_TYPE_ARRAY, __u32, struct config, 1);

// Debug statistics map
BPF_MAP(debug_stats_map, BPF_MAP_TYPE_ARRAY, __u32, struct debug_stats, 1);

// Helper functions
static __always_inline void fill_event_header(struct event_header *header, __u32 event_type) {
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

static __always_inline int should_trace_pid(__u32 pid) {
    // Skip kernel threads (pid 0) and init (pid 1)
    if (pid <= 1) {
        return 0;
    }
    
    // TODO: Add PID filtering logic based on configuration
    return 1;
}

static __always_inline int get_config_value(__u32 key, __u32 *value) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
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

// Sampling helper
static __always_inline int should_sample(__u32 rate) {
    if (rate == 0) return 0;
    if (rate >= 100) return 1;
    
    return (bpf_get_prandom_u32() % 100) < rate;
}



// Optimized helper functions for tracepoint-based monitoring

// Enhanced error recording with detailed tracking
static __always_inline void record_error(__u32 error_type) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
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

// Event-specific statistics recording
static __always_inline void record_exec_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->exec_events, 1);
        __sync_fetch_and_add(&stats->events_processed, 1);
    }
}

static __always_inline void record_exit_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->exit_events, 1);
        __sync_fetch_and_add(&stats->events_processed, 1);
    }
}

// Filtering statistics
static __always_inline void record_sampling_skipped(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->sampling_skipped, 1);
    }
}

static __always_inline void record_pid_filtered(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->pid_filtered, 1);
    }
}

// Safe configuration access with fallback
static __always_inline int get_config_value_safe(__u32 key, __u32 *value, __u32 fallback) {
    int ret = get_config_value(key, value);
    if (ret < 0) {
        record_error(ERROR_CONFIG_ERROR);
        *value = fallback;
        return 0;
    }
    return ret;
}



#ifndef USE_KPROBE_FALLBACK

// Error handling helpers (defined early to avoid forward declaration issues)
static __always_inline int handle_allocation_failure(void) {
    record_error(ERROR_ALLOCATION_FAILURE);
    
    // Try to free up space by dropping some events if possible
    // In eBPF, we can't directly manage memory, but we can signal the issue
    // The user space should monitor allocation failures and adjust ring buffer size
    
    return 0;  // Continue processing other events
}

static __always_inline int handle_config_error(void) {
    record_error(ERROR_CONFIG_ERROR);
    
    // For config errors, we should continue with safe defaults
    // This allows the system to remain functional even with config issues
    
    return 1;  // Use default configuration and continue
}

static __always_inline int handle_data_read_error(void) {
    record_error(ERROR_DATA_READ_ERROR);
    
    // For data read errors, we skip the current event but continue processing
    // This prevents one bad event from stopping the entire monitoring
    
    return 0;  // Skip this event but continue processing
}

// New error handling function for tracepoint-specific errors
static __always_inline int handle_tracepoint_error(void) {
    record_error(ERROR_TRACEPOINT_ERROR);
    
    // For tracepoint errors, we should continue processing
    // The error might be transient or specific to one event
    
    return 0;  // Skip this event but continue processing
}

// Common event preprocessing check (eliminates code duplication)
static __always_inline int should_process_event(__u32 monitor_type) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // PID filtering check
    if (!should_trace_pid(pid)) {
        record_pid_filtered();
        return 0;
    }
    
    // Configuration check with safe fallback
    __u32 enabled = 0;
    get_config_value_safe(monitor_type, &enabled, 1);  // Default to enabled
    
    if (!enabled) {
        return 0;
    }
    
    // Sampling rate check with safe fallback
    __u32 rate = 100;
    get_config_value_safe(MONITOR_SAMPLING_RATE, &rate, 100);  // Default to 100%
    
    if (!should_sample(rate)) {
        record_sampling_skipped();
        return 0;
    }
    
    return 1;
}

// Basic event allocation (use allocate_process_event_with_retry for production)
static __always_inline struct process_event* allocate_process_event(__u32 event_type) {
    struct process_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        record_error(ERROR_ALLOCATION_FAILURE);
        return NULL;
    }
    
    fill_event_header(&event->header, event_type);
    return event;
}

// Extract filename from sched_process_exec tracepoint context
static __always_inline int extract_filename_from_exec_ctx(
    struct trace_event_raw_sched_process_exec *ctx,
    char *filename, 
    size_t size) {
    
    // Get filename offset from __data_loc_filename
    __u32 offset = ctx->__data_loc_filename & 0xFFFF;
    
    // Validate offset to prevent out-of-bounds access
    if (offset > 4096) {  // Reasonable upper bound
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

// Get parent PID from sched_process_exec tracepoint context
static __always_inline __u32 get_parent_pid_from_exec_ctx(
    struct trace_event_raw_sched_process_exec *ctx) {
    
    return ctx->old_pid;
}

// Fill process execution event info from tracepoint context with enhanced error handling
static __always_inline void fill_process_exec_info(
    struct process_event *event,
    struct trace_event_raw_sched_process_exec *ctx) {
    
    // Get accurate parent process ID from tracepoint context
    // Use safe access with bounds checking
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
        __builtin_memset(event->filename, 0, sizeof(event->filename));
        handle_data_read_error();
    } else if (!ctx) {
        // If context is null, clear filename and record error
        __builtin_memset(event->filename, 0, sizeof(event->filename));
        handle_tracepoint_error();
    }
    
    // Clear args for now (command line args extraction is complex)
    __builtin_memset(event->args, 0, sizeof(event->args));
}

// Fill process exit event info from tracepoint context
static __always_inline void fill_process_exit_info(
    struct process_event *event,
    struct trace_event_raw_sched_process_exit *ctx) {
    
    // For exit events, parent PID is not available in the tracepoint
    event->ppid = 0;
    
    // Note: sched_process_exit tracepoint doesn't directly provide exit code
    // The exit code would need to be captured from sys_exit/sys_exit_group syscalls
    // For now, we set it to 0 and rely on the unified exit monitoring mechanism
    event->exit_code = 0;
    
    // Clear filename and args for exit events
    __builtin_memset(event->filename, 0, sizeof(event->filename));
    __builtin_memset(event->args, 0, sizeof(event->args));
}

// Enhanced allocation function with retry logic
static __always_inline struct process_event* allocate_process_event_with_retry(__u32 event_type) {
    struct process_event *event;
    
    // First attempt
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        fill_event_header(&event->header, event_type);
        return event;
    }
    
    // Record the allocation failure
    record_error(ERROR_ALLOCATION_FAILURE);
    
    // For eBPF, we can't implement complex retry logic due to verifier constraints
    // But we can try once more with BPF_RB_FORCE_WAKEUP flag to wake up consumers
    event = bpf_ringbuf_reserve(&events, sizeof(*event), BPF_RB_FORCE_WAKEUP);
    if (event) {
        fill_event_header(&event->header, event_type);
        return event;
    }
    
    // If both attempts fail, return NULL
    return NULL;
}

#endif /* USE_KPROBE_FALLBACK */

#endif /* __COMMON_H__ */