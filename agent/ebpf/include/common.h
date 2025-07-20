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

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
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

// Network monitoring tracepoint context structures

// TCP socket state change tracepoint context
struct trace_event_raw_inet_sock_set_state {
    struct trace_entry ent;
    const void *skaddr;         // Socket address
    __s32 oldstate;             // Previous socket state
    __s32 newstate;             // New socket state
    __u16 sport;                // Source port
    __u16 dport;                // Destination port
    __u16 family;               // Address family (AF_INET/AF_INET6)
    __u16 protocol;             // Protocol (IPPROTO_TCP/UDP)
    __u8 saddr[4];              // Source address (IPv4)
    __u8 daddr[4];              // Destination address (IPv4)
    __u8 saddr_v6[16];          // Source address (IPv6)
    __u8 daddr_v6[16];          // Destination address (IPv6)
    char __data[0];             // Variable length data area
};

// Socket send message tracepoint context
struct trace_event_raw_sock_sendmsg {
    struct trace_entry ent;
    const void *sk;             // Socket pointer
    __u32 size;                 // Message size
    __s32 ret;                  // Return value
    char __data[0];             // Variable length data area
};

// Socket receive message tracepoint context
struct trace_event_raw_sock_recvmsg {
    struct trace_entry ent;
    const void *sk;             // Socket pointer
    __u32 size;                 // Message size
    __s32 ret;                  // Return value
    char __data[0];             // Variable length data area
};

// File system monitoring tracepoint context structures

// VFS file open tracepoint context
struct trace_event_raw_vfs_open {
    struct trace_entry ent;
    __u32 __data_loc_filename;  // Offset to filename in __data
    __u32 flags;                // File open flags
    __u16 mode;                 // File mode
    __s32 ret;                  // Return value (file descriptor)
    char __data[0];             // Variable length data area
};

// VFS file write tracepoint context
struct trace_event_raw_vfs_write {
    struct trace_entry ent;
    __u32 __data_loc_filename;  // Offset to filename in __data
    __u64 offset;               // File offset
    __u64 count;                // Number of bytes to write
    __s64 ret;                  // Return value (bytes written)
    char __data[0];             // Variable length data area
};

// VFS file unlink tracepoint context
struct trace_event_raw_vfs_unlink {
    struct trace_entry ent;
    __u32 __data_loc_filename;  // Offset to filename in __data
    __u32 __data_loc_pathname;  // Offset to full pathname in __data
    __s32 ret;                  // Return value
    char __data[0];             // Variable length data area
};

// System call tracepoint context structures

// System call enter tracepoint context
struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    __s64 id;                   // System call number
    __u64 args[6];              // System call arguments
    char __data[0];             // Variable length data area
};

// System call exit tracepoint context (already defined above for process exit)
// struct trace_event_raw_sys_exit is already defined for process monitoring

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

// Network event allocation and processing functions

// Basic network event allocation
static __always_inline struct network_event* allocate_network_event(__u32 event_type) {
    struct network_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        record_error(ERROR_ALLOCATION_FAILURE);
        return NULL;
    }
    
    fill_event_header(&event->header, event_type);
    return event;
}

// Enhanced network event allocation with retry logic
static __always_inline struct network_event* allocate_network_event_with_retry(__u32 event_type) {
    struct network_event *event;
    
    // First attempt
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        fill_event_header(&event->header, event_type);
        return event;
    }
    
    // Record the allocation failure
    record_error(ERROR_ALLOCATION_FAILURE);
    
    // Try once more with BPF_RB_FORCE_WAKEUP flag to wake up consumers
    event = bpf_ringbuf_reserve(&events, sizeof(*event), BPF_RB_FORCE_WAKEUP);
    if (event) {
        fill_event_header(&event->header, event_type);
        return event;
    }
    
    // If both attempts fail, return NULL
    return NULL;
}

// Network information extraction helper functions

// Extract IPv4 address and port information from tracepoint context
static __always_inline void extract_ipv4_info_from_ctx(
    struct network_event *event,
    struct trace_event_raw_inet_sock_set_state *ctx) {
    
    if (!ctx || !event) {
        handle_tracepoint_error();
        return;
    }
    
    // Set address family and protocol
    event->family = ctx->family;
    event->protocol = ctx->protocol;
    
    // Extract ports
    event->sport = ctx->sport;
    event->dport = ctx->dport;
    
    // Extract IPv4 addresses
    if (ctx->family == AF_INET) {
        // Copy IPv4 addresses from tracepoint context
        __builtin_memcpy(&event->saddr_v4, ctx->saddr, 4);
        __builtin_memcpy(&event->daddr_v4, ctx->daddr, 4);
    }
}

// Extract IPv6 address and port information from tracepoint context
static __always_inline void extract_ipv6_info_from_ctx(
    struct network_event *event,
    struct trace_event_raw_inet_sock_set_state *ctx) {
    
    if (!ctx || !event) {
        handle_tracepoint_error();
        return;
    }
    
    // Set address family and protocol
    event->family = ctx->family;
    event->protocol = ctx->protocol;
    
    // Extract ports
    event->sport = ctx->sport;
    event->dport = ctx->dport;
    
    // Extract IPv6 addresses
    if (ctx->family == AF_INET6) {
        // Copy IPv6 addresses from tracepoint context
        __builtin_memcpy(event->saddr_v6, ctx->saddr_v6, 16);
        __builtin_memcpy(event->daddr_v6, ctx->daddr_v6, 16);
    }
}

// Fill network event information from inet_sock_set_state tracepoint context
static __always_inline void fill_network_info_from_state_ctx(
    struct network_event *event,
    struct trace_event_raw_inet_sock_set_state *ctx) {
    
    if (!ctx || !event) {
        handle_tracepoint_error();
        return;
    }
    
    // Determine address family and extract appropriate information
    if (ctx->family == AF_INET) {
        extract_ipv4_info_from_ctx(event, ctx);
    } else if (ctx->family == AF_INET6) {
        extract_ipv6_info_from_ctx(event, ctx);
    } else {
        // Unknown address family, record error but continue
        handle_data_read_error();
        event->family = ctx->family;
        event->protocol = ctx->protocol;
        event->sport = ctx->sport;
        event->dport = ctx->dport;
    }
}

// Extract basic socket information from sock_sendmsg/sock_recvmsg tracepoint context
static __always_inline int extract_socket_info_from_sk(
    struct network_event *event,
    const void *sk_ptr) {
    
    if (!sk_ptr || !event) {
        handle_tracepoint_error();
        return -1;
    }
    
    // Note: Direct socket structure access requires careful kernel version handling
    // For now, we'll set basic defaults and rely on other tracepoints for detailed info
    // In a full implementation, this would use bpf_probe_read_kernel to safely read
    // socket structure fields based on kernel version compatibility
    
    // Set default values - actual implementation would read from socket structure
    event->family = AF_INET;  // Default assumption
    event->protocol = 6;      // TCP default
    event->sport = 0;         // Unknown
    event->dport = 0;         // Unknown
    event->saddr_v4 = 0;      // Unknown
    event->daddr_v4 = 0;      // Unknown
    
    return 0;
}

// Fill network event information from sock_sendmsg tracepoint context
static __always_inline void fill_network_info_from_sendmsg_ctx(
    struct network_event *event,
    struct trace_event_raw_sock_sendmsg *ctx) {
    
    if (!ctx || !event) {
        handle_tracepoint_error();
        return;
    }
    
    // Extract socket information
    if (extract_socket_info_from_sk(event, ctx->sk) < 0) {
        handle_data_read_error();
    }
    
    // Additional context-specific information could be extracted here
    // For example, message size could be stored in a custom field if needed
}

// Fill network event information from sock_recvmsg tracepoint context
static __always_inline void fill_network_info_from_recvmsg_ctx(
    struct network_event *event,
    struct trace_event_raw_sock_recvmsg *ctx) {
    
    if (!ctx || !event) {
        handle_tracepoint_error();
        return;
    }
    
    // Extract socket information
    if (extract_socket_info_from_sk(event, ctx->sk) < 0) {
        handle_data_read_error();
    }
    
    // Additional context-specific information could be extracted here
    // For example, message size could be stored in a custom field if needed
}

// Network event statistics recording
static __always_inline void record_network_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->events_processed, 1);
        // Note: network_events field would need to be added to debug_stats structure
        // This is a placeholder for the extended statistics structure
    }
}

// File system event allocation and processing functions

// Basic file event allocation
static __always_inline struct file_event* allocate_file_event(__u32 event_type) {
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        record_error(ERROR_ALLOCATION_FAILURE);
        return NULL;
    }
    
    fill_event_header(&event->header, event_type);
    return event;
}

// Enhanced file event allocation with retry logic
static __always_inline struct file_event* allocate_file_event_with_retry(__u32 event_type) {
    struct file_event *event;
    
    // First attempt
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        fill_event_header(&event->header, event_type);
        return event;
    }
    
    // Record the allocation failure
    record_error(ERROR_ALLOCATION_FAILURE);
    
    // Try once more with BPF_RB_FORCE_WAKEUP flag to wake up consumers
    event = bpf_ringbuf_reserve(&events, sizeof(*event), BPF_RB_FORCE_WAKEUP);
    if (event) {
        fill_event_header(&event->header, event_type);
        return event;
    }
    
    // If both attempts fail, return NULL
    return NULL;
}

// File path extraction helper functions

// Extract filename from VFS tracepoint context using __data_loc_filename
static __always_inline int extract_filename_from_vfs_ctx(
    void *ctx_base,
    __u32 data_loc_filename,
    char *filename,
    size_t size) {
    
    // Get filename offset from __data_loc_filename
    __u32 offset = data_loc_filename & 0xFFFF;
    
    // Validate offset to prevent out-of-bounds access
    if (offset > 4096) {  // Reasonable upper bound
        record_error(ERROR_DATA_READ_ERROR);
        return -1;
    }
    
    // Read filename from __data area using kernel-safe read
    int ret = bpf_probe_read_kernel_str(filename, size, (char *)ctx_base + offset);
    if (ret < 0) {
        record_error(ERROR_DATA_READ_ERROR);
        return ret;
    }
    
    return 0;
}

// Extract pathname from VFS tracepoint context using __data_loc_pathname
static __always_inline int extract_pathname_from_vfs_ctx(
    void *ctx_base,
    __u32 data_loc_pathname,
    char *pathname,
    size_t size) {
    
    // Get pathname offset from __data_loc_pathname
    __u32 offset = data_loc_pathname & 0xFFFF;
    
    // Validate offset to prevent out-of-bounds access
    if (offset > 4096) {  // Reasonable upper bound
        record_error(ERROR_DATA_READ_ERROR);
        return -1;
    }
    
    // Read pathname from __data area using kernel-safe read
    int ret = bpf_probe_read_kernel_str(pathname, size, (char *)ctx_base + offset);
    if (ret < 0) {
        record_error(ERROR_DATA_READ_ERROR);
        return ret;
    }
    
    return 0;
}

// Fill file event information from vfs_open tracepoint context
static __always_inline void fill_file_info_from_open_ctx(
    struct file_event *event,
    struct trace_event_raw_vfs_open *ctx) {
    
    if (!ctx || !event) {
        handle_tracepoint_error();
        return;
    }
    
    // Extract file open flags and mode
    event->flags = ctx->flags;
    event->mode = ctx->mode;
    event->fd = ctx->ret;  // File descriptor from return value
    event->size = 0;       // Not applicable for open events
    event->offset = 0;     // Not applicable for open events
    
    // Extract filename from tracepoint context with error handling
    if (extract_filename_from_vfs_ctx(ctx, ctx->__data_loc_filename, 
                                      event->filename, sizeof(event->filename)) < 0) {
        // On error, clear filename and record the error
        __builtin_memset(event->filename, 0, sizeof(event->filename));
        handle_data_read_error();
    }
}

// Fill file event information from vfs_write tracepoint context
static __always_inline void fill_file_info_from_write_ctx(
    struct file_event *event,
    struct trace_event_raw_vfs_write *ctx) {
    
    if (!ctx || !event) {
        handle_tracepoint_error();
        return;
    }
    
    // Extract write-specific information
    event->flags = 0;           // Not available in write context
    event->mode = 0;            // Not available in write context
    event->fd = -1;             // Not directly available
    event->size = ctx->count;   // Number of bytes to write
    event->offset = ctx->offset; // File offset
    
    // Extract filename from tracepoint context with error handling
    if (extract_filename_from_vfs_ctx(ctx, ctx->__data_loc_filename,
                                      event->filename, sizeof(event->filename)) < 0) {
        // On error, clear filename and record the error
        __builtin_memset(event->filename, 0, sizeof(event->filename));
        handle_data_read_error();
    }
}

// Fill file event information from vfs_unlink tracepoint context
static __always_inline void fill_file_info_from_unlink_ctx(
    struct file_event *event,
    struct trace_event_raw_vfs_unlink *ctx) {
    
    if (!ctx || !event) {
        handle_tracepoint_error();
        return;
    }
    
    // Extract unlink-specific information
    event->flags = 0;      // Not applicable for unlink events
    event->mode = 0;       // Not applicable for unlink events
    event->fd = -1;        // Not applicable for unlink events
    event->size = 0;       // Not applicable for unlink events
    event->offset = 0;     // Not applicable for unlink events
    
    // Try to extract pathname first (more complete path), fallback to filename
    if (extract_pathname_from_vfs_ctx(ctx, ctx->__data_loc_pathname,
                                      event->filename, sizeof(event->filename)) < 0) {
        // Fallback to filename if pathname extraction fails
        if (extract_filename_from_vfs_ctx(ctx, ctx->__data_loc_filename,
                                          event->filename, sizeof(event->filename)) < 0) {
            // On error, clear filename and record the error
            __builtin_memset(event->filename, 0, sizeof(event->filename));
            handle_data_read_error();
        }
    }
}

// File event error handling helpers

// Handle file path extraction errors
static __always_inline int handle_file_path_error(void) {
    record_error(ERROR_DATA_READ_ERROR);
    
    // For file path errors, we can continue processing the event
    // with partial information (other fields may still be valid)
    return 1;  // Continue processing with partial data
}

// Handle file information read errors
static __always_inline int handle_file_info_error(void) {
    record_error(ERROR_DATA_READ_ERROR);
    
    // For file info errors, we should skip the event
    // as the core information is likely corrupted
    return 0;  // Skip this event
}

// File event statistics recording
static __always_inline void record_file_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->events_processed, 1);
        // Note: file_events field would need to be added to debug_stats structure
        // This is a placeholder for the extended statistics structure
    }
}

// Unified file event processing helper
static __always_inline int should_process_file_event(void) {
    return should_process_event(MONITOR_FILE);
}

// System call event allocation and processing functions

// Basic system call event allocation
static __always_inline struct syscall_event* allocate_syscall_event(__u32 event_type) {
    struct syscall_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        record_error(ERROR_ALLOCATION_FAILURE);
        return NULL;
    }
    
    fill_event_header(&event->header, event_type);
    return event;
}

// Enhanced system call event allocation with retry logic
static __always_inline struct syscall_event* allocate_syscall_event_with_retry(__u32 event_type) {
    struct syscall_event *event;
    
    // First attempt
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        fill_event_header(&event->header, event_type);
        return event;
    }
    
    // Record the allocation failure
    record_error(ERROR_ALLOCATION_FAILURE);
    
    // Try once more with BPF_RB_FORCE_WAKEUP flag to wake up consumers
    event = bpf_ringbuf_reserve(&events, sizeof(*event), BPF_RB_FORCE_WAKEUP);
    if (event) {
        fill_event_header(&event->header, event_type);
        return event;
    }
    
    // If both attempts fail, return NULL
    return NULL;
}

// System call filtering and sampling functions

// System call whitelist - only monitor critical system calls
static __always_inline int should_trace_syscall(__u64 syscall_nr) {
    // Based on requirements 3.1 and 3.3, filter to critical system calls
    switch (syscall_nr) {
        case 2:    // sys_open
        case 257:  // sys_openat
        case 3:    // sys_close
        case 1:    // sys_write
        case 0:    // sys_read
        case 59:   // sys_execve
        case 322:  // sys_execveat
        case 42:   // sys_connect
        case 43:   // sys_accept
        case 288:  // sys_accept4
        case 10:   // sys_unlink
        case 263:  // sys_unlinkat
        case 83:   // sys_mkdir
        case 84:   // sys_rmdir
        case 82:   // sys_rename
        case 316:  // sys_renameat2
        case 49:   // sys_bind
        case 50:   // sys_listen
        case 41:   // sys_socket
        case 85:   // sys_creat
        case 5:    // sys_fstat
        case 4:    // sys_stat
        case 6:    // sys_lstat
            return 1;
        default:
            return 0;
    }
}

// System call sampling strategy - higher frequency calls get lower sampling rates
static __always_inline int should_sample_syscall(__u64 syscall_nr) {
    __u32 base_rate = 100;
    get_config_value_safe(MONITOR_SAMPLING_RATE, &base_rate, 100);
    
    // Apply different sampling rates based on syscall frequency characteristics
    __u32 adjusted_rate = base_rate;
    
    switch (syscall_nr) {
        case 0:    // sys_read - very high frequency
        case 1:    // sys_write - very high frequency
            adjusted_rate = base_rate / 10;  // 10x lower sampling
            break;
        case 4:    // sys_stat - high frequency
        case 5:    // sys_fstat - high frequency
        case 6:    // sys_lstat - high frequency
            adjusted_rate = base_rate / 5;   // 5x lower sampling
            break;
        case 2:    // sys_open - medium frequency
        case 257:  // sys_openat - medium frequency
        case 3:    // sys_close - medium frequency
            adjusted_rate = base_rate / 2;   // 2x lower sampling
            break;
        default:
            // Low frequency syscalls use full sampling rate
            adjusted_rate = base_rate;
            break;
    }
    
    return should_sample(adjusted_rate);
}

// System call information extraction helper functions

// Fill system call event information from sys_enter tracepoint context
static __always_inline void fill_syscall_info_from_enter_ctx(
    struct syscall_event *event,
    struct trace_event_raw_sys_enter *ctx) {
    
    if (!ctx || !event) {
        handle_tracepoint_error();
        return;
    }
    
    // Extract system call number and arguments
    event->syscall_nr = ctx->id;
    event->ret = 0;  // Not available in enter context, will be filled by exit
    
    // Copy system call arguments with bounds checking
    for (int i = 0; i < 6; i++) {
        event->args[i] = ctx->args[i];
    }
}

// Fill system call event information from sys_exit tracepoint context
static __always_inline void fill_syscall_info_from_exit_ctx(
    struct syscall_event *event,
    struct trace_event_raw_sys_exit *ctx) {
    
    if (!ctx || !event) {
        handle_tracepoint_error();
        return;
    }
    
    // Extract system call number and return value
    event->syscall_nr = ctx->id;
    event->ret = ctx->ret;
    
    // Arguments are not available in exit context, clear them
    for (int i = 0; i < 6; i++) {
        event->args[i] = 0;
    }
}

// Extract specific system call arguments based on syscall type
static __always_inline void extract_syscall_args(
    struct syscall_event *event,
    __u64 syscall_nr,
    __u64 args[6]) {
    
    if (!event) {
        handle_tracepoint_error();
        return;
    }
    
    // Copy all arguments first
    for (int i = 0; i < 6; i++) {
        event->args[i] = args[i];
    }
    
    // For specific syscalls, we could extract and validate specific arguments
    // This is a placeholder for more sophisticated argument processing
    switch (syscall_nr) {
        case 2:    // sys_open
        case 257:  // sys_openat
            // args[0] = dirfd (for openat), filename (for open)
            // args[1] = filename (for openat), flags (for open)
            // args[2] = flags (for openat), mode (for open)
            // args[3] = mode (for openat)
            break;
        case 59:   // sys_execve
            // args[0] = filename
            // args[1] = argv
            // args[2] = envp
            break;
        case 42:   // sys_connect
            // args[0] = sockfd
            // args[1] = addr
            // args[2] = addrlen
            break;
        default:
            // Generic argument handling - already copied above
            break;
    }
}

// System call error handling helpers

// Handle system call filtering errors
static __always_inline int handle_syscall_filter_error(void) {
    record_error(ERROR_DATA_READ_ERROR);
    
    // For syscall filter errors, we should skip the event
    // but continue processing other syscalls
    return 0;  // Skip this syscall event
}

// Handle system call argument extraction errors
static __always_inline int handle_syscall_args_error(void) {
    record_error(ERROR_DATA_READ_ERROR);
    
    // For argument extraction errors, we can still process the event
    // with partial information (syscall number and return value)
    return 1;  // Continue processing with partial data
}

// System call event statistics recording
static __always_inline void record_syscall_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->events_processed, 1);
        // Note: syscall_events field would need to be added to debug_stats structure
        // This is a placeholder for the extended statistics structure
    }
}

// System call sampling statistics recording
static __always_inline void record_syscall_sampling_skipped(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->sampling_skipped, 1);
        // Note: syscall_sampling_skipped field would need to be added to debug_stats structure
        // This is a placeholder for the extended statistics structure
    }
}

// Unified system call event processing helper
static __always_inline int should_process_syscall_event(__u64 syscall_nr) {
    // First check if system call monitoring is enabled
    if (!should_process_event(MONITOR_SYSCALL)) {
        return 0;
    }
    
    // Check if this specific syscall should be traced
    if (!should_trace_syscall(syscall_nr)) {
        return 0;
    }
    
    // Apply syscall-specific sampling
    if (!should_sample_syscall(syscall_nr)) {
        record_syscall_sampling_skipped();
        return 0;
    }
    
    return 1;
}

// System call name resolution helper (for debugging and logging)
static __always_inline const char* get_syscall_name(__u64 syscall_nr) {
    switch (syscall_nr) {
        case 0: return "read";
        case 1: return "write";
        case 2: return "open";
        case 3: return "close";
        case 4: return "stat";
        case 5: return "fstat";
        case 6: return "lstat";
        case 10: return "unlink";
        case 41: return "socket";
        case 42: return "connect";
        case 43: return "accept";
        case 49: return "bind";
        case 50: return "listen";
        case 59: return "execve";
        case 82: return "rename";
        case 83: return "mkdir";
        case 84: return "rmdir";
        case 85: return "creat";
        case 257: return "openat";
        case 263: return "unlinkat";
        case 288: return "accept4";
        case 316: return "renameat2";
        case 322: return "execveat";
        default: return "unknown";
    }
}

#endif /* USE_KPROBE_FALLBACK */

#endif /* __COMMON_H__ */