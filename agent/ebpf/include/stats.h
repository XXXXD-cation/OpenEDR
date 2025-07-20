#ifndef __STATS_H__
#define __STATS_H__

#include <linux/types.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

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

// Error types for statistics
enum error_type {
    ERROR_EVENT_DROPPED = 0,
    ERROR_ALLOCATION_FAILURE = 1,
    ERROR_CONFIG_ERROR = 2,
    ERROR_DATA_READ_ERROR = 3,
    ERROR_TRACEPOINT_ERROR = 4,
};

// Debug and error statistics
struct debug_stats {
    // General event statistics
    __u64 events_processed;     // Total events processed
    __u64 events_dropped;       // Events dropped due to various reasons
    __u64 allocation_failures;  // Ring buffer allocation failures
    __u64 config_errors;        // Configuration read errors
    __u64 data_read_errors;     // Data read/extraction errors
    __u64 tracepoint_errors;    // Tracepoint-specific errors
    
    // Process monitoring statistics
    __u64 exec_events;          // Process execution events
    __u64 exit_events;          // Process exit events
    
    // Network monitoring statistics
    __u64 network_events;       // Total network events
    __u64 network_connect_events; // Network connection events
    __u64 network_accept_events;  // Network accept events
    __u64 network_sendmsg_events; // Network send message events
    __u64 network_recvmsg_events; // Network receive message events
    __u64 network_ipv4_events;    // IPv4 network events
    __u64 network_ipv6_events;    // IPv6 network events
    __u64 network_tcp_events;     // TCP protocol events
    __u64 network_udp_events;     // UDP protocol events
    
    // File system monitoring statistics
    __u64 file_events;          // Total file system events
    __u64 file_open_events;     // File open events
    __u64 file_write_events;    // File write events
    __u64 file_unlink_events;   // File delete/unlink events
    __u64 file_path_extraction_errors; // File path extraction failures
    __u64 file_type_filtered;   // Files filtered by type/extension
    
    // System call monitoring statistics
    __u64 syscall_events;       // Total system call events
    __u64 syscall_enter_events; // System call enter events
    __u64 syscall_exit_events;  // System call exit events
    __u64 syscall_filtered;     // System calls filtered by whitelist
    
    // Sampling and filtering statistics
    __u64 sampling_skipped;     // Events skipped due to sampling
    __u64 network_sampling_skipped; // Network events skipped by sampling
    __u64 file_sampling_skipped;    // File events skipped by sampling
    __u64 syscall_sampling_skipped; // Syscall events skipped by sampling
    __u64 pid_filtered;         // Events filtered by PID
    
    // Error tracking and debugging
    __u64 socket_info_errors;   // Socket information extraction errors
    __u64 last_error_timestamp; // Timestamp of last error
    __u32 last_error_type;      // Type of last error
    __u32 last_error_pid;       // PID that caused last error
    
    // Performance monitoring fields
    __u64 last_event_timestamp; // Timestamp of last processed event
    __u32 events_per_second;    // Current events per second rate
    __u32 avg_processing_time_ns; // Average event processing time in nanoseconds
    __u32 peak_events_per_second; // Peak events per second observed
    __u32 ringbuf_utilization_percent; // Ring buffer utilization percentage
    
    // Adaptive sampling statistics
    __u32 current_sampling_rate; // Current adaptive sampling rate
    __u32 sampling_adjustments;  // Number of sampling rate adjustments
    __u64 high_load_periods;     // Number of high load periods detected
    __u64 low_load_periods;      // Number of low load periods detected
    
    // Memory and resource usage
    __u32 max_concurrent_events; // Maximum concurrent events in processing
    __u32 current_memory_usage_kb; // Current estimated memory usage in KB
    __u32 peak_memory_usage_kb;    // Peak memory usage observed in KB
};

// Debug statistics map is defined in common.h

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

// Network event statistics recording
static __always_inline void record_network_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->network_events, 1);
        __sync_fetch_and_add(&stats->events_processed, 1);
    }
}

static __always_inline void record_network_connect_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->network_connect_events, 1);
        record_network_event();
    }
}

static __always_inline void record_network_accept_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->network_accept_events, 1);
        record_network_event();
    }
}

static __always_inline void record_network_sendmsg_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->network_sendmsg_events, 1);
        record_network_event();
    }
}

static __always_inline void record_network_recvmsg_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->network_recvmsg_events, 1);
        record_network_event();
    }
}

static __always_inline void record_network_protocol_event(__u16 protocol) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        if (protocol == IPPROTO_TCP) {
            __sync_fetch_and_add(&stats->network_tcp_events, 1);
        } else if (protocol == IPPROTO_UDP) {
            __sync_fetch_and_add(&stats->network_udp_events, 1);
        }
    }
}

static __always_inline void record_network_family_event(__u16 family) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        if (family == AF_INET) {
            __sync_fetch_and_add(&stats->network_ipv4_events, 1);
        } else if (family == AF_INET6) {
            __sync_fetch_and_add(&stats->network_ipv6_events, 1);
        }
    }
}

static __always_inline void record_network_sampling_skipped(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->network_sampling_skipped, 1);
    }
}

static __always_inline void record_socket_info_error(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->socket_info_errors, 1);
    }
}

// File system event statistics recording
static __always_inline void record_file_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->file_events, 1);
        __sync_fetch_and_add(&stats->events_processed, 1);
    }
}

static __always_inline void record_file_open_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->file_open_events, 1);
        record_file_event();
    }
}

static __always_inline void record_file_write_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->file_write_events, 1);
        record_file_event();
    }
}

static __always_inline void record_file_unlink_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->file_unlink_events, 1);
        record_file_event();
    }
}

static __always_inline void record_file_path_extraction_error(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->file_path_extraction_errors, 1);
    }
}

static __always_inline void record_file_type_filtered(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->file_type_filtered, 1);
    }
}

static __always_inline void record_file_sampling_skipped(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->file_sampling_skipped, 1);
    }
}

// System call event statistics recording
static __always_inline void record_syscall_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->syscall_events, 1);
        __sync_fetch_and_add(&stats->events_processed, 1);
    }
}

static __always_inline void record_syscall_enter_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->syscall_enter_events, 1);
        record_syscall_event();
    }
}

static __always_inline void record_syscall_exit_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->syscall_exit_events, 1);
        record_syscall_event();
    }
}

static __always_inline void record_syscall_filtered(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->syscall_filtered, 1);
    }
}

static __always_inline void record_syscall_sampling_skipped(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->syscall_sampling_skipped, 1);
    }
}

// General sampling and filtering statistics
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

#endif /* __STATS_H__ */