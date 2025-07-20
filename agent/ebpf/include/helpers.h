#ifndef __HELPERS_H__
#define __HELPERS_H__

#include <linux/types.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "events.h"
#include "config.h"

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

// Ring buffer for events is defined in common.h

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

// Sampling helper
static __always_inline int should_sample(__u32 rate) {
    if (rate == 0) return 0;
    if (rate >= 100) return 1;
    
    return (bpf_get_prandom_u32() % 100) < rate;
}

// Check if we should process an event based on monitor type
static __always_inline int should_process_event(__u32 monitor_type) {
    __u32 enabled = 0;
    if (get_config_value_safe(monitor_type, &enabled, 1) < 0) {
        return 1; // Default to enabled if config unavailable
    }
    return enabled;
}

// Handle allocation failure
static __always_inline int handle_allocation_failure(void) {
    record_error(ERROR_ALLOCATION_FAILURE);
    return 0;
}

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

// System call enter tracepoint context
struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    __s64 id;                   // System call number
    __u64 args[6];              // System call arguments
    char __data[0];             // Variable length data area
};

#endif /* USE_KPROBE_FALLBACK */

// Fill process execution information from tracepoint context
static __always_inline void fill_process_exec_info(struct process_event *event, 
                                                   struct trace_event_raw_sched_process_exec *ctx) {
    if (!event || !ctx) return;
    
    event->ppid = ctx->old_pid;
    event->exit_code = 0; // Not applicable for exec events
    
    // Extract filename from variable data area
    if (ctx->__data_loc_filename) {
        bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), 
                                 (char *)ctx + ctx->__data_loc_filename);
    } else {
        __builtin_memcpy(event->filename, "<unknown>", 10);
    }
    
    // Clear args for now (could be extended to capture command line)
    event->args[0] = '\0';
}

// Fill process exit information from tracepoint context
static __always_inline void fill_process_exit_info(struct process_event *event,
                                                   struct trace_event_raw_sched_process_exit *ctx) {
    if (!event || !ctx) return;
    
    event->ppid = 0; // Not available in exit context
    event->exit_code = 0; // Would need to be captured from sys_exit tracepoint
    
    // Copy command name from context
    __builtin_memcpy(event->filename, ctx->comm, sizeof(ctx->comm));
    event->filename[sizeof(ctx->comm)] = '\0';
    
    // Clear args
    event->args[0] = '\0';
}

#endif /* __HELPERS_H__ */