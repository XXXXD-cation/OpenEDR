#ifndef __SYSCALL_H__
#define __SYSCALL_H__

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "helpers.h"
#include "events.h"

// Common system call numbers (architecture-independent)
#ifndef __NR_execve
#define __NR_execve 59
#endif

#ifndef __NR_open
#define __NR_open 2
#endif

#ifndef __NR_openat
#define __NR_openat 257
#endif

#ifndef __NR_connect
#define __NR_connect 42
#endif

#ifndef __NR_accept
#define __NR_accept 43
#endif

#ifndef __NR_write
#define __NR_write 1
#endif

#ifndef __NR_unlink
#define __NR_unlink 87
#endif

#ifndef __NR_exit
#define __NR_exit 60
#endif

#ifndef __NR_exit_group
#define __NR_exit_group 231
#endif

// System call filtering - only monitor critical system calls
static __always_inline int should_trace_syscall(__u64 syscall_nr) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        // Default whitelist if config unavailable
        switch (syscall_nr) {
            case __NR_execve:
            case __NR_open:
            case __NR_openat:
            case __NR_connect:
            case __NR_accept:
            case __NR_write:
            case __NR_unlink:
                return 1;
            default:
                return 0;
        }
    }
    
    // If whitelist is empty, allow all syscalls
    if (cfg->syscall_whitelist_size == 0) {
        return 1;
    }
    
    // Check if syscall is in whitelist
    for (__u32 i = 0; i < cfg->syscall_whitelist_size && i < 32; i++) {
        if (cfg->syscall_whitelist[i] == syscall_nr) {
            return 1;
        }
    }
    
    record_syscall_filtered();
    return 0; // Syscall not in whitelist
}

// System call sampling strategy - high frequency syscalls use lower sampling rates
static __always_inline int should_sample_syscall(__u64 syscall_nr) {
    __u32 rate = 0;
    if (get_syscall_sampling_rate(&rate) != 0) {
        return 1; // Default to sampling if config unavailable
    }
    
    // Apply different sampling rates based on syscall frequency
    switch (syscall_nr) {
        case __NR_write:
            // High frequency syscall - use reduced sampling
            rate = rate / 4; // 25% of configured rate
            break;
        case __NR_open:
        case __NR_openat:
            // Medium frequency syscall - use half sampling
            rate = rate / 2; // 50% of configured rate
            break;
        case __NR_execve:
        case __NR_connect:
        case __NR_accept:
        case __NR_unlink:
            // Low frequency syscall - use full sampling
            break;
        default:
            // Unknown syscall - use conservative sampling
            rate = rate / 8; // 12.5% of configured rate
            break;
    }
    
    if (!should_sample(rate)) {
        record_syscall_sampling_skipped();
        return 0;
    }
    
    return 1;
}

// System call event allocation with retry
static __always_inline struct syscall_event* allocate_syscall_event_with_retry(__u32 event_type) {
    struct syscall_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        record_error(ERROR_ALLOCATION_FAILURE);
        return NULL;
    }
    
    // Initialize event header
    fill_event_header(&event->header, event_type);
    
    return event;
}

// System call event submission
static __always_inline void submit_syscall_event(struct syscall_event *event) {
    if (event) {
        bpf_ringbuf_submit(event, 0);
    }
}

// System call event discard
static __always_inline void discard_syscall_event(struct syscall_event *event) {
    if (event) {
        bpf_ringbuf_discard(event, 0);
    }
}

// System call argument extraction
static __always_inline void extract_syscall_args(struct syscall_event *event, 
                                                  __u64 syscall_nr,
                                                  const __u64 *args) {
    if (!should_capture_syscall_args()) {
        // Clear arguments if not configured to capture them
        for (int i = 0; i < 6; i++) {
            event->args[i] = 0;
        }
        return;
    }
    
    // Copy syscall arguments
    for (int i = 0; i < 6; i++) {
        event->args[i] = args[i];
    }
}

// System call return value extraction (simple version)
static __always_inline void extract_syscall_retval_simple(struct syscall_event *event, 
                                                          __s64 ret) {
    if (!should_capture_syscall_retval()) {
        event->ret = 0;
        return;
    }
    
    event->ret = ret;
}

// System call monitoring decision based on configuration
static __always_inline int should_monitor_syscall_event(void) {
    // Check if syscall monitoring is enabled
    __u32 enabled = 0;
    if (get_config_value(MONITOR_SYSCALL, &enabled) != 0 || !enabled) {
        return 0;
    }
    
    return 1;
}

// System call name lookup (for debugging)
static __always_inline const char* get_syscall_name(__u64 syscall_nr) {
    switch (syscall_nr) {
        case __NR_execve: return "execve";
        case __NR_open: return "open";
        case __NR_openat: return "openat";
        case __NR_connect: return "connect";
        case __NR_accept: return "accept";
        case __NR_write: return "write";
        case __NR_unlink: return "unlink";
        case __NR_exit: return "exit";
        case __NR_exit_group: return "exit_group";
        default: return "unknown";
    }
}

// System call category classification
static __always_inline int get_syscall_category(__u64 syscall_nr) {
    switch (syscall_nr) {
        case __NR_execve:
            return 1; // Process management
        case __NR_open:
        case __NR_openat:
        case __NR_write:
        case __NR_unlink:
            return 2; // File operations
        case __NR_connect:
        case __NR_accept:
            return 3; // Network operations
        case __NR_exit:
        case __NR_exit_group:
            return 4; // Process termination
        default:
            return 0; // Unknown/other
    }
}

// Adaptive sampling based on system load
static __always_inline void adjust_syscall_sampling_rate(void) {
    if (!is_adaptive_sampling_enabled()) {
        return;
    }
    
    // TODO: Implement adaptive sampling logic based on:
    // - Current event processing rate
    // - System load indicators
    // - Ring buffer utilization
    // - Error rates
}

// Alias for compatibility with syscall monitor
static __always_inline int should_process_syscall_event(__u64 syscall_nr) {
    return should_monitor_syscall_event() && should_trace_syscall(syscall_nr);
}

// Alias for compatibility with syscall monitor
static __always_inline int is_syscall_in_whitelist(__u64 syscall_nr) {
    return should_trace_syscall(syscall_nr);
}

// System call number validation helper
static __always_inline int validate_syscall_number(__u64 syscall_nr) {
    // Basic validation - syscall numbers should be reasonable
    // Most Linux syscalls are in the range 0-400
    if (syscall_nr > 1000) {
        record_error(ERROR_DATA_READ_ERROR);
        return 0; // Invalid syscall number
    }
    
    return 1; // Valid syscall number
}

// Validate syscall event data
static __always_inline int validate_syscall_event(struct syscall_event *event) {
    if (!event) {
        return 0;
    }
    
    // Validate syscall number is reasonable
    if (!validate_syscall_number(event->syscall_nr)) {
        return 0;
    }
    
    return 1;
}

#endif /* __SYSCALL_H__ */