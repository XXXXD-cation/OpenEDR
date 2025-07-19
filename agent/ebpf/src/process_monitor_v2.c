#include "common.h"

// eBPF Process Monitor V2 - Optimized Implementation
// This version addresses the following issues from the original:
// 1. Uses stable tracepoints instead of unstable kprobes
// 2. Eliminates code duplication through shared helper functions
// 3. Fixes parent PID logic to get actual parent process ID
// 4. Simplifies process exit monitoring to avoid duplicate events
// 5. Enhances error handling and debugging capabilities

#ifndef USE_KPROBE_FALLBACK

// Optimized tracepoint-based process execution handler
// Uses sched_process_exec tracepoint for stable process monitoring
SEC("tp/sched/sched_process_exec")
int trace_process_exec_v2(struct trace_event_raw_sched_process_exec *ctx) {
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
    // This provides accurate parent PID and process information
    fill_process_exec_info(event, ctx);
    
    // Record successful exec event processing for monitoring
    record_exec_event();
    
    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Optimized tracepoint-based process exit handler
// Uses sched_process_exit tracepoint for unified exit monitoring
SEC("tp/sched/sched_process_exit")
int trace_process_exit_v2(struct trace_event_raw_sched_process_exit *ctx) {
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
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Additional tracepoint for capturing exit codes from syscalls
// This complements sched_process_exit to provide complete exit information
SEC("tp/syscalls/sys_exit_exit")
int trace_sys_exit_v2(struct trace_event_raw_sys_exit *ctx) {
    // Only process if we're monitoring processes
    __u32 enabled = 0;
    if (get_config_value_safe(MONITOR_PROCESS, &enabled, 1) < 0 || !enabled) {
        return 0;
    }
    
    // Basic PID filtering
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    if (!should_trace_pid(pid)) {
        return 0;
    }
    
    // For exit syscalls, we mainly want to capture the exit code
    // This information can be correlated with sched_process_exit events
    // in user space for complete process exit information
    
    // Allocate a minimal event for exit code tracking
    struct process_event *event = allocate_process_event_with_retry(EVENT_PROCESS_EXIT);
    if (!event) {
        return handle_allocation_failure();
    }
    
    // Fill basic information
    event->ppid = 0;  // Will be filled by sched_process_exit correlation
    event->exit_code = (__u32)ctx->ret;  // Actual exit code from syscall
    
    // Clear filename and args for syscall exit events
    __builtin_memset(event->filename, 0, sizeof(event->filename));
    __builtin_memset(event->args, 0, sizeof(event->args));
    
    // Submit event for correlation in user space
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Alternative tracepoint for exit_group syscalls
SEC("tp/syscalls/sys_exit_exit_group")
int trace_sys_exit_group_v2(struct trace_event_raw_sys_exit *ctx) {
    // Only process if we're monitoring processes
    __u32 enabled = 0;
    if (get_config_value_safe(MONITOR_PROCESS, &enabled, 1) < 0 || !enabled) {
        return 0;
    }
    
    // Basic PID filtering
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
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
    event->exit_code = (__u32)ctx->ret;  // Actual exit code from syscall
    
    // Clear filename and args for syscall exit events
    __builtin_memset(event->filename, 0, sizeof(event->filename));
    __builtin_memset(event->args, 0, sizeof(event->args));
    
    // Submit event for correlation in user space
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

#else /* USE_KPROBE_FALLBACK */

// Fallback kprobe implementations for older kernels
// These maintain compatibility while providing basic functionality

SEC("kprobe/sys_execve")
int trace_sys_execve_fallback(struct pt_regs *ctx) {
    // Use common preprocessing check
    if (!should_process_event(MONITOR_PROCESS)) {
        return 0;
    }
    
    // Get syscall arguments
    const char *filename = (const char *)PT_REGS_PARM1(ctx);
    if (!filename) {
        return handle_data_read_error();
    }
    
    // Allocate event
    struct process_event *event = allocate_process_event_with_retry(EVENT_PROCESS_EXEC);
    if (!event) {
        return handle_allocation_failure();
    }
    
    // Fill event information (with limitations of kprobe approach)
    event->ppid = bpf_get_current_pid_tgid() >> 32;  // Still incorrect, but best we can do with kprobe
    event->exit_code = 0;
    
    // Get filename from user space
    if (bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename) < 0) {
        __builtin_memset(event->filename, 0, sizeof(event->filename));
        handle_data_read_error();
    }
    
    // Clear args
    __builtin_memset(event->args, 0, sizeof(event->args));
    
    // Record and submit
    record_exec_event();
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

SEC("kprobe/sys_exit")
int trace_sys_exit_fallback(struct pt_regs *ctx) {
    // Use common preprocessing check
    if (!should_process_event(MONITOR_PROCESS)) {
        return 0;
    }
    
    // Get exit code from syscall argument
    int exit_code = (int)PT_REGS_PARM1(ctx);
    
    // Allocate event
    struct process_event *event = allocate_process_event_with_retry(EVENT_PROCESS_EXIT);
    if (!event) {
        return handle_allocation_failure();
    }
    
    // Fill event information
    event->ppid = bpf_get_current_pid_tgid() >> 32;  // Still incorrect, but best we can do
    event->exit_code = exit_code;
    
    // Clear filename and args for exit events
    __builtin_memset(event->filename, 0, sizeof(event->filename));
    __builtin_memset(event->args, 0, sizeof(event->args));
    
    // Record and submit
    record_exit_event();
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Note: We only use one exit handler in fallback mode to avoid duplication
// sys_exit_group is not monitored separately to prevent duplicate events

#endif /* USE_KPROBE_FALLBACK */

// Debug interface for user space to read statistics
SEC("kprobe/dummy_debug_stats")
int debug_stats_reader(struct pt_regs *ctx) {
    // This is a dummy function that user space can attach to
    // for reading debug statistics. The actual reading happens
    // through the debug_stats_map from user space.
    return 0;
}

char _license[] SEC("license") = "GPL";