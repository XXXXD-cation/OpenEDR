#include "common.h"

// Simple kprobe for process execution (execve syscall)
SEC("kprobe/sys_execve")
int trace_sys_execve(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we should trace this PID
    if (!should_trace_pid(pid)) {
        return 0;
    }
    
    // Check if process monitoring is enabled
    __u32 enabled = 0;
    if (get_config_value(0, &enabled) < 0 || !enabled) {
        return 0;
    }
    
    // Check sampling rate
    __u32 rate = 100;
    get_config_value(4, &rate);
    if (!should_sample(rate)) {
        return 0;
    }
    
    // Get syscall arguments
    const char *filename = (const char *)PT_REGS_PARM1(ctx);
    
    if (!filename) {
        return 0;
    }
    
    // Reserve space in ring buffer
    struct process_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event header
    fill_event_header(&event->header, EVENT_PROCESS_EXEC);
    
    // Get parent PID (simplified - use current task's parent)
    event->ppid = bpf_get_current_pid_tgid() >> 32; // TGID of current process
    event->exit_code = 0; // Not applicable for exec events
    
    // Get filename from user space
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    
    // Clear args for now (getting command line args is complex)
    __builtin_memset(event->args, 0, sizeof(event->args));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Simple kprobe for process exit (exit syscall)
SEC("kprobe/sys_exit")
int trace_sys_exit(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we should trace this PID
    if (!should_trace_pid(pid)) {
        return 0;
    }
    
    // Check if process monitoring is enabled
    __u32 enabled = 0;
    if (get_config_value(0, &enabled) < 0 || !enabled) {
        return 0;
    }
    
    // Check sampling rate
    __u32 rate = 100;
    get_config_value(4, &rate);
    if (!should_sample(rate)) {
        return 0;
    }
    
    // Get exit code from syscall argument
    int exit_code = (int)PT_REGS_PARM1(ctx);
    
    // Reserve space in ring buffer
    struct process_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event header
    fill_event_header(&event->header, EVENT_PROCESS_EXIT);
    
    // Get parent PID (simplified)
    event->ppid = bpf_get_current_pid_tgid() >> 32; // TGID of current process
    event->exit_code = exit_code;
    
    // Clear filename and args for exit events
    __builtin_memset(event->filename, 0, sizeof(event->filename));
    __builtin_memset(event->args, 0, sizeof(event->args));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Simple kprobe for exit_group syscall (process group exit)
SEC("kprobe/sys_exit_group")
int trace_sys_exit_group(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we should trace this PID
    if (!should_trace_pid(pid)) {
        return 0;
    }
    
    // Check if process monitoring is enabled
    __u32 enabled = 0;
    if (get_config_value(0, &enabled) < 0 || !enabled) {
        return 0;
    }
    
    // Check sampling rate
    __u32 rate = 100;
    get_config_value(4, &rate);
    if (!should_sample(rate)) {
        return 0;
    }
    
    // Get exit code from syscall argument
    int exit_code = (int)PT_REGS_PARM1(ctx);
    
    // Reserve space in ring buffer
    struct process_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event header
    fill_event_header(&event->header, EVENT_PROCESS_EXIT);
    
    // Get parent PID (simplified)
    event->ppid = bpf_get_current_pid_tgid() >> 32; // TGID of current process
    event->exit_code = exit_code;
    
    // Clear filename and args for exit events
    __builtin_memset(event->filename, 0, sizeof(event->filename));
    __builtin_memset(event->args, 0, sizeof(event->args));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

#ifndef USE_KPROBE_FALLBACK

// New tracepoint-based process execution handler
SEC("tp/sched/sched_process_exec")
int trace_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
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
    
    // Record successful exec event processing
    record_exec_event();
    
    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// New tracepoint-based process exit handler
SEC("tp/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_exit *ctx) {
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
    
    // Record successful exit event processing
    record_exit_event();
    
    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

#endif /* USE_KPROBE_FALLBACK */

char _license[] SEC("license") = "GPL";