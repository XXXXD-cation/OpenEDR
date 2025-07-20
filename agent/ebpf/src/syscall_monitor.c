#include "common.h"

// OpenEDR System Call Monitor - Tracepoint-based Implementation
//
// This module implements system call monitoring using stable kernel tracepoints
// for system call enter and exit events. It integrates with the unified event
// processing framework established in the process monitor implementation.

#ifndef USE_KPROBE_FALLBACK


// System call return value validation and extraction helper
static __always_inline int extract_syscall_retval(struct syscall_event *event,
                                                 const struct trace_event_raw_sys_exit *ctx) {
    if (!event || !ctx) {
        record_error(ERROR_DATA_READ_ERROR);
        return -1;
    }
    
    // Check if syscall return value capture is enabled
    if (!should_capture_syscall_retval()) {
        // Set return value to 0 if capture is disabled
        event->ret = 0;
        return 0;
    }
    
    // Extract system call return value with validation
    // The ret field in the tracepoint context contains the return value
    if (bpf_probe_read_kernel(&event->ret, sizeof(event->ret), &ctx->ret) != 0) {
        // If we can't read the return value, set it to 0
        event->ret = 0;
        record_error(ERROR_DATA_READ_ERROR);
        return -1;
    }
    
    return 0;
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

// System call event validation function
static __always_inline int validate_syscall_event(struct syscall_event *event) {
    if (!event) {
        return 0; // Invalid event structure
    }
    
    // Validate syscall number is reasonable
    if (!validate_syscall_number(event->syscall_nr)) {
        return 0; // Invalid syscall number
    }
    
    // Additional validation could be added here for specific syscalls
    // For now, we accept all valid syscall numbers
    
    return 1; // Event is valid
}

// System call error handling function
static __always_inline int handle_syscall_error(__u32 error_type, struct syscall_event *event) {
    record_error(ERROR_DATA_READ_ERROR);
    
    switch (error_type) {
        case 1: // SYSCALL_ARG_EXTRACTION_ERROR
            // Clear arguments and continue
            if (event) {
                for (int i = 0; i < 6; i++) {
                    event->args[i] = 0;
                }
            }
            return 1; // Continue processing
            
        case 2: // SYSCALL_RETVAL_EXTRACTION_ERROR
            // Set return value to 0 and continue
            if (event) {
                event->ret = 0;
            }
            return 1; // Continue processing
            
        case 3: // SYSCALL_NUMBER_INVALID
            // Invalid syscall number, skip event
            return 0; // Drop event
            
        case 4: // SYSCALL_CONTEXT_READ_ERROR
            // Context read failed, skip event
            record_error(ERROR_TRACEPOINT_ERROR);
            return 0; // Drop event
            
        default:
            // Unknown error type, skip event for safety
            return 0; // Drop event
    }
}

// System call enter tracepoint handler
SEC("tp/syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we should trace this PID
    if (!should_trace_pid(pid)) {
        record_pid_filtered();
        return 0;
    }
    
    // Validate syscall number first
    if (!validate_syscall_number(ctx->id)) {
        return 0;
    }
    
    // Check if we should process this syscall event
    if (!should_process_syscall_event(ctx->id)) {
        return 0;
    }
    
    // Check if this specific syscall is in the whitelist
    if (!is_syscall_in_whitelist(ctx->id)) {
        record_syscall_filtered();
        return 0;
    }
    
    // Check syscall-specific sampling rate
    __u32 rate = 100;
    if (get_syscall_sampling_rate(&rate) < 0) {
        rate = 100; // Default to full sampling if config unavailable
    }
    
    if (!should_sample(rate)) {
        record_syscall_sampling_skipped();
        return 0;
    }
    
    // Allocate syscall event with retry logic
    struct syscall_event *event = allocate_syscall_event_with_retry(EVENT_SYSCALL);
    if (!event) {
        return 0;
    }
    
    // Set syscall number
    event->syscall_nr = ctx->id;
    
    // Extract syscall arguments using the existing helper function
    extract_syscall_args(event, ctx->id, ctx->args);
    
    // Set return value to 0 for enter events (will be filled on exit)
    event->ret = 0;
    
    // Validate the extracted syscall event data
    if (!validate_syscall_event(event)) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    // Record statistics
    record_syscall_enter_event();
    
    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// System call exit tracepoint handler
SEC("tp/syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we should trace this PID
    if (!should_trace_pid(pid)) {
        record_pid_filtered();
        return 0;
    }
    
    // Validate syscall number first
    if (!validate_syscall_number(ctx->id)) {
        return 0;
    }
    
    // Check if we should process this syscall event
    if (!should_process_syscall_event(ctx->id)) {
        return 0;
    }
    
    // Check if this specific syscall is in the whitelist
    if (!is_syscall_in_whitelist(ctx->id)) {
        record_syscall_filtered();
        return 0;
    }
    
    // Check syscall-specific sampling rate
    __u32 rate = 100;
    if (get_syscall_sampling_rate(&rate) < 0) {
        rate = 100; // Default to full sampling if config unavailable
    }
    
    if (!should_sample(rate)) {
        record_syscall_sampling_skipped();
        return 0;
    }
    
    // Allocate syscall event with retry logic
    struct syscall_event *event = allocate_syscall_event_with_retry(EVENT_SYSCALL);
    if (!event) {
        return 0;
    }
    
    // Set syscall number
    event->syscall_nr = ctx->id;
    
    // Clear arguments for exit events (we don't have access to them here)
    for (int i = 0; i < 6; i++) {
        event->args[i] = 0;
    }
    
    // Extract syscall return value with error handling
    if (extract_syscall_retval(event, ctx) < 0) {
        // Handle extraction error but continue processing
        if (!handle_syscall_error(2, event)) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
    }
    
    // Validate the extracted syscall event data
    if (!validate_syscall_event(event)) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    // Record statistics
    record_syscall_exit_event();
    
    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

#else

// Fallback kprobe implementations for older kernels
// These are simplified versions for compatibility

// Generic syscall entry kprobe handler
SEC("kprobe/sys_call_table")
int trace_syscall_entry_fallback(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we should trace this PID
    if (!should_trace_pid(pid)) {
        record_pid_filtered();
        return 0;
    }
    
    // Get syscall number from register (architecture-specific)
    __u64 syscall_nr = PT_REGS_PARM1(ctx);
    
    // Validate syscall number
    if (!validate_syscall_number(syscall_nr)) {
        return 0;
    }
    
    // Check if we should process this syscall event
    if (!should_process_syscall_event(syscall_nr)) {
        return 0;
    }
    
    // Check if this specific syscall is in the whitelist
    if (!is_syscall_in_whitelist(syscall_nr)) {
        record_syscall_filtered();
        return 0;
    }
    
    // Check syscall-specific sampling rate
    __u32 rate = 100;
    if (get_syscall_sampling_rate(&rate) < 0) {
        rate = 100; // Default to full sampling if config unavailable
    }
    
    if (!should_sample(rate)) {
        record_syscall_sampling_skipped();
        return 0;
    }
    
    // Reserve space in ring buffer
    struct syscall_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        record_error(ERROR_ALLOCATION_FAILURE);
        return 0;
    }
    
    // Fill event header
    fill_event_header(&event->header, EVENT_SYSCALL);
    
    // Set syscall number
    event->syscall_nr = syscall_nr;
    
    // Extract arguments if enabled (simplified for kprobe)
    if (should_capture_syscall_args()) {
        event->args[0] = PT_REGS_PARM1(ctx);
        event->args[1] = PT_REGS_PARM2(ctx);
        event->args[2] = PT_REGS_PARM3(ctx);
        event->args[3] = PT_REGS_PARM4(ctx);
        event->args[4] = PT_REGS_PARM5(ctx);
        event->args[5] = PT_REGS_PARM6(ctx);
    } else {
        for (int i = 0; i < 6; i++) {
            event->args[i] = 0;
        }
    }
    
    // Set return value to 0 for entry events
    event->ret = 0;
    
    // Record statistics
    record_syscall_enter_event();
    
    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

#endif /* USE_KPROBE_FALLBACK */

char _license[] SEC("license") = "GPL";