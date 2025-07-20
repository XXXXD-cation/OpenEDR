#include "common.h"

// OpenEDR Process Monitor V2 - Optimized Tracepoint Implementation
//
// Key improvements over V1:
// - Uses stable kernel tracepoints instead of unstable kprobes
// - Eliminates code duplication through shared helper functions  
// - Provides accurate parent PID extraction from tracepoint context
// - Unified process exit monitoring without duplicate events
// - Enhanced error handling and debugging capabilities

// Process execution monitoring using stable sched_process_exec tracepoint
SEC("tp/sched/sched_process_exec")
int trace_process_exec_v2(struct trace_event_raw_sched_process_exec *ctx) {
    if (!should_process_event(MONITOR_PROCESS)) {
        return 0;
    }
    
    struct process_event *event = allocate_process_event_with_retry(EVENT_PROCESS_EXEC);
    if (!event) {
        return handle_allocation_failure();
    }
    
    fill_process_exec_info(event, ctx);
    record_exec_event();
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Process exit monitoring using stable sched_process_exit tracepoint
SEC("tp/sched/sched_process_exit")
int trace_process_exit_v2(struct trace_event_raw_sched_process_exit *ctx) {
    if (!should_process_event(MONITOR_PROCESS)) {
        return 0;
    }
    
    struct process_event *event = allocate_process_event_with_retry(EVENT_PROCESS_EXIT);
    if (!event) {
        return handle_allocation_failure();
    }
    
    fill_process_exit_info(event, ctx);
    record_exit_event();
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Note: Additional syscall tracepoints for exit code capture have been removed
// to simplify the implementation. The sched_process_exit tracepoint provides
// sufficient information for process exit monitoring.

// Fallback kprobe implementations have been removed as they are no longer needed.
// The V2 implementation focuses exclusively on stable tracepoint-based monitoring.
// For older kernels that don't support tracepoints, use process_monitor.c instead.

// Debug statistics are now accessed directly through the debug_stats_map
// from user space, eliminating the need for a dummy debug function.

char _license[] SEC("license") = "GPL";