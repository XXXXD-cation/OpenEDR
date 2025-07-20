#include "common.h"

// OpenEDR Process Monitor - Legacy Implementation
// 
// This file has been cleaned up and deprecated kprobe implementations removed.
// For production use, prefer process_monitor_v2.c which contains the optimized
// tracepoint-based implementation with enhanced error handling and debugging.
//
// This file is maintained for compatibility and fallback purposes only.

#ifndef USE_KPROBE_FALLBACK

// Tracepoint-based process execution handler
SEC("tp/sched/sched_process_exec")
int trace_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
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

// Tracepoint-based process exit handler
SEC("tp/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_exit *ctx) {
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

#endif /* USE_KPROBE_FALLBACK */

char _license[] SEC("license") = "GPL";