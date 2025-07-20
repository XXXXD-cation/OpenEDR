#ifndef __COMMON_H__
#define __COMMON_H__

// Core Linux and eBPF includes
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

// Include events.h first for event structure definitions
#include "events.h"

// Forward declare config and debug_stats structures
struct config;
struct debug_stats;

// Map definitions (must be defined before config.h and stats.h)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct debug_stats);
} debug_stats_map SEC(".maps");

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Include specialized headers that depend on maps
#include "config.h"
#include "stats.h"
#include "helpers.h"
#include "network.h"
#include "file.h"
#include "syscall.h"

// Process event allocation with retry (for backward compatibility)
static __always_inline struct process_event* allocate_process_event_with_retry(__u32 event_type) {
    struct process_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        record_error(ERROR_ALLOCATION_FAILURE);
        return NULL;
    }
    
    // Initialize event header
    fill_event_header(&event->header, event_type);
    
    return event;
}

// Process event submission
static __always_inline void submit_process_event(struct process_event *event) {
    if (event) {
        bpf_ringbuf_submit(event, 0);
    }
}

// Process event discard
static __always_inline void discard_process_event(struct process_event *event) {
    if (event) {
        bpf_ringbuf_discard(event, 0);
    }
}

// Unified event allocation dispatcher
static __always_inline void* allocate_event(__u32 event_type) {
    switch (event_type) {
        case EVENT_PROCESS_EXEC:
        case EVENT_PROCESS_EXIT:
            return allocate_process_event_with_retry(event_type);
        case EVENT_NETWORK_CONNECT:
        case EVENT_NETWORK_ACCEPT:
            return allocate_network_event_with_retry(event_type);
        case EVENT_FILE_OPEN:
        case EVENT_FILE_WRITE:
        case EVENT_FILE_UNLINK:
            return allocate_file_event_with_retry(event_type);
        case EVENT_SYSCALL:
            return allocate_syscall_event_with_retry(event_type);
        default:
            return NULL;
    }
}

#endif /* __COMMON_H__ */