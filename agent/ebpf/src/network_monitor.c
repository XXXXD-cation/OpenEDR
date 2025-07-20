#include "common.h"

// OpenEDR Network Monitor - Tracepoint-based Implementation
//
// This module implements network monitoring using stable kernel tracepoints
// for TCP connection state changes and network data transmission events.
// It integrates with the unified event processing framework established
// in the process monitor implementation.

#ifndef USE_KPROBE_FALLBACK

// TCP connection state monitoring using inet_sock_set_state tracepoint
// This tracepoint is triggered when TCP socket state changes occur
SEC("tp/sock/inet_sock_set_state")
int trace_inet_sock_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    // Check if we should process this network event based on configuration
    // This includes checking if network monitoring is enabled, protocol filtering,
    // IPv6 support, and applying sampling rates
    if (!should_process_network_event(ctx->family, ctx->protocol)) {
        return 0;
    }
    
    // Only process TCP protocol events for connection tracking
    // UDP events are handled separately as they are connectionless
    if (ctx->protocol != IPPROTO_TCP) {
        return 0;
    }
    
    // Determine event type based on socket state transition
    // TCP states: ESTABLISHED=1, SYN_SENT=2, SYN_RECV=3, LISTEN=10
    // We focus on transitions to ESTABLISHED state to capture connections
    __u32 event_type;
    
    if (ctx->newstate == 1) {  // TCP_ESTABLISHED
        if (ctx->oldstate == 2) {  // SYN_SENT -> ESTABLISHED (outbound connection)
            event_type = EVENT_NETWORK_CONNECT;
        } else if (ctx->oldstate == 3) {  // SYN_RECV -> ESTABLISHED (inbound connection)
            event_type = EVENT_NETWORK_ACCEPT;
        } else {
            // Other transitions to ESTABLISHED, treat as connect
            // This handles edge cases and ensures we don't miss connections
            event_type = EVENT_NETWORK_CONNECT;
        }
    } else {
        // Skip other state transitions (CLOSE, FIN_WAIT, etc.)
        // These could be added in future for connection termination tracking
        return 0;
    }
    
    // Allocate network event with retry logic
    // Uses the unified allocation framework with fallback retry
    struct network_event *event = allocate_network_event_with_retry(event_type);
    if (!event) {
        return handle_allocation_failure();
    }
    
    // Fill network information from tracepoint context with error handling
    // This extracts addresses, ports, and protocol information
    if (!fill_network_info_from_inet_sock_state(event, ctx)) {
        // Network information extraction failed, discard the event
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    // Record event statistics for monitoring and debugging
    if (event_type == EVENT_NETWORK_CONNECT) {
        record_network_connect_event();
    } else {
        record_network_accept_event();
    }
    
    // Record protocol and family statistics
    record_network_protocol_event(ctx->protocol);
    record_network_family_event(ctx->family);
    
    // Submit event to ring buffer for user space processing
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Network data transmission monitoring using sock_sendmsg tracepoint
SEC("tp/sock/sock_sendmsg")
int trace_sock_sendmsg(struct trace_event_raw_sock_sendmsg *ctx) {
    // For now, we only track connection events, not data transmission
    // This tracepoint is available for future enhancement to monitor
    // data flow patterns and volumes
    
    // Record sendmsg event for statistics
    record_network_sendmsg_event();
    
    return 0;
}

// Network data reception monitoring using sock_recvmsg tracepoint
SEC("tp/sock/sock_recvmsg")
int trace_sock_recvmsg(struct trace_event_raw_sock_recvmsg *ctx) {
    // For now, we only track connection events, not data transmission
    // This tracepoint is available for future enhancement to monitor
    // data flow patterns and volumes
    
    // Record recvmsg event for statistics
    record_network_recvmsg_event();
    
    return 0;
}

#else

// Fallback implementations for older kernels would go here
// For now, network monitoring requires modern tracepoint support

#endif /* USE_KPROBE_FALLBACK */

char _license[] SEC("license") = "GPL";