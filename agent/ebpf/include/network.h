#ifndef __NETWORK_H__
#define __NETWORK_H__

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "helpers.h"

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

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

// Network byte order conversion helpers (eBPF doesn't have standard ntohl/htonl)
static __always_inline __u32 bpf_ntohl(__u32 netlong) {
    return ((__u32)(netlong) << 24) | 
           (((__u32)(netlong) << 8) & 0x00FF0000) |
           (((__u32)(netlong) >> 8) & 0x0000FF00) |
           ((__u32)(netlong) >> 24);
}

static __always_inline __u16 bpf_ntohs(__u16 netshort) {
    return ((__u16)(netshort) << 8) | ((__u16)(netshort) >> 8);
}

static __always_inline __u32 bpf_htonl(__u32 hostlong) {
    return bpf_ntohl(hostlong); // Same operation for conversion both ways
}

static __always_inline __u16 bpf_htons(__u16 hostshort) {
    return bpf_ntohs(hostshort); // Same operation for conversion both ways
}

// Basic socket address structure
struct sockaddr {
    __u16 sa_family;
    char sa_data[14];
};

// Network monitoring tracepoint context structures

// TCP socket state change tracepoint context
struct trace_event_raw_inet_sock_set_state {
    struct trace_entry ent;
    const void *skaddr;         // Socket address
    __s32 oldstate;             // Previous socket state
    __s32 newstate;             // New socket state
    __u16 sport;                // Source port
    __u16 dport;                // Destination port
    __u16 family;               // Address family (AF_INET/AF_INET6)
    __u16 protocol;             // Protocol (IPPROTO_TCP/UDP)
    __u8 saddr[4];              // Source address (IPv4)
    __u8 daddr[4];              // Destination address (IPv4)
    __u8 saddr_v6[16];          // Source address (IPv6)
    __u8 daddr_v6[16];          // Destination address (IPv6)
    char __data[0];             // Variable length data area
};

// Socket send message tracepoint context
struct trace_event_raw_sock_sendmsg {
    struct trace_entry ent;
    const void *sk;             // Socket pointer
    __u32 size;                 // Message size
    __s32 ret;                  // Return value
    char __data[0];             // Variable length data area
};

// Socket receive message tracepoint context
struct trace_event_raw_sock_recvmsg {
    struct trace_entry ent;
    const void *sk;             // Socket pointer
    __u32 size;                 // Message size
    __s32 ret;                  // Return value
    char __data[0];             // Variable length data area
};

// Network information extraction functions
static __always_inline void extract_ipv4_info(struct network_event *event, 
                                               const __u8 *saddr, 
                                               const __u8 *daddr) {
    // Copy IPv4 addresses (4 bytes each)
    if (saddr) {
        event->saddr_v4 = *(__u32*)saddr;
    }
    if (daddr) {
        event->daddr_v4 = *(__u32*)daddr;
    }
}

static __always_inline void extract_ipv6_info(struct network_event *event, 
                                               const __u8 *saddr, 
                                               const __u8 *daddr) {
    // Copy IPv6 addresses (16 bytes each)
    if (saddr) {
        for (int i = 0; i < 16; i++) {
            event->saddr_v6[i] = saddr[i];
        }
    }
    if (daddr) {
        for (int i = 0; i < 16; i++) {
            event->daddr_v6[i] = daddr[i];
        }
    }
}

// Network event allocation with retry
static __always_inline struct network_event* allocate_network_event_with_retry(__u32 event_type) {
    struct network_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        record_error(ERROR_ALLOCATION_FAILURE);
        return NULL;
    }
    
    // Initialize event header
    fill_event_header(&event->header, event_type);
    
    return event;
}

// Network event submission
static __always_inline void submit_network_event(struct network_event *event) {
    if (event) {
        bpf_ringbuf_submit(event, 0);
    }
}

// Network event discard
static __always_inline void discard_network_event(struct network_event *event) {
    if (event) {
        bpf_ringbuf_discard(event, 0);
    }
}

// Network protocol validation
static __always_inline int is_supported_protocol(__u16 protocol) {
    return (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP);
}

// Network family validation
static __always_inline int is_supported_family(__u16 family) {
    return (family == AF_INET || family == AF_INET6);
}

// Network event filtering based on configuration
static __always_inline int should_monitor_network_event(__u16 family, __u16 protocol) {
    // Check if network monitoring is enabled
    __u32 enabled = 0;
    if (get_config_value(MONITOR_NETWORK, &enabled) != 0 || !enabled) {
        return 0;
    }
    
    // Check protocol-specific settings
    if (protocol == IPPROTO_TCP && !is_tcp_monitoring_enabled()) {
        return 0;
    }
    
    if (protocol == IPPROTO_UDP && !is_udp_monitoring_enabled()) {
        return 0;
    }
    
    // Check IPv6 settings
    if (family == AF_INET6 && !is_ipv6_monitoring_enabled()) {
        return 0;
    }
    
    return 1;
}

// Network sampling decision
static __always_inline int should_sample_network_event(void) {
    __u32 rate = 0;
    if (get_network_sampling_rate(&rate) != 0) {
        return 1; // Default to sampling if config unavailable
    }
    
    if (!should_sample(rate)) {
        record_network_sampling_skipped();
        return 0;
    }
    
    return 1;
}

// Alias for compatibility with network monitor
static __always_inline int should_process_network_event(__u16 family, __u16 protocol) {
    return should_monitor_network_event(family, protocol);
}

// Fill network information from inet socket state tracepoint
static __always_inline int fill_network_info_from_inet_sock_state(struct network_event *event,
                                                                  struct trace_event_raw_inet_sock_set_state *ctx) {
    if (!event || !ctx) {
        return 0;
    }
    
    // Fill basic network information
    event->family = ctx->family;
    event->protocol = ctx->protocol;
    event->sport = bpf_ntohs(ctx->sport);
    event->dport = bpf_ntohs(ctx->dport);
    
    // Fill address information based on family
    if (ctx->family == AF_INET) {
        extract_ipv4_info(event, ctx->saddr, ctx->daddr);
    } else if (ctx->family == AF_INET6) {
        extract_ipv6_info(event, ctx->saddr_v6, ctx->daddr_v6);
    }
    
    return 1;
}

#endif /* __NETWORK_H__ */