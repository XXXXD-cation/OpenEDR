#include "common.h"

// Simple kprobe for sys_connect
SEC("kprobe/sys_connect")
int trace_sys_connect(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we should trace this PID
    if (!should_trace_pid(pid)) {
        return 0;
    }
    
    // Check if network monitoring is enabled
    __u32 enabled = 0;
    if (get_config_value(1, &enabled) < 0 || !enabled) {
        return 0;
    }
    
    // Check sampling rate
    __u32 rate = 100;
    get_config_value(4, &rate);
    if (!should_sample(rate)) {
        return 0;
    }
    
    // Get syscall arguments
    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    int addrlen = (int)PT_REGS_PARM3(ctx);
    
    if (!addr || addrlen < sizeof(struct sockaddr)) {
        return 0;
    }
    
    // Reserve space in ring buffer
    struct network_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event header
    fill_event_header(&event->header, EVENT_NETWORK_CONNECT);
    
    // Read address family
    __u16 family;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    
    event->family = family;
    event->protocol = 6; // TCP (simplified assumption)
    event->sport = 0;    // Source port not easily available at syscall level
    event->dport = 0;    // Will try to extract if possible
    
    // Try to extract destination info based on family
    if (family == AF_INET) {
        struct sockaddr_in addr_in;
        if (addrlen >= sizeof(addr_in)) {
            bpf_probe_read_user(&addr_in, sizeof(addr_in), addr);
            event->daddr_v4 = addr_in.sin_addr.s_addr;
            event->dport = __builtin_bswap16(addr_in.sin_port);
        }
    } else if (family == AF_INET6) {
        struct sockaddr_in6 addr_in6;
        if (addrlen >= sizeof(addr_in6)) {
            bpf_probe_read_user(&addr_in6, sizeof(addr_in6), addr);
            __builtin_memcpy(&event->daddr_v6, &addr_in6.sin6_addr, 16);
            event->dport = __builtin_bswap16(addr_in6.sin6_port);
        }
    }
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Simple kprobe for sys_accept
SEC("kprobe/sys_accept")
int trace_sys_accept(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we should trace this PID
    if (!should_trace_pid(pid)) {
        return 0;
    }
    
    // Check if network monitoring is enabled
    __u32 enabled = 0;
    if (get_config_value(1, &enabled) < 0 || !enabled) {
        return 0;
    }
    
    // Check sampling rate
    __u32 rate = 100;
    get_config_value(4, &rate);
    if (!should_sample(rate)) {
        return 0;
    }
    
    // Reserve space in ring buffer
    struct network_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event header
    fill_event_header(&event->header, EVENT_NETWORK_ACCEPT);
    
    // For accept, we have limited info at syscall entry
    event->family = AF_INET;  // Assume IPv4 for simplicity
    event->protocol = 6;      // TCP
    event->sport = 0;         // Not available at syscall level
    event->dport = 0;         // Not available at syscall level
    event->saddr_v4 = 0;      // Not available at syscall level
    event->daddr_v4 = 0;      // Not available at syscall level
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Simple kprobe for sys_accept4
SEC("kprobe/sys_accept4")
int trace_sys_accept4(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we should trace this PID
    if (!should_trace_pid(pid)) {
        return 0;
    }
    
    // Check if network monitoring is enabled
    __u32 enabled = 0;
    if (get_config_value(1, &enabled) < 0 || !enabled) {
        return 0;
    }
    
    // Check sampling rate
    __u32 rate = 100;
    get_config_value(4, &rate);
    if (!should_sample(rate)) {
        return 0;
    }
    
    // Reserve space in ring buffer
    struct network_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event header
    fill_event_header(&event->header, EVENT_NETWORK_ACCEPT);
    
    // For accept4, similar to accept
    event->family = AF_INET;  // Assume IPv4 for simplicity
    event->protocol = 6;      // TCP
    event->sport = 0;         // Not available at syscall level
    event->dport = 0;         // Not available at syscall level
    event->saddr_v4 = 0;      // Not available at syscall level
    event->daddr_v4 = 0;      // Not available at syscall level
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

char _license[] SEC("license") = "GPL";