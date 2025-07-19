#include "common.h"

// Simple kprobe for sys_openat
SEC("kprobe/sys_openat")
int trace_sys_openat(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we should trace this PID
    if (!should_trace_pid(pid)) {
        return 0;
    }
    
    // Check if file monitoring is enabled
    __u32 enabled = 0;
    if (get_config_value(2, &enabled) < 0 || !enabled) {
        return 0;
    }
    
    // Check sampling rate
    __u32 rate = 100;
    get_config_value(4, &rate);
    if (!should_sample(rate)) {
        return 0;
    }
    
    // Get syscall arguments using PT_REGS_PARM macros
    const char *filename = (const char *)PT_REGS_PARM2(ctx);
    int flags = (int)PT_REGS_PARM3(ctx);
    __u16 mode = (__u16)PT_REGS_PARM4(ctx);
    
    if (!filename) {
        return 0;
    }
    
    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event header
    fill_event_header(&event->header, EVENT_FILE_OPEN);
    
    // Get filename from user space
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    
    event->flags = flags;
    event->mode = mode;
    event->fd = -1;    // Will be available in return probe
    event->size = 0;
    event->offset = 0;
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Simple kprobe for sys_write
SEC("kprobe/sys_write")
int trace_sys_write(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we should trace this PID
    if (!should_trace_pid(pid)) {
        return 0;
    }
    
    // Check if file monitoring is enabled
    __u32 enabled = 0;
    if (get_config_value(2, &enabled) < 0 || !enabled) {
        return 0;
    }
    
    // Check sampling rate
    __u32 rate = 100;
    get_config_value(4, &rate);
    if (!should_sample(rate)) {
        return 0;
    }
    
    // Get syscall arguments
    int fd = (int)PT_REGS_PARM1(ctx);
    __u64 count = (__u64)PT_REGS_PARM3(ctx);
    
    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event header
    fill_event_header(&event->header, EVENT_FILE_WRITE);
    
    // For write syscalls, we can't easily get the filename
    // We'll use a placeholder and rely on fd tracking in userspace
    __builtin_memcpy(event->filename, "<fd>", 5);
    
    event->fd = fd;
    event->flags = 0;
    event->mode = 0;
    event->size = count;
    event->offset = 0;
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Simple kprobe for sys_unlinkat
SEC("kprobe/sys_unlinkat")
int trace_sys_unlinkat(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we should trace this PID
    if (!should_trace_pid(pid)) {
        return 0;
    }
    
    // Check if file monitoring is enabled
    __u32 enabled = 0;
    if (get_config_value(2, &enabled) < 0 || !enabled) {
        return 0;
    }
    
    // Check sampling rate
    __u32 rate = 100;
    get_config_value(4, &rate);
    if (!should_sample(rate)) {
        return 0;
    }
    
    // Get syscall arguments
    const char *pathname = (const char *)PT_REGS_PARM2(ctx);
    
    if (!pathname) {
        return 0;
    }
    
    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event header
    fill_event_header(&event->header, EVENT_FILE_UNLINK);
    
    // Get filename from user space
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), pathname);
    
    event->fd = -1;
    event->flags = 0;
    event->mode = 0;
    event->size = 0;
    event->offset = 0;
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

char _license[] SEC("license") = "GPL";