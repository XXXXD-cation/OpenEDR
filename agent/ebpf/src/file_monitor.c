#include "common.h"

// OpenEDR File System Monitor - Tracepoint-based Implementation
//
// This module implements file system monitoring using stable kernel tracepoints
// for VFS operations including file open, write, and unlink events.
// It integrates with the unified event processing framework established
// in the process monitor implementation.

#ifndef USE_KPROBE_FALLBACK

// Enhanced file path extraction function with comprehensive error handling
static __always_inline int extract_file_path(char *dest, __u32 dest_size, 
                                            char *data, __u32 offset) {
    if (!dest || dest_size == 0) {
        record_file_path_extraction_error();
        return -1;
    }
    
    // Initialize destination buffer
    dest[0] = '\0';
    
    if (!data) {
        record_file_path_extraction_error();
        // Set fallback value for null data
        if (dest_size > 9) {
            __builtin_memcpy(dest, "<no-data>", 10);
        }
        return -1;
    }
    
    if (offset == 0) {
        record_file_path_extraction_error();
        // Set fallback value for zero offset
        if (dest_size > 11) {
            __builtin_memcpy(dest, "<no-offset>", 12);
        }
        return -1;
    }
    
    // Get configured maximum path length
    __u32 max_path_len = 0;
    if (get_max_file_path_len(&max_path_len) < 0) {
        max_path_len = MAX_PATH_LEN;
    }
    
    // Use the smaller of dest_size-1 and max_path_len to avoid buffer overflows
    __u32 copy_len = dest_size - 1; // Leave space for null terminator
    if (copy_len > max_path_len) {
        copy_len = max_path_len;
    }
    
    // Ensure minimum buffer size for meaningful paths
    if (copy_len < 2) {
        record_file_path_extraction_error();
        return -1;
    }
    
    // Extract filename from variable data area with bounds checking
    int ret = bpf_probe_read_kernel_str(dest, copy_len, data + offset);
    if (ret < 0) {
        record_file_path_extraction_error();
        // Set a fallback value based on error type
        if (dest_size > 9) {
            __builtin_memcpy(dest, "<unknown>", 10);
        }
        return -1;
    }
    
    // Validate extracted path is not empty
    if (dest[0] == '\0') {
        record_file_path_extraction_error();
        if (dest_size > 7) {
            __builtin_memcpy(dest, "<empty>", 8);
        }
        return -1;
    }
    
    return 0;
}

// Extract file operation flags with validation and normalization
static __always_inline __u32 extract_file_flags(__u32 raw_flags) {
    // Validate flags are within reasonable range
    // Most file flags are in the lower 16 bits
    if (raw_flags > 0xFFFF) {
        // Suspicious flags value, mask to reasonable range
        raw_flags &= 0xFFFF;
    }
    
    // Return normalized flags - user space can interpret them
    // Common flags: O_RDONLY=0, O_WRONLY=1, O_RDWR=2, O_CREAT=64, O_TRUNC=512, etc.
    return raw_flags;
}

// Extract and validate file mode with comprehensive checks
static __always_inline __u16 extract_file_mode(__u16 raw_mode) {
    // Validate mode is not completely invalid
    if (raw_mode == 0xFFFF) {
        // Invalid mode, return default read-only permissions
        return 0x0444; // r--r--r--
    }
    
    // Mask to keep only permission bits (lower 12 bits)
    // This removes file type bits and keeps only permissions
    __u16 mode = raw_mode & 0x0FFF;
    
    // Ensure mode has at least some valid permission bits
    if (mode == 0) {
        // No permissions set, return minimal read permission for owner
        return 0x0400; // r--------
    }
    
    return mode;
}

// Extract file size with comprehensive bounds checking and validation
static __always_inline __u64 extract_file_size(__u64 raw_size) {
    // Check for obviously invalid values (negative when cast to signed)
    if (raw_size > 0x7FFFFFFFFFFFFFFFULL) {
        // Size seems unreasonable, might be an error value (-1, -EINVAL, etc.)
        return 0;
    }
    
    // Check for extremely large file sizes (> 1TB) which might indicate corruption
    const __u64 MAX_REASONABLE_FILE_SIZE = 1024ULL * 1024ULL * 1024ULL * 1024ULL; // 1TB
    if (raw_size > MAX_REASONABLE_FILE_SIZE) {
        // Log this as potentially suspicious but don't zero it out
        // User space can decide how to handle very large files
        return raw_size;
    }
    
    return raw_size;
}

// Extract file offset with comprehensive validation and bounds checking
static __always_inline __u64 extract_file_offset(__u64 raw_offset) {
    // Check for obviously invalid values (negative when cast to signed)
    if (raw_offset > 0x7FFFFFFFFFFFFFFFULL) {
        // Offset seems unreasonable, might be an error value (-1, -EINVAL, etc.)
        return 0;
    }
    
    // Check for extremely large offsets (> 1TB) which might indicate corruption
    const __u64 MAX_REASONABLE_FILE_OFFSET = 1024ULL * 1024ULL * 1024ULL * 1024ULL; // 1TB
    if (raw_offset > MAX_REASONABLE_FILE_OFFSET) {
        // Log this as potentially suspicious but don't zero it out
        // User space can decide how to handle very large offsets
        return raw_offset;
    }
    
    return raw_offset;
}

// Comprehensive file information extraction function
static __always_inline int fill_file_info(struct file_event *event,
                                         char *tracepoint_data,
                                         __u32 filename_offset,
                                         __u32 flags,
                                         __u16 mode,
                                         __s32 fd,
                                         __u64 size,
                                         __u64 offset) {
    if (!event) {
        return -1;
    }
    
    // Extract file path with error handling
    if (extract_file_path(event->filename, sizeof(event->filename),
                         tracepoint_data, filename_offset) < 0) {
        // Path extraction failed, but continue with other fields
        record_file_path_extraction_error();
    }
    
    // Extract and validate file operation flags
    event->flags = extract_file_flags(flags);
    
    // Extract and validate file mode
    event->mode = extract_file_mode(mode);
    
    // Set file descriptor
    event->fd = fd;
    
    // Extract and validate file size
    event->size = extract_file_size(size);
    
    // Extract and validate file offset
    event->offset = extract_file_offset(offset);
    
    return 0;
}

// Comprehensive file event error handling function with detailed error recovery
static __always_inline int handle_file_error(__u32 error_type, struct file_event *event) {
    record_error(ERROR_DATA_READ_ERROR);
    
    switch (error_type) {
        case 1: // FILE_PATH_EXTRACTION_ERROR
            record_file_path_extraction_error();
            // Continue processing with placeholder filename
            if (event && sizeof(event->filename) > 9) {
                __builtin_memcpy(event->filename, "<unknown>", 10);
            }
            return 1; // Continue processing
            
        case 2: // FILE_INFO_READ_ERROR
            // Critical error, skip event entirely
            record_file_path_extraction_error();
            return 0;
            
        case 3: // FILE_SIZE_INVALID
            // Set size to 0 and continue
            if (event) {
                event->size = 0;
            }
            return 1;
            
        case 4: // FILE_OFFSET_INVALID
            // Set offset to 0 and continue
            if (event) {
                event->offset = 0;
            }
            return 1;
            
        case 5: // FILE_FLAGS_INVALID
            // Set flags to 0 (no specific flags) and continue
            if (event) {
                event->flags = 0;
            }
            return 1;
            
        case 6: // FILE_MODE_INVALID
            // Set mode to default read-only and continue
            if (event) {
                event->mode = 0x0444; // r--r--r--
            }
            return 1;
            
        case 7: // FILE_FD_INVALID
            // Set fd to -1 (invalid) and continue
            if (event) {
                event->fd = -1;
            }
            return 1;
            
        case 8: // FILE_TRACEPOINT_DATA_CORRUPT
            // Tracepoint data appears corrupted, skip event
            record_error(ERROR_TRACEPOINT_ERROR);
            return 0;
            
        case 9: // FILE_BUFFER_OVERFLOW_RISK
            // Buffer overflow risk detected, skip event for safety
            record_error(ERROR_DATA_READ_ERROR);
            return 0;
            
        case 10: // FILE_PARTIAL_DATA_AVAILABLE
            // Some data is available but incomplete, continue with partial info
            if (event && sizeof(event->filename) > 9) {
                __builtin_memcpy(event->filename, "<partial>", 10);
            }
            return 1;
            
        default:
            // Unknown error type, skip event for safety
            record_error(ERROR_DATA_READ_ERROR);
            return 0;
    }
}

// Enhanced file information validation function
static __always_inline int validate_file_event_data(struct file_event *event) {
    if (!event) {
        return 0; // Invalid event structure
    }
    
    // Validate filename is not completely empty or invalid
    if (event->filename[0] == '\0') {
        return handle_file_error(1, event); // Path extraction error
    }
    
    // Check for obviously corrupted filename (all null bytes beyond first)
    int has_content = 0;
    for (int i = 0; i < 32 && i < sizeof(event->filename); i++) {
        if (event->filename[i] != '\0') {
            has_content = 1;
            break;
        }
    }
    
    if (!has_content) {
        return handle_file_error(1, event); // Path extraction error
    }
    
    // Validate file descriptor is reasonable (not extremely negative)
    if (event->fd < -1000) {
        return handle_file_error(7, event); // FD invalid
    }
    
    // All validations passed
    return 1;
}



// VFS file open tracepoint handler
SEC("tp/vfs/vfs_open")
int trace_vfs_open(struct trace_event_raw_vfs_open *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we should trace this PID
    if (!should_trace_pid(pid)) {
        record_pid_filtered();
        return 0;
    }
    
    // Check if file monitoring is enabled
    __u32 enabled = 0;
    if (get_config_value_safe(2, &enabled, 0) < 0 || !enabled) {
        return 0;
    }
    
    // Check file-specific sampling rate
    __u32 rate = 100;
    if (get_file_sampling_rate(&rate) < 0) {
        rate = 100; // Default to full sampling if config unavailable
    }
    
    if (!should_sample(rate)) {
        record_file_sampling_skipped();
        return 0;
    }
    
    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        record_error(ERROR_ALLOCATION_FAILURE);
        return 0;
    }
    
    // Fill event header
    fill_event_header(&event->header, EVENT_FILE_OPEN);
    
    // Use comprehensive file information extraction
    if (fill_file_info(event, (char *)ctx, ctx->__data_loc_filename,
                      ctx->flags, ctx->mode, ctx->ret, 0, 0) < 0) {
        // Handle extraction error but continue processing
        if (!handle_file_error(2, event)) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
    }
    
    // Validate the extracted file event data
    if (!validate_file_event_data(event)) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    // Apply file type filtering
    if (!should_monitor_file_type(event->filename)) {
        record_file_type_filtered();
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    // Record statistics
    record_file_open_event();
    
    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// VFS file write tracepoint handler
SEC("tp/vfs/vfs_write")
int trace_vfs_write(struct trace_event_raw_vfs_write *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we should trace this PID
    if (!should_trace_pid(pid)) {
        record_pid_filtered();
        return 0;
    }
    
    // Check if file monitoring is enabled
    __u32 enabled = 0;
    if (get_config_value_safe(2, &enabled, 0) < 0 || !enabled) {
        return 0;
    }
    
    // Check if file write monitoring is specifically enabled
    if (!is_file_write_monitoring_enabled()) {
        return 0;
    }
    
    // Check file-specific sampling rate
    __u32 rate = 100;
    if (get_file_sampling_rate(&rate) < 0) {
        rate = 100; // Default to full sampling if config unavailable
    }
    
    if (!should_sample(rate)) {
        record_file_sampling_skipped();
        return 0;
    }
    
    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        record_error(ERROR_ALLOCATION_FAILURE);
        return 0;
    }
    
    // Fill event header
    fill_event_header(&event->header, EVENT_FILE_WRITE);
    
    // Use comprehensive file information extraction for write events
    if (fill_file_info(event, (char *)ctx, ctx->__data_loc_filename,
                      0, 0, -1, ctx->count, ctx->offset) < 0) {
        // Handle extraction error but continue processing
        if (!handle_file_error(1, event)) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
    }
    
    // Validate the extracted file event data
    if (!validate_file_event_data(event)) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    // Apply file type filtering
    if (!should_monitor_file_type(event->filename)) {
        record_file_type_filtered();
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    // Record statistics
    record_file_write_event();
    
    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// VFS file unlink (delete) tracepoint handler
SEC("tp/vfs/vfs_unlink")
int trace_vfs_unlink(struct trace_event_raw_vfs_unlink *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we should trace this PID
    if (!should_trace_pid(pid)) {
        record_pid_filtered();
        return 0;
    }
    
    // Check if file monitoring is enabled
    __u32 enabled = 0;
    if (get_config_value_safe(2, &enabled, 0) < 0 || !enabled) {
        return 0;
    }
    
    // Check if file delete monitoring is specifically enabled
    if (!is_file_delete_monitoring_enabled()) {
        return 0;
    }
    
    // Check file-specific sampling rate
    __u32 rate = 100;
    if (get_file_sampling_rate(&rate) < 0) {
        rate = 100; // Default to full sampling if config unavailable
    }
    
    if (!should_sample(rate)) {
        record_file_sampling_skipped();
        return 0;
    }
    
    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        record_error(ERROR_ALLOCATION_FAILURE);
        return 0;
    }
    
    // Fill event header
    fill_event_header(&event->header, EVENT_FILE_UNLINK);
    
    // Try pathname first, then filename as fallback for unlink events
    if (fill_file_info(event, (char *)ctx, ctx->__data_loc_pathname,
                      0, 0, -1, 0, 0) < 0) {
        // If pathname extraction fails, try filename
        if (fill_file_info(event, (char *)ctx, ctx->__data_loc_filename,
                          0, 0, -1, 0, 0) < 0) {
            // Handle extraction error but continue processing
            if (!handle_file_error(1, event)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
        }
    }
    
    // Validate the extracted file event data
    if (!validate_file_event_data(event)) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    // Apply file type filtering
    if (!should_monitor_file_type(event->filename)) {
        record_file_type_filtered();
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    // Record statistics
    record_file_unlink_event();
    
    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

#else

// Fallback kprobe implementations for older kernels
// These are simplified versions for compatibility

SEC("kprobe/sys_openat")
int trace_sys_openat_fallback(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we should trace this PID
    if (!should_trace_pid(pid)) {
        record_pid_filtered();
        return 0;
    }
    
    // Check if file monitoring is enabled
    __u32 enabled = 0;
    if (get_config_value_safe(2, &enabled, 0) < 0 || !enabled) {
        return 0;
    }
    
    // Check file-specific sampling rate
    __u32 rate = 100;
    if (get_file_sampling_rate(&rate) < 0) {
        rate = 100; // Default to full sampling if config unavailable
    }
    
    if (!should_sample(rate)) {
        record_file_sampling_skipped();
        return 0;
    }
    
    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        record_error(ERROR_ALLOCATION_FAILURE);
        return 0;
    }
    
    // Fill event header
    fill_event_header(&event->header, EVENT_FILE_OPEN);
    
    // Get syscall arguments using PT_REGS_PARM macros
    const char *filename = (const char *)PT_REGS_PARM2(ctx);
    int flags = (int)PT_REGS_PARM3(ctx);
    __u16 mode = (__u16)PT_REGS_PARM4(ctx);
    
    // Extract filename with error handling
    if (filename) {
        if (bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename) < 0) {
            if (!handle_file_error(1, event)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
        }
    } else {
        if (!handle_file_error(1, event)) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
    }
    
    // Extract and validate file information
    event->flags = extract_file_flags(flags);
    event->mode = extract_file_mode(mode);
    event->fd = -1;
    event->size = 0;
    event->offset = 0;
    
    // Apply file type filtering
    if (!should_monitor_file_type(event->filename)) {
        record_file_type_filtered();
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    record_file_open_event();
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

SEC("kprobe/sys_write")
int trace_sys_write_fallback(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we should trace this PID
    if (!should_trace_pid(pid)) {
        record_pid_filtered();
        return 0;
    }
    
    // Check if file monitoring is enabled
    __u32 enabled = 0;
    if (get_config_value_safe(2, &enabled, 0) < 0 || !enabled) {
        return 0;
    }
    
    if (!is_file_write_monitoring_enabled()) {
        return 0;
    }
    
    // Check file-specific sampling rate
    __u32 rate = 100;
    if (get_file_sampling_rate(&rate) < 0) {
        rate = 100; // Default to full sampling if config unavailable
    }
    
    if (!should_sample(rate)) {
        record_file_sampling_skipped();
        return 0;
    }
    
    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        record_error(ERROR_ALLOCATION_FAILURE);
        return 0;
    }
    
    // Fill event header
    fill_event_header(&event->header, EVENT_FILE_WRITE);
    
    int fd = (int)PT_REGS_PARM1(ctx);
    __u64 count = (__u64)PT_REGS_PARM3(ctx);
    
    __builtin_memcpy(event->filename, "<fd>", 5);
    event->fd = fd;
    event->flags = 0;
    event->mode = 0;
    event->size = count;
    event->offset = 0;
    
    // Apply file type filtering (for fd-based operations, we can't filter by extension)
    // So we allow all fd-based write operations
    
    record_file_write_event();
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

SEC("kprobe/sys_unlinkat")
int trace_sys_unlinkat_fallback(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Check if we should trace this PID
    if (!should_trace_pid(pid)) {
        record_pid_filtered();
        return 0;
    }
    
    // Check if file monitoring is enabled
    __u32 enabled = 0;
    if (get_config_value_safe(2, &enabled, 0) < 0 || !enabled) {
        return 0;
    }
    
    if (!is_file_delete_monitoring_enabled()) {
        return 0;
    }
    
    // Check file-specific sampling rate
    __u32 rate = 100;
    if (get_file_sampling_rate(&rate) < 0) {
        rate = 100; // Default to full sampling if config unavailable
    }
    
    if (!should_sample(rate)) {
        record_file_sampling_skipped();
        return 0;
    }
    
    // Reserve space in ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        record_error(ERROR_ALLOCATION_FAILURE);
        return 0;
    }
    
    // Fill event header
    fill_event_header(&event->header, EVENT_FILE_UNLINK);
    
    const char *pathname = (const char *)PT_REGS_PARM2(ctx);
    
    if (pathname) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), pathname);
    } else {
        __builtin_memcpy(event->filename, "<unknown>", 10);
    }
    
    event->fd = -1;
    event->flags = 0;
    event->mode = 0;
    event->size = 0;
    event->offset = 0;
    
    // Apply file type filtering
    if (!should_monitor_file_type(event->filename)) {
        record_file_type_filtered();
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    record_file_unlink_event();
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

#endif /* USE_KPROBE_FALLBACK */

char _license[] SEC("license") = "GPL";