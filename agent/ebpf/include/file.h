#ifndef __FILE_H__
#define __FILE_H__

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "helpers.h"
#include "events.h"

// File system monitoring tracepoint context structures

// VFS file open tracepoint context
struct trace_event_raw_vfs_open {
    struct trace_entry ent;
    __u32 __data_loc_filename;  // Offset to filename in __data
    __u32 flags;                // File open flags
    __u16 mode;                 // File mode
    __s32 ret;                  // Return value (file descriptor)
    char __data[0];             // Variable length data area
};

// VFS file write tracepoint context
struct trace_event_raw_vfs_write {
    struct trace_entry ent;
    __u32 __data_loc_filename;  // Offset to filename in __data
    __u64 offset;               // File offset
    __u64 count;                // Number of bytes to write
    __s64 ret;                  // Return value (bytes written)
    char __data[0];             // Variable length data area
};

// VFS file unlink tracepoint context
struct trace_event_raw_vfs_unlink {
    struct trace_entry ent;
    __u32 __data_loc_filename;  // Offset to filename in __data
    __u32 __data_loc_pathname;  // Offset to full pathname in __data
    __s32 ret;                  // Return value
    char __data[0];             // Variable length data area
};

// Simple hash function for file extensions (djb2 algorithm)
static __always_inline __u32 hash_file_extension(const char *ext, __u32 len) {
    __u32 hash = 5381;
    
    // Limit loop iterations for eBPF verifier
    for (__u32 i = 0; i < len && i < 16; i++) {
        if (ext[i] == '\0') break;
        
        // Convert to lowercase for case-insensitive matching
        char c = ext[i];
        if (c >= 'A' && c <= 'Z') {
            c = c + ('a' - 'A');
        }
        
        hash = ((hash << 5) + hash) + c;
    }
    
    return hash;
}

// Extract file extension from filename
static __always_inline int extract_file_extension(const char *filename, char *ext, __u32 ext_size) {
    if (!filename || !ext || ext_size == 0) {
        return -1;
    }
    
    // Initialize extension buffer
    ext[0] = '\0';
    
    // Find the last dot in the filename
    int last_dot = -1;
    int filename_len = 0;
    
    // Calculate filename length and find last dot (limit iterations for eBPF)
    for (int i = 0; i < MAX_PATH_LEN && filename[i] != '\0'; i++) {
        if (filename[i] == '.') {
            last_dot = i;
        }
        filename_len = i + 1;
    }
    
    // No extension found
    if (last_dot == -1 || last_dot == filename_len - 1) {
        return -1;
    }
    
    // Extract extension (without the dot)
    int ext_start = last_dot + 1;
    int ext_len = filename_len - ext_start;
    
    // Ensure we don't exceed buffer size
    if (ext_len >= ext_size) {
        ext_len = ext_size - 1;
    }
    
    // Copy extension using bpf_probe_read_kernel_str for safety
    if (bpf_probe_read_kernel_str(ext, ext_size, &filename[ext_start]) < 0) {
        return -1;
    }
    
    return ext_len;
}

// Check if file extension is in whitelist
static __always_inline int is_file_extension_whitelisted(const char *filename) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        return 1; // Default to allowed if config unavailable
    }
    
    // If whitelist is empty, allow all files
    if (cfg->whitelist_size == 0) {
        return 1;
    }
    
    // Extract file extension
    char ext[16];
    if (extract_file_extension(filename, ext, sizeof(ext)) < 0) {
        // No extension found - check if we allow files without extensions
        // For now, allow files without extensions
        return 1;
    }
    
    // Hash the extension
    __u32 ext_hash = hash_file_extension(ext, sizeof(ext));
    
    // Check if extension hash is in whitelist
    for (__u32 i = 0; i < cfg->whitelist_size && i < 16; i++) {
        if (cfg->file_extensions_whitelist[i] == ext_hash) {
            return 1; // Extension is whitelisted
        }
    }
    
    return 0; // Extension not in whitelist
}

// Check if file extension is in blacklist
static __always_inline int is_file_extension_blacklisted(const char *filename) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        return 0; // Default to not blacklisted if config unavailable
    }
    
    // If blacklist is empty, don't block any files
    if (cfg->blacklist_size == 0) {
        return 0;
    }
    
    // Extract file extension
    char ext[16];
    if (extract_file_extension(filename, ext, sizeof(ext)) < 0) {
        // No extension found - don't blacklist files without extensions
        return 0;
    }
    
    // Hash the extension
    __u32 ext_hash = hash_file_extension(ext, sizeof(ext));
    
    // Check if extension hash is in blacklist
    for (__u32 i = 0; i < cfg->blacklist_size && i < 16; i++) {
        if (cfg->file_extensions_blacklist[i] == ext_hash) {
            return 1; // Extension is blacklisted
        }
    }
    
    return 0; // Extension not in blacklist
}

// Main file type filtering function
static __always_inline int should_monitor_file_type(const char *filename) {
    // If file type filtering is disabled, monitor all files
    if (!is_file_type_filtering_enabled()) {
        return 1;
    }
    
    // Check blacklist first (takes precedence)
    if (is_file_extension_blacklisted(filename)) {
        record_file_type_filtered();
        return 0; // File type is blacklisted
    }
    
    // Check whitelist
    if (!is_file_extension_whitelisted(filename)) {
        record_file_type_filtered();
        return 0; // File type not in whitelist
    }
    
    return 1; // File type should be monitored
}

// File event allocation with retry
static __always_inline struct file_event* allocate_file_event_with_retry(__u32 event_type) {
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        record_error(ERROR_ALLOCATION_FAILURE);
        return NULL;
    }
    
    // Initialize event header
    fill_event_header(&event->header, event_type);
    
    return event;
}

// File event submission
static __always_inline void submit_file_event(struct file_event *event) {
    if (event) {
        bpf_ringbuf_submit(event, 0);
    }
}

// File event discard
static __always_inline void discard_file_event(struct file_event *event) {
    if (event) {
        bpf_ringbuf_discard(event, 0);
    }
}

// File path extraction helper (simple version for basic use)
static __always_inline int extract_file_path_simple(char *dest, __u32 dest_size, const char *src) {
    if (!dest || !src || dest_size == 0) {
        return -1;
    }
    
    // Get maximum path length from configuration
    __u32 max_len = 0;
    if (get_max_file_path_len(&max_len) != 0) {
        max_len = MAX_PATH_LEN;
    }
    
    // Use the smaller of dest_size and configured max length
    __u32 copy_len = dest_size < max_len ? dest_size : max_len;
    
    // Copy path using bpf_probe_read_kernel_str for safety
    if (bpf_probe_read_kernel_str(dest, copy_len, src) < 0) {
        record_file_path_extraction_error();
        return -1;
    }
    
    return 0;
}

// Enhanced file path extraction function with comprehensive error handling
// This version matches the signature used in file_monitor.c
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

// File monitoring decision based on configuration
static __always_inline int should_monitor_file_event(__u32 event_type) {
    // Check if file monitoring is enabled
    __u32 enabled = 0;
    if (get_config_value(MONITOR_FILE, &enabled) != 0 || !enabled) {
        return 0;
    }
    
    // Check event-specific settings
    switch (event_type) {
        case EVENT_FILE_WRITE:
            if (!is_file_write_monitoring_enabled()) {
                return 0;
            }
            break;
        case EVENT_FILE_UNLINK:
            if (!is_file_delete_monitoring_enabled()) {
                return 0;
            }
            break;
        default:
            break;
    }
    
    return 1;
}

// File sampling decision
static __always_inline int should_sample_file_event(void) {
    __u32 rate = 0;
    if (get_file_sampling_rate(&rate) != 0) {
        return 1; // Default to sampling if config unavailable
    }
    
    if (!should_sample(rate)) {
        record_file_sampling_skipped();
        return 0;
    }
    
    return 1;
}

#endif /* __FILE_H__ */