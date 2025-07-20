#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

// Monitor types for configuration
enum monitor_type {
    MONITOR_PROCESS = 0,
    MONITOR_NETWORK = 1,
    MONITOR_FILE = 2,
    MONITOR_SYSCALL = 3,
    MONITOR_SAMPLING_RATE = 4,
    MONITOR_NETWORK_SAMPLING_RATE = 5,
    MONITOR_FILE_SAMPLING_RATE = 6,
    MONITOR_SYSCALL_SAMPLING_RATE = 7,
    MONITOR_TCP_ENABLED = 8,
    MONITOR_UDP_ENABLED = 9,
    MONITOR_IPV6_ENABLED = 10,
    MONITOR_FILE_WRITE_ENABLED = 11,
    MONITOR_FILE_DELETE_ENABLED = 12,
    MONITOR_MAX_FILE_PATH_LEN = 13,
    MONITOR_SYSCALL_ARGS_ENABLED = 14,
    MONITOR_SYSCALL_RETVAL_ENABLED = 15,
    MONITOR_ADAPTIVE_SAMPLING_ENABLED = 16,
};

// Configuration map
struct config {
    // Basic monitoring enables
    __u32 enable_process_monitoring;
    __u32 enable_network_monitoring;
    __u32 enable_file_monitoring;
    __u32 enable_syscall_monitoring;
    
    // Global sampling rate (default for all event types)
    __u32 sampling_rate;
    
    // Event-specific sampling rates
    __u32 network_sampling_rate;
    __u32 file_sampling_rate;
    __u32 syscall_sampling_rate;
    
    // File monitoring configuration
    __u32 max_file_path_len;        // Maximum file path length to capture
    __u32 enable_file_write_monitoring;
    __u32 enable_file_delete_monitoring;
    __u32 file_type_filter_enabled; // Enable file type filtering
    __u32 file_extensions_whitelist[16]; // Allowed file extensions (as hashes)
    __u32 file_extensions_blacklist[16]; // Blocked file extensions (as hashes)
    __u32 whitelist_size;           // Number of entries in whitelist
    __u32 blacklist_size;           // Number of entries in blacklist
    
    // Network monitoring configuration
    __u32 enable_tcp_monitoring;
    __u32 enable_udp_monitoring;
    __u32 enable_ipv6_monitoring;
    
    // System call monitoring configuration
    __u32 syscall_whitelist[32];    // Array of allowed system call numbers
    __u32 syscall_whitelist_size;   // Number of entries in whitelist
    __u32 enable_syscall_args;      // Whether to capture syscall arguments
    __u32 enable_syscall_retval;    // Whether to capture return values
    
    // Performance tuning
    __u32 ringbuf_size_kb;          // Ring buffer size in KB
    __u32 max_events_per_sec;       // Rate limiting threshold
    __u32 enable_adaptive_sampling; // Enable dynamic sampling adjustment
};

// Helper macros
#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
    struct { \
        __uint(type, _type); \
        __uint(max_entries, _max_entries); \
        __type(key, _key_type); \
        __type(value, _value_type); \
    } _name SEC(".maps")

// Configuration map is defined in common.h

// Configuration access functions
static __always_inline int get_config_value(__u32 key, __u32 *value) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        return -1;
    }
    
    switch (key) {
        case 0: *value = cfg->enable_process_monitoring; break;
        case 1: *value = cfg->enable_network_monitoring; break;
        case 2: *value = cfg->enable_file_monitoring; break;
        case 3: *value = cfg->enable_syscall_monitoring; break;
        case 4: *value = cfg->sampling_rate; break;
        default: return -1;
    }
    
    return 0;
}

// Extended configuration access helpers for new monitoring types
static __always_inline int get_network_sampling_rate(__u32 *rate) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        return -1;
    }
    
    *rate = cfg->network_sampling_rate > 0 ? cfg->network_sampling_rate : cfg->sampling_rate;
    return 0;
}

static __always_inline int get_file_sampling_rate(__u32 *rate) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        return -1;
    }
    
    *rate = cfg->file_sampling_rate > 0 ? cfg->file_sampling_rate : cfg->sampling_rate;
    return 0;
}

static __always_inline int get_syscall_sampling_rate(__u32 *rate) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        return -1;
    }
    
    *rate = cfg->syscall_sampling_rate > 0 ? cfg->syscall_sampling_rate : cfg->sampling_rate;
    return 0;
}

static __always_inline int is_tcp_monitoring_enabled(void) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        return 1; // Default to enabled
    }
    
    return cfg->enable_tcp_monitoring;
}

static __always_inline int is_udp_monitoring_enabled(void) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        return 1; // Default to enabled
    }
    
    return cfg->enable_udp_monitoring;
}

static __always_inline int is_ipv6_monitoring_enabled(void) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        return 1; // Default to enabled
    }
    
    return cfg->enable_ipv6_monitoring;
}

static __always_inline int is_file_write_monitoring_enabled(void) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        return 1; // Default to enabled
    }
    
    return cfg->enable_file_write_monitoring;
}

static __always_inline int is_file_delete_monitoring_enabled(void) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        return 1; // Default to enabled
    }
    
    return cfg->enable_file_delete_monitoring;
}

static __always_inline int get_max_file_path_len(__u32 *len) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        return -1;
    }
    
    *len = cfg->max_file_path_len > 0 ? cfg->max_file_path_len : MAX_PATH_LEN;
    return 0;
}

static __always_inline int is_file_type_filtering_enabled(void) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        return 0; // Default to disabled
    }
    
    return cfg->file_type_filter_enabled;
}

static __always_inline int should_capture_syscall_args(void) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        return 1; // Default to enabled
    }
    
    return cfg->enable_syscall_args;
}

static __always_inline int should_capture_syscall_retval(void) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        return 1; // Default to enabled
    }
    
    return cfg->enable_syscall_retval;
}

static __always_inline int is_adaptive_sampling_enabled(void) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        return 0; // Default to disabled
    }
    
    return cfg->enable_adaptive_sampling;
}

// Safe configuration value getter with default fallback
static __always_inline int get_config_value_safe(__u32 key, __u32 *value, __u32 default_value) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        *value = default_value;
        return -1;
    }
    
    switch (key) {
        case 0: *value = cfg->enable_process_monitoring; break;
        case 1: *value = cfg->enable_network_monitoring; break;
        case 2: *value = cfg->enable_file_monitoring; break;
        case 3: *value = cfg->enable_syscall_monitoring; break;
        case 4: *value = cfg->sampling_rate; break;
        default: 
            *value = default_value;
            return -1;
    }
    
    return 0;
}

#endif /* __CONFIG_H__ */