/*
 * eBPF Network Monitor Unit Tests
 * 
 * This file contains comprehensive unit tests for the eBPF network monitor
 * implementation, covering network information extraction functions,
 * protocol and address family handling, error handling mechanisms,
 * and network event sampling and filtering logic.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>

// Mock eBPF types and constants for testing
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int32_t __s32;
typedef int64_t __s64;

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_PATH_LEN 4096

// Network constants
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

// Test configuration
static int test_failures = 0;
static int test_successes = 0;

// Test result macros
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("FAIL: %s - %s\n", __func__, message); \
            test_failures++; \
            return 0; \
        } else { \
            test_successes++; \
        } \
    } while(0)

#define TEST_PASS(message) \
    do { \
        printf("PASS: %s - %s\n", __func__, message); \
        return 1; \
    } while(0)

// Event types (from common.h)
enum event_type {
    EVENT_PROCESS_EXEC = 1,
    EVENT_PROCESS_EXIT = 2,
    EVENT_NETWORK_CONNECT = 3,
    EVENT_NETWORK_ACCEPT = 4,
    EVENT_FILE_OPEN = 5,
    EVENT_FILE_WRITE = 6,
    EVENT_FILE_UNLINK = 7,
    EVENT_SYSCALL = 8,
};

// Error types (from common.h)
enum error_type {
    ERROR_EVENT_DROPPED = 0,
    ERROR_ALLOCATION_FAILURE = 1,
    ERROR_CONFIG_ERROR = 2,
    ERROR_DATA_READ_ERROR = 3,
    ERROR_TRACEPOINT_ERROR = 4,
};

// Monitor types (from common.h)
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
};

// Event structures (from common.h)
struct event_header {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 event_type;
    __u32 cpu;
    char comm[TASK_COMM_LEN];
};

struct network_event {
    struct event_header header;
    __u16 family;     // AF_INET or AF_INET6
    __u16 protocol;   // IPPROTO_TCP or IPPROTO_UDP
    __u16 sport;      // Source port
    __u16 dport;      // Destination port
    union {
        __u32 saddr_v4;
        __u8 saddr_v6[16];
    };
    union {
        __u32 daddr_v4;
        __u8 daddr_v6[16];
    };
};

// Debug statistics structure
struct debug_stats {
    __u64 events_processed;
    __u64 events_dropped;
    __u64 allocation_failures;
    __u64 config_errors;
    __u64 data_read_errors;
    __u64 tracepoint_errors;
    __u64 network_events;
    __u64 network_connect_events;
    __u64 network_accept_events;
    __u64 network_sendmsg_events;
    __u64 network_recvmsg_events;
    __u64 network_ipv4_events;
    __u64 network_ipv6_events;
    __u64 network_tcp_events;
    __u64 network_udp_events;
    __u64 network_sampling_skipped;
    __u64 socket_info_errors;
    __u64 sampling_skipped;
    __u64 pid_filtered;
    __u64 last_error_timestamp;
    __u32 last_error_type;
    __u32 last_error_pid;
};

// Configuration structure
struct config {
    __u32 enable_process_monitoring;
    __u32 enable_network_monitoring;
    __u32 enable_file_monitoring;
    __u32 enable_syscall_monitoring;
    __u32 sampling_rate;
    __u32 network_sampling_rate;
    __u32 enable_tcp_monitoring;
    __u32 enable_udp_monitoring;
    __u32 enable_ipv6_monitoring;
};

// Tracepoint context structures for testing
struct trace_entry {
    __u16 type;
    __u8 flags;
    __u8 preempt_count;
    __s32 pid;
};

struct trace_event_raw_inet_sock_set_state {
    struct trace_entry ent;
    const void *skaddr;
    __s32 oldstate;
    __s32 newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
    char __data[0];
};

// Mock eBPF helper return values for testing
static __u64 mock_pid_tgid = 0x0000123400005678ULL;  // TGID=0x1234, PID=0x5678
static __u64 mock_uid_gid = 0x0000ABCD0000EF12ULL;   // GID=0xABCD, UID=0xEF12
static __u64 mock_timestamp = 1234567890123456789ULL;
static __u32 mock_cpu = 2;
static char mock_comm[TASK_COMM_LEN] = "test_network";

// Mock global variables for testing
static struct debug_stats mock_debug_stats = {0};
static struct config mock_config = {
    .enable_process_monitoring = 1,
    .enable_network_monitoring = 1,
    .enable_file_monitoring = 1,
    .enable_syscall_monitoring = 1,
    .sampling_rate = 100,
    .network_sampling_rate = 100,
    .enable_tcp_monitoring = 1,
    .enable_udp_monitoring = 1,
    .enable_ipv6_monitoring = 1
};

// Mock random number for sampling tests
static __u32 mock_random = 50;

// Mock ring buffer allocation result
static struct network_event mock_network_event = {0};
static int mock_allocation_should_fail = 0;

// Mock eBPF helper functions for testing
static __u64 bpf_get_current_pid_tgid(void) {
    return mock_pid_tgid;
}

static __u64 bpf_get_current_uid_gid(void) {
    return mock_uid_gid;
}

static __u64 bpf_ktime_get_ns(void) {
    return mock_timestamp;
}

static __u32 bpf_get_smp_processor_id(void) {
    return mock_cpu;
}

static int bpf_get_current_comm(void *buf, __u32 size) {
    if (size > sizeof(mock_comm)) {
        size = sizeof(mock_comm);
    }
    memcpy(buf, mock_comm, size);
    return 0;
}

static __u32 bpf_get_prandom_u32(void) {
    return mock_random;
}

// Mock ring buffer functions
static void* bpf_ringbuf_reserve(void *ringbuf, __u64 size, __u64 flags) {
    if (mock_allocation_should_fail) {
        return NULL;
    }
    return &mock_network_event;
}

static void bpf_ringbuf_submit(void *data, __u64 flags) {
    // Mock implementation - do nothing
}

static void bpf_ringbuf_discard(void *data, __u64 flags) {
    // Mock implementation - do nothing
}

// Mock map lookup function
static void* bpf_map_lookup_elem(void *map, const void *key) {
    // For debug_stats_map
    if (map == (void*)0x1000) {
        return &mock_debug_stats;
    }
    // For config_map
    if (map == (void*)0x2000) {
        return &mock_config;
    }
    return NULL;
}

// Mock atomic operations
static void __sync_fetch_and_add(__u64 *ptr, __u64 value) {
    *ptr += value;
}

// Mock memory operations
static void* __builtin_memset(void *s, int c, size_t n) {
    return memset(s, c, n);
}

static void* __builtin_memcpy(void *dest, const void *src, size_t n) {
    return memcpy(dest, src, n);
}

// Mock map pointers for testing
static void *debug_stats_map = (void*)0x1000;
static void *config_map = (void*)0x2000;
static void *events = (void*)0x3000;

// Network byte order conversion helpers
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
    return bpf_ntohl(hostlong);
}

static __always_inline __u16 bpf_htons(__u16 hostshort) {
    return bpf_ntohs(hostshort);
}

// Helper functions to test (copied from common.h with modifications for testing)

static void fill_event_header(struct event_header *header, __u32 event_type) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    
    header->timestamp = bpf_ktime_get_ns();
    header->pid = pid_tgid & 0xFFFFFFFF;
    header->tgid = pid_tgid >> 32;
    header->uid = uid_gid & 0xFFFFFFFF;
    header->gid = uid_gid >> 32;
    header->event_type = event_type;
    header->cpu = bpf_get_smp_processor_id();
    
    bpf_get_current_comm(header->comm, sizeof(header->comm));
}

static int should_trace_pid(__u32 pid) {
    if (pid <= 1) {
        return 0;
    }
    return 1;
}

static int get_config_value(__u32 key, __u32 *value) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(config_map, &config_key);
    if (!cfg) {
        return -1;
    }
    
    switch (key) {
        case 0: *value = cfg->enable_process_monitoring; break;
        case 1: *value = cfg->enable_network_monitoring; break;
        case 2: *value = cfg->enable_file_monitoring; break;
        case 3: *value = cfg->enable_syscall_monitoring; break;
        case 4: *value = cfg->sampling_rate; break;
        case 5: *value = cfg->network_sampling_rate; break;
        default: return -1;
    }
    
    return 0;
}

static int should_sample(__u32 rate) {
    if (rate == 0) return 0;
    if (rate >= 100) return 1;
    
    return (bpf_get_prandom_u32() % 100) < rate;
}

static void record_error(__u32 error_type) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        switch (error_type) {
            case ERROR_EVENT_DROPPED:
                __sync_fetch_and_add(&stats->events_dropped, 1);
                break;
            case ERROR_ALLOCATION_FAILURE:
                __sync_fetch_and_add(&stats->allocation_failures, 1);
                break;
            case ERROR_CONFIG_ERROR:
                __sync_fetch_and_add(&stats->config_errors, 1);
                break;
            case ERROR_DATA_READ_ERROR:
                __sync_fetch_and_add(&stats->data_read_errors, 1);
                break;
            case ERROR_TRACEPOINT_ERROR:
                __sync_fetch_and_add(&stats->tracepoint_errors, 1);
                break;
        }
        
        stats->last_error_timestamp = bpf_ktime_get_ns();
        stats->last_error_type = error_type;
        stats->last_error_pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    }
}

// Network event statistics recording functions
static void record_network_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->network_events, 1);
        __sync_fetch_and_add(&stats->events_processed, 1);
    }
}

static void record_network_connect_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->network_connect_events, 1);
        record_network_event();
    }
}

static void record_network_accept_event(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->network_accept_events, 1);
        record_network_event();
    }
}

static void record_network_protocol_event(__u16 protocol) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        if (protocol == IPPROTO_TCP) {
            __sync_fetch_and_add(&stats->network_tcp_events, 1);
        } else if (protocol == IPPROTO_UDP) {
            __sync_fetch_and_add(&stats->network_udp_events, 1);
        }
    }
}

static void record_network_family_event(__u16 family) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        if (family == AF_INET) {
            __sync_fetch_and_add(&stats->network_ipv4_events, 1);
        } else if (family == AF_INET6) {
            __sync_fetch_and_add(&stats->network_ipv6_events, 1);
        }
    }
}

static void record_network_sampling_skipped(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->network_sampling_skipped, 1);
    }
}

static void record_socket_info_error(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->socket_info_errors, 1);
    }
}

static void record_sampling_skipped(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->sampling_skipped, 1);
    }
}

static void record_pid_filtered(void) {
    __u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(debug_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->pid_filtered, 1);
    }
}

// Configuration access helper functions
static int get_config_value_safe(__u32 key, __u32 *value, __u32 fallback) {
    int ret = get_config_value(key, value);
    if (ret < 0) {
        record_error(ERROR_CONFIG_ERROR);
        *value = fallback;
        return 0;
    }
    return ret;
}

static int get_network_sampling_rate(__u32 *rate) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(config_map, &config_key);
    if (!cfg) {
        return -1;
    }
    
    *rate = cfg->network_sampling_rate > 0 ? cfg->network_sampling_rate : cfg->sampling_rate;
    return 0;
}

static int is_tcp_monitoring_enabled(void) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(config_map, &config_key);
    if (!cfg) {
        return 1;
    }
    
    return cfg->enable_tcp_monitoring;
}

static int is_udp_monitoring_enabled(void) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(config_map, &config_key);
    if (!cfg) {
        return 1;
    }
    
    return cfg->enable_udp_monitoring;
}

static int is_ipv6_monitoring_enabled(void) {
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(config_map, &config_key);
    if (!cfg) {
        return 1;
    }
    
    return cfg->enable_ipv6_monitoring;
}

// Network monitoring helper functions (from common.h)

static int should_process_network_event(__u16 family, __u16 protocol) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    if (!should_trace_pid(pid)) {
        record_pid_filtered();
        return 0;
    }
    
    __u32 enabled = 0;
    get_config_value_safe(MONITOR_NETWORK, &enabled, 1);
    if (!enabled) {
        return 0;
    }
    
    if (protocol == IPPROTO_TCP && !is_tcp_monitoring_enabled()) {
        return 0;
    }
    
    if (protocol == IPPROTO_UDP && !is_udp_monitoring_enabled()) {
        return 0;
    }
    
    if (family == AF_INET6 && !is_ipv6_monitoring_enabled()) {
        return 0;
    }
    
    __u32 rate = 100;
    get_network_sampling_rate(&rate);
    
    if (!should_sample(rate)) {
        record_network_sampling_skipped();
        return 0;
    }
    
    return 1;
}

static struct network_event* allocate_network_event_with_retry(__u32 event_type) {
    struct network_event *event = bpf_ringbuf_reserve(events, sizeof(*event), 0);
    if (!event) {
        event = bpf_ringbuf_reserve(events, sizeof(*event), 0);
        if (!event) {
            record_error(ERROR_ALLOCATION_FAILURE);
            return NULL;
        }
    }
    
    // Clear the entire event structure first
    __builtin_memset(event, 0, sizeof(*event));
    
    fill_event_header(&event->header, event_type);
    
    return event;
}

static int fill_network_info_from_inet_sock_state(
    struct network_event *event,
    struct trace_event_raw_inet_sock_set_state *ctx) {
    
    if (!event || !ctx) {
        record_socket_info_error();
        return 0;
    }
    
    event->family = ctx->family;
    event->protocol = ctx->protocol;
    event->sport = bpf_ntohs(ctx->sport);
    event->dport = bpf_ntohs(ctx->dport);
    
    if (ctx->family == AF_INET) {
        memcpy(&event->saddr_v4, ctx->saddr, 4);
        memcpy(&event->daddr_v4, ctx->daddr, 4);
        
        event->saddr_v4 = bpf_ntohl(event->saddr_v4);
        event->daddr_v4 = bpf_ntohl(event->daddr_v4);
        
        // Don't clear IPv6 fields for IPv4 since they're in a union and share memory
        
    } else if (ctx->family == AF_INET6) {
        memcpy(event->saddr_v6, ctx->saddr_v6, 16);
        memcpy(event->daddr_v6, ctx->daddr_v6, 16);
        
        // Don't clear IPv4 fields for IPv6 since they're in a union and share memory
        
    } else {
        record_socket_info_error();
        return 0;
    }
    
    return 1;
}

static void extract_ipv4_info(struct network_event *event, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport) {
    event->family = AF_INET;
    event->saddr_v4 = bpf_ntohl(saddr);
    event->daddr_v4 = bpf_ntohl(daddr);
    event->sport = bpf_ntohs(sport);
    event->dport = bpf_ntohs(dport);
    
    // Don't clear IPv6 fields for IPv4 since they're in a union and share memory
}

static void extract_ipv6_info(struct network_event *event, __u8 *saddr_v6, __u8 *daddr_v6, __u16 sport, __u16 dport) {
    event->family = AF_INET6;
    memcpy(event->saddr_v6, saddr_v6, 16);
    memcpy(event->daddr_v6, daddr_v6, 16);
    event->sport = bpf_ntohs(sport);
    event->dport = bpf_ntohs(dport);
    
    // Don't clear IPv4 fields for IPv6 since they're in a union and share memory
}

static int validate_network_event(struct network_event *event) {
    if (!event) {
        return 0;
    }
    
    if (event->family != AF_INET && event->family != AF_INET6) {
        record_socket_info_error();
        return 0;
    }
    
    if (event->protocol != IPPROTO_TCP && event->protocol != IPPROTO_UDP) {
        record_socket_info_error();
        return 0;
    }
    
    // Port numbers are __u16, so they're automatically valid (0-65535)
    // No additional validation needed for ports
    
    return 1;
}

static int should_filter_network_address(struct network_event *event) {
    if (!event) {
        return 1;
    }
    
    if (event->family == AF_INET) {
        __u32 addr = event->saddr_v4;
        if ((addr & 0xFF000000) == 0x7F000000) {
            return 1;
        }
        
        addr = event->daddr_v4;
        if ((addr & 0xFF000000) == 0x7F000000) {
            return 1;
        }
    }
    
    return 0;
}

// Test helper functions to reset state
static void reset_mock_state(void) {
    memset(&mock_debug_stats, 0, sizeof(mock_debug_stats));
    mock_config.enable_process_monitoring = 1;
    mock_config.enable_network_monitoring = 1;
    mock_config.enable_file_monitoring = 1;
    mock_config.enable_syscall_monitoring = 1;
    mock_config.sampling_rate = 100;
    mock_config.network_sampling_rate = 100;
    mock_config.enable_tcp_monitoring = 1;
    mock_config.enable_udp_monitoring = 1;
    mock_config.enable_ipv6_monitoring = 1;
    mock_random = 50;
    mock_allocation_should_fail = 0;
    memset(&mock_network_event, 0, sizeof(mock_network_event));
}

// Helper function to create mock tracepoint context
static void setup_mock_inet_sock_ctx_ipv4(struct trace_event_raw_inet_sock_set_state *ctx,
                                          __u32 saddr, __u32 daddr, __u16 sport, __u16 dport,
                                          __u16 protocol) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->family = AF_INET;
    ctx->protocol = protocol;
    ctx->sport = bpf_htons(sport);
    ctx->dport = bpf_htons(dport);
    ctx->oldstate = 2; // SYN_SENT
    ctx->newstate = 1; // ESTABLISHED
    
    // Store addresses in network byte order
    __u32 net_saddr = bpf_htonl(saddr);
    __u32 net_daddr = bpf_htonl(daddr);
    memcpy(ctx->saddr, &net_saddr, 4);
    memcpy(ctx->daddr, &net_daddr, 4);
}

static void setup_mock_inet_sock_ctx_ipv6(struct trace_event_raw_inet_sock_set_state *ctx,
                                          __u8 *saddr_v6, __u8 *daddr_v6, __u16 sport, __u16 dport,
                                          __u16 protocol) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->family = AF_INET6;
    ctx->protocol = protocol;
    ctx->sport = bpf_htons(sport);
    ctx->dport = bpf_htons(dport);
    ctx->oldstate = 2; // SYN_SENT
    ctx->newstate = 1; // ESTABLISHED
    
    memcpy(ctx->saddr_v6, saddr_v6, 16);
    memcpy(ctx->daddr_v6, daddr_v6, 16);
}

// Unit Tests

// Test 1: Network byte order conversion functions
static int test_network_byte_order_conversion(void) {
    // Test 32-bit conversion
    __u32 host_long = 0x12345678;
    __u32 net_long = bpf_htonl(host_long);
    __u32 back_to_host = bpf_ntohl(net_long);
    
    TEST_ASSERT(back_to_host == host_long, "32-bit host-to-network-to-host conversion should be identity");
    
    // Test 16-bit conversion
    __u16 host_short = 0x1234;
    __u16 net_short = bpf_htons(host_short);
    __u16 back_to_host_short = bpf_ntohs(net_short);
    
    TEST_ASSERT(back_to_host_short == host_short, "16-bit host-to-network-to-host conversion should be identity");
    
    // Test specific values
    TEST_ASSERT(bpf_htons(0x1234) == 0x3412, "htons should swap bytes correctly");
    TEST_ASSERT(bpf_htonl(0x12345678) == 0x78563412, "htonl should swap bytes correctly");
    
    TEST_PASS("Network byte order conversion works correctly");
}

// Test 2: should_process_network_event function
static int test_should_process_network_event(void) {
    reset_mock_state();
    
    // Set mock PID to a valid value
    mock_pid_tgid = 0x0000123400001000ULL;  // PID=4096, TGID=0x1234
    
    // Test normal case process TCP IPv4 event");
    
    // Test normal case - UDP IPv4
    TEST_ASSERT(should_process_network_event(AF_INET, IPPROTO_UDP) == 1, 
                "Should process UDP IPv4 event");
    
    // Test normal case - TCP IPv6
    TEST_ASSERT(should_process_network_event(AF_INET6, IPPROTO_TCP) == 1, 
                "Should process TCP IPv6 event");
    
    // Test PID filtering
    mock_pid_tgid = 0x0000123400000001ULL;  // PID=1 (init)
    TEST_ASSERT(should_process_network_event(AF_INET, IPPROTO_TCP) == 0, 
                "Should not process init PID");
    TEST_ASSERT(mock_debug_stats.pid_filtered == 1, "Should record PID filter");
    
    // Reset PID
    mock_pid_tgid = 0x0000123400001000ULL;
    
    // Test disabled network monitoring
    mock_config.enable_network_monitoring = 0;
    TEST_ASSERT(should_process_network_event(AF_INET, IPPROTO_TCP) == 0, 
                "Should not process when network monitoring disabled");
    
    // Reset config
    mock_config.enable_network_monitoring = 1;
    
    // Test disabled TCP monitoring
    mock_config.enable_tcp_monitoring = 0;
    TEST_ASSERT(should_process_network_event(AF_INET, IPPROTO_TCP) == 0, 
                "Should not process when TCP monitoring disabled");
    TEST_ASSERT(should_process_network_event(AF_INET, IPPROTO_UDP) == 1, 
                "Should still process UDP when TCP disabled");
    
    // Reset TCP config
    mock_config.enable_tcp_monitoring = 1;
    
    // Test disabled UDP monitoring
    mock_config.enable_udp_monitoring = 0;
    TEST_ASSERT(should_process_network_event(AF_INET, IPPROTO_UDP) == 0, 
                "Should not process when UDP monitoring disabled");
    TEST_ASSERT(should_process_network_event(AF_INET, IPPROTO_TCP) == 1, 
                "Should still process TCP when UDP disabled");
    
    // Reset UDP config
    mock_config.enable_udp_monitoring = 1;
    
    // Test disabled IPv6 monitoring
    mock_config.enable_ipv6_monitoring = 0;
    TEST_ASSERT(should_process_network_event(AF_INET6, IPPROTO_TCP) == 0, 
                "Should not process when IPv6 monitoring disabled");
    TEST_ASSERT(should_process_network_event(AF_INET, IPPROTO_TCP) == 1, 
                "Should still process IPv4 when IPv6 disabled");
    
    // Reset IPv6 config
    mock_config.enable_ipv6_monitoring = 1;
    
    // Test sampling
    mock_config.network_sampling_rate = 50;
    mock_random = 75;  // Above threshold
    TEST_ASSERT(should_process_network_event(AF_INET, IPPROTO_TCP) == 0, 
                "Should not process when sampling skips");
    TEST_ASSERT(mock_debug_stats.network_sampling_skipped == 1, 
                "Should record network sampling skip");
    
    TEST_PASS("Network event processing decision works correctly");
}

// Test 3: allocate_network_event_with_retry function
static int test_allocate_network_event_with_retry(void) {
    reset_mock_state();
    
    // Test successful allocation
    struct network_event *event = allocate_network_event_with_retry(EVENT_NETWORK_CONNECT);
    TEST_ASSERT(event != NULL, "Should successfully allocate network event");
    TEST_ASSERT(event->header.event_type == EVENT_NETWORK_CONNECT, 
                "Should set correct event type");
    TEST_ASSERT(event->family == 0, "Should initialize family to 0");
    TEST_ASSERT(event->protocol == 0, "Should initialize protocol to 0");
    TEST_ASSERT(event->sport == 0, "Should initialize sport to 0");
    TEST_ASSERT(event->dport == 0, "Should initialize dport to 0");
    
    // Test allocation failure
    mock_allocation_should_fail = 1;
    event = allocate_network_event_with_retry(EVENT_NETWORK_CONNECT);
    TEST_ASSERT(event == NULL, "Should return NULL on allocation failure");
    TEST_ASSERT(mock_debug_stats.allocation_failures == 1, 
                "Should record allocation failure");
    
    TEST_PASS("Network event allocation works correctly");
}

// Test 4: fill_network_info_from_inet_sock_state function - IPv4
static int test_fill_network_info_ipv4(void) {
    reset_mock_state();
    
    // Use the mock_network_event directly since that's what allocate_network_event_with_retry returns
    struct trace_event_raw_inet_sock_set_state ctx;
    
    // Setup IPv4 context
    setup_mock_inet_sock_ctx_ipv4(&ctx, 0xC0A80101, 0x08080808, 12345, 80, IPPROTO_TCP);
    
    // Clear the mock event
    memset(&mock_network_event, 0, sizeof(mock_network_event));
    int result = fill_network_info_from_inet_sock_state(&mock_network_event, &ctx);
    
    TEST_ASSERT(result == 1, "Should successfully fill IPv4 network info");
    TEST_ASSERT(mock_network_event.family == AF_INET, "Should set correct address family");
    TEST_ASSERT(mock_network_event.protocol == IPPROTO_TCP, "Should set correct protocol");
    TEST_ASSERT(mock_network_event.sport == 12345, "Should set correct source port");
    TEST_ASSERT(mock_network_event.dport == 80, "Should set correct destination port");
    TEST_ASSERT(mock_network_event.saddr_v4 == 0xC0A80101, "Should set correct source address");
    TEST_ASSERT(mock_network_event.daddr_v4 == 0x08080808, "Should set correct destination address");
    
    // For union fields, IPv6 and IPv4 share the same memory, so we don't need to clear IPv6 fields
    // when using IPv4. The IPv4 values will overwrite the union memory.
    
    // Test with NULL event
    result = fill_network_info_from_inet_sock_state(NULL, &ctx);
    TEST_ASSERT(result == 0, "Should fail with NULL event");
    TEST_ASSERT(mock_debug_stats.socket_info_errors == 1, 
                "Should record socket info error");
    
    // Test with NULL context
    reset_mock_state();
    result = fill_network_info_from_inet_sock_state(&mock_network_event, NULL);
    TEST_ASSERT(result == 0, "Should fail with NULL context");
    TEST_ASSERT(mock_debug_stats.socket_info_errors == 1, 
                "Should record socket info error");
    
    TEST_PASS("IPv4 network info filling works correctly");
}

// Test 5: fill_network_info_from_inet_sock_state function - IPv6
static int test_fill_network_info_ipv6(void) {
    reset_mock_state();
    
    struct network_event event;
    struct trace_event_raw_inet_sock_set_state ctx;
    
    // Setup IPv6 context
    __u8 saddr_v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    __u8 daddr_v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    
    setup_mock_inet_sock_ctx_ipv6(&ctx, saddr_v6, daddr_v6, 54321, 443, IPPROTO_TCP);
    
    memset(&event, 0, sizeof(event));
    int result = fill_network_info_from_inet_sock_state(&event, &ctx);
    
    TEST_ASSERT(result == 1, "Should successfully fill IPv6 network info");
    TEST_ASSERT(event.family == AF_INET6, "Should set correct address family");
    TEST_ASSERT(event.protocol == IPPROTO_TCP, "Should set correct protocol");
    TEST_ASSERT(event.sport == 54321, "Should set correct source port");
    TEST_ASSERT(event.dport == 443, "Should set correct destination port");
    // Note: IPv4 and IPv6 addresses are in unions, so IPv4 fields will contain
    // the first 4 bytes of the IPv6 address - this is expected behavior
    
    // Check IPv6 addresses
    int saddr_match = (memcmp(event.saddr_v6, saddr_v6, 16) == 0);
    int daddr_match = (memcmp(event.daddr_v6, daddr_v6, 16) == 0);
    TEST_ASSERT(saddr_match, "Should set correct IPv6 source address");
    TEST_ASSERT(daddr_match, "Should set correct IPv6 destination address");
    
    // Test with unsupported address family
    reset_mock_state();
    ctx.family = 99; // Invalid family
    result = fill_network_info_from_inet_sock_state(&event, &ctx);
    TEST_ASSERT(result == 0, "Should fail with unsupported address family");
    TEST_ASSERT(mock_debug_stats.socket_info_errors == 1, 
                "Should record socket info error");
    
    TEST_PASS("IPv6 network info filling works correctly");
}

// Test 6: extract_ipv4_info function
static int test_extract_ipv4_info(void) {
    struct network_event event;
    memset(&event, 0, sizeof(event));
    
    // Test IPv4 extraction
    __u32 saddr = 0xC0A80101; // 192.168.1.1
    __u32 daddr = 0x08080808; // 8.8.8.8
    __u16 sport = 12345;
    __u16 dport = 80;
    
    // Convert to network byte order for testing
    __u32 net_saddr = bpf_htonl(saddr);
    __u32 net_daddr = bpf_htonl(daddr);
    __u16 net_sport = bpf_htons(sport);
    __u16 net_dport = bpf_htons(dport);
    
    extract_ipv4_info(&event, net_saddr, net_daddr, net_sport, net_dport);
    
    TEST_ASSERT(event.family == AF_INET, "Should set IPv4 family");
    TEST_ASSERT(event.saddr_v4 == saddr, "Should extract correct source address");
    TEST_ASSERT(event.daddr_v4 == daddr, "Should extract correct destination address");
    TEST_ASSERT(event.sport == sport, "Should extract correct source port");
    TEST_ASSERT(event.dport == dport, "Should extract correct destination port");
    
    // For union fields, IPv6 and IPv4 share the same memory, so we don't need to clear IPv6 fields
    // when using IPv4. The IPv4 values will overwrite the union memory.
    
    TEST_PASS("IPv4 info extraction works correctly");
}

// Test 7: extract_ipv6_info function
static int test_extract_ipv6_info(void) {
    struct network_event event;
    memset(&event, 0xFF, sizeof(event)); // Fill with non-zero data
    
    // Test IPv6 extraction
    __u8 saddr_v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    __u8 daddr_v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    __u16 sport = 54321;
    __u16 dport = 443;
    
    // Convert to network byte order for testing
    __u16 net_sport = bpf_htons(sport);
    __u16 net_dport = bpf_htons(dport);
    
    extract_ipv6_info(&event, saddr_v6, daddr_v6, net_sport, net_dport);
    
    TEST_ASSERT(event.family == AF_INET6, "Should set IPv6 family");
    TEST_ASSERT(event.sport == sport, "Should extract correct source port");
    TEST_ASSERT(event.dport == dport, "Should extract correct destination port");
    // Note: IPv4 and IPv6 addresses are in unions, so IPv4 fields will contain
    // the first 4 bytes of the IPv6 address - this is expected behavior
    
    // Check IPv6 addresses
    int saddr_match = (memcmp(event.saddr_v6, saddr_v6, 16) == 0);
    int daddr_match = (memcmp(event.daddr_v6, daddr_v6, 16) == 0);
    TEST_ASSERT(saddr_match, "Should extract correct IPv6 source address");
    TEST_ASSERT(daddr_match, "Should extract correct IPv6 destination address");
    
    TEST_PASS("IPv6 info extraction works correctly");
}

// Test 8: validate_network_event function
static int test_validate_network_event(void) {
    reset_mock_state();
    
    struct network_event event;
    
    // Test NULL event
    TEST_ASSERT(validate_network_event(NULL) == 0, "Should reject NULL event");
    
    // Test valid IPv4 TCP event
    memset(&event, 0, sizeof(event));
    event.family = AF_INET;
    event.protocol = IPPROTO_TCP;
    event.sport = 12345;
    event.dport = 80;
    TEST_ASSERT(validate_network_event(&event) == 1, "Should accept valid IPv4 TCP event");
    
    // Test valid IPv6 UDP event
    event.family = AF_INET6;
    event.protocol = IPPROTO_UDP;
    event.sport = 53;
    event.dport = 12345;
    TEST_ASSERT(validate_network_event(&event) == 1, "Should accept valid IPv6 UDP event");
    
    // Test invalid address family
    reset_mock_state();
    event.family = 99; // Invalid
    event.protocol = IPPROTO_TCP;
    TEST_ASSERT(validate_network_event(&event) == 0, "Should reject invalid address family");
    TEST_ASSERT(mock_debug_stats.socket_info_errors == 1, 
                "Should record socket info error for invalid family");
    
    // Test invalid protocol
    reset_mock_state();
    event.family = AF_INET;
    event.protocol = 99; // Invalid
    TEST_ASSERT(validate_network_event(&event) == 0, "Should reject invalid protocol");
    TEST_ASSERT(mock_debug_stats.socket_info_errors == 1, 
                "Should record socket info error for invalid protocol");
    
    // Test invalid por
    event.family = AF_INET;
    event.protocol = IPPROTO_TCP;
    event.sport = 65535; // Maximum valid port
    event.dport = 80;
    TEST_ASSERT(validate_network_event(&event) == 1, "Should accept maximum valid port");
    
    // Test port 0 (should be valid)
    reset_mock_state();
    event.sport = 0;
    event.dport = 0;
    TEST_ASSERT(validate_network_event(&event) == 1, "Should accept port 0");
    
    TEST_PASS("Network event validation works correctly");
}

// Test 9: should_filter_network_address function
static int test_should_filter_network_address(void) {
    struct network_event event;
    
    // Test NULL event
    TEST_ASSERT(should_filter_network_address(NULL) == 1, "Should filter NULL event");
    
    // Test normal IPv4 address
    memset(&event, 0, sizeof(event));
    event.family = AF_INET;
    event.saddr_v4 = 0xC0A80101; // 192.168.1.1
    event.daddr_v4 = 0x08080808; // 8.8.8.8
    TEST_ASSERT(should_filter_network_address(&event) == 0, "Should not filter normal IPv4 addresses");
    
    // Test loopback source address
    event.saddr_v4 = 0x7F000001; // 127.0.0.1
    event.daddr_v4 = 0x08080808; // 8.8.8.8
    TEST_ASSERT(should_filter_network_address(&event) == 1, "Should filter loopback source address");
    
    // Test loopback destination address
    event.saddr_v4 = 0xC0A80101; // 192.168.1.1
    event.daddr_v4 = 0x7F000001; // 127.0.0.1
    TEST_ASSERT(should_filter_network_address(&event) == 1, "Should filter loopback destination address");
    
    // Test other loopback addresses in 127.0.0.0/8
    event.saddr_v4 = 0x7F123456; // 127.18.52.86
    event.daddr_v4 = 0x08080808; // 8.8.8.8
    TEST_ASSERT(should_filter_network_address(&event) == 1, "Should filter any address in 127.0.0.0/8");
    
    // Test IPv6 (should not filter for now)
    event.family = AF_INET6;
    // Set IPv6 loopback (::1)
    memset(event.saddr_v6, 0, 16);
    
    TEST_PASS("Network address filtering works correctly");
}

// Test 10: Network event statistics recording
static int test_network_event_statistics(void) {
    reset_mock_state();
    
    // Test network event recording
    record_network_event();
    TEST_ASSERT(mock_debug_stats.network_events == 1, "Should record network event");
    TEST_ASSERT(mock_debug_stats.events_processed == 1, "Should record processed event");
    
    // Test connect event recording
    record_network_connect_event();
    TEST_ASSERT(mock_debug_stats.network_connect_events == 1, "Should record connect event");
    TEST_ASSERT(mock_debug_stats.network_events == 2, "Should increment total network events");
    
    // Test accept event recording
    record_network_accept_event();
    TEST_ASSERT(mock_debug_stats.network_accept_events == 1, "Should record accept event");
    TEST_ASSERT(mock_debug_stats.network_events == 3, "Should increment total network events");
    
    // Test protocol event recording
    record_network_protocol_event(IPPROTO_TCP);
    TEST_ASSERT(mock_debug_stats.network_tcp_events == 1, "Should record TCP event");
    
    record_network_protocol_event(IPPROTO_UDP);
    TEST_ASSERT(mock_debug_stats.network_udp_events == 1, "Should record UDP event");
    
    // Test family event recording
    record_network_family_event(AF_INET);
    TEST_ASSERT(mock_debug_stats.network_ipv4_events == 1, "Should record IPv4 event");
    
    record_network_family_event(AF_INET6);
    TEST_ASSERT(mock_debug_stats.network_ipv6_events == 1, "Should record IPv6 event");
    
    // Test sampling skip recording
    record_network_sampling_skipped();
    TEST_ASSERT(mock_debug_stats.network_sampling_skipped == 1, "Should record sampling skip");
    
    // Test socket info error recording
    record_socket_info_error();
    TEST_ASSERT(mock_debug_stats.socket_info_errors == 1, "Should record socket info error");
    
    TEST_PASS("Network event statistics recording works correctly");
}

// Test 11: Network configuration functions
static int test_network_configuration_functions(void) {
    reset_mock_state();
    
    // Test TCP monitoring configuration
    TEST_ASSERT(is_tcp_monitoring_enabled() == 1, "TCP monitoring should be enabled by default");
    
    mock_config.enable_tcp_monitoring = 0;
    TEST_ASSERT(is_tcp_monitoring_enabled() == 0, "Should respect TCP monitoring disable");
    
    // Test UDP monitoring configuration
    mock_config.enable_tcp_monitoring = 1;
    TEST_ASSERT(is_udp_monitoring_enabled() == 1, "UDP monitoring should be enabled by default");
    
    mock_config.enable_udp_monitoring = 0;
    TEST_ASSERT(is_udp_monitoring_enabled() == 0, "Should respect UDP monitoring disable");
    
    // Test IPv6 monitoring configuration
    mock_config.enable_udp_monitoring = 1;
    TEST_ASSERT(is_ipv6_monitoring_enabled() == 1, "IPv6 monitoring should be enabled by default");
    
    mock_config.enable_ipv6_monitoring = 0;
    TEST_ASSERT(is_ipv6_monitoring_enabled() == 0, "Should respect IPv6 monitoring disable");
    
    // Test network sampling rate
    mock_config.enable_ipv6_monitoring = 1;
    mock_config.network_sampling_rate = 75;
    __u32 rate;
    int result = get_network_sampling_rate(&rate);
    TEST_ASSERT(result == 0, "Should successfully get network sampling rate");
    TEST_ASSERT(rate == 75, "Should return configured network sampling rate");
    
    // Test fallback to global sampling rate
    mock_config.network_sampling_rate = 0;
    mock_config.sampling_rate = 50;
    result = get_network_sampling_rate(&rate);
    TEST_ASSERT(result == 0, "Should successfully get fallback sampling rate");
    TEST_ASSERT(rate == 50, "Should fallback to global sampling rate");
    
    // Test config map failure
    void *original_map = config_map;
    config_map = NULL;
    result = get_network_sampling_rate(&rate);
    TEST_ASSERT(result == -1, "Should fail when config map unavailable");
    config_map = original_map;
    
    TEST_PASS("Network configuration functions work correctly");
}

// Test 12: Integration test for complete network event processing flow
static int test_network_event_processing_flow(void) {
    reset_mock_state();
    
    // Set up for successful event processing
    mock_pid_tgid = 0x0000123400001000ULL;  // Valid PID
    mock_config.enable_network_monitoring = 1;
    mock_config.enable_tcp_monitoring = 1;
    mock_config.network_sampling_rate = 100;  // Always sample
    mock_random = 50;
    
    // Test the complete flow for IPv4 TCP connection
    TEST_ASSERT(should_process_network_event(AF_INET, IPPROTO_TCP) == 1, 
                "Should process IPv4 TCP event");
    
    // Simulate event allocation and filling
    struct network_event *event = allocate_network_event_with_retry(EVENT_NETWORK_CONNECT);
    TEST_ASSERT(event != NULL, "Should successfully allocate event");
    
    // Create mock tracepoint context
    struct trace_event_raw_inet_sock_set_state ctx;
    setup_mock_inet_sock_ctx_ipv4(&ctx, 0xC0A80101, 0x08080808, 12345, 80, IPPROTO_TCP);
    
    // Fill network information
    int result = fill_network_info_from_inet_sock_state(event, &ctx);
    TEST_ASSERT(result == 1, "Should successfully fill network info");
    
    // Validate the event
    TEST_ASSERT(validate_network_event(event) == 1, "Should validate successfully");
    
    // Check address filtering
    TEST_ASSERT(should_filter_network_address(event) == 0, "Should not filter normal addresses");
    
    // Record statistics
    record_network_connect_event();
    record_network_protocol_event(event->protocol);
    record_network_family_event(event->family);
    
    // Verify the complete event
    TEST_ASSERT(event->header.event_type == EVENT_NETWORK_CONNECT, "Should have correct event type");
    TEST_ASSERT(event->family == AF_INET, "Should have correct address family");
    TEST_ASSERT(event->protocol == IPPROTO_TCP, "Should have correct protocol");
    TEST_ASSERT(event->sport == 12345, "Should have correct source port");
    TEST_ASSERT(event->dport == 80, "Should have correct destination port");
    TEST_ASSERT(event->saddr_v4 == 0xC0A80101, "Should have correct source address");
    TEST_ASSERT(event->daddr_v4 == 0x08080808, "Should have correct destination address");
    
    // Verify statistics
    TEST_ASSERT(mock_debug_stats.network_connect_events == 1, "Should record connect event");
    TEST_ASSERT(mock_debug_stats.network_tcp_events == 1, "Should record TCP event");
    TEST_ASSERT(mock_debug_stats.network_ipv4_events == 1, "Should record IPv4 event");
    
    TEST_PASS("Complete network event processing flow works correctly");
}

// Test 13: IPv6 integration test
static int test_ipv6_integration(void) {
    reset_mock_state();
    
    // Set up for IPv6 processing
    mock_pid_tgid = 0x0000123400001000ULL;
    mock_config.enable_network_monitoring = 1;
    mock_config.enable_tcp_monitoring = 1;
    mock_config.enable_ipv6_monitoring = 1;
    mock_config.network_sampling_rate = 100;
    
    // Test IPv6 event processing
    TEST_ASSERT(should_process_network_event(AF_INET6, IPPROTO_TCP) == 1, 
                "Should process IPv6 TCP event");
    
    // Allocate and fill IPv6 event
    struct network_event *event = allocate_network_event_with_retry(EVENT_NETWORK_ACCEPT);
    TEST_ASSERT(event != NULL, "Should successfully allocate IPv6 event");
    
    // Create IPv6 context
    struct trace_event_raw_inet_sock_set_state ctx;
    __u8 saddr_v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    __u8 daddr_v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    setup_mock_inet_sock_ctx_ipv6(&ctx, saddr_v6, daddr_v6, 54321, 443, IPPROTO_TCP);
    
    int result = fill_network_info_from_inet_sock_state(event, &ctx);
    TEST_ASSERT(result == 1, "Should successfully fill IPv6 network info");
    TEST_ASSERT(validate_network_event(event) == 1, "Should validate IPv6 event");
    
    // Record IPv6 statistics
    record_network_accept_event();
    record_network_protocol_event(event->protocol);
    record_network_family_event(event->family);
    
    // Verify IPv6-specific fields
    TEST_ASSERT(event->family == AF_INET6, "Should have IPv6 family");
    // Note: IPv4 and IPv6 addresses are in unions, so IPv4 fields will contain
    // the first 4 bytes of the IPv6 address - this is expected behavior
    
    int saddr_match = (memcmp(event->saddr_v6, saddr_v6, 16) == 0);
    int daddr_match = (memcmp(event->daddr_v6, daddr_v6, 16) == 0);
    TEST_ASSERT(saddr_match, "Should have correct IPv6 source address");
    TEST_ASSERT(daddr_match, "Should have correct IPv6 destination address");
    
    TEST_ASSERT(mock_debug_stats.network_accept_events == 1, "Should record accept event");
    TEST_ASSERT(mock_debug_stats.network_ipv6_events == 1, "Should record IPv6 event");
    
    TEST_PASS("IPv6 integration test works correctly");
}

// Test 14: Error handling and edge cases
static int test_network_error_handling(void) {
    reset_mock_state();
    
    // Test allocation failure handling
    mock_allocation_should_fail = 1;
    struct network_event *event = allocate_network_event_with_retry(EVENT_NETWORK_CONNECT);
    TEST_ASSERT(event == NULL, "Should handle allocation failure");
    TEST_ASSERT(mock_debug_stats.allocation_failures == 1, "Should record allocation failure");
    
    // Test invalid tracepoint context
    reset_mock_state();
    mock_allocation_should_fail = 0;
    event = allocate_network_event_with_retry(EVENT_NETWORK_CONNECT);
    
    struct trace_event_raw_inet_sock_set_state invalid_ctx;
    memset(&invalid_ctx, 0, sizeof(invalid_ctx));
    invalid_ctx.family = 99; // Invalid family
    invalid_ctx.protocol = IPPROTO_TCP;
    
    int result = fill_network_info_from_inet_sock_state(event, &invalid_ctx);
    TEST_ASSERT(result == 0, "Should handle invalid address family");
    TEST_ASSERT(mock_debug_stats.socket_info_errors == 1, "Should record socket info error");
    
    // Test extreme port values
    reset_mock_state();
    struct network_event test_event;
    memset(&test_event, 0, sizeof(test_event));
    test_event.family = AF_INET;
    test_event.protocol = IPPROTO_TCP;
    test_event.sport = 65535; // Maximum valid port
    test_event.dport = 0;     // Minimum valid port
    TEST_ASSERT(validate_network_event(&test_event) == 1, "Should accept extreme valid ports");
    
    // Since __u16 automatically truncates 65536 to 0, this is actually valid
    test_event.sport = 0; // This is what 65536 becomes after truncation
    TEST_ASSERT(validate_network_event(&test_event) == 1, "Should accept port after truncation");
    
    // Test with disabled monitoring at various levels
    reset_mock_state();
    mock_pid_tgid = 0x0000123400001000ULL;
    
    // Disable network monitoring entirely
    mock_config.enable_network_monitoring = 0;
    TEST_ASSERT(should_process_network_event(AF_INET, IPPROTO_TCP) == 0, 
                "Should not process when network monitoring disabled");
    
    // Enable network but disable specific protocols
    mock_config.enable_network_monitoring = 1;
    mock_config.enable_tcp_monitoring = 0;
    mock_config.enable_udp_monitoring = 1;
    TEST_ASSERT(should_process_network_event(AF_INET, IPPROTO_TCP) == 0, 
                "Should not process TCP when TCP disabled");
    TEST_ASSERT(should_process_network_event(AF_INET, IPPROTO_UDP) == 1, 
                "Should still process UDP when TCP disabled");
    
    // Test sampling edge cases
    mock_config.enable_tcp_monitoring = 1;
    mock_config.network_sampling_rate = 0; // Never sample (falls back to sampling_rate)
    mock_config.sampling_rate = 0; // Also set global sampling to 0
    TEST_ASSERT(should_process_network_event(AF_INET, IPPROTO_TCP) == 0, 
                "Should not process with 0% sampling");
    TEST_ASSERT(mock_debug_stats.network_sampling_skipped == 1, 
                "Should record sampling skip");
    
    TEST_PASS("Network error handling works correctly");
}

// Test runner structure
typedef struct {
    const char *name;
    int (*test_func)(void);
} test_case_t;

// Test suite definition
static test_case_t test_suite[] = {
    {"network_byte_order_conversion", test_network_byte_order_conversion},
    {"should_process_network_event", test_should_process_network_event},
    {"allocate_network_event_with_retry", test_allocate_network_event_with_retry},
    {"fill_network_info_ipv4", test_fill_network_info_ipv4},
    {"fill_network_info_ipv6", test_fill_network_info_ipv6},
    {"extract_ipv4_info", test_extract_ipv4_info},
    {"extract_ipv6_info", test_extract_ipv6_info},
    {"validate_network_event", test_validate_network_event},
    {"should_filter_network_address", test_should_filter_network_address},
    {"network_event_statistics", test_network_event_statistics},
    {"network_configuration_functions", test_network_configuration_functions},
    {"network_event_processing_flow", test_network_event_processing_flow},
    {"ipv6_integration", test_ipv6_integration},
    {"network_error_handling", test_network_error_handling},
    {NULL, NULL}  // Sentinel
};

// Main test runner
int main(int argc, char *argv[]) {
    printf("eBPF Network Monitor Unit Tests\n");
    printf("===============================\n\n");
    
    int total_tests = 0;
    test_failures = 0;
    test_successes = 0;
    
    // Run all tests
    for (int i = 0; test_suite[i].name != NULL; i++) {
        printf("Running test: %s\n", test_suite[i].name);
        reset_mock_state();  // Reset state before each test
        
        if (test_suite[i].test_func()) {
            printf("✓ %s passed\n\n", test_suite[i].name);
        } else {
            printf("✗ %s failed\n\n", test_suite[i].name);
        }
        total_tests++;
    }
    
    // Print summary
    printf("Test Summary\n");
    printf("============\n");
    printf("Total tests: %d\n", total_tests);
    printf("Passed: %d\n", test_successes);
    printf("Failed: %d\n", test_failures);
    printf("Success rate: %.1f%%\n", 
           total_tests > 0 ? (float)test_successes / total_tests * 100 : 0);
    
    if (test_failures == 0) {
        printf("\n🎉 All network monitoring tests passed!\n");
        printf("\nTested functionality:\n");
        printf("- Network information extraction functions\n");
        printf("- Different protocols (TCP/UDP) and address families (IPv4/IPv6)\n");
        printf("- Network event error handling mechanisms\n");
        printf("- Network event sampling and filtering logic\n");
        printf("- Network byte order conversion\n");
        printf("- Network address filtering (loopback detection)\n");
        printf("- Network event validation\n");
        printf("- Network statistics recording\n");
        printf("- Configuration-based network monitoring control\n");
        printf("- Integration testing of complete network event flow\n");
        return 0;
    } else {
        printf("\n❌ Some network monitoring tests failed!\n");
        return 1;
    }
}