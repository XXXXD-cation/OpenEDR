// Mock eBPF structures and functions for performance testing
#define _GNU_SOURCE
#include "performance_test_common.h"

// Performance test configuration
#define MAX_TEST_DURATION_SEC 60
#define HIGH_LOAD_PROCESSES 1000
#define STRESS_TEST_ITERATIONS 10000
#define MEMORY_SAMPLE_INTERVAL_MS 100
#define CPU_SAMPLE_INTERVAL_MS 50

// Test result structures
struct performance_metrics {
    double avg_latency_ns;
    double max_latency_ns;
    double min_latency_ns;
    uint64_t total_events;
    uint64_t events_per_second;
    uint64_t memory_usage_kb;
    double cpu_usage_percent;
    uint64_t allocation_failures;
    uint64_t processing_errors;
};

struct comparison_results {
    struct performance_metrics kprobe_metrics;
    struct performance_metrics tracepoint_metrics;
    double performance_improvement_percent;
    double stability_score;
    int reliability_rating;
};

// Global test state
static volatile int test_running = 0;
static volatile int high_load_active = 0;

// Mock implementations for testing
static uint64_t mock_timestamp_ns = 0;
static uint32_t mock_pid_counter = 1000;
struct config mock_config = {
    .enable_process_monitoring = 1,
    .enable_network_monitoring = 0,
    .enable_file_monitoring = 0,
    .enable_syscall_monitoring = 0,
    .sampling_rate = 100
};
struct debug_stats mock_kprobe_stats = {0};
struct debug_stats mock_tracepoint_stats = {0};
char mock_events_buffer[4096];

// Performance measurement utilities
static inline uint64_t get_timestamp_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static inline double calculate_cpu_usage(void) {
    static struct rusage prev_usage = {0};
    static struct timeval prev_time = {0};
    
    struct rusage current_usage;
    struct timeval current_time;
    
    getrusage(RUSAGE_SELF, &current_usage);
    gettimeofday(&current_time, NULL);
    
    if (prev_time.tv_sec == 0) {
        prev_usage = current_usage;
        prev_time = current_time;
        return 0.0;
    }
    
    double user_time = (current_usage.ru_utime.tv_sec - prev_usage.ru_utime.tv_sec) +
                      (current_usage.ru_utime.tv_usec - prev_usage.ru_utime.tv_usec) / 1000000.0;
    double sys_time = (current_usage.ru_stime.tv_sec - prev_usage.ru_stime.tv_sec) +
                     (current_usage.ru_stime.tv_usec - prev_usage.ru_stime.tv_usec) / 1000000.0;
    double wall_time = (current_time.tv_sec - prev_time.tv_sec) +
                      (current_time.tv_usec - prev_time.tv_usec) / 1000000.0;
    
    prev_usage = current_usage;
    prev_time = current_time;
    
    return ((user_time + sys_time) / wall_time) * 100.0;
}

static inline uint64_t get_memory_usage_kb(void) {
    FILE *status = fopen("/proc/self/status", "r");
    if (!status) return 0;
    
    char line[256];
    uint64_t vmrss = 0;
    
    while (fgets(line, sizeof(line), status)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line, "VmRSS: %lu kB", &vmrss);
            break;
        }
    }
    
    fclose(status);
    return vmrss;
}

// Mock eBPF helper functions for performance testing
uint64_t bpf_get_current_pid_tgid(void) {
    return ((uint64_t)getpid() << 32) | (uint32_t)mock_pid_counter++;
}

uint64_t bpf_ktime_get_ns(void) {
    return mock_timestamp_ns = get_timestamp_ns();
}

uint64_t bpf_get_current_uid_gid(void) {
    return ((uint64_t)getuid() << 32) | (uint32_t)getgid();
}

uint32_t bpf_get_smp_processor_id(void) {
    return 0; // Mock single CPU
}

int bpf_get_current_comm(void *comm, uint32_t size) {
    strncpy((char*)comm, "test_process", size);
    return 0;
}

uint32_t bpf_get_prandom_u32(void) {
    return rand();
}

// Mock ring buffer operations
void* bpf_ringbuf_reserve(void *ringbuf, uint64_t size, uint64_t flags) {
    static char mock_buffer[4096];
    return mock_buffer;
}

void bpf_ringbuf_submit(void *data, uint64_t flags) {
    // Mock submission - just increment counter
}

// Mock map operations
void* bpf_map_lookup_elem(void *map, const void *key) {
    // For testing, we just return the appropriate mock data
    // In real eBPF, map would be checked by address
    return test_running ? &mock_tracepoint_stats : &mock_kprobe_stats;
}

// Mock probe read functions
long bpf_probe_read_user_str(void *dst, uint32_t size, const void *unsafe_ptr) {
    strncpy((char*)dst, "/bin/test", size);
    return strlen("/bin/test");
}

long bpf_probe_read_kernel_str(void *dst, uint32_t size, const void *unsafe_ptr) {
    strncpy((char*)dst, "/bin/test", size);
    return strlen("/bin/test");
}

// Helper function implementations
void fill_event_header(struct event_header *header, __u32 event_type) {
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

int should_trace_pid(__u32 pid) {
    // Skip kernel threads (pid 0) and init (pid 1)
    if (pid <= 1) {
        return 0;
    }
    return 1;
}

int get_config_value(__u32 key, __u32 *value) {
    struct config *cfg = &mock_config;
    
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

int should_sample(__u32 rate) {
    if (rate == 0) return 0;
    if (rate >= 100) return 1;
    
    return (bpf_get_prandom_u32() % 100) < rate;
}

void record_error(__u32 error_type) {
    struct debug_stats *stats = test_running ? &mock_tracepoint_stats : &mock_kprobe_stats;
    
    switch (error_type) {
        case ERROR_EVENT_DROPPED:
            stats->events_dropped++;
            break;
        case ERROR_ALLOCATION_FAILURE:
            stats->allocation_failures++;
            break;
        case ERROR_CONFIG_ERROR:
            stats->config_errors++;
            break;
        case ERROR_DATA_READ_ERROR:
            stats->data_read_errors++;
            break;
        case ERROR_TRACEPOINT_ERROR:
            stats->tracepoint_errors++;
            break;
    }
    
    stats->last_error_timestamp = bpf_ktime_get_ns();
    stats->last_error_type = error_type;
    stats->last_error_pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
}

void record_exec_event(void) {
    struct debug_stats *stats = test_running ? &mock_tracepoint_stats : &mock_kprobe_stats;
    stats->exec_events++;
    stats->events_processed++;
}

void record_exit_event(void) {
    struct debug_stats *stats = test_running ? &mock_tracepoint_stats : &mock_kprobe_stats;
    stats->exit_events++;
    stats->events_processed++;
}

void record_sampling_skipped(void) {
    struct debug_stats *stats = test_running ? &mock_tracepoint_stats : &mock_kprobe_stats;
    stats->sampling_skipped++;
}

void record_pid_filtered(void) {
    struct debug_stats *stats = test_running ? &mock_tracepoint_stats : &mock_kprobe_stats;
    stats->pid_filtered++;
}

int get_config_value_safe(__u32 key, __u32 *value, __u32 fallback) {
    int ret = get_config_value(key, value);
    if (ret < 0) {
        record_error(ERROR_CONFIG_ERROR);
        *value = fallback;
        return 0;
    }
    return ret;
}

int should_process_event(__u32 monitor_type) {
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    if (!should_trace_pid(pid)) {
        record_pid_filtered();
        return 0;
    }
    
    __u32 enabled = 0;
    get_config_value_safe(monitor_type, &enabled, 1);
    
    if (!enabled) {
        return 0;
    }
    
    __u32 rate = 100;
    get_config_value_safe(MONITOR_SAMPLING_RATE, &rate, 100);
    
    if (!should_sample(rate)) {
        record_sampling_skipped();
        return 0;
    }
    
    return 1;
}

struct process_event* allocate_process_event(__u32 event_type) {
    struct process_event *event = bpf_ringbuf_reserve(mock_events_buffer, sizeof(*event), 0);
    if (!event) {
        record_error(ERROR_ALLOCATION_FAILURE);
        return NULL;
    }
    
    fill_event_header(&event->header, event_type);
    return event;
}

int extract_filename_from_exec_ctx(struct trace_event_raw_sched_process_exec *ctx, char *filename, size_t size) {
    // Mock implementation - just copy a test filename
    strncpy(filename, "/bin/test", size);
    return 0;
}

__u32 get_parent_pid_from_exec_ctx(struct trace_event_raw_sched_process_exec *ctx) {
    return ctx->old_pid;
}

void fill_process_exec_info(struct process_event *event, struct trace_event_raw_sched_process_exec *ctx) {
    if (ctx) {
        event->ppid = get_parent_pid_from_exec_ctx(ctx);
    } else {
        event->ppid = 0;
        handle_tracepoint_error();
    }
    
    event->exit_code = 0;
    
    if (ctx && extract_filename_from_exec_ctx(ctx, event->filename, sizeof(event->filename)) < 0) {
        memset(event->filename, 0, sizeof(event->filename));
        handle_data_read_error();
    } else if (!ctx) {
        memset(event->filename, 0, sizeof(event->filename));
        handle_tracepoint_error();
    }
    
    memset(event->args, 0, sizeof(event->args));
}

void fill_process_exit_info(struct process_event *event, struct trace_event_raw_sched_process_exit *ctx) {
    event->ppid = 0;
    event->exit_code = 0;
    
    memset(event->filename, 0, sizeof(event->filename));
    memset(event->args, 0, sizeof(event->args));
}

struct process_event* allocate_process_event_with_retry(__u32 event_type) {
    struct process_event *event;
    
    event = bpf_ringbuf_reserve(mock_events_buffer, sizeof(*event), 0);
    if (event) {
        fill_event_header(&event->header, event_type);
        return event;
    }
    
    record_error(ERROR_ALLOCATION_FAILURE);
    
    // Try once more
    event = bpf_ringbuf_reserve(mock_events_buffer, sizeof(*event), 0);
    if (event) {
        fill_event_header(&event->header, event_type);
        return event;
    }
    
    return NULL;
}

int handle_allocation_failure(void) {
    record_error(ERROR_ALLOCATION_FAILURE);
    return 0;
}

int handle_config_error(void) {
    record_error(ERROR_CONFIG_ERROR);
    return 1;
}

int handle_data_read_error(void) {
    record_error(ERROR_DATA_READ_ERROR);
    return 0;
}

int handle_tracepoint_error(void) {
    record_error(ERROR_TRACEPOINT_ERROR);
    return 0;
}

// Performance test implementations

// Simulate kprobe-based event processing
static uint64_t simulate_kprobe_processing(int iterations) {
    uint64_t start_time = get_timestamp_ns();
    uint64_t total_latency = 0;
    
    for (int i = 0; i < iterations; i++) {
        uint64_t event_start = get_timestamp_ns();
        
        // Simulate kprobe overhead
        uint32_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
        
        // Multiple checks (code duplication in original)
        if (!should_trace_pid(pid)) continue;
        
        uint32_t enabled = 0;
        if (get_config_value(0, &enabled) < 0 || !enabled) continue;
        
        uint32_t rate = 100;
        get_config_value(4, &rate);
        if (!should_sample(rate)) continue;
        
        // Simulate event allocation and processing
        struct process_event *event = bpf_ringbuf_reserve(mock_events_buffer, sizeof(*event), 0);
        if (!event) {
            mock_kprobe_stats.allocation_failures++;
            continue;
        }
        
        fill_event_header(&event->header, EVENT_PROCESS_EXEC);
        event->ppid = bpf_get_current_pid_tgid() >> 32; // Incorrect parent PID
        event->exit_code = 0;
        
        // Simulate user space read (slower)
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), "/bin/test");
        memset(event->args, 0, sizeof(event->args));
        
        bpf_ringbuf_submit(event, 0);
        
        uint64_t event_end = get_timestamp_ns();
        total_latency += (event_end - event_start);
        mock_kprobe_stats.events_processed++;
    }
    
    uint64_t end_time = get_timestamp_ns();
    return end_time - start_time;
}

// Simulate tracepoint-based event processing
static uint64_t simulate_tracepoint_processing(int iterations) {
    uint64_t start_time = get_timestamp_ns();
    uint64_t total_latency = 0;
    
    for (int i = 0; i < iterations; i++) {
        uint64_t event_start = get_timestamp_ns();
        
        // Simulate optimized tracepoint processing
        if (!should_process_event(MONITOR_PROCESS)) {
            mock_tracepoint_stats.sampling_skipped++;
            continue;
        }
        
        // Simulate enhanced allocation with retry
        struct process_event *event = allocate_process_event_with_retry(EVENT_PROCESS_EXEC);
        if (!event) {
            mock_tracepoint_stats.allocation_failures++;
            continue;
        }
        
        // Simulate tracepoint context (more accurate data)
        struct trace_event_raw_sched_process_exec mock_ctx = {
            .pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF,
            .old_pid = 1000, // Correct parent PID
            .__data_loc_filename = 64 // Mock offset
        };
        
        fill_process_exec_info(event, &mock_ctx);
        record_exec_event();
        
        bpf_ringbuf_submit(event, 0);
        
        uint64_t event_end = get_timestamp_ns();
        total_latency += (event_end - event_start);
        mock_tracepoint_stats.events_processed++;
    }
    
    uint64_t end_time = get_timestamp_ns();
    return end_time - start_time;
}

// High load stress test
static void* high_load_generator(void *arg) {
    int process_count = *(int*)arg;
    
    while (high_load_active) {
        for (int i = 0; i < process_count; i++) {
            pid_t pid = fork();
            if (pid == 0) {
                // Child process - simulate short-lived process
                execl("/bin/true", "true", NULL);
                exit(0);
            } else if (pid > 0) {
                // Parent - wait for child
                waitpid(pid, NULL, 0);
            }
        }
        usleep(1000); // 1ms delay between batches
    }
    
    return NULL;
}

// Memory monitoring thread
static void* memory_monitor(void *arg) {
    struct performance_metrics *metrics = (struct performance_metrics*)arg;
    uint64_t max_memory = 0;
    uint64_t samples = 0;
    uint64_t total_memory = 0;
    
    while (test_running) {
        uint64_t current_memory = get_memory_usage_kb();
        if (current_memory > max_memory) {
            max_memory = current_memory;
        }
        total_memory += current_memory;
        samples++;
        
        usleep(MEMORY_SAMPLE_INTERVAL_MS * 1000);
    }
    
    metrics->memory_usage_kb = samples > 0 ? total_memory / samples : 0;
    return NULL;
}

// CPU monitoring thread
static void* cpu_monitor(void *arg) {
    struct performance_metrics *metrics = (struct performance_metrics*)arg;
    double total_cpu = 0.0;
    uint64_t samples = 0;
    
    while (test_running) {
        double current_cpu = calculate_cpu_usage();
        if (current_cpu > 0) {
            total_cpu += current_cpu;
            samples++;
        }
        
        usleep(CPU_SAMPLE_INTERVAL_MS * 1000);
    }
    
    metrics->cpu_usage_percent = samples > 0 ? total_cpu / samples : 0.0;
    return NULL;
}

// Run performance benchmark
static struct performance_metrics run_performance_test(
    const char *test_name,
    uint64_t (*test_func)(int),
    int iterations,
    int duration_sec) {
    
    struct performance_metrics metrics = {0};
    
    printf("Running %s performance test...\n", test_name);
    printf("Iterations: %d, Duration: %d seconds\n", iterations, duration_sec);
    
    // Start monitoring threads
    test_running = 1;
    pthread_t memory_thread, cpu_thread;
    pthread_create(&memory_thread, NULL, memory_monitor, &metrics);
    pthread_create(&cpu_thread, NULL, cpu_monitor, &metrics);
    
    // Run the actual test
    uint64_t start_time = get_timestamp_ns();
    uint64_t test_duration = test_func(iterations);
    uint64_t end_time = get_timestamp_ns();
    
    // Stop monitoring
    test_running = 0;
    pthread_join(memory_thread, NULL);
    pthread_join(cpu_thread, NULL);
    
    // Calculate metrics
    metrics.total_events = iterations;
    metrics.avg_latency_ns = (double)test_duration / iterations;
    metrics.events_per_second = (uint64_t)((double)iterations * 1000000000.0 / test_duration);
    
    // Get error statistics
    struct debug_stats *stats = test_name[0] == 'k' ? &mock_kprobe_stats : &mock_tracepoint_stats;
    metrics.allocation_failures = stats->allocation_failures;
    metrics.processing_errors = stats->config_errors + stats->data_read_errors + stats->tracepoint_errors;
    
    printf("✓ %s test completed\n", test_name);
    printf("  Average latency: %.2f ns\n", metrics.avg_latency_ns);
    printf("  Events per second: %lu\n", metrics.events_per_second);
    printf("  Memory usage: %lu KB\n", metrics.memory_usage_kb);
    printf("  CPU usage: %.2f%%\n", metrics.cpu_usage_percent);
    printf("  Allocation failures: %lu\n", metrics.allocation_failures);
    printf("  Processing errors: %lu\n", metrics.processing_errors);
    printf("\n");
    
    return metrics;
}

// High load stability test
static int run_stability_test(const char *test_name, uint64_t (*test_func)(int)) {
    printf("Running %s stability test under high load...\n", test_name);
    
    // Start high load generator
    high_load_active = 1;
    pthread_t load_thread;
    int process_count = HIGH_LOAD_PROCESSES;
    pthread_create(&load_thread, NULL, high_load_generator, &process_count);
    
    // Run test under load
    test_running = 1;
    uint64_t start_time = get_timestamp_ns();
    uint64_t errors_before = test_name[0] == 'k' ? 
        mock_kprobe_stats.allocation_failures + mock_kprobe_stats.config_errors :
        mock_tracepoint_stats.allocation_failures + mock_tracepoint_stats.config_errors;
    
    uint64_t test_duration = test_func(STRESS_TEST_ITERATIONS);
    
    uint64_t errors_after = test_name[0] == 'k' ? 
        mock_kprobe_stats.allocation_failures + mock_kprobe_stats.config_errors :
        mock_tracepoint_stats.allocation_failures + mock_tracepoint_stats.config_errors;
    
    test_running = 0;
    
    // Stop high load generator
    high_load_active = 0;
    pthread_join(load_thread, NULL);
    
    uint64_t error_increase = errors_after - errors_before;
    double error_rate = (double)error_increase / STRESS_TEST_ITERATIONS * 100.0;
    
    printf("✓ %s stability test completed\n", test_name);
    printf("  Test duration: %.2f ms\n", test_duration / 1000000.0);
    printf("  Error increase: %lu\n", error_increase);
    printf("  Error rate: %.2f%%\n", error_rate);
    printf("  Stability rating: %s\n", error_rate < 1.0 ? "EXCELLENT" : 
                                      error_rate < 5.0 ? "GOOD" : 
                                      error_rate < 10.0 ? "FAIR" : "POOR");
    printf("\n");
    
    return error_rate < 5.0 ? 1 : 0; // Return 1 for stable, 0 for unstable
}

// Memory stress test
static int run_memory_stress_test(const char *test_name, uint64_t (*test_func)(int)) {
    printf("Running %s memory stress test...\n", test_name);
    
    uint64_t initial_memory = get_memory_usage_kb();
    uint64_t peak_memory = initial_memory;
    
    // Run multiple iterations to stress memory
    for (int round = 0; round < 10; round++) {
        test_running = 1;
        test_func(STRESS_TEST_ITERATIONS / 10);
        test_running = 0;
        
        uint64_t current_memory = get_memory_usage_kb();
        if (current_memory > peak_memory) {
            peak_memory = current_memory;
        }
        
        // Small delay between rounds
        usleep(100000); // 100ms
    }
    
    uint64_t memory_increase = peak_memory - initial_memory;
    double memory_growth_percent = (double)memory_increase / initial_memory * 100.0;
    
    printf("✓ %s memory stress test completed\n", test_name);
    printf("  Initial memory: %lu KB\n", initial_memory);
    printf("  Peak memory: %lu KB\n", peak_memory);
    printf("  Memory increase: %lu KB\n", memory_increase);
    printf("  Memory growth: %.2f%%\n", memory_growth_percent);
    printf("  Memory efficiency: %s\n", memory_growth_percent < 10.0 ? "EXCELLENT" :
                                        memory_growth_percent < 25.0 ? "GOOD" :
                                        memory_growth_percent < 50.0 ? "FAIR" : "POOR");
    printf("\n");
    
    return memory_growth_percent < 25.0 ? 1 : 0; // Return 1 for efficient, 0 for inefficient
}

// CPU stress test
static int run_cpu_stress_test(const char *test_name, uint64_t (*test_func)(int)) {
    printf("Running %s CPU stress test...\n", test_name);
    
    test_running = 1;
    pthread_t cpu_thread;
    struct performance_metrics metrics = {0};
    pthread_create(&cpu_thread, NULL, cpu_monitor, &metrics);
    
    // Run intensive test
    uint64_t start_time = get_timestamp_ns();
    test_func(STRESS_TEST_ITERATIONS * 2);
    uint64_t end_time = get_timestamp_ns();
    
    test_running = 0;
    pthread_join(cpu_thread, NULL);
    
    double test_duration_sec = (end_time - start_time) / 1000000000.0;
    double cpu_efficiency = (STRESS_TEST_ITERATIONS * 2) / test_duration_sec / 1000.0; // K events/sec
    
    printf("✓ %s CPU stress test completed\n", test_name);
    printf("  Test duration: %.2f seconds\n", test_duration_sec);
    printf("  Average CPU usage: %.2f%%\n", metrics.cpu_usage_percent);
    printf("  Processing rate: %.2f K events/sec\n", cpu_efficiency);
    printf("  CPU efficiency: %s\n", metrics.cpu_usage_percent < 50.0 ? "EXCELLENT" :
                                     metrics.cpu_usage_percent < 75.0 ? "GOOD" :
                                     metrics.cpu_usage_percent < 90.0 ? "FAIR" : "POOR");
    printf("\n");
    
    return metrics.cpu_usage_percent < 75.0 ? 1 : 0; // Return 1 for efficient, 0 for inefficient
}

// Compare performance between kprobe and tracepoint
static struct comparison_results compare_performance(void) {
    struct comparison_results results = {0};
    
    printf("=== Performance Comparison: Kprobe vs Tracepoint ===\n\n");
    
    // Reset statistics
    memset(&mock_kprobe_stats, 0, sizeof(mock_kprobe_stats));
    memset(&mock_tracepoint_stats, 0, sizeof(mock_tracepoint_stats));
    
    // Run kprobe performance test
    results.kprobe_metrics = run_performance_test("kprobe", simulate_kprobe_processing, 
                                                  STRESS_TEST_ITERATIONS, 30);
    
    // Reset for tracepoint test
    memset(&mock_tracepoint_stats, 0, sizeof(mock_tracepoint_stats));
    
    // Run tracepoint performance test
    results.tracepoint_metrics = run_performance_test("tracepoint", simulate_tracepoint_processing, 
                                                      STRESS_TEST_ITERATIONS, 30);
    
    // Calculate improvement
    if (results.kprobe_metrics.avg_latency_ns > 0) {
        results.performance_improvement_percent = 
            ((results.kprobe_metrics.avg_latency_ns - results.tracepoint_metrics.avg_latency_ns) / 
             results.kprobe_metrics.avg_latency_ns) * 100.0;
    }
    
    // Calculate stability score (lower error rate = higher stability)
    double kprobe_error_rate = (double)(results.kprobe_metrics.allocation_failures + 
                                       results.kprobe_metrics.processing_errors) / 
                              results.kprobe_metrics.total_events * 100.0;
    double tracepoint_error_rate = (double)(results.tracepoint_metrics.allocation_failures + 
                                           results.tracepoint_metrics.processing_errors) / 
                                  results.tracepoint_metrics.total_events * 100.0;
    
    results.stability_score = (100.0 - tracepoint_error_rate) - (100.0 - kprobe_error_rate);
    
    // Calculate reliability rating (1-10 scale)
    if (results.performance_improvement_percent > 20.0 && results.stability_score > 5.0) {
        results.reliability_rating = 10;
    } else if (results.performance_improvement_percent > 10.0 && results.stability_score > 0.0) {
        results.reliability_rating = 8;
    } else if (results.performance_improvement_percent > 0.0) {
        results.reliability_rating = 6;
    } else {
        results.reliability_rating = 4;
    }
    
    return results;
}

// Print detailed comparison report
static void print_comparison_report(struct comparison_results *results) {
    printf("=== Detailed Performance Comparison Report ===\n\n");
    
    printf("Kprobe Implementation:\n");
    printf("  Average latency: %.2f ns\n", results->kprobe_metrics.avg_latency_ns);
    printf("  Events per second: %lu\n", results->kprobe_metrics.events_per_second);
    printf("  Memory usage: %lu KB\n", results->kprobe_metrics.memory_usage_kb);
    printf("  CPU usage: %.2f%%\n", results->kprobe_metrics.cpu_usage_percent);
    printf("  Allocation failures: %lu\n", results->kprobe_metrics.allocation_failures);
    printf("  Processing errors: %lu\n", results->kprobe_metrics.processing_errors);
    printf("\n");
    
    printf("Tracepoint Implementation:\n");
    printf("  Average latency: %.2f ns\n", results->tracepoint_metrics.avg_latency_ns);
    printf("  Events per second: %lu\n", results->tracepoint_metrics.events_per_second);
    printf("  Memory usage: %lu KB\n", results->tracepoint_metrics.memory_usage_kb);
    printf("  CPU usage: %.2f%%\n", results->tracepoint_metrics.cpu_usage_percent);
    printf("  Allocation failures: %lu\n", results->tracepoint_metrics.allocation_failures);
    printf("  Processing errors: %lu\n", results->tracepoint_metrics.processing_errors);
    printf("\n");
    
    printf("Performance Analysis:\n");
    printf("  Performance improvement: %.2f%%\n", results->performance_improvement_percent);
    printf("  Stability score: %.2f\n", results->stability_score);
    printf("  Reliability rating: %d/10\n", results->reliability_rating);
    printf("\n");
    
    printf("Recommendations:\n");
    if (results->performance_improvement_percent > 15.0) {
        printf("  ✓ Tracepoint implementation shows significant performance improvement\n");
    } else if (results->performance_improvement_percent > 5.0) {
        printf("  ✓ Tracepoint implementation shows moderate performance improvement\n");
    } else {
        printf("  ⚠ Performance improvement is minimal\n");
    }
    
    if (results->stability_score > 10.0) {
        printf("  ✓ Tracepoint implementation is significantly more stable\n");
    } else if (results->stability_score > 0.0) {
        printf("  ✓ Tracepoint implementation is more stable\n");
    } else {
        printf("  ⚠ Stability improvement is minimal\n");
    }
    
    if (results->reliability_rating >= 8) {
        printf("  ✓ Strongly recommend tracepoint implementation\n");
    } else if (results->reliability_rating >= 6) {
        printf("  ✓ Recommend tracepoint implementation\n");
    } else {
        printf("  ⚠ Consider additional optimization\n");
    }
    printf("\n");
}
// Main test execution function
int main(int argc, char *argv[]) {
    printf("eBPF Process Monitor Performance Test Suite\n");
    printf("==========================================\n\n");
    
    // Initialize random seed for sampling tests
    srand(time(NULL));
    
    int test_passed = 0;
    int test_total = 0;
    
    printf("Starting comprehensive performance analysis...\n\n");
    
    // 1. Basic Performance Comparison
    printf("=== Phase 1: Basic Performance Comparison ===\n");
    struct comparison_results comparison = compare_performance();
    print_comparison_report(&comparison);
    test_total++;
    if (comparison.performance_improvement_percent > 0) {
        test_passed++;
        printf("✓ Performance comparison: PASSED\n");
    } else {
        printf("✗ Performance comparison: FAILED\n");
    }
    printf("\n");
    
    // 2. Stability Tests
    printf("=== Phase 2: High Load Stability Tests ===\n");
    
    // Reset stats for stability tests
    memset(&mock_kprobe_stats, 0, sizeof(mock_kprobe_stats));
    memset(&mock_tracepoint_stats, 0, sizeof(mock_tracepoint_stats));
    
    int kprobe_stability = run_stability_test("kprobe", simulate_kprobe_processing);
    int tracepoint_stability = run_stability_test("tracepoint", simulate_tracepoint_processing);
    
    test_total += 2;
    if (kprobe_stability) {
        test_passed++;
        printf("✓ Kprobe stability test: PASSED\n");
    } else {
        printf("✗ Kprobe stability test: FAILED\n");
    }
    
    if (tracepoint_stability) {
        test_passed++;
        printf("✓ Tracepoint stability test: PASSED\n");
    } else {
        printf("✗ Tracepoint stability test: FAILED\n");
    }
    printf("\n");
    
    // 3. Memory Usage Tests
    printf("=== Phase 3: Memory Usage Tests ===\n");
    
    // Reset stats for memory tests
    memset(&mock_kprobe_stats, 0, sizeof(mock_kprobe_stats));
    memset(&mock_tracepoint_stats, 0, sizeof(mock_tracepoint_stats));
    
    int kprobe_memory = run_memory_stress_test("kprobe", simulate_kprobe_processing);
    int tracepoint_memory = run_memory_stress_test("tracepoint", simulate_tracepoint_processing);
    
    test_total += 2;
    if (kprobe_memory) {
        test_passed++;
        printf("✓ Kprobe memory test: PASSED\n");
    } else {
        printf("✗ Kprobe memory test: FAILED\n");
    }
    
    if (tracepoint_memory) {
        test_passed++;
        printf("✓ Tracepoint memory test: PASSED\n");
    } else {
        printf("✗ Tracepoint memory test: FAILED\n");
    }
    printf("\n");
    
    // 4. CPU Usage Tests
    printf("=== Phase 4: CPU Usage Tests ===\n");
    
    // Reset stats for CPU tests
    memset(&mock_kprobe_stats, 0, sizeof(mock_kprobe_stats));
    memset(&mock_tracepoint_stats, 0, sizeof(mock_tracepoint_stats));
    
    int kprobe_cpu = run_cpu_stress_test("kprobe", simulate_kprobe_processing);
    int tracepoint_cpu = run_cpu_stress_test("tracepoint", simulate_tracepoint_processing);
    
    test_total += 2;
    if (kprobe_cpu) {
        test_passed++;
        printf("✓ Kprobe CPU test: PASSED\n");
    } else {
        printf("✗ Kprobe CPU test: FAILED\n");
    }
    
    if (tracepoint_cpu) {
        test_passed++;
        printf("✓ Tracepoint CPU test: PASSED\n");
    } else {
        printf("✗ Tracepoint CPU test: FAILED\n");
    }
    printf("\n");
    
    // 5. Final Summary and Recommendations
    printf("=== Final Test Summary ===\n");
    printf("Tests passed: %d/%d\n", test_passed, test_total);
    printf("Success rate: %.1f%%\n", (double)test_passed / test_total * 100.0);
    printf("\n");
    
    printf("=== Performance Optimization Recommendations ===\n");
    
    // Overall recommendation based on all tests
    int overall_tracepoint_better = 0;
    if (comparison.performance_improvement_percent > 5.0) overall_tracepoint_better++;
    if (tracepoint_stability > kprobe_stability) overall_tracepoint_better++;
    if (tracepoint_memory > kprobe_memory) overall_tracepoint_better++;
    if (tracepoint_cpu > kprobe_cpu) overall_tracepoint_better++;
    
    if (overall_tracepoint_better >= 3) {
        printf("🎯 STRONG RECOMMENDATION: Use tracepoint-based implementation\n");
        printf("   - Better performance in %d out of 4 categories\n", overall_tracepoint_better);
        printf("   - Performance improvement: %.1f%%\n", comparison.performance_improvement_percent);
        printf("   - Reliability rating: %d/10\n", comparison.reliability_rating);
    } else if (overall_tracepoint_better >= 2) {
        printf("✓ RECOMMENDATION: Consider tracepoint-based implementation\n");
        printf("   - Better performance in %d out of 4 categories\n", overall_tracepoint_better);
        printf("   - Performance improvement: %.1f%%\n", comparison.performance_improvement_percent);
    } else {
        printf("⚠ MIXED RESULTS: Both implementations have trade-offs\n");
        printf("   - Tracepoint better in %d out of 4 categories\n", overall_tracepoint_better);
        printf("   - Consider workload-specific testing\n");
    }
    
    printf("\n=== Detailed Metrics Summary ===\n");
    printf("Performance Improvement: %.2f%%\n", comparison.performance_improvement_percent);
    printf("Stability Score: %.2f\n", comparison.stability_score);
    printf("Memory Efficiency: %s vs %s\n", 
           kprobe_memory ? "GOOD" : "POOR",
           tracepoint_memory ? "GOOD" : "POOR");
    printf("CPU Efficiency: %s vs %s\n",
           kprobe_cpu ? "GOOD" : "POOR", 
           tracepoint_cpu ? "GOOD" : "POOR");
    
    printf("\n🎉 Performance test suite completed!\n");
    
    // Return success if most tests passed
    return (test_passed >= test_total * 0.7) ? 0 : 1;
}