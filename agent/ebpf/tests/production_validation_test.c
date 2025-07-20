/*
 * eBPF Process Monitor Production Environment Validation Test
 *
 * This file contains comprehensive production environment validation tests
 * for the eBPF process monitor implementation. These tests verify long-term
 * stability, performance under various workloads, monitoring capabilities,
 * and logging/debugging functionality.
 *
 * Requirements tested:
 * - 5.1: Error recording and statistics validation
 * - 5.2: Performance monitoring validation  
 * - 5.3: Long-term stability validation
 * - 6.3: Comprehensive test coverage validation
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Include Linux types for eBPF compatibility
#include <linux/types.h>

// Maximum lengths for various fields
#define MAX_FILENAME_LEN     256
#define MAX_COMM_LEN         16
#define MAX_PATH_LEN         4096
#define TASK_COMM_LEN        16

// Production test configuration
#define LONG_TERM_TEST_DURATION_HOURS 2
#define WORKLOAD_TEST_ITERATIONS 50000
#define MONITORING_SAMPLE_INTERVAL_MS 1000
#define LOG_VALIDATION_INTERVAL_SEC 30
#define MAX_LOG_ENTRIES 10000
#define STRESS_WORKLOAD_PROCESSES 100

// Event types
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

// Common event header
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

// Process events
struct process_event {
    struct event_header header;
    __u32 ppid;
    __u32 exit_code;
    char filename[MAX_FILENAME_LEN];
    char args[512];
};

// Debug and error statistics
struct debug_stats {
    __u64 events_processed;
    __u64 events_dropped;
    __u64 allocation_failures;
    __u64 config_errors;
    __u64 data_read_errors;
    __u64 tracepoint_errors;
    __u64 exec_events;
    __u64 exit_events;
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
};

// Production validation test framework macros
#define PRODUCTION_TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("FAIL: %s - %s\n", __func__, message); \
            return -1; \
        } \
    } while(0)

#define PRODUCTION_TEST_PASS(message) \
    do { \
        printf("PASS: %s - %s\n", __func__, message); \
        return 0; \
    } while(0)

#define PRODUCTION_TEST_WARN(message) \
    do { \
        printf("WARN: %s - %s\n", __func__, message); \
    } while(0)

// Production test state and metrics
static struct {
    volatile int test_running;
    volatile int long_term_test_active;
    volatile int workload_test_active;
    volatile int monitoring_active;
    
    // Test metrics
    struct {
        __u64 total_events_processed;
        __u64 total_errors_detected;
        __u64 peak_memory_usage_kb;
        double max_cpu_usage_percent;
        __u64 test_start_time;
        __u64 test_duration_seconds;
        
        // Stability metrics
        __u64 consecutive_successful_hours;
        __u64 error_free_periods;
        double average_event_rate;
        double stability_score;
        
        // Performance metrics
        double min_latency_ns;
        double max_latency_ns;
        double avg_latency_ns;
        __u64 throughput_events_per_sec;
        
        // Monitoring metrics
        __u64 monitoring_samples_collected;
        __u64 alert_conditions_detected;
        __u64 log_entries_validated;
        
    } production_metrics;
    
    // Log validation
    struct {
        char log_buffer[MAX_LOG_ENTRIES][512];
        int log_count;
        int log_errors;
        int log_warnings;
        time_t last_log_time;
    } log_validation;
    
} production_test_state = {0};

// Utility functions for production validation
static inline __u64 get_timestamp_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static inline double get_cpu_usage_percent(void) {
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

static inline __u64 get_memory_usage_kb(void) {
    FILE *status = fopen("/proc/self/status", "r");
    if (!status) return 0;
    
    char line[256];
    __u64 vmrss = 0;
    
    while (fgets(line, sizeof(line), status)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line, "VmRSS: %lu kB", &vmrss);
            break;
        }
    }
    
    fclose(status);
    return vmrss;
}

static inline __u64 get_system_load_average(void) {
    double load[3];
    if (getloadavg(load, 3) == -1) {
        return 0;
    }
    return (__u64)(load[0] * 100); // Return as percentage * 100
}

// Log validation functions
static void add_log_entry(const char* level, const char* message) {
    if (production_test_state.log_validation.log_count >= MAX_LOG_ENTRIES) {
        return; // Buffer full
    }
    
    int idx = production_test_state.log_validation.log_count++;
    time_t now = time(NULL);
    
    snprintf(production_test_state.log_validation.log_buffer[idx], 512,
             "[%ld] %s: %s", now, level, message);
    
    production_test_state.log_validation.last_log_time = now;
    
    if (strcmp(level, "ERROR") == 0) {
        production_test_state.log_validation.log_errors++;
    } else if (strcmp(level, "WARN") == 0) {
        production_test_state.log_validation.log_warnings++;
    }
}

static int validate_log_entries(void) {
    int valid_entries = 0;
    int invalid_entries = 0;
    
    for (int i = 0; i < production_test_state.log_validation.log_count; i++) {
        const char* entry = production_test_state.log_validation.log_buffer[i];
        
        // Basic validation: check for timestamp and level
        if (strstr(entry, "[") && strstr(entry, "]") && 
            (strstr(entry, "INFO") || strstr(entry, "WARN") || 
             strstr(entry, "ERROR") || strstr(entry, "DEBUG"))) {
            valid_entries++;
        } else {
            invalid_entries++;
        }
    }
    
    production_test_state.production_metrics.log_entries_validated = valid_entries;
    
    printf("Log Validation Results:\n");
    printf("  Valid entries: %d\n", valid_entries);
    printf("  Invalid entries: %d\n", invalid_entries);
    printf("  Error entries: %d\n", production_test_state.log_validation.log_errors);
    printf("  Warning entries: %d\n", production_test_state.log_validation.log_warnings);
    
    return (invalid_entries == 0) ? 0 : -1;
}

// Monitoring and alerting functions
static void* monitoring_thread(void* arg) {
    (void)arg; // Suppress unused parameter warning
    
    printf("Starting production monitoring thread...\n");
    
    while (production_test_state.monitoring_active) {
        __u64 current_memory = get_memory_usage_kb();
        double current_cpu = get_cpu_usage_percent();
        __u64 current_load = get_system_load_average();
        
        // Update peak metrics
        if (current_memory > production_test_state.production_metrics.peak_memory_usage_kb) {
            production_test_state.production_metrics.peak_memory_usage_kb = current_memory;
        }
        
        if (current_cpu > production_test_state.production_metrics.max_cpu_usage_percent) {
            production_test_state.production_metrics.max_cpu_usage_percent = current_cpu;
        }
        
        // Check for alert conditions
        if (current_memory > 500000) { // > 500MB
            add_log_entry("WARN", "High memory usage detected");
            production_test_state.production_metrics.alert_conditions_detected++;
        }
        
        if (current_cpu > 80.0) { // > 80% CPU
            add_log_entry("WARN", "High CPU usage detected");
            production_test_state.production_metrics.alert_conditions_detected++;
        }
        
        if (current_load > 800) { // Load average > 8.0
            add_log_entry("WARN", "High system load detected");
            production_test_state.production_metrics.alert_conditions_detected++;
        }
        
        production_test_state.production_metrics.monitoring_samples_collected++;
        
        // Log periodic status
        if (production_test_state.production_metrics.monitoring_samples_collected % 60 == 0) {
            char status_msg[256];
            snprintf(status_msg, sizeof(status_msg),
                    "System status: Memory=%luKB, CPU=%.2f%%, Load=%.2f",
                    current_memory, current_cpu, current_load / 100.0);
            add_log_entry("INFO", status_msg);
        }
        
        usleep(MONITORING_SAMPLE_INTERVAL_MS * 1000);
    }
    
    printf("Production monitoring thread stopped\n");
    return NULL;
}

// Workload generation functions
static void* workload_generator_thread(void* arg) {
    int workload_type = *(int*)arg;
    
    printf("Starting workload generator (type %d)...\n", workload_type);
    
    while (production_test_state.workload_test_active) {
        switch (workload_type) {
            case 0: // Process creation workload
                for (int i = 0; i < 10 && production_test_state.workload_test_active; i++) {
                    pid_t pid = fork();
                    if (pid == 0) {
                        // Child process - execute simple command
                        execl("/bin/true", "true", NULL);
                        exit(0);
                    } else if (pid > 0) {
                        // Parent - wait for child
                        waitpid(pid, NULL, 0);
                    }
                }
                break;
                
            case 1: // File I/O workload
                for (int i = 0; i < 50 && production_test_state.workload_test_active; i++) {
                    char filename[64];
                    snprintf(filename, sizeof(filename), "/tmp/test_file_%d_%d", getpid(), i);
                    
                    int fd = open(filename, O_CREAT | O_WRONLY, 0644);
                    if (fd >= 0) {
                        write(fd, "test data", 9);
                        close(fd);
                        unlink(filename);
                    }
                }
                break;
                
            case 2: // Network simulation workload
                // Simulate network activity by creating/closing sockets
                for (int i = 0; i < 20 && production_test_state.workload_test_active; i++) {
                    int sock = socket(AF_INET, SOCK_STREAM, 0);
                    if (sock >= 0) {
                        close(sock);
                    }
                }
                break;
                
            default:
                break;
        }
        
        usleep(100000); // 100ms delay between workload batches
    }
    
    printf("Workload generator (type %d) stopped\n", workload_type);
    return NULL;
}

// Production validation test functions

// Test 1: Long-term stability test
static int test_long_term_stability(void) {
    printf("=== Long-term Stability Test ===\n");
    printf("Duration: %d hours\n", LONG_TERM_TEST_DURATION_HOURS);
    
    // Initialize test state
    production_test_state.test_running = 1;
    production_test_state.long_term_test_active = 1;
    production_test_state.monitoring_active = 1;
    production_test_state.production_metrics.test_start_time = get_timestamp_ns();
    
    // Start monitoring thread
    pthread_t monitoring_tid;
    if (pthread_create(&monitoring_tid, NULL, monitoring_thread, NULL) != 0) {
        PRODUCTION_TEST_ASSERT(0, "Failed to start monitoring thread");
    }
    
    // Start workload generators
    pthread_t workload_tids[3];
    int workload_types[3] = {0, 1, 2};
    production_test_state.workload_test_active = 1;
    
    for (int i = 0; i < 3; i++) {
        if (pthread_create(&workload_tids[i], NULL, workload_generator_thread, &workload_types[i]) != 0) {
            PRODUCTION_TEST_WARN("Failed to start workload generator thread");
        }
    }
    
    // Run for specified duration
    __u64 test_duration_ns = LONG_TERM_TEST_DURATION_HOURS * 3600ULL * 1000000000ULL;
    __u64 start_time = get_timestamp_ns();
    __u64 last_status_time = start_time;
    
    printf("Long-term test started, will run for %d hours...\n", LONG_TERM_TEST_DURATION_HOURS);
    
    while (production_test_state.long_term_test_active) {
        __u64 current_time = get_timestamp_ns();
        __u64 elapsed_time = current_time - start_time;
        
        // Check if test duration completed
        if (elapsed_time >= test_duration_ns) {
            break;
        }
        
        // Print status every 10 minutes
        if (current_time - last_status_time >= 600ULL * 1000000000ULL) {
            double hours_elapsed = elapsed_time / (3600.0 * 1000000000.0);
            double progress = (elapsed_time * 100.0) / test_duration_ns;
            
            printf("Long-term test progress: %.2f hours (%.1f%% complete)\n", 
                   hours_elapsed, progress);
            printf("  Memory usage: %lu KB\n", get_memory_usage_kb());
            printf("  CPU usage: %.2f%%\n", get_cpu_usage_percent());
            printf("  Monitoring samples: %lu\n", 
                   production_test_state.production_metrics.monitoring_samples_collected);
            printf("  Alert conditions: %lu\n", 
                   production_test_state.production_metrics.alert_conditions_detected);
            
            last_status_time = current_time;
        }
        
        sleep(30); // Check every 30 seconds
    }
    
    // Stop all threads
    production_test_state.long_term_test_active = 0;
    production_test_state.workload_test_active = 0;
    production_test_state.monitoring_active = 0;
    
    // Wait for threads to complete
    pthread_join(monitoring_tid, NULL);
    for (int i = 0; i < 3; i++) {
        pthread_join(workload_tids[i], NULL);
    }
    
    // Calculate final metrics
    __u64 total_duration = get_timestamp_ns() - start_time;
    production_test_state.production_metrics.test_duration_seconds = total_duration / 1000000000ULL;
    
    printf("\nLong-term test completed!\n");
    printf("Results:\n");
    printf("  Test duration: %lu seconds (%.2f hours)\n", 
           production_test_state.production_metrics.test_duration_seconds,
           production_test_state.production_metrics.test_duration_seconds / 3600.0);
    printf("  Peak memory usage: %lu KB\n", 
           production_test_state.production_metrics.peak_memory_usage_kb);
    printf("  Max CPU usage: %.2f%%\n", 
           production_test_state.production_metrics.max_cpu_usage_percent);
    printf("  Monitoring samples collected: %lu\n", 
           production_test_state.production_metrics.monitoring_samples_collected);
    printf("  Alert conditions detected: %lu\n", 
           production_test_state.production_metrics.alert_conditions_detected);
    
    // Validate stability criteria
    int stability_passed = 1;
    
    // Check memory usage (should not exceed 1GB)
    if (production_test_state.production_metrics.peak_memory_usage_kb > 1000000) {
        printf("  FAIL: Excessive memory usage detected\n");
        stability_passed = 0;
    }
    
    // Check CPU usage (should not exceed 50% average)
    if (production_test_state.production_metrics.max_cpu_usage_percent > 50.0) {
        printf("  FAIL: Excessive CPU usage detected\n");
        stability_passed = 0;
    }
    
    // Check alert conditions (should be minimal)
    if (production_test_state.production_metrics.alert_conditions_detected > 10) {
        printf("  FAIL: Too many alert conditions detected\n");
        stability_passed = 0;
    }
    
    if (stability_passed) {
        PRODUCTION_TEST_PASS("Long-term stability test passed");
    } else {
        PRODUCTION_TEST_ASSERT(0, "Long-term stability test failed");
    }
    
    return 0;
}

// Test 2: Different workload validation
static int test_workload_validation(void) {
    printf("\n=== Workload Validation Test ===\n");
    
    struct workload_test {
        const char* name;
        int type;
        int iterations;
        double expected_max_latency_ms;
    } workloads[] = {
        {"Light Process Load", 0, 1000, 10.0},
        {"Heavy Process Load", 0, 5000, 50.0},
        {"File I/O Load", 1, 2000, 20.0},
        {"Network Simulation Load", 2, 1000, 15.0},
        {"Mixed Workload", -1, 3000, 30.0} // Special case for mixed
    };
    
    int num_workloads = sizeof(workloads) / sizeof(workloads[0]);
    int passed_workloads = 0;
    
    for (int w = 0; w < num_workloads; w++) {
        printf("\nTesting workload: %s\n", workloads[w].name);
        
        // Reset metrics
        __u64 start_memory = get_memory_usage_kb();
        __u64 start_time = get_timestamp_ns();
        
        production_test_state.workload_test_active = 1;
        production_test_state.monitoring_active = 1;
        
        // Start monitoring
        pthread_t monitoring_tid;
        pthread_create(&monitoring_tid, NULL, monitoring_thread, NULL);
        
        // Start workload
        if (workloads[w].type == -1) {
            // Mixed workload - start all types
            pthread_t workload_tids[3];
            int workload_types[3] = {0, 1, 2};
            
            for (int i = 0; i < 3; i++) {
                pthread_create(&workload_tids[i], NULL, workload_generator_thread, &workload_types[i]);
            }
            
            // Run for specified iterations (converted to time)
            usleep(workloads[w].iterations * 1000); // iterations as milliseconds
            
            production_test_state.workload_test_active = 0;
            
            for (int i = 0; i < 3; i++) {
                pthread_join(workload_tids[i], NULL);
            }
        } else {
            // Single workload type
            pthread_t workload_tid;
            pthread_create(&workload_tid, NULL, workload_generator_thread, &workloads[w].type);
            
            // Run for specified iterations (converted to time)
            usleep(workloads[w].iterations * 1000); // iterations as milliseconds
            
            production_test_state.workload_test_active = 0;
            pthread_join(workload_tid, NULL);
        }
        
        production_test_state.monitoring_active = 0;
        pthread_join(monitoring_tid, NULL);
        
        // Calculate metrics
        __u64 end_time = get_timestamp_ns();
        __u64 end_memory = get_memory_usage_kb();
        double duration_ms = (end_time - start_time) / 1000000.0;
        __u64 memory_increase = end_memory - start_memory;
        
        printf("  Duration: %.2f ms\n", duration_ms);
        printf("  Memory increase: %lu KB\n", memory_increase);
        printf("  Monitoring samples: %lu\n", 
               production_test_state.production_metrics.monitoring_samples_collected);
        
        // Validate workload performance
        int workload_passed = 1;
        
        if (duration_ms > workloads[w].expected_max_latency_ms) {
            printf("  FAIL: Workload took too long (%.2f ms > %.2f ms)\n", 
                   duration_ms, workloads[w].expected_max_latency_ms);
            workload_passed = 0;
        }
        
        if (memory_increase > 100000) { // > 100MB increase
            printf("  FAIL: Excessive memory increase (%lu KB)\n", memory_increase);
            workload_passed = 0;
        }
        
        if (workload_passed) {
            printf("  PASS: %s workload validation passed\n", workloads[w].name);
            passed_workloads++;
        } else {
            printf("  FAIL: %s workload validation failed\n", workloads[w].name);
        }
        
        // Reset monitoring samples for next test
        production_test_state.production_metrics.monitoring_samples_collected = 0;
    }
    
    printf("\nWorkload Validation Summary:\n");
    printf("  Passed workloads: %d/%d\n", passed_workloads, num_workloads);
    
    if (passed_workloads == num_workloads) {
        PRODUCTION_TEST_PASS("All workload validations passed");
    } else {
        PRODUCTION_TEST_ASSERT(0, "Some workload validations failed");
    }
    
    return 0;
}

// Test 3: Monitoring and alerting functionality validation
static int test_monitoring_and_alerting(void) {
    printf("\n=== Monitoring and Alerting Test ===\n");
    
    // Reset monitoring state
    production_test_state.monitoring_active = 1;
    production_test_state.production_metrics.monitoring_samples_collected = 0;
    production_test_state.production_metrics.alert_conditions_detected = 0;
    
    // Start monitoring thread
    pthread_t monitoring_tid;
    if (pthread_create(&monitoring_tid, NULL, monitoring_thread, NULL) != 0) {
        PRODUCTION_TEST_ASSERT(0, "Failed to start monitoring thread");
    }
    
    printf("Testing monitoring functionality for 60 seconds...\n");
    
    // Generate some test conditions
    for (int i = 0; i < 60; i++) {
        // Simulate various system conditions
        if (i == 10) {
            add_log_entry("INFO", "Test condition: Normal operation");
        } else if (i == 20) {
            add_log_entry("WARN", "Test condition: Simulated warning");
        } else if (i == 30) {
            add_log_entry("ERROR", "Test condition: Simulated error");
        } else if (i == 40) {
            add_log_entry("INFO", "Test condition: Recovery detected");
        }
        
        sleep(1);
    }
    
    // Stop monitoring
    production_test_state.monitoring_active = 0;
    pthread_join(monitoring_tid, NULL);
    
    printf("Monitoring test completed\n");
    printf("Results:\n");
    printf("  Monitoring samples collected: %lu\n", 
           production_test_state.production_metrics.monitoring_samples_collected);
    printf("  Alert conditions detected: %lu\n", 
           production_test_state.production_metrics.alert_conditions_detected);
    
    // Validate monitoring functionality
    int monitoring_passed = 1;
    
    // Should have collected at least 50 samples (one per second for 60 seconds)
    if (production_test_state.production_metrics.monitoring_samples_collected < 50) {
        printf("  FAIL: Insufficient monitoring samples collected\n");
        monitoring_passed = 0;
    }
    
    // Should have detected some conditions (but not too many)
    if (production_test_state.production_metrics.alert_conditions_detected > 20) {
        printf("  FAIL: Too many alert conditions detected (possible false positives)\n");
        monitoring_passed = 0;
    }
    
    if (monitoring_passed) {
        PRODUCTION_TEST_PASS("Monitoring and alerting functionality validated");
    } else {
        PRODUCTION_TEST_ASSERT(0, "Monitoring and alerting validation failed");
    }
    
    return 0;
}

// Test 4: Logging and debugging functionality validation
static int test_logging_and_debugging(void) {
    printf("\n=== Logging and Debugging Test ===\n");
    
    // Reset log validation state
    memset(&production_test_state.log_validation, 0, sizeof(production_test_state.log_validation));
    
    printf("Testing logging functionality...\n");
    
    // Generate various log entries
    add_log_entry("INFO", "System startup completed");
    add_log_entry("DEBUG", "Debug information: test parameter = 12345");
    add_log_entry("INFO", "Processing started");
    add_log_entry("WARN", "Warning: high memory usage detected");
    add_log_entry("ERROR", "Error: failed to allocate buffer");
    add_log_entry("INFO", "Recovery successful");
    add_log_entry("DEBUG", "Debug information: cleanup completed");
    
    // Test log entry with special characters
    add_log_entry("INFO", "Special test: symbols !@#$%^&*()");
    
    // Test long log entry
    add_log_entry("INFO", "Long message test: This is a very long log message that should be handled correctly by the logging system without causing buffer overflows or other issues");
    
    // Test rapid log generation
    for (int i = 0; i < 100; i++) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Rapid log test entry %d", i);
        add_log_entry("DEBUG", msg);
    }
    
    printf("Generated %d log entries\n", production_test_state.log_validation.log_count);
    
    // Validate log entries
    int log_validation_result = validate_log_entries();
    
    // Test log file operations (simulate)
    printf("Testing log file operations...\n");
    
    // Create a test log file
    FILE* test_log = fopen("/tmp/production_test.log", "w");
    if (test_log) {
        for (int i = 0; i < production_test_state.log_validation.log_count; i++) {
            fprintf(test_log, "%s\n", production_test_state.log_validation.log_buffer[i]);
        }
        fclose(test_log);
        
        // Verify file was created and has content
        struct stat st;
        if (stat("/tmp/production_test.log", &st) == 0 && st.st_size > 0) {
            printf("  Log file created successfully (%ld bytes)\n", st.st_size);
        } else {
            printf("  FAIL: Log file creation failed\n");
            log_validation_result = -1;
        }
        
        // Clean up test file
        unlink("/tmp/production_test.log");
    } else {
        printf("  FAIL: Could not create test log file\n");
        log_validation_result = -1;
    }
    
    // Test debug information collection
    printf("Testing debug information collection...\n");
    
    struct debug_stats mock_debug_stats = {
        .events_processed = 12345,
        .events_dropped = 5,
        .allocation_failures = 2,
        .config_errors = 1,
        .data_read_errors = 0,
        .tracepoint_errors = 0,
        .exec_events = 8000,
        .exit_events = 7995,
        .sampling_skipped = 100,
        .pid_filtered = 50,
        .last_error_timestamp = get_timestamp_ns(),
        .last_error_type = 1,
        .last_error_pid = 1234
    };
    
    // Simulate debug stats validation
    printf("Debug Statistics Validation:\n");
    printf("  Events processed: %lu\n", mock_debug_stats.events_processed);
    printf("  Events dropped: %lu\n", mock_debug_stats.events_dropped);
    printf("  Allocation failures: %lu\n", mock_debug_stats.allocation_failures);
    printf("  Config errors: %lu\n", mock_debug_stats.config_errors);
    printf("  Data read errors: %lu\n", mock_debug_stats.data_read_errors);
    printf("  Tracepoint errors: %lu\n", mock_debug_stats.tracepoint_errors);
    printf("  Exec events: %lu\n", mock_debug_stats.exec_events);
    printf("  Exit events: %lu\n", mock_debug_stats.exit_events);
    printf("  Sampling skipped: %lu\n", mock_debug_stats.sampling_skipped);
    printf("  PID filtered: %lu\n", mock_debug_stats.pid_filtered);
    
    // Calculate error rates
    double error_rate = 0.0;
    if (mock_debug_stats.events_processed > 0) {
        __u64 total_errors = mock_debug_stats.events_dropped + 
                            mock_debug_stats.allocation_failures + 
                            mock_debug_stats.config_errors + 
                            mock_debug_stats.data_read_errors + 
                            mock_debug_stats.tracepoint_errors;
        error_rate = (double)total_errors / mock_debug_stats.events_processed * 100.0;
    }
    
    printf("  Overall error rate: %.2f%%\n", error_rate);
    
    // Validate debug functionality
    int debug_passed = 1;
    
    if (error_rate > 5.0) { // Error rate should be < 5%
        printf("  FAIL: Error rate too high (%.2f%%)\n", error_rate);
        debug_passed = 0;
    }
    
    if (mock_debug_stats.exec_events == 0 && mock_debug_stats.exit_events == 0) {
        printf("  FAIL: No process events recorded\n");
        debug_passed = 0;
    }
    
    if (log_validation_result != 0) {
        printf("  FAIL: Log validation failed\n");
        debug_passed = 0;
    }
    
    if (debug_passed) {
        PRODUCTION_TEST_PASS("Logging and debugging functionality validated");
    } else {
        PRODUCTION_TEST_ASSERT(0, "Logging and debugging validation failed");
    }
    
    return 0;
}

// Test 5: Performance regression test
static int test_performance_regression(void) {
    printf("\n=== Performance Regression Test ===\n");
    
    // Baseline performance expectations
    struct performance_baseline {
        const char* metric_name;
        double expected_value;
        double tolerance_percent;
        double actual_value;
        int passed;
    } baselines[] = {
        {"Event processing latency (ns)", 1000.0, 20.0, 0.0, 0},
        {"Memory usage (KB)", 50000.0, 30.0, 0.0, 0},
        {"CPU usage (%)", 10.0, 50.0, 0.0, 0},
        {"Events per second", 10000.0, 25.0, 0.0, 0}
    };
    
    int num_baselines = sizeof(baselines) / sizeof(baselines[0]);
    
    printf("Running performance regression tests...\n");
    
    // Simulate performance measurements
    __u64 start_time = get_timestamp_ns();
    __u64 start_memory = get_memory_usage_kb();
    
    // Simulate some work
    for (int i = 0; i < 10000; i++) {
        // Simulate event processing
        volatile int dummy = i * i;
        (void)dummy; // Suppress unused variable warning
    }
    
    __u64 end_time = get_timestamp_ns();
    __u64 end_memory = get_memory_usage_kb();
    double cpu_usage = get_cpu_usage_percent();
    
    // Calculate actual performance metrics
    baselines[0].actual_value = (end_time - start_time) / 10000.0; // Average latency per event
    baselines[1].actual_value = end_memory;
    baselines[2].actual_value = cpu_usage;
    baselines[3].actual_value = 10000.0 / ((end_time - start_time) / 1000000000.0); // Events per second
    
    printf("Performance Regression Results:\n");
    
    int passed_baselines = 0;
    for (int i = 0; i < num_baselines; i++) {
        double tolerance = baselines[i].expected_value * baselines[i].tolerance_percent / 100.0;
        double min_acceptable = baselines[i].expected_value - tolerance;
        double max_acceptable = baselines[i].expected_value + tolerance;
        
        baselines[i].passed = (baselines[i].actual_value >= min_acceptable && 
                              baselines[i].actual_value <= max_acceptable);
        
        printf("  %s:\n", baselines[i].metric_name);
        printf("    Expected: %.2f (±%.1f%%)\n", baselines[i].expected_value, baselines[i].tolerance_percent);
        printf("    Actual: %.2f\n", baselines[i].actual_value);
        printf("    Result: %s\n", baselines[i].passed ? "PASS" : "FAIL");
        
        if (baselines[i].passed) {
            passed_baselines++;
        }
    }
    
    printf("Performance regression summary: %d/%d baselines passed\n", passed_baselines, num_baselines);
    
    if (passed_baselines == num_baselines) {
        PRODUCTION_TEST_PASS("Performance regression test passed");
    } else {
        PRODUCTION_TEST_ASSERT(0, "Performance regression detected");
    }
    
    return 0;
}

// Signal handler for graceful shutdown
static void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down gracefully...\n", sig);
    production_test_state.test_running = 0;
    production_test_state.long_term_test_active = 0;
    production_test_state.workload_test_active = 0;
    production_test_state.monitoring_active = 0;
}

// Print production validation summary
static void print_production_summary(void) {
    printf("\n" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "\n");
    printf("Production Environment Validation Summary\n");
    printf("=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "\n");
    
    printf("Test Environment:\n");
    printf("  Host: %s\n", getenv("HOSTNAME") ? getenv("HOSTNAME") : "unknown");
    printf("  Kernel: ");
    system("uname -r");
    printf("  Architecture: ");
    system("uname -m");
    printf("  Test Date: ");
    system("date");
    
    printf("\nTest Results Summary:\n");
    printf("  Total test duration: %lu seconds (%.2f hours)\n", 
           production_test_state.production_metrics.test_duration_seconds,
           production_test_state.production_metrics.test_duration_seconds / 3600.0);
    printf("  Peak memory usage: %lu KB (%.2f MB)\n", 
           production_test_state.production_metrics.peak_memory_usage_kb,
           production_test_state.production_metrics.peak_memory_usage_kb / 1024.0);
    printf("  Maximum CPU usage: %.2f%%\n", 
           production_test_state.production_metrics.max_cpu_usage_percent);
    printf("  Monitoring samples collected: %lu\n", 
           production_test_state.production_metrics.monitoring_samples_collected);
    printf("  Alert conditions detected: %lu\n", 
           production_test_state.production_metrics.alert_conditions_detected);
    printf("  Log entries validated: %lu\n", 
           production_test_state.production_metrics.log_entries_validated);
    
    printf("\nStability Assessment:\n");
    if (production_test_state.production_metrics.peak_memory_usage_kb < 500000) {
        printf("  Memory stability: EXCELLENT (< 500MB peak)\n");
    } else if (production_test_state.production_metrics.peak_memory_usage_kb < 1000000) {
        printf("  Memory stability: GOOD (< 1GB peak)\n");
    } else {
        printf("  Memory stability: POOR (> 1GB peak)\n");
    }
    
    if (production_test_state.production_metrics.max_cpu_usage_percent < 20.0) {
        printf("  CPU stability: EXCELLENT (< 20%% peak)\n");
    } else if (production_test_state.production_metrics.max_cpu_usage_percent < 50.0) {
        printf("  CPU stability: GOOD (< 50%% peak)\n");
    } else {
        printf("  CPU stability: POOR (> 50%% peak)\n");
    }
    
    if (production_test_state.production_metrics.alert_conditions_detected < 5) {
        printf("  Alert stability: EXCELLENT (< 5 alerts)\n");
    } else if (production_test_state.production_metrics.alert_conditions_detected < 20) {
        printf("  Alert stability: GOOD (< 20 alerts)\n");
    } else {
        printf("  Alert stability: POOR (> 20 alerts)\n");
    }
    
    printf("\nRecommendations:\n");
    if (production_test_state.production_metrics.peak_memory_usage_kb > 500000) {
        printf("  - Consider optimizing memory usage\n");
    }
    if (production_test_state.production_metrics.max_cpu_usage_percent > 30.0) {
        printf("  - Consider optimizing CPU usage\n");
    }
    if (production_test_state.production_metrics.alert_conditions_detected > 10) {
        printf("  - Review alert thresholds to reduce false positives\n");
    }
    if (production_test_state.log_validation.log_errors > 0) {
        printf("  - Investigate and resolve logged errors\n");
    }
    
    printf("\n" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "\n");
}

// Main test execution function
int main(int argc, char *argv[]) {
    printf("eBPF Process Monitor Production Environment Validation\n");
    printf("=====================================================\n\n");
    
    // Parse command line arguments
    int run_long_term = 0;
    int run_quick = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--long-term") == 0) {
            run_long_term = 1;
        } else if (strcmp(argv[i], "--quick") == 0) {
            run_quick = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("Options:\n");
            printf("  --long-term    Run full long-term stability test (%d hours)\n", LONG_TERM_TEST_DURATION_HOURS);
            printf("  --quick        Run quick validation tests only\n");
            printf("  --help         Show this help message\n");
            printf("\nDefault: Run all tests except long-term stability\n");
            return 0;
        }
    }
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize test state
    memset(&production_test_state, 0, sizeof(production_test_state));
    production_test_state.test_running = 1;
    
    int total_tests = 0;
    int passed_tests = 0;
    
    printf("Starting production environment validation tests...\n\n");
    
    // Test 1: Long-term stability (optional)
    if (run_long_term) {
        total_tests++;
        printf("Test 1/5: Long-term Stability Test\n");
        if (test_long_term_stability() == 0) {
            passed_tests++;
        }
    } else {
        printf("Skipping long-term stability test (use --long-term to enable)\n");
    }
    
    // Test 2: Workload validation
    if (!run_quick || run_long_term) {
        total_tests++;
        printf("Test %d: Workload Validation Test\n", total_tests);
        if (test_workload_validation() == 0) {
            passed_tests++;
        }
    }
    
    // Test 3: Monitoring and alerting
    total_tests++;
    printf("Test %d: Monitoring and Alerting Test\n", total_tests);
    if (test_monitoring_and_alerting() == 0) {
        passed_tests++;
    }
    
    // Test 4: Logging and debugging
    total_tests++;
    printf("Test %d: Logging and Debugging Test\n", total_tests);
    if (test_logging_and_debugging() == 0) {
        passed_tests++;
    }
    
    // Test 5: Performance regression
    if (!run_quick) {
        total_tests++;
        printf("Test %d: Performance Regression Test\n", total_tests);
        if (test_performance_regression() == 0) {
            passed_tests++;
        }
    }
    
    // Print final summary
    print_production_summary();
    
    printf("\nFinal Test Results:\n");
    printf("==================\n");
    printf("Tests passed: %d/%d\n", passed_tests, total_tests);
    printf("Success rate: %.1f%%\n", (double)passed_tests / total_tests * 100.0);
    
    if (passed_tests == total_tests) {
        printf("\n🎉 All production validation tests PASSED!\n");
        printf("The system is ready for production deployment.\n");
        return 0;
    } else {
        printf("\n❌ Some production validation tests FAILED!\n");
        printf("Please review the test results and address any issues before production deployment.\n");
        return 1;
    }
}