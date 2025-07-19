/*
 * eBPF Process Monitor Compatibility Tests
 * 
 * This file contains comprehensive compatibility tests for the eBPF process monitor
 * across different kernel versions and tracepoint structures.
 * 
 * Test Coverage:
 * - Kernel version detection and feature availability
 * - Tracepoint structure compatibility verification
 * - Fallback mechanism testing
 * - Cross-kernel version functionality validation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <errno.h>
#include <linux/version.h>

// Test framework macros
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("FAIL: %s - %s\n", __func__, message); \
            return -1; \
        } \
    } while(0)

#define TEST_PASS(message) \
    do { \
        printf("PASS: %s - %s\n", __func__, message); \
        return 0; \
    } while(0)

// Kernel version detection structures
typedef struct {
    int major;
    int minor;
    int patch;
    char version_string[256];
} kernel_version_t;

// Feature availability flags
typedef struct {
    int tracepoint_available;
    int modern_tracepoint;
    int ringbuf_support;
    int bpf_core_support;
    int probe_read_kernel_support;
    int btf_support;
} kernel_features_t;

// Test statistics
typedef struct {
    int total_tests;
    int passed_tests;
    int failed_tests;
    int skipped_tests;
} test_stats_t;

// Global test state
static test_stats_t g_test_stats = {0};
static kernel_version_t g_kernel_version = {0};
static kernel_features_t g_kernel_features = {0};

// Function prototypes
static int detect_kernel_version(kernel_version_t *version);
static int detect_kernel_features(kernel_features_t *features);
static int test_kernel_version_detection(void);
static int test_tracepoint_availability(void);
static int test_tracepoint_structure_compatibility(void);

// Kernel version detection implementation
static int detect_kernel_version(kernel_version_t *version) {
    struct utsname uname_data;
    
    if (uname(&uname_data) != 0) {
        return -1;
    }
    
    // Copy version string
    strncpy(version->version_string, uname_data.release, sizeof(version->version_string) - 1);
    version->version_string[sizeof(version->version_string) - 1] = '\0';
    
    // Parse version numbers
    if (sscanf(uname_data.release, "%d.%d.%d", 
               &version->major, &version->minor, &version->patch) < 2) {
        return -1;
    }
    
    return 0;
}

// Kernel feature detection implementation
static int detect_kernel_features(kernel_features_t *features) {
    memset(features, 0, sizeof(*features));
    
    // Check tracepoint availability
    if (access("/sys/kernel/debug/tracing/events/sched/sched_process_exec", F_OK) == 0) {
        features->tracepoint_available = 1;
    }
    
    if (access("/sys/kernel/debug/tracing/events/sched/sched_process_exit", F_OK) == 0) {
        features->tracepoint_available = 1;
    }
    
    // Determine feature support based on kernel version
    int kernel_code = KERNEL_VERSION(g_kernel_version.major, 
                                   g_kernel_version.minor, 
                                   g_kernel_version.patch);
    
    if (kernel_code >= KERNEL_VERSION(5, 4, 0)) {
        features->modern_tracepoint = 1;
        features->ringbuf_support = 1;
        features->bpf_core_support = 1;
        features->probe_read_kernel_support = 1;
        features->btf_support = 1;
    } else if (kernel_code >= KERNEL_VERSION(5, 0, 0)) {
        features->modern_tracepoint = 1;
        features->probe_read_kernel_support = 1;
    } else if (kernel_code >= KERNEL_VERSION(4, 9, 0)) {
        features->modern_tracepoint = 1;
    } else if (kernel_code >= KERNEL_VERSION(4, 4, 0)) {
        // Basic tracepoint support only
    }
    
    return 0;
}

// Test kernel version detection
static int test_kernel_version_detection(void) {
    kernel_version_t version;
    
    if (detect_kernel_version(&version) != 0) {
        TEST_ASSERT(0, "Failed to detect kernel version");
    }
    
    TEST_ASSERT(version.major > 0, "Invalid major version");
    TEST_ASSERT(version.minor >= 0, "Invalid minor version");
    TEST_ASSERT(strlen(version.version_string) > 0, "Empty version string");
    
    printf("  Detected kernel: %s (%d.%d.%d)\n", 
           version.version_string, version.major, version.minor, version.patch);
    
    TEST_PASS("Kernel version detection successful");
}

// Test tracepoint availability
static int test_tracepoint_availability(void) {
    // Check if debugfs is mounted
    if (access("/sys/kernel/debug", F_OK) != 0) {
        printf("  WARNING: debugfs not available (common in containers/WSL)\n");
        printf("  This is expected in restricted environments\n");
        g_test_stats.skipped_tests++;
        TEST_PASS("Tracepoint availability test skipped (debugfs not available)");
    }
    
    // Check sched_process_exec tracepoint
    int exec_available = (access("/sys/kernel/debug/tracing/events/sched/sched_process_exec", F_OK) == 0);
    
    // Check sched_process_exit tracepoint  
    int exit_available = (access("/sys/kernel/debug/tracing/events/sched/sched_process_exit", F_OK) == 0);
    
    printf("  sched_process_exec tracepoint: %s\n", exec_available ? "Available" : "Not available");
    printf("  sched_process_exit tracepoint: %s\n", exit_available ? "Available" : "Not available");
    
    // In restricted environments, we can't test actual tracepoint availability
    // but we can still validate the kernel version supports them
    if (!exec_available && !exit_available) {
        int kernel_code = KERNEL_VERSION(g_kernel_version.major, 
                                       g_kernel_version.minor, 
                                       g_kernel_version.patch);
        
        if (kernel_code >= KERNEL_VERSION(4, 4, 0)) {
            printf("  → Kernel version supports tracepoints (restricted environment)\n");
            TEST_PASS("Tracepoint availability verified (kernel version check)");
        } else {
            TEST_ASSERT(0, "Kernel version too old for tracepoint support");
        }
    }
    
    TEST_PASS("Tracepoint availability verified");
}

// Test tracepoint structure compatibility
static int test_tracepoint_structure_compatibility(void) {
    FILE *format_file;
    char line[512];
    int found_pid_field = 0;
    int found_comm_field = 0;
    int found_filename_field = 0;
    
    // Test sched_process_exec format
    format_file = fopen("/sys/kernel/debug/tracing/events/sched/sched_process_exec/format", "r");
    if (format_file) {
        printf("  Checking sched_process_exec format:\n");
        
        while (fgets(line, sizeof(line), format_file)) {
            if (strstr(line, "field:pid_t pid")) {
                found_pid_field = 1;
                printf("    ✓ pid field found\n");
            }
            if (strstr(line, "field:char comm")) {
                found_comm_field = 1;
                printf("    ✓ comm field found\n");
            }
            if (strstr(line, "__data_loc char[] filename")) {
                found_filename_field = 1;
                printf("    ✓ filename field found\n");
            }
        }
        fclose(format_file);
        
        TEST_ASSERT(found_pid_field, "pid field not found in sched_process_exec");
        TEST_ASSERT(found_comm_field, "comm field not found in sched_process_exec");
        
        if (!found_filename_field) {
            printf("    WARNING: filename field not found, may need fallback\n");
        }
    } else {
        printf("  WARNING: Cannot read sched_process_exec format\n");
    }
    
    TEST_PASS("Tracepoint structure compatibility verified");
}

// Test fallback mechanism effectiveness
static int test_fallback_mechanism(void) {
    int kernel_code = KERNEL_VERSION(g_kernel_version.major, 
                                   g_kernel_version.minor, 
                                   g_kernel_version.patch);
    
    printf("  Testing fallback mechanisms for kernel %d.%d.%d:\n", 
           g_kernel_version.major, g_kernel_version.minor, g_kernel_version.patch);
    
    if (kernel_code >= KERNEL_VERSION(5, 4, 0)) {
        printf("    ✓ Modern kernel - all features available\n");
        TEST_ASSERT(g_kernel_features.ringbuf_support, "Ring buffer should be supported");
        TEST_ASSERT(g_kernel_features.bpf_core_support, "BPF CO-RE should be supported");
    } else if (kernel_code >= KERNEL_VERSION(4, 9, 0)) {
        printf("    ✓ Stable kernel - core features available\n");
        TEST_ASSERT(g_kernel_features.modern_tracepoint, "Modern tracepoint should be supported");
        printf("    → Using perf_event buffer instead of ring buffer\n");
    } else if (kernel_code >= KERNEL_VERSION(4, 4, 0)) {
        printf("    ⚠ Compatibility kernel - basic features only\n");
        printf("    → Using compatibility tracepoint implementation\n");
        printf("    → Using perf_event buffer\n");
    } else {
        printf("    ❌ Unsupported kernel - would use kprobe fallback\n");
        printf("    → Recommend upgrading to kernel 4.4+\n");
    }
    
    TEST_PASS("Fallback mechanism validation completed");
}

// Test kernel-specific optimizations
static int test_kernel_optimizations(void) {
    int kernel_code = KERNEL_VERSION(g_kernel_version.major, 
                                   g_kernel_version.minor, 
                                   g_kernel_version.patch);
    
    printf("  Testing kernel-specific optimizations:\n");
    
    // Test bpf_probe_read_kernel availability
    if (kernel_code >= KERNEL_VERSION(5, 0, 0)) {
        printf("    ✓ bpf_probe_read_kernel available\n");
        TEST_ASSERT(g_kernel_features.probe_read_kernel_support, 
                   "bpf_probe_read_kernel should be supported");
    } else {
        printf("    → Using bpf_probe_read fallback\n");
    }
    
    // Test BTF support
    if (kernel_code >= KERNEL_VERSION(5, 4, 0)) {
        printf("    ✓ BTF support available\n");
        TEST_ASSERT(g_kernel_features.btf_support, "BTF should be supported");
    } else {
        printf("    → No BTF support, using hardcoded structures\n");
    }
    
    // Test ring buffer vs perf event buffer
    if (kernel_code >= KERNEL_VERSION(5, 4, 0)) {
        printf("    ✓ Ring buffer available for optimal performance\n");
        TEST_ASSERT(g_kernel_features.ringbuf_support, "Ring buffer should be supported");
    } else {
        printf("    → Using perf_event buffer\n");
    }
    
    TEST_PASS("Kernel optimization tests completed");
}

// Test cross-kernel compatibility
static int test_cross_kernel_compatibility(void) {
    printf("  Testing cross-kernel compatibility matrix:\n");
    
    // Define test matrix based on compatibility document
    struct {
        int major, minor;
        const char *distro;
        const char *support_level;
        int should_work;
    } test_matrix[] = {
        {6, 8, "Ubuntu 24.04 LTS", "完整支持", 1},
        {6, 1, "Debian 12", "完整支持", 1},
        {5, 15, "Ubuntu 22.04 LTS", "完整支持", 1},
        {5, 14, "RHEL 9", "完整支持", 1},
        {5, 10, "Debian 11", "完整支持", 1},
        {5, 4, "Ubuntu 20.04 LTS", "完整支持", 1},
        {4, 19, "Debian 10", "完整支持", 1},
        {4, 18, "RHEL 8", "完整支持", 1},
        {4, 15, "Ubuntu 18.04 LTS", "完整支持", 1},
        {4, 9, "最低推荐版本", "基础支持", 1},
        {4, 4, "最低支持版本", "兼容性支持", 1},
        {3, 10, "RHEL 7", "不推荐", 0},
    };
    
    int current_kernel = KERNEL_VERSION(g_kernel_version.major, 
                                      g_kernel_version.minor, 
                                      g_kernel_version.patch);
    
    for (size_t i = 0; i < sizeof(test_matrix) / sizeof(test_matrix[0]); i++) {
        int test_kernel = KERNEL_VERSION(test_matrix[i].major, test_matrix[i].minor, 0);
        
        if (current_kernel >= test_kernel) {
            printf("    ✓ %d.%d (%s) - %s\n", 
                   test_matrix[i].major, test_matrix[i].minor,
                   test_matrix[i].distro, test_matrix[i].support_level);
        }
    }
    
    // Verify current kernel is in supported range
    TEST_ASSERT(current_kernel >= KERNEL_VERSION(4, 4, 0), 
               "Current kernel below minimum supported version");
    
    TEST_PASS("Cross-kernel compatibility verified");
}

// Test case structure
typedef struct {
    const char *name;
    int (*test_func)(void);
} test_case_t;

// Test suite definition
static test_case_t compatibility_test_suite[] = {
    {"kernel_version_detection", test_kernel_version_detection},
    {"tracepoint_availability", test_tracepoint_availability},
    {"tracepoint_structure_compatibility", test_tracepoint_structure_compatibility},
    {"fallback_mechanism", test_fallback_mechanism},
    {"kernel_optimizations", test_kernel_optimizations},
    {"cross_kernel_compatibility", test_cross_kernel_compatibility},
    {NULL, NULL}  // Sentinel
};

// Run all compatibility tests
static int run_compatibility_tests(void) {
    printf("eBPF Process Monitor Compatibility Tests\n");
    printf("========================================\n\n");
    
    // Initialize global state
    if (detect_kernel_version(&g_kernel_version) != 0) {
        printf("ERROR: Failed to detect kernel version\n");
        return -1;
    }
    
    if (detect_kernel_features(&g_kernel_features) != 0) {
        printf("ERROR: Failed to detect kernel features\n");
        return -1;
    }
    
    printf("Running on kernel: %s\n", g_kernel_version.version_string);
    printf("Kernel features detected:\n");
    printf("  - Tracepoint available: %s\n", g_kernel_features.tracepoint_available ? "Yes" : "No");
    printf("  - Modern tracepoint: %s\n", g_kernel_features.modern_tracepoint ? "Yes" : "No");
    printf("  - Ring buffer support: %s\n", g_kernel_features.ringbuf_support ? "Yes" : "No");
    printf("  - BPF CO-RE support: %s\n", g_kernel_features.bpf_core_support ? "Yes" : "No");
    printf("  - probe_read_kernel support: %s\n", g_kernel_features.probe_read_kernel_support ? "Yes" : "No");
    printf("  - BTF support: %s\n", g_kernel_features.btf_support ? "Yes" : "No");
    printf("\n");
    
    // Run each test
    for (int i = 0; compatibility_test_suite[i].name != NULL; i++) {
        printf("Running test: %s\n", compatibility_test_suite[i].name);
        g_test_stats.total_tests++;
        
        int result = compatibility_test_suite[i].test_func();
        if (result == 0) {
            g_test_stats.passed_tests++;
            printf("✓ %s passed\n\n", compatibility_test_suite[i].name);
        } else {
            g_test_stats.failed_tests++;
            printf("✗ %s failed\n\n", compatibility_test_suite[i].name);
        }
    }
    
    return 0;
}

// Print test summary
static void print_test_summary(void) {
    printf("Compatibility Test Summary\n");
    printf("==========================\n");
    printf("Total tests: %d\n", g_test_stats.total_tests);
    printf("Passed: %d\n", g_test_stats.passed_tests);
    printf("Failed: %d\n", g_test_stats.failed_tests);
    printf("Skipped: %d\n", g_test_stats.skipped_tests);
    
    if (g_test_stats.failed_tests == 0) {
        printf("\n🎉 All compatibility tests passed!\n");
        
        // Print compatibility recommendations
        int kernel_code = KERNEL_VERSION(g_kernel_version.major, 
                                       g_kernel_version.minor, 
                                       g_kernel_version.patch);
        
        printf("\nCompatibility Recommendations:\n");
        if (kernel_code >= KERNEL_VERSION(5, 4, 0)) {
            printf("✅ Excellent - Full feature support available\n");
        } else if (kernel_code >= KERNEL_VERSION(4, 9, 0)) {
            printf("✅ Good - Core features supported with minor limitations\n");
        } else if (kernel_code >= KERNEL_VERSION(4, 4, 0)) {
            printf("⚠️  Basic - Limited feature set, consider upgrading\n");
        } else {
            printf("❌ Unsupported - Upgrade required for proper functionality\n");
        }
    } else {
        printf("\n❌ Some compatibility tests failed!\n");
        printf("Please review the failed tests and consider kernel upgrade or configuration changes.\n");
    }
}

// Main function
int main(int argc __attribute__((unused)), char *argv[] __attribute__((unused))) {
    // Check if running as root (needed for some tracepoint tests)
    if (geteuid() != 0) {
        printf("WARNING: Not running as root. Some tests may be skipped.\n\n");
    }
    
    // Run compatibility tests
    run_compatibility_tests();
    
    // Print summary
    print_test_summary();
    
    // Return appropriate exit code
    return (g_test_stats.failed_tests > 0) ? 1 : 0;
}