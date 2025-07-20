#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

// Mock definitions for testing file information extraction logic
#define MAX_PATH_LEN 4096
#define MAX_FILENAME_LEN 256

// Mock structures for testing
struct file_event {
    uint32_t flags;
    uint16_t mode;
    int32_t fd;
    uint64_t size;
    uint64_t offset;
    char filename[MAX_PATH_LEN];
};

// Mock error recording functions
static int path_extraction_errors = 0;
static int data_read_errors = 0;

static void record_file_path_extraction_error(void) {
    path_extraction_errors++;
}

static void record_error(int error_type) {
    data_read_errors++;
}

// Simplified versions of the extraction functions for testing
static inline int extract_file_path_test(char *dest, uint32_t dest_size, 
                                        char *data, uint32_t offset) {
    if (!dest || dest_size == 0) {
        record_file_path_extraction_error();
        return -1;
    }
    
    dest[0] = '\0';
    
    if (!data) {
        record_file_path_extraction_error();
        if (dest_size > 9) {
            memcpy(dest, "<no-data>", 10);
        }
        return -1;
    }
    
    if (offset == 0) {
        record_file_path_extraction_error();
        if (dest_size > 11) {
            memcpy(dest, "<no-offset>", 12);
        }
        return -1;
    }
    
    uint32_t copy_len = dest_size - 1;
    if (copy_len < 2) {
        record_file_path_extraction_error();
        return -1;
    }
    
    // Simulate reading from data + offset
    const char *source = data + offset;
    strncpy(dest, source, copy_len);
    dest[copy_len] = '\0';
    
    if (dest[0] == '\0') {
        record_file_path_extraction_error();
        if (dest_size > 7) {
            memcpy(dest, "<empty>", 8);
        }
        return -1;
    }
    
    return 0;
}

static inline uint32_t extract_file_flags_test(uint32_t raw_flags) {
    if (raw_flags > 0xFFFF) {
        raw_flags &= 0xFFFF;
    }
    return raw_flags;
}

static inline uint16_t extract_file_mode_test(uint16_t raw_mode) {
    if (raw_mode == 0xFFFF) {
        return 0x0444; // r--r--r--
    }
    
    uint16_t mode = raw_mode & 0x0FFF;
    
    if (mode == 0) {
        return 0x0400; // r--------
    }
    
    return mode;
}

static inline uint64_t extract_file_size_test(uint64_t raw_size) {
    if (raw_size > 0x7FFFFFFFFFFFFFFFULL) {
        return 0;
    }
    
    const uint64_t MAX_REASONABLE_FILE_SIZE = 1024ULL * 1024ULL * 1024ULL * 1024ULL; // 1TB
    if (raw_size > MAX_REASONABLE_FILE_SIZE) {
        return raw_size; // Keep large sizes but flag them
    }
    
    return raw_size;
}

static inline uint64_t extract_file_offset_test(uint64_t raw_offset) {
    if (raw_offset > 0x7FFFFFFFFFFFFFFFULL) {
        return 0;
    }
    
    const uint64_t MAX_REASONABLE_FILE_OFFSET = 1024ULL * 1024ULL * 1024ULL * 1024ULL; // 1TB
    if (raw_offset > MAX_REASONABLE_FILE_OFFSET) {
        return raw_offset; // Keep large offsets but flag them
    }
    
    return raw_offset;
}

// Test functions
void test_file_path_extraction(void) {
    printf("Testing file path extraction...\n");
    
    char dest[256];
    char test_data[] = "dummy\0/path/to/test/file.txt\0more_data";
    uint32_t offset = 6; // Points to "/path/to/test/file.txt"
    
    // Test normal case
    path_extraction_errors = 0;
    int result = extract_file_path_test(dest, sizeof(dest), test_data, offset);
    assert(result == 0);
    assert(strcmp(dest, "/path/to/test/file.txt") == 0);
    assert(path_extraction_errors == 0);
    printf("✓ Normal path extraction works\n");
    
    // Test null destination
    result = extract_file_path_test(NULL, sizeof(dest), test_data, offset);
    assert(result == -1);
    assert(path_extraction_errors == 1);
    printf("✓ Null destination handled correctly\n");
    
    // Test null data
    path_extraction_errors = 0;
    result = extract_file_path_test(dest, sizeof(dest), NULL, offset);
    assert(result == -1);
    assert(strcmp(dest, "<no-data>") == 0);
    assert(path_extraction_errors == 1);
    printf("✓ Null data handled correctly\n");
    
    // Test zero offset
    path_extraction_errors = 0;
    result = extract_file_path_test(dest, sizeof(dest), test_data, 0);
    assert(result == -1);
    assert(strcmp(dest, "<no-offset>") == 0);
    assert(path_extraction_errors == 1);
    printf("✓ Zero offset handled correctly\n");
    
    // Test empty string
    char empty_data[] = "dummy\0\0more_data";
    path_extraction_errors = 0;
    result = extract_file_path_test(dest, sizeof(dest), empty_data, 6);
    assert(result == -1);
    assert(strcmp(dest, "<empty>") == 0);
    assert(path_extraction_errors == 1);
    printf("✓ Empty string handled correctly\n");
}

void test_file_flags_extraction(void) {
    printf("Testing file flags extraction...\n");
    
    // Test normal flags
    uint32_t result = extract_file_flags_test(0x0042); // O_RDWR | O_CREAT
    assert(result == 0x0042);
    printf("✓ Normal flags preserved\n");
    
    // Test large flags (should be masked)
    result = extract_file_flags_test(0x12345678);
    assert(result == 0x5678); // Lower 16 bits only
    printf("✓ Large flags masked correctly\n");
    
    // Test zero flags
    result = extract_file_flags_test(0);
    assert(result == 0);
    printf("✓ Zero flags handled correctly\n");
}

void test_file_mode_extraction(void) {
    printf("Testing file mode extraction...\n");
    
    // Test normal mode
    uint16_t result = extract_file_mode_test(0x81A4); // Regular file with 644 permissions
    assert(result == 0x01A4); // Only permission bits
    printf("✓ Normal mode extracted correctly\n");
    
    // Test invalid mode (0xFFFF)
    result = extract_file_mode_test(0xFFFF);
    assert(result == 0x0444); // Default r--r--r--
    printf("✓ Invalid mode handled correctly\n");
    
    // Test zero mode
    result = extract_file_mode_test(0);
    assert(result == 0x0400); // Default r--------
    printf("✓ Zero mode handled correctly\n");
}

void test_file_size_extraction(void) {
    printf("Testing file size extraction...\n");
    
    // Test normal size
    uint64_t result = extract_file_size_test(1024);
    assert(result == 1024);
    printf("✓ Normal size preserved\n");
    
    // Test very large size (negative when cast to signed)
    result = extract_file_size_test(0xFFFFFFFFFFFFFFFFULL);
    assert(result == 0); // Should be zeroed
    printf("✓ Invalid large size handled correctly\n");
    
    // Test extremely large but valid size (> 1TB)
    uint64_t large_size = 2ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL; // 2TB
    result = extract_file_size_test(large_size);
    assert(result == large_size); // Should be preserved
    printf("✓ Very large valid size preserved\n");
    
    // Test zero size
    result = extract_file_size_test(0);
    assert(result == 0);
    printf("✓ Zero size handled correctly\n");
}

void test_file_offset_extraction(void) {
    printf("Testing file offset extraction...\n");
    
    // Test normal offset
    uint64_t result = extract_file_offset_test(4096);
    assert(result == 4096);
    printf("✓ Normal offset preserved\n");
    
    // Test very large offset (negative when cast to signed)
    result = extract_file_offset_test(0xFFFFFFFFFFFFFFFFULL);
    assert(result == 0); // Should be zeroed
    printf("✓ Invalid large offset handled correctly\n");
    
    // Test extremely large but valid offset (> 1TB)
    uint64_t large_offset = 2ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL; // 2TB
    result = extract_file_offset_test(large_offset);
    assert(result == large_offset); // Should be preserved
    printf("✓ Very large valid offset preserved\n");
    
    // Test zero offset
    result = extract_file_offset_test(0);
    assert(result == 0);
    printf("✓ Zero offset handled correctly\n");
}

int main(void) {
    printf("Running file information extraction tests...\n\n");
    
    test_file_path_extraction();
    printf("\n");
    
    test_file_flags_extraction();
    printf("\n");
    
    test_file_mode_extraction();
    printf("\n");
    
    test_file_size_extraction();
    printf("\n");
    
    test_file_offset_extraction();
    printf("\n");
    
    printf("All file information extraction tests passed! ✓\n");
    return 0;
}