#include <stdio.h>
#include <string.h>
#include <assert.h>

// Simplified types for testing
typedef unsigned int __u32;
typedef unsigned long long __u64;

// Mock configuration structure (simplified)
struct config {
    __u32 file_type_filter_enabled;
    __u32 file_extensions_whitelist[16];
    __u32 file_extensions_blacklist[16];
    __u32 whitelist_size;
    __u32 blacklist_size;
};

// Mock configuration for testing
static struct config test_config = {
    .file_type_filter_enabled = 1,
    .whitelist_size = 3,
    .blacklist_size = 2,
    .file_extensions_whitelist = {0, 0, 0}, // Will be filled with hashes
    .file_extensions_blacklist = {0, 0}     // Will be filled with hashes
};

// Mock map lookup function
struct config* mock_bpf_map_lookup_elem(void *map, void *key) {
    (void)map; (void)key; // Suppress unused parameter warnings
    return &test_config;
}

// Simplified hash function for file extensions (djb2 algorithm)
static __u32 hash_file_extension(const char *ext, __u32 len) {
    __u32 hash = 5381;
    
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
static int extract_file_extension(const char *filename, char *ext, __u32 ext_size) {
    if (!filename || !ext || ext_size == 0) {
        return -1;
    }
    
    // Initialize extension buffer
    ext[0] = '\0';
    
    // Find the last dot in the filename
    int last_dot = -1;
    int filename_len = 0;
    
    // Calculate filename length and find last dot
    for (int i = 0; i < 4096 && filename[i] != '\0'; i++) {
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
    if (ext_len >= (int)ext_size) {
        ext_len = ext_size - 1;
    }
    
    // Copy extension
    strncpy(ext, &filename[ext_start], ext_len);
    ext[ext_len] = '\0';
    
    return ext_len;
}

// Check if file type filtering is enabled
static int is_file_type_filtering_enabled(void) {
    return test_config.file_type_filter_enabled;
}

// Check if file extension is in whitelist
static int is_file_extension_whitelisted(const char *filename) {
    // If whitelist is empty, allow all files
    if (test_config.whitelist_size == 0) {
        return 1;
    }
    
    // Extract file extension
    char ext[16];
    if (extract_file_extension(filename, ext, sizeof(ext)) < 0) {
        // No extension found - allow files without extensions
        return 1;
    }
    
    // Hash the extension
    __u32 ext_hash = hash_file_extension(ext, sizeof(ext));
    
    // Check if extension hash is in whitelist
    for (__u32 i = 0; i < test_config.whitelist_size && i < 16; i++) {
        if (test_config.file_extensions_whitelist[i] == ext_hash) {
            return 1; // Extension is whitelisted
        }
    }
    
    return 0; // Extension not in whitelist
}

// Check if file extension is in blacklist
static int is_file_extension_blacklisted(const char *filename) {
    // If blacklist is empty, don't block any files
    if (test_config.blacklist_size == 0) {
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
    for (__u32 i = 0; i < test_config.blacklist_size && i < 16; i++) {
        if (test_config.file_extensions_blacklist[i] == ext_hash) {
            return 1; // Extension is blacklisted
        }
    }
    
    return 0; // Extension not in blacklist
}

// Main file type filtering function
static int should_monitor_file_type(const char *filename) {
    // If file type filtering is disabled, monitor all files
    if (!is_file_type_filtering_enabled()) {
        return 1;
    }
    
    // Check blacklist first (takes precedence)
    if (is_file_extension_blacklisted(filename)) {
        return 0; // File type is blacklisted
    }
    
    // Check whitelist
    if (!is_file_extension_whitelisted(filename)) {
        return 0; // File type not in whitelist
    }
    
    return 1; // File type should be monitored
}

// Test hash function
void test_hash_function() {
    printf("Testing hash function...\n");
    
    // Test basic hashing
    __u32 hash1 = hash_file_extension("txt", 3);
    __u32 hash2 = hash_file_extension("TXT", 3);
    __u32 hash3 = hash_file_extension("pdf", 3);
    
    // Case insensitive - should be equal
    assert(hash1 == hash2);
    
    // Different extensions should have different hashes
    assert(hash1 != hash3);
    
    printf("Hash function tests passed!\n");
}

// Test file extension extraction
void test_extension_extraction() {
    printf("Testing extension extraction...\n");
    
    char ext[16];
    int result;
    
    // Test normal file with extension
    result = extract_file_extension("/path/to/file.txt", ext, sizeof(ext));
    assert(result > 0);
    assert(strcmp(ext, "txt") == 0);
    
    // Test file without extension
    result = extract_file_extension("/path/to/file", ext, sizeof(ext));
    assert(result < 0);
    
    // Test file with multiple dots
    result = extract_file_extension("/path/to/file.tar.gz", ext, sizeof(ext));
    assert(result > 0);
    assert(strcmp(ext, "gz") == 0);
    
    // Test file ending with dot
    result = extract_file_extension("/path/to/file.", ext, sizeof(ext));
    assert(result < 0);
    
    printf("Extension extraction tests passed!\n");
}

// Test whitelist functionality
void test_whitelist() {
    printf("Testing whitelist functionality...\n");
    
    // Setup whitelist with common extensions
    test_config.file_type_filter_enabled = 1;
    test_config.whitelist_size = 3;
    test_config.blacklist_size = 0;
    
    // Add hashes for txt, pdf, doc
    test_config.file_extensions_whitelist[0] = hash_file_extension("txt", 3);
    test_config.file_extensions_whitelist[1] = hash_file_extension("pdf", 3);
    test_config.file_extensions_whitelist[2] = hash_file_extension("doc", 3);
    
    // Test whitelisted files
    assert(should_monitor_file_type("/path/to/document.txt") == 1);
    assert(should_monitor_file_type("/path/to/document.pdf") == 1);
    assert(should_monitor_file_type("/path/to/document.doc") == 1);
    
    // Test non-whitelisted files
    assert(should_monitor_file_type("/path/to/script.sh") == 0);
    assert(should_monitor_file_type("/path/to/image.jpg") == 0);
    
    // Test files without extension (should be allowed)
    assert(should_monitor_file_type("/path/to/file") == 1);
    
    printf("Whitelist tests passed!\n");
}

// Test blacklist functionality
void test_blacklist() {
    printf("Testing blacklist functionality...\n");
    
    // Setup blacklist with dangerous extensions
    test_config.file_type_filter_enabled = 1;
    test_config.whitelist_size = 0; // Empty whitelist means allow all
    test_config.blacklist_size = 2;
    
    // Add hashes for exe, bat
    test_config.file_extensions_blacklist[0] = hash_file_extension("exe", 3);
    test_config.file_extensions_blacklist[1] = hash_file_extension("bat", 3);
    
    // Test blacklisted files
    assert(should_monitor_file_type("/path/to/malware.exe") == 0);
    assert(should_monitor_file_type("/path/to/script.bat") == 0);
    
    // Test non-blacklisted files
    assert(should_monitor_file_type("/path/to/document.txt") == 1);
    assert(should_monitor_file_type("/path/to/image.jpg") == 1);
    
    // Test files without extension (should be allowed)
    assert(should_monitor_file_type("/path/to/file") == 1);
    
    printf("Blacklist tests passed!\n");
}

// Test combined whitelist and blacklist
void test_combined_filtering() {
    printf("Testing combined whitelist and blacklist...\n");
    
    // Setup both whitelist and blacklist
    test_config.file_type_filter_enabled = 1;
    test_config.whitelist_size = 2;
    test_config.blacklist_size = 1;
    
    // Whitelist: txt, exe
    test_config.file_extensions_whitelist[0] = hash_file_extension("txt", 3);
    test_config.file_extensions_whitelist[1] = hash_file_extension("exe", 3);
    
    // Blacklist: exe (should take precedence over whitelist)
    test_config.file_extensions_blacklist[0] = hash_file_extension("exe", 3);
    
    // Test that blacklist takes precedence
    assert(should_monitor_file_type("/path/to/program.exe") == 0);
    
    // Test whitelisted file not in blacklist
    assert(should_monitor_file_type("/path/to/document.txt") == 1);
    
    // Test file not in whitelist
    assert(should_monitor_file_type("/path/to/image.jpg") == 0);
    
    printf("Combined filtering tests passed!\n");
}

// Test disabled filtering
void test_disabled_filtering() {
    printf("Testing disabled filtering...\n");
    
    // Disable filtering
    test_config.file_type_filter_enabled = 0;
    
    // All files should be allowed when filtering is disabled
    assert(should_monitor_file_type("/path/to/document.txt") == 1);
    assert(should_monitor_file_type("/path/to/malware.exe") == 1);
    assert(should_monitor_file_type("/path/to/script.sh") == 1);
    assert(should_monitor_file_type("/path/to/file") == 1);
    
    printf("Disabled filtering tests passed!\n");
}

int main() {
    printf("Starting file type filtering tests...\n\n");
    
    test_hash_function();
    test_extension_extraction();
    test_whitelist();
    test_blacklist();
    test_combined_filtering();
    test_disabled_filtering();
    
    printf("\nAll file type filtering tests passed successfully!\n");
    return 0;
}