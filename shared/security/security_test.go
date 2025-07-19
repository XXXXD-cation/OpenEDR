package security

import (
	"path/filepath"
	"testing"
)

func TestSafeUint64ToInt64(t *testing.T) {
	tests := []struct {
		name        string
		input       uint64
		expected    int64
		expectError bool
	}{
		{
			name:        "valid conversion - zero",
			input:       0,
			expected:    0,
			expectError: false,
		},
		{
			name:        "valid conversion - small positive",
			input:       12345,
			expected:    12345,
			expectError: false,
		},
		{
			name:        "valid conversion - max int64",
			input:       1<<63 - 1,
			expected:    1<<63 - 1,
			expectError: false,
		},
		{
			name:        "overflow - max int64 + 1",
			input:       1 << 63,
			expected:    0,
			expectError: true,
		},
		{
			name:        "overflow - max uint64",
			input:       ^uint64(0),
			expected:    0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SafeUint64ToInt64(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				if result != tt.expected {
					t.Errorf("expected result %d, got %d", tt.expected, result)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("expected result %d, got %d", tt.expected, result)
				}
			}
		})
	}
}

func TestSafeTimestampConversion(t *testing.T) {
	tests := []struct {
		name        string
		input       uint64
		expectError bool
	}{
		{
			name:        "valid timestamp",
			input:       1640995200000000000, // 2022-01-01 00:00:00 UTC in nanoseconds
			expectError: false,
		},
		{
			name:        "zero timestamp",
			input:       0,
			expectError: false,
		},
		{
			name:        "overflow timestamp",
			input:       ^uint64(0),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SafeTimestampConversion(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result.IsZero() && tt.input != 0 {
					t.Errorf("expected non-zero time for input %d", tt.input)
				}
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	tempDir := t.TempDir()
	allowedDirs := []string{tempDir, "/tmp", "/var/log"}

	tests := []struct {
		name        string
		path        string
		allowedDirs []string
		expectError bool
	}{
		{
			name:        "valid path in allowed directory",
			path:        filepath.Join(tempDir, "test.txt"),
			allowedDirs: allowedDirs,
			expectError: false,
		},
		{
			name:        "empty path",
			path:        "",
			allowedDirs: allowedDirs,
			expectError: true,
		},
		{
			name:        "path traversal attempt",
			path:        "../../../etc/passwd",
			allowedDirs: allowedDirs,
			expectError: true,
		},
		{
			name:        "path not in allowed directories",
			path:        "/etc/passwd",
			allowedDirs: allowedDirs,
			expectError: true,
		},
		{
			name:        "no allowed directories specified",
			path:        "/any/path",
			allowedDirs: nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePath(tt.path, tt.allowedDirs)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:        "simple path",
			input:       "test.txt",
			expected:    "test.txt",
			expectError: false,
		},
		{
			name:        "path with current directory",
			input:       "./test.txt",
			expected:    "test.txt",
			expectError: false,
		},
		{
			name:        "empty path",
			input:       "",
			expected:    "",
			expectError: true,
		},
		{
			name:        "path traversal attempt",
			input:       "../../../etc/passwd",
			expected:    "",
			expectError: true,
		},
		{
			name:        "complex valid path",
			input:       "dir1/dir2/../file.txt",
			expected:    "dir1/file.txt",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SanitizePath(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("expected result %q, got %q", tt.expected, result)
				}
			}
		})
	}
}

func TestValidateArchivePath(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		path        string
		targetDir   string
		expectError bool
	}{
		{
			name:        "valid archive path",
			path:        "file.txt",
			targetDir:   tempDir,
			expectError: false,
		},
		{
			name:        "valid nested path",
			path:        "dir/file.txt",
			targetDir:   tempDir,
			expectError: false,
		},
		{
			name:        "empty path",
			path:        "",
			targetDir:   tempDir,
			expectError: true,
		},
		{
			name:        "path traversal attempt",
			path:        "../../../etc/passwd",
			targetDir:   tempDir,
			expectError: true,
		},
		{
			name:        "path with traversal sequences",
			path:        "dir/../../../etc/passwd",
			targetDir:   tempDir,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateArchivePath(tt.path, tt.targetDir)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestDefaultArchiveExtractionLimits(t *testing.T) {
	limits := DefaultArchiveExtractionLimits()

	if limits.MaxFileSize <= 0 {
		t.Errorf("expected positive MaxFileSize, got %d", limits.MaxFileSize)
	}
	if limits.MaxTotalSize <= 0 {
		t.Errorf("expected positive MaxTotalSize, got %d", limits.MaxTotalSize)
	}
	if limits.MaxFileCount <= 0 {
		t.Errorf("expected positive MaxFileCount, got %d", limits.MaxFileCount)
	}
	if limits.MaxDepth <= 0 {
		t.Errorf("expected positive MaxDepth, got %d", limits.MaxDepth)
	}
}

func TestArchiveExtractionTracker(t *testing.T) {
	limits := ArchiveExtractionLimits{
		MaxFileSize:  1000,
		MaxTotalSize: 5000,
		MaxFileCount: 3,
		MaxDepth:     2,
	}
	tracker := NewArchiveExtractionTracker(limits)

	// Test valid file
	err := tracker.ValidateFile("file1.txt", 500)
	if err != nil {
		t.Errorf("unexpected error for valid file: %v", err)
	}
	tracker.RecordExtraction(500)

	// Test file count limit
	tracker.ValidateFile("file2.txt", 500)
	tracker.RecordExtraction(500)
	tracker.ValidateFile("file3.txt", 500)
	tracker.RecordExtraction(500)

	err = tracker.ValidateFile("file4.txt", 500)
	if err == nil {
		t.Errorf("expected error for file count limit exceeded")
	}

	// Test with new tracker for size limits
	tracker2 := NewArchiveExtractionTracker(limits)

	// Test individual file size limit
	err = tracker2.ValidateFile("large_file.txt", 2000)
	if err == nil {
		t.Errorf("expected error for file size limit exceeded")
	}

	// Test total size limit
	tracker2.ValidateFile("file1.txt", 1000)
	tracker2.RecordExtraction(1000)
	tracker2.ValidateFile("file2.txt", 1000)
	tracker2.RecordExtraction(1000)
	tracker2.ValidateFile("file3.txt", 1000)
	tracker2.RecordExtraction(1000)

	err = tracker2.ValidateFile("file4.txt", 1000)
	if err == nil {
		t.Errorf("expected error for total size limit exceeded")
	}

	// Test directory depth limit
	tracker3 := NewArchiveExtractionTracker(limits)
	err = tracker3.ValidateFile("dir1/dir2/dir3/file.txt", 100)
	if err == nil {
		t.Errorf("expected error for directory depth limit exceeded")
	}

	// Test valid depth
	err = tracker3.ValidateFile("dir1/file.txt", 100)
	if err != nil {
		t.Errorf("unexpected error for valid depth: %v", err)
	}
}

func TestArchiveExtractionTrackerStats(t *testing.T) {
	limits := DefaultArchiveExtractionLimits()
	tracker := NewArchiveExtractionTracker(limits)

	// Initial stats should be zero
	fileCount, extractedSize := tracker.GetStats()
	if fileCount != 0 || extractedSize != 0 {
		t.Errorf("expected initial stats to be zero, got fileCount=%d, extractedSize=%d", fileCount, extractedSize)
	}

	// Record some extractions
	tracker.RecordExtraction(100)
	tracker.RecordExtraction(200)

	fileCount, extractedSize = tracker.GetStats()
	if fileCount != 2 {
		t.Errorf("expected fileCount=2, got %d", fileCount)
	}
	if extractedSize != 300 {
		t.Errorf("expected extractedSize=300, got %d", extractedSize)
	}
}

func TestValidateArchiveEntry(t *testing.T) {
	tempDir := t.TempDir()
	limits := ArchiveExtractionLimits{
		MaxFileSize:  1000,
		MaxTotalSize: 5000,
		MaxFileCount: 10,
		MaxDepth:     5,
	}
	tracker := NewArchiveExtractionTracker(limits)

	tests := []struct {
		name        string
		path        string
		size        int64
		targetDir   string
		tracker     *ArchiveExtractionTracker
		expectError bool
	}{
		{
			name:        "valid entry",
			path:        "file.txt",
			size:        500,
			targetDir:   tempDir,
			tracker:     tracker,
			expectError: false,
		},
		{
			name:        "path traversal attempt",
			path:        "../../../etc/passwd",
			size:        100,
			targetDir:   tempDir,
			tracker:     tracker,
			expectError: true,
		},
		{
			name:        "file too large",
			path:        "large.txt",
			size:        2000,
			targetDir:   tempDir,
			tracker:     tracker,
			expectError: true,
		},
		{
			name:        "valid entry without tracker",
			path:        "file2.txt",
			size:        500,
			targetDir:   tempDir,
			tracker:     nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateArchiveEntry(tt.path, tt.size, tt.targetDir, tt.tracker)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
