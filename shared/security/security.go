package security

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Common security errors
var (
	ErrInvalidPath     = errors.New("invalid file path")
	ErrPathTraversal   = errors.New("path traversal attempt detected")
	ErrIntegerOverflow = errors.New("integer overflow detected")
	ErrUnsafeTLSConfig = errors.New("unsafe TLS configuration")
	ErrInvalidArchive  = errors.New("invalid archive entry")
)

// SafeUint64ToInt64 safely converts uint64 to int64, checking for overflow
func SafeUint64ToInt64(val uint64) (int64, error) {
	const maxInt64 = 1<<63 - 1
	if val > maxInt64 {
		return 0, fmt.Errorf("%w: value %d exceeds maximum int64", ErrIntegerOverflow, val)
	}
	return int64(val), nil
}

// SafeTimestampConversion safely converts uint64 timestamp to time.Time
func SafeTimestampConversion(timestamp uint64) (time.Time, error) {
	safeTimestamp, err := SafeUint64ToInt64(timestamp)
	if err != nil {
		return time.Time{}, fmt.Errorf("timestamp conversion failed: %w", err)
	}
	return time.Unix(0, safeTimestamp), nil
}

// ValidatePath validates file path security, checking against allowed directories
func ValidatePath(path string, allowedDirs []string) error {
	if path == "" {
		return fmt.Errorf("%w: empty path", ErrInvalidPath)
	}

	// Clean the path to resolve any . or .. components
	cleanPath := filepath.Clean(path)

	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("%w: path contains traversal sequences", ErrPathTraversal)
	}

	// Convert to absolute path for comparison
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return fmt.Errorf("%w: failed to resolve absolute path: %v", ErrInvalidPath, err)
	}

	// Check if path is within allowed directories
	if len(allowedDirs) > 0 {
		allowed := false
		for _, allowedDir := range allowedDirs {
			allowedAbs, err := filepath.Abs(allowedDir)
			if err != nil {
				continue
			}
			if strings.HasPrefix(absPath, allowedAbs+string(filepath.Separator)) || absPath == allowedAbs {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: path not in allowed directories", ErrInvalidPath)
		}
	}

	return nil
}

// SanitizePath cleans and normalizes a file path
func SanitizePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%w: empty path", ErrInvalidPath)
	}

	// Clean the path to resolve . and .. components
	cleanPath := filepath.Clean(path)

	// Check for remaining traversal attempts after cleaning
	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("%w: path contains unresolved traversal sequences", ErrPathTraversal)
	}

	return cleanPath, nil
}

// ArchiveExtractionLimits defines limits for archive extraction
type ArchiveExtractionLimits struct {
	MaxFileSize  int64 // Maximum size for individual files (bytes)
	MaxTotalSize int64 // Maximum total extracted size (bytes)
	MaxFileCount int   // Maximum number of files to extract
	MaxDepth     int   // Maximum directory depth
}

// DefaultArchiveExtractionLimits returns sensible default limits
func DefaultArchiveExtractionLimits() ArchiveExtractionLimits {
	return ArchiveExtractionLimits{
		MaxFileSize:  100 * 1024 * 1024,  // 100MB per file
		MaxTotalSize: 1024 * 1024 * 1024, // 1GB total
		MaxFileCount: 10000,              // 10k files max
		MaxDepth:     32,                 // 32 levels deep
	}
}

// ArchiveExtractionTracker tracks extraction progress against limits
type ArchiveExtractionTracker struct {
	limits        ArchiveExtractionLimits
	totalSize     int64
	fileCount     int
	extractedSize int64
}

// NewArchiveExtractionTracker creates a new extraction tracker
func NewArchiveExtractionTracker(limits ArchiveExtractionLimits) *ArchiveExtractionTracker {
	return &ArchiveExtractionTracker{
		limits: limits,
	}
}

// ValidateFile validates a file before extraction
func (t *ArchiveExtractionTracker) ValidateFile(path string, size int64) error {
	// Check file count limit
	if t.fileCount >= t.limits.MaxFileCount {
		return fmt.Errorf("%w: file count limit exceeded (%d)", ErrInvalidArchive, t.limits.MaxFileCount)
	}

	// Check individual file size limit
	if size > t.limits.MaxFileSize {
		return fmt.Errorf("%w: file size limit exceeded (%d bytes)", ErrInvalidArchive, t.limits.MaxFileSize)
	}

	// Check total size limit
	if t.extractedSize+size > t.limits.MaxTotalSize {
		return fmt.Errorf("%w: total extraction size limit exceeded (%d bytes)", ErrInvalidArchive, t.limits.MaxTotalSize)
	}

	// Check directory depth
	depth := strings.Count(filepath.Clean(path), string(filepath.Separator))
	if depth > t.limits.MaxDepth {
		return fmt.Errorf("%w: directory depth limit exceeded (%d)", ErrInvalidArchive, t.limits.MaxDepth)
	}

	return nil
}

// RecordExtraction records a successful file extraction
func (t *ArchiveExtractionTracker) RecordExtraction(size int64) {
	t.fileCount++
	t.extractedSize += size
}

// GetStats returns current extraction statistics
func (t *ArchiveExtractionTracker) GetStats() (fileCount int, extractedSize int64) {
	return t.fileCount, t.extractedSize
}

// ValidateArchivePath validates paths within archive files to prevent path traversal
func ValidateArchivePath(path string, targetDir string) error {
	if path == "" {
		return fmt.Errorf("%w: empty archive path", ErrInvalidPath)
	}

	// Clean the path
	cleanPath := filepath.Clean(path)

	// Check for path traversal sequences
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("%w: archive path contains traversal sequences", ErrPathTraversal)
	}

	// Ensure the target path would be within the target directory
	targetPath := filepath.Join(targetDir, cleanPath)
	targetAbs, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("%w: failed to resolve target path: %v", ErrInvalidArchive, err)
	}

	targetDirAbs, err := filepath.Abs(targetDir)
	if err != nil {
		return fmt.Errorf("%w: failed to resolve target directory: %v", ErrInvalidArchive, err)
	}

	if !strings.HasPrefix(targetAbs, targetDirAbs+string(filepath.Separator)) && targetAbs != targetDirAbs {
		return fmt.Errorf("%w: archive path would escape target directory", ErrPathTraversal)
	}

	return nil
}

// ValidateArchiveEntry performs comprehensive validation of an archive entry
func ValidateArchiveEntry(path string, size int64, targetDir string, tracker *ArchiveExtractionTracker) error {
	// Validate path for traversal attacks
	if err := ValidateArchivePath(path, targetDir); err != nil {
		return err
	}

	// Validate against extraction limits
	if tracker != nil {
		if err := tracker.ValidateFile(path, size); err != nil {
			return err
		}
	}

	return nil
}
