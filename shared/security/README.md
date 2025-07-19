# Security Package

The security package provides common security utilities for the OpenEDR project, including safe type conversions, path validation, and security event logging.

## Features

### Safe Integer Conversions
- `SafeUint64ToInt64`: Safely converts uint64 to int64 with overflow detection
- `SafeTimestampConversion`: Safely converts uint64 timestamps to time.Time

### Path Validation
- `ValidatePath`: Validates file paths against allowed directories
- `SanitizePath`: Cleans and normalizes file paths
- `ValidateArchivePath`: Validates paths within archive files to prevent path traversal

### Security Event Logging
- `SecurityEvent`: Structured security event logging
- `ValidationResult`: Validation result tracking with errors and warnings

## Usage Examples

### Safe Integer Conversion

```go
import "github.com/XXXXD-cation/OpenEDR/shared/security"

// Safe uint64 to int64 conversion
timestamp := uint64(1640995200000000000)
safeTimestamp, err := security.SafeUint64ToInt64(timestamp)
if err != nil {
    // Handle overflow error
    log.Error("Integer overflow detected", err)
    return
}

// Safe timestamp conversion
timeValue, err := security.SafeTimestampConversion(timestamp)
if err != nil {
    // Handle conversion error
    log.Error("Timestamp conversion failed", err)
    return
}
```

### Path Validation

```go
import "github.com/XXXXD-cation/OpenEDR/shared/security"

// Validate file path
allowedDirs := []string{"/tmp", "/var/log", "/home/user/data"}
err := security.ValidatePath("/tmp/config.yaml", allowedDirs)
if err != nil {
    // Handle invalid path
    log.Error("Invalid file path", err)
    return
}

// Sanitize path
cleanPath, err := security.SanitizePath("./config/../data/file.txt")
if err != nil {
    // Handle path sanitization error
    log.Error("Path sanitization failed", err)
    return
}
// cleanPath will be "data/file.txt"

// Validate archive path
err = security.ValidateArchivePath("data/file.txt", "/tmp/extract")
if err != nil {
    // Handle path traversal attempt
    log.Error("Archive path validation failed", err)
    return
}
```

### Security Event Logging

```go
import "github.com/XXXXD-cation/OpenEDR/shared/security"

// Create a security event
event := security.NewSecurityEvent(
    security.PathTraversalAttempt,
    security.SeverityHigh,
    "file-handler",
    "Detected path traversal attempt",
)

// Add details and context
event.AddDetail("attempted_path", "../../../etc/passwd").
    AddDetail("source_ip", "192.168.1.100").
    SetRemediation("Block the request and log the incident").
    SetSource("web-api").
    SetUserContext("user123", "session456")

// Convert to JSON for logging
jsonData, err := event.ToJSON()
if err != nil {
    log.Error("Failed to serialize security event", err)
    return
}

log.Info("Security event recorded", string(jsonData))
```

### Validation Results

```go
import "github.com/XXXXD-cation/OpenEDR/shared/security"

// Create validation result
result := &security.ValidationResult{Valid: true}

// Add errors and warnings
result.AddError("tls_config", "InsecureSkipVerify is enabled in production", "TLS_001")
result.AddWarning("file_permissions", "File permissions are too permissive", "PERM_001")

// Check results
if result.HasErrors() {
    log.Error("Validation failed with errors", result.Errors)
    return
}

if result.HasWarnings() {
    log.Warn("Validation completed with warnings", result.Warnings)
}
```

## Error Types

The package defines several common security error types:

- `ErrInvalidPath`: Invalid file path
- `ErrPathTraversal`: Path traversal attempt detected
- `ErrIntegerOverflow`: Integer overflow detected
- `ErrUnsafeTLSConfig`: Unsafe TLS configuration
- `ErrInvalidArchive`: Invalid archive entry

## Security Event Types

- `PathTraversalAttempt`: Path traversal attack attempt
- `IntegerOverflowDetected`: Integer overflow detected
- `UnsafeTLSConfiguration`: Unsafe TLS configuration detected
- `InvalidArchiveEntry`: Invalid archive entry detected
- `UnauthorizedFileAccess`: Unauthorized file access attempt
- `MaliciousInputDetected`: Malicious input detected
- `ConfigurationViolation`: Security configuration violation

## Security Severity Levels

- `SeverityLow`: Low severity security event
- `SeverityMedium`: Medium severity security event
- `SeverityHigh`: High severity security event
- `SeverityCritical`: Critical severity security event

## Testing

Run the test suite:

```bash
go test -v ./shared/security/
```

Run tests with coverage:

```bash
go test -cover ./shared/security/
```