package security

import (
	"encoding/json"
	"time"
)

// SecurityEventType represents different types of security events
type SecurityEventType int

const (
	PathTraversalAttempt SecurityEventType = iota
	IntegerOverflowDetected
	UnsafeTLSConfiguration
	InvalidArchiveEntry
	UnauthorizedFileAccess
	MaliciousInputDetected
	ConfigurationViolation
)

// String returns the string representation of SecurityEventType
func (t SecurityEventType) String() string {
	switch t {
	case PathTraversalAttempt:
		return "PATH_TRAVERSAL_ATTEMPT"
	case IntegerOverflowDetected:
		return "INTEGER_OVERFLOW_DETECTED"
	case UnsafeTLSConfiguration:
		return "UNSAFE_TLS_CONFIGURATION"
	case InvalidArchiveEntry:
		return "INVALID_ARCHIVE_ENTRY"
	case UnauthorizedFileAccess:
		return "UNAUTHORIZED_FILE_ACCESS"
	case MaliciousInputDetected:
		return "MALICIOUS_INPUT_DETECTED"
	case ConfigurationViolation:
		return "CONFIGURATION_VIOLATION"
	default:
		return "UNKNOWN_SECURITY_EVENT"
	}
}

// SecuritySeverity represents the severity level of security events
type SecuritySeverity int

const (
	SeverityLow SecuritySeverity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns the string representation of SecuritySeverity
func (s SecuritySeverity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// SecurityEvent represents a security-related event in the system
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        SecurityEventType      `json:"type"`
	Severity    SecuritySeverity       `json:"severity"`
	Component   string                 `json:"component"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details"`
	Remediation string                 `json:"remediation"`
	Source      string                 `json:"source"`
	UserID      string                 `json:"user_id,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
}

// NewSecurityEvent creates a new security event with the given parameters
func NewSecurityEvent(eventType SecurityEventType, severity SecuritySeverity, component, message string) *SecurityEvent {
	return &SecurityEvent{
		ID:        generateEventID(),
		Timestamp: time.Now().UTC(),
		Type:      eventType,
		Severity:  severity,
		Component: component,
		Message:   message,
		Details:   make(map[string]interface{}),
	}
}

// AddDetail adds a key-value detail to the security event
func (e *SecurityEvent) AddDetail(key string, value interface{}) *SecurityEvent {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	return e
}

// SetRemediation sets the remediation advice for the security event
func (e *SecurityEvent) SetRemediation(remediation string) *SecurityEvent {
	e.Remediation = remediation
	return e
}

// SetSource sets the source of the security event
func (e *SecurityEvent) SetSource(source string) *SecurityEvent {
	e.Source = source
	return e
}

// SetUserContext sets user-related context for the security event
func (e *SecurityEvent) SetUserContext(userID, sessionID string) *SecurityEvent {
	e.UserID = userID
	e.SessionID = sessionID
	return e
}

// ToJSON converts the security event to JSON format
func (e *SecurityEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// ValidationResult represents the result of a security validation
type ValidationResult struct {
	Valid    bool                `json:"valid"`
	Errors   []ValidationError   `json:"errors,omitempty"`
	Warnings []ValidationWarning `json:"warnings,omitempty"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// AddError adds a validation error to the result
func (r *ValidationResult) AddError(field, message, code string) {
	r.Valid = false
	r.Errors = append(r.Errors, ValidationError{
		Field:   field,
		Message: message,
		Code:    code,
	})
}

// AddWarning adds a validation warning to the result
func (r *ValidationResult) AddWarning(field, message, code string) {
	r.Warnings = append(r.Warnings, ValidationWarning{
		Field:   field,
		Message: message,
		Code:    code,
	})
}

// HasErrors returns true if the validation result has errors
func (r *ValidationResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// HasWarnings returns true if the validation result has warnings
func (r *ValidationResult) HasWarnings() bool {
	return len(r.Warnings) > 0
}

// generateEventID generates a unique ID for security events
func generateEventID() string {
	// Simple timestamp-based ID for now
	// In production, consider using UUID or other unique ID generation
	return time.Now().Format("20060102150405.000000")
}
