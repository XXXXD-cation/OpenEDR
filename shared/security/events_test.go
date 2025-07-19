package security

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSecurityEventType_String(t *testing.T) {
	tests := []struct {
		eventType SecurityEventType
		expected  string
	}{
		{PathTraversalAttempt, "PATH_TRAVERSAL_ATTEMPT"},
		{IntegerOverflowDetected, "INTEGER_OVERFLOW_DETECTED"},
		{UnsafeTLSConfiguration, "UNSAFE_TLS_CONFIGURATION"},
		{InvalidArchiveEntry, "INVALID_ARCHIVE_ENTRY"},
		{UnauthorizedFileAccess, "UNAUTHORIZED_FILE_ACCESS"},
		{MaliciousInputDetected, "MALICIOUS_INPUT_DETECTED"},
		{ConfigurationViolation, "CONFIGURATION_VIOLATION"},
		{SecurityEventType(999), "UNKNOWN_SECURITY_EVENT"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.eventType.String()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestSecuritySeverity_String(t *testing.T) {
	tests := []struct {
		severity SecuritySeverity
		expected string
	}{
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
		{SecuritySeverity(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.severity.String()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestNewSecurityEvent(t *testing.T) {
	eventType := PathTraversalAttempt
	severity := SeverityHigh
	component := "test-component"
	message := "test message"

	event := NewSecurityEvent(eventType, severity, component, message)

	if event == nil {
		t.Fatal("expected non-nil event")
	}

	if event.Type != eventType {
		t.Errorf("expected type %v, got %v", eventType, event.Type)
	}

	if event.Severity != severity {
		t.Errorf("expected severity %v, got %v", severity, event.Severity)
	}

	if event.Component != component {
		t.Errorf("expected component %q, got %q", component, event.Component)
	}

	if event.Message != message {
		t.Errorf("expected message %q, got %q", message, event.Message)
	}

	if event.ID == "" {
		t.Error("expected non-empty ID")
	}

	if event.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}

	if event.Details == nil {
		t.Error("expected non-nil details map")
	}
}

func TestSecurityEvent_AddDetail(t *testing.T) {
	event := NewSecurityEvent(PathTraversalAttempt, SeverityHigh, "test", "test")

	key := "test-key"
	value := "test-value"

	result := event.AddDetail(key, value)

	if result != event {
		t.Error("expected AddDetail to return the same event instance")
	}

	if event.Details[key] != value {
		t.Errorf("expected detail %q to be %q, got %v", key, value, event.Details[key])
	}
}

func TestSecurityEvent_SetRemediation(t *testing.T) {
	event := NewSecurityEvent(PathTraversalAttempt, SeverityHigh, "test", "test")

	remediation := "test remediation"
	result := event.SetRemediation(remediation)

	if result != event {
		t.Error("expected SetRemediation to return the same event instance")
	}

	if event.Remediation != remediation {
		t.Errorf("expected remediation %q, got %q", remediation, event.Remediation)
	}
}

func TestSecurityEvent_SetSource(t *testing.T) {
	event := NewSecurityEvent(PathTraversalAttempt, SeverityHigh, "test", "test")

	source := "test-source"
	result := event.SetSource(source)

	if result != event {
		t.Error("expected SetSource to return the same event instance")
	}

	if event.Source != source {
		t.Errorf("expected source %q, got %q", source, event.Source)
	}
}

func TestSecurityEvent_SetUserContext(t *testing.T) {
	event := NewSecurityEvent(PathTraversalAttempt, SeverityHigh, "test", "test")

	userID := "test-user"
	sessionID := "test-session"
	result := event.SetUserContext(userID, sessionID)

	if result != event {
		t.Error("expected SetUserContext to return the same event instance")
	}

	if event.UserID != userID {
		t.Errorf("expected userID %q, got %q", userID, event.UserID)
	}

	if event.SessionID != sessionID {
		t.Errorf("expected sessionID %q, got %q", sessionID, event.SessionID)
	}
}

func TestSecurityEvent_ToJSON(t *testing.T) {
	event := NewSecurityEvent(PathTraversalAttempt, SeverityHigh, "test-component", "test message")
	event.AddDetail("key1", "value1")
	event.SetRemediation("test remediation")
	event.SetSource("test-source")
	event.SetUserContext("user123", "session456")

	jsonData, err := event.ToJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify we can unmarshal it back
	var unmarshaled SecurityEvent
	err = json.Unmarshal(jsonData, &unmarshaled)
	if err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if unmarshaled.Type != event.Type {
		t.Errorf("expected type %v, got %v", event.Type, unmarshaled.Type)
	}

	if unmarshaled.Component != event.Component {
		t.Errorf("expected component %q, got %q", event.Component, unmarshaled.Component)
	}
}

func TestValidationResult_AddError(t *testing.T) {
	result := &ValidationResult{Valid: true}

	field := "test-field"
	message := "test error"
	code := "TEST_ERROR"

	result.AddError(field, message, code)

	if result.Valid {
		t.Error("expected Valid to be false after adding error")
	}

	if len(result.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(result.Errors))
	}

	error := result.Errors[0]
	if error.Field != field {
		t.Errorf("expected field %q, got %q", field, error.Field)
	}

	if error.Message != message {
		t.Errorf("expected message %q, got %q", message, error.Message)
	}

	if error.Code != code {
		t.Errorf("expected code %q, got %q", code, error.Code)
	}
}

func TestValidationResult_AddWarning(t *testing.T) {
	result := &ValidationResult{Valid: true}

	field := "test-field"
	message := "test warning"
	code := "TEST_WARNING"

	result.AddWarning(field, message, code)

	if !result.Valid {
		t.Error("expected Valid to remain true after adding warning")
	}

	if len(result.Warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(result.Warnings))
	}

	warning := result.Warnings[0]
	if warning.Field != field {
		t.Errorf("expected field %q, got %q", field, warning.Field)
	}

	if warning.Message != message {
		t.Errorf("expected message %q, got %q", message, warning.Message)
	}

	if warning.Code != code {
		t.Errorf("expected code %q, got %q", code, warning.Code)
	}
}

func TestValidationResult_HasErrors(t *testing.T) {
	result := &ValidationResult{}

	if result.HasErrors() {
		t.Error("expected HasErrors to be false for empty result")
	}

	result.AddError("field", "message", "code")

	if !result.HasErrors() {
		t.Error("expected HasErrors to be true after adding error")
	}
}

func TestValidationResult_HasWarnings(t *testing.T) {
	result := &ValidationResult{}

	if result.HasWarnings() {
		t.Error("expected HasWarnings to be false for empty result")
	}

	result.AddWarning("field", "message", "code")

	if !result.HasWarnings() {
		t.Error("expected HasWarnings to be true after adding warning")
	}
}

func TestGenerateEventID(t *testing.T) {
	id1 := generateEventID()
	time.Sleep(1 * time.Millisecond) // Ensure different timestamps
	id2 := generateEventID()

	if id1 == "" {
		t.Error("expected non-empty ID")
	}

	if id2 == "" {
		t.Error("expected non-empty ID")
	}

	if id1 == id2 {
		t.Error("expected different IDs for different calls")
	}
}
