package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		config  LogConfig
		wantErr bool
	}{
		{
			name: "console logger",
			config: LogConfig{
				Level: "info",
				File:  "", // 明确指定为控制台输出
			},
			wantErr: false,
		},
		{
			name: "file logger",
			config: LogConfig{
				Level:      "debug",
				File:       filepath.Join(t.TempDir(), "test.log"),
				MaxSize:    10,
				MaxBackups: 3,
				MaxAge:     7,
				Compress:   true,
			},
			wantErr: false,
		},
		{
			name: "invalid directory",
			config: LogConfig{
				Level: "info",
				File:  "/invalid/path/test.log",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := New(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, log)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, log)
				if log != nil {
					// 对于控制台logger，Close可能会返回sync错误，这在测试环境中是正常的
					err := log.Close()
					if tt.config.File == "" {
						// 控制台logger的sync错误是可以接受的
						if err != nil && !strings.Contains(err.Error(), "sync") {
							t.Errorf("Unexpected error: %v", err)
						}
					} else {
						assert.NoError(t, err)
					}
				}
			}
		})
	}
}

func TestZapLogger_LogLevels(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	config := LogConfig{
		Level:      "debug",
		File:       logFile,
		MaxSize:    10,
		MaxBackups: 3,
		MaxAge:     7,
		Compress:   false,
	}

	log, err := New(config)
	require.NoError(t, err)
	require.NotNil(t, log)
	defer log.Close()

	// Test all log levels
	log.Debug("debug message: %s", "test")
	log.Info("info message: %s", "test")
	log.Warn("warn message: %s", "test")
	log.Error("error message: %s", "test")

	// Give some time for async logging
	time.Sleep(100 * time.Millisecond)

	// Check if log file was created and contains messages
	assert.FileExists(t, logFile)

	content, err := os.ReadFile(logFile)
	require.NoError(t, err)

	logContent := string(content)
	assert.Contains(t, logContent, "debug message")
	assert.Contains(t, logContent, "info message")
	assert.Contains(t, logContent, "warn message")
	assert.Contains(t, logContent, "error message")
}

func TestZapLogger_SetLevel(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	config := LogConfig{
		Level: "info",
		File:  logFile,
	}

	log, err := New(config)
	require.NoError(t, err)
	require.NotNil(t, log)
	defer log.Close()

	// Log at different levels
	log.Debug("debug message - should not appear")
	log.Info("info message - should appear")

	// Change level to debug
	log.SetLevel(DebugLevel)
	log.Debug("debug message - should appear after level change")

	time.Sleep(100 * time.Millisecond)

	content, err := os.ReadFile(logFile)
	require.NoError(t, err)

	logContent := string(content)
	// First debug message should not be there (count should be 0)
	assert.Equal(t, 0, strings.Count(logContent, "debug message - should not appear"))
	// Info message should be there
	assert.Contains(t, logContent, "info message - should appear")
	// Second debug message should be there
	assert.Contains(t, logContent, "debug message - should appear after level change")
}

func TestZapLogger_GetMetrics(t *testing.T) {
	config := LogConfig{
		Level: "debug",
	}

	log, err := New(config)
	require.NoError(t, err)
	require.NotNil(t, log)
	defer log.Close()

	// Log some messages
	log.Debug("debug")
	log.Info("info")
	log.Warn("warn")
	log.Error("error")
	log.Error("another error")

	metrics := log.GetMetrics()
	assert.Equal(t, int64(1), metrics["DEBUG"])
	assert.Equal(t, int64(1), metrics["INFO"])
	assert.Equal(t, int64(1), metrics["WARN"])
	assert.Equal(t, int64(2), metrics["ERROR"])
	assert.Equal(t, int64(2), metrics["errors"]) // Total error count
}

func TestGlobalLogger(t *testing.T) {
	// Test global logger functions
	Debug("global debug: %s", "test")
	Info("global info: %s", "test")
	Warn("global warn: %s", "test")
	Error("global error: %s", "test")

	// Create custom logger and set as global
	config := LogConfig{
		Level: "warn",
	}

	customLog, err := New(config)
	require.NoError(t, err)
	defer customLog.Close()

	SetGlobalLogger(customLog)

	// These should work without panicking
	Debug("should not appear")
	Warn("should appear")
}

func TestLogRotation(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "rotation_test.log")

	config := LogConfig{
		Level:      "info",
		File:       logFile,
		MaxSize:    1, // 1MB - small for testing
		MaxBackups: 2,
		MaxAge:     1,
		Compress:   false,
	}

	log, err := New(config)
	require.NoError(t, err)
	require.NotNil(t, log)
	defer log.Close()

	// Log a message to create the file
	log.Info("test message")
	time.Sleep(100 * time.Millisecond)

	// Verify log file exists
	assert.FileExists(t, logFile)
}
