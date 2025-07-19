package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.NotNil(t, cfg)
	assert.Equal(t, "1.0.0", cfg.Version)
	assert.Equal(t, "localhost:8443", cfg.ServerAddress)
	assert.Equal(t, "info", cfg.LogLevel)
	assert.NotEmpty(t, cfg.LogFile)

	// Test TLS config
	assert.NotEmpty(t, cfg.TLS.CertFile)
	assert.NotEmpty(t, cfg.TLS.KeyFile)
	assert.NotEmpty(t, cfg.TLS.CAFile)
	assert.Equal(t, "localhost", cfg.TLS.ServerName)

	// Test performance settings
	assert.Equal(t, 5, cfg.Performance.MaxCPUPercent)
	assert.Equal(t, 200, cfg.Performance.MaxMemoryMB)
	assert.Equal(t, 10000, cfg.Performance.EventBufferSize)
	assert.Equal(t, 100, cfg.Performance.BatchSize)
	assert.Equal(t, 10, cfg.Performance.FlushInterval)

	// Test update settings
	assert.True(t, cfg.Update.Enabled)
	assert.Equal(t, 24, cfg.Update.CheckInterval)
	assert.Equal(t, "https://update.openedr.com", cfg.Update.UpdateServer)
	assert.False(t, cfg.Update.AutoUpdate)

	// Test collectors
	assert.True(t, cfg.Collectors.Process.Enabled)
	assert.True(t, cfg.Collectors.Network.Enabled)
	assert.True(t, cfg.Collectors.File.Enabled)
	assert.Equal(t, 1.0, cfg.Collectors.Process.SamplingRate)
	assert.Equal(t, 0.1, cfg.Collectors.File.SamplingRate)
}

func TestLoad_NewFile(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")

	// Load should create default config if file doesn't exist
	cfg, err := Load(configFile)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, configFile, cfg.ConfigFile)
	assert.FileExists(t, configFile)

	// Verify default values
	assert.Equal(t, "1.0.0", cfg.Version)
	assert.Equal(t, "localhost:8443", cfg.ServerAddress)
}

func TestLoad_ExistingYAML(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")

	// Create a test config file
	yamlContent := `
version: "2.0.0"
server_address: "test.example.com:9443"
log_level: "debug"
log_file: "/tmp/test.log"
performance:
  max_cpu_percent: 10
  max_memory_mb: 500
update:
  enabled: false
  auto_update: true
collectors:
  process:
    enabled: false
    sampling_rate: 0.5
`

	err := os.WriteFile(configFile, []byte(yamlContent), 0600)
	require.NoError(t, err)

	cfg, err := Load(configFile)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "2.0.0", cfg.Version)
	assert.Equal(t, "test.example.com:9443", cfg.ServerAddress)
	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, "/tmp/test.log", cfg.LogFile)
	assert.Equal(t, 10, cfg.Performance.MaxCPUPercent)
	assert.Equal(t, 500, cfg.Performance.MaxMemoryMB)
	assert.False(t, cfg.Update.Enabled)
	assert.True(t, cfg.Update.AutoUpdate)
	assert.False(t, cfg.Collectors.Process.Enabled)
	assert.Equal(t, 0.5, cfg.Collectors.Process.SamplingRate)
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid config",
			modify:  func(c *Config) {},
			wantErr: false,
		},
		{
			name: "empty server address",
			modify: func(c *Config) {
				c.ServerAddress = ""
			},
			wantErr: true,
			errMsg:  "server address is required",
		},
		{
			name: "invalid CPU percent - too low",
			modify: func(c *Config) {
				c.Performance.MaxCPUPercent = 0
			},
			wantErr: true,
			errMsg:  "max CPU percent must be between 1 and 100",
		},
		{
			name: "invalid CPU percent - too high",
			modify: func(c *Config) {
				c.Performance.MaxCPUPercent = 101
			},
			wantErr: true,
			errMsg:  "max CPU percent must be between 1 and 100",
		},
		{
			name: "invalid memory - too low",
			modify: func(c *Config) {
				c.Performance.MaxMemoryMB = 10
			},
			wantErr: true,
			errMsg:  "max memory must be at least 50MB",
		},
		{
			name: "invalid event buffer size",
			modify: func(c *Config) {
				c.Performance.EventBufferSize = 50
			},
			wantErr: true,
			errMsg:  "event buffer size must be at least 100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)

			err := cfg.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetSetString(t *testing.T) {
	cfg := DefaultConfig()

	// Test GetString
	assert.Equal(t, "", cfg.GetString("agent_id"))
	assert.Equal(t, "localhost:8443", cfg.GetString("server_address"))
	assert.Equal(t, "info", cfg.GetString("log_level"))
	assert.Equal(t, "", cfg.GetString("unknown_key"))

	// Test SetString
	err := cfg.SetString("agent_id", "test-agent-123")
	assert.NoError(t, err)
	assert.Equal(t, "test-agent-123", cfg.GetString("agent_id"))

	err = cfg.SetString("server_address", "new.example.com:9443")
	assert.NoError(t, err)
	assert.Equal(t, "new.example.com:9443", cfg.GetString("server_address"))

	err = cfg.SetString("log_level", "debug")
	assert.NoError(t, err)
	assert.Equal(t, "debug", cfg.GetString("log_level"))

	// Test unknown key
	err = cfg.SetString("unknown_key", "value")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown config key")
}

func TestLoad_PathValidation(t *testing.T) {
	// Test dangerous path patterns (should be caught even in test environment)
	dangerousPaths := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",
		"/tmp/../../../etc/shadow",
	}

	for _, path := range dangerousPaths {
		t.Run("dangerous_path_"+path, func(t *testing.T) {
			_, err := Load(path)
			// Should fail due to dangerous pattern detection
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "dangerous path pattern")
		})
	}
}

func TestContainsDangerousPatterns(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "safe path",
			path:     "/etc/openedr/config.yaml",
			expected: false,
		},
		{
			name:     "relative safe path",
			path:     "config/agent.yaml",
			expected: false,
		},
		{
			name:     "path traversal with ../",
			path:     "../../../etc/passwd",
			expected: true,
		},
		{
			name:     "path traversal with ..",
			path:     "/tmp/../etc/shadow",
			expected: true,
		},
		{
			name:     "windows path traversal",
			path:     "..\\..\\windows\\system32",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsDangerousPatterns(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}
