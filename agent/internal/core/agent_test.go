package core

import (
	"context"
	"testing"
	"time"

	"github.com/XXXXD-cation/OpenEDR/agent/internal/config"
	"github.com/XXXXD-cation/OpenEDR/shared/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockCollector implements the Collector interface for testing
type MockCollector struct {
	name    string
	started bool
	stopped bool
	metrics CollectorMetrics
}

func (m *MockCollector) Name() string {
	return m.name
}

func (m *MockCollector) Start(ctx context.Context) error {
	m.started = true
	// Simulate collector running
	<-ctx.Done()
	return nil
}

func (m *MockCollector) Stop() error {
	m.stopped = true
	return nil
}

func (m *MockCollector) GetMetrics() CollectorMetrics {
	return m.metrics
}

func TestNew(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Version = "test-version"

	log, err := logger.New(logger.LogConfig{Level: "debug"})
	require.NoError(t, err)
	defer log.Close()

	agent, err := New(cfg, log)
	require.NoError(t, err)
	require.NotNil(t, agent)

	status := agent.GetStatus()
	assert.Equal(t, "initializing", status.State)
	assert.Equal(t, "test-version", status.Version)
	assert.NotZero(t, status.StartTime)
}

func TestNew_InvalidInputs(t *testing.T) {
	cfg := config.DefaultConfig()
	log, err := logger.New(logger.LogConfig{Level: "debug"})
	require.NoError(t, err)
	defer log.Close()

	// Test nil config
	agent, err := New(nil, log)
	assert.Error(t, err)
	assert.Nil(t, agent)
	assert.Contains(t, err.Error(), "config is required")

	// Test nil logger
	agent, err = New(cfg, nil)
	assert.Error(t, err)
	assert.Nil(t, agent)
	assert.Contains(t, err.Error(), "logger is required")
}

func TestRegisterCollector(t *testing.T) {
	cfg := config.DefaultConfig()
	log, err := logger.New(logger.LogConfig{Level: "debug"})
	require.NoError(t, err)
	defer log.Close()

	agent, err := New(cfg, log)
	require.NoError(t, err)

	collector := &MockCollector{name: "test-collector"}
	agent.RegisterCollector(collector)

	// We can't directly test if collector is registered without exposing internals
	// But we can test that it doesn't panic and the agent still works
	status := agent.GetStatus()
	assert.Equal(t, "initializing", status.State)
}

func TestGetStatus(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Version = "test-version-123"

	log, err := logger.New(logger.LogConfig{Level: "debug"})
	require.NoError(t, err)
	defer log.Close()

	agent, err := New(cfg, log)
	require.NoError(t, err)

	status := agent.GetStatus()
	assert.Equal(t, "initializing", status.State)
	assert.Equal(t, "test-version-123", status.Version)
	assert.NotZero(t, status.StartTime)
	assert.NotEmpty(t, status.Uptime)
}

func TestAgentStatus_Concurrent(t *testing.T) {
	cfg := config.DefaultConfig()
	log, err := logger.New(logger.LogConfig{Level: "debug"})
	require.NoError(t, err)
	defer log.Close()

	agent, err := New(cfg, log)
	require.NoError(t, err)

	// Test concurrent access to status
	done := make(chan bool)

	// Start multiple goroutines accessing status
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < 100; j++ {
				status := agent.GetStatus()
				assert.NotEmpty(t, status.State)
				assert.NotEmpty(t, status.Version)
			}
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent status access")
		}
	}
}

func TestCollectorMetrics(t *testing.T) {
	// Test CollectorMetrics struct
	metrics := CollectorMetrics{
		EventsCollected: 1000,
		ErrorCount:      5,
		LastError:       "connection timeout",
		LastEventTime:   time.Now(),
	}

	assert.Equal(t, uint64(1000), metrics.EventsCollected)
	assert.Equal(t, uint64(5), metrics.ErrorCount)
	assert.Equal(t, "connection timeout", metrics.LastError)
	assert.NotZero(t, metrics.LastEventTime)
}
