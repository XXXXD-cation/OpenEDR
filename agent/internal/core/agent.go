package core

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/XXXXD-cation/OpenEDR/agent/internal/config"
	"github.com/XXXXD-cation/OpenEDR/agent/internal/grpc"
	"github.com/XXXXD-cation/OpenEDR/shared/logger"
	"github.com/XXXXD-cation/OpenEDR/shared/proto/agent"
	"github.com/XXXXD-cation/OpenEDR/shared/proto/common"
)

// Agent represents the EDR agent instance
type Agent struct {
	config     *config.Config
	logger     logger.Logger
	client     *grpc.Client
	collectors []Collector

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Metrics
	startTime time.Time
	status    AgentStatus
	statusMux sync.RWMutex
}

// AgentStatus represents the current agent status
type AgentStatus struct {
	State      string    `json:"state"`
	StartTime  time.Time `json:"start_time"`
	LastUpdate time.Time `json:"last_update"`
	Version    string    `json:"version"`
	Uptime     string    `json:"uptime"`
}

// Collector interface for all data collectors
type Collector interface {
	Name() string
	Start(ctx context.Context) error
	Stop() error
	GetMetrics() CollectorMetrics
}

// CollectorMetrics represents metrics for a collector
type CollectorMetrics struct {
	EventsCollected uint64
	ErrorCount      uint64
	LastError       string
	LastEventTime   time.Time
}

// New creates a new Agent instance
func New(cfg *config.Config, logger logger.Logger) (*Agent, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	ctx, cancel := context.WithCancel(context.Background())

	agent := &Agent{
		config:     cfg,
		logger:     logger,
		collectors: make([]Collector, 0),
		ctx:        ctx,
		cancel:     cancel,
		startTime:  time.Now(),
		status: AgentStatus{
			State:     "initializing",
			StartTime: time.Now(),
			Version:   cfg.Version,
		},
	}

	return agent, nil
}

// RegisterCollector registers a new collector
func (a *Agent) RegisterCollector(collector Collector) {
	a.collectors = append(a.collectors, collector)
	a.logger.Info("Registered collector: %s", collector.Name())
}

// Start starts the agent
func (a *Agent) Start() error {
	a.logger.Info("Starting OpenEDR Agent v%s", a.config.Version)

	// Update status
	a.updateStatus("connecting", "")

	// Initialize gRPC client
	var err error
	clientConfig := grpc.ClientConfig{
		ServerAddr: a.config.ServerAddress,
		TLSConfig:  a.config.TLS,
		AgentInfo:  a.buildAgentInfo(),
		OnCommand:  a.handleCommand,
	}
	a.client, err = grpc.NewClient(clientConfig)
	if err != nil {
		return fmt.Errorf("failed to create gRPC client: %w", err)
	}

	// Connect to server
	if err := a.client.Connect(a.ctx); err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}

	// Register with server
	if err := a.client.Register(a.ctx); err != nil {
		return fmt.Errorf("failed to register with server: %w", err)
	}

	a.updateStatus("running", "Agent started successfully")

	// Start all collectors
	for _, collector := range a.collectors {
		a.wg.Add(1)
		go func(c Collector) {
			defer a.wg.Done()
			a.logger.Info("Starting collector: %s", c.Name())
			if err := c.Start(a.ctx); err != nil {
				a.logger.Error("Collector %s failed: %v", c.Name(), err)
			}
		}(collector)
	}

	// Start health check routine
	a.wg.Add(1)
	go a.healthCheckRoutine()

	// Start metrics reporting routine
	a.wg.Add(1)
	go a.metricsReportingRoutine()

	return nil
}

// Stop stops the agent
func (a *Agent) Stop() error {
	a.logger.Info("Stopping OpenEDR Agent")
	a.updateStatus("stopping", "Agent shutdown initiated")

	// Cancel context to signal all goroutines
	a.cancel()

	// Stop all collectors
	for _, collector := range a.collectors {
		a.logger.Info("Stopping collector: %s", collector.Name())
		if err := collector.Stop(); err != nil {
			a.logger.Error("Error stopping collector %s: %v", collector.Name(), err)
		}
	}

	// Disconnect from server
	if a.client != nil {
		if err := a.client.Close(); err != nil {
			a.logger.Error("Error closing client connection: %v", err)
		}
	}

	// Wait for all goroutines to finish
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()

	// Wait with timeout
	select {
	case <-done:
		a.logger.Info("Agent stopped successfully")
	case <-time.After(30 * time.Second):
		a.logger.Warn("Agent stop timeout - some goroutines may still be running")
	}

	a.updateStatus("stopped", "Agent stopped")
	return nil
}

// GetStatus returns the current agent status
func (a *Agent) GetStatus() AgentStatus {
	a.statusMux.RLock()
	defer a.statusMux.RUnlock()

	status := a.status
	status.Uptime = time.Since(a.startTime).String()
	return status
}

// updateStatus updates the agent status
func (a *Agent) updateStatus(state, message string) {
	a.statusMux.Lock()
	defer a.statusMux.Unlock()

	a.status.State = state
	a.status.LastUpdate = time.Now()

	if message != "" {
		a.logger.Info("Status update: %s - %s", state, message)
	}
}

// healthCheckRoutine performs periodic health checks
func (a *Agent) healthCheckRoutine() {
	defer a.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			// Perform health check
			if err := a.performHealthCheck(); err != nil {
				a.logger.Error("Health check failed: %v", err)
				a.updateStatus("degraded", fmt.Sprintf("Health check failed: %v", err))
			} else {
				a.updateStatus("running", "")
			}
		}
	}
}

// performHealthCheck performs a health check
func (a *Agent) performHealthCheck() error {
	// Check collectors
	for _, collector := range a.collectors {
		metrics := collector.GetMetrics()
		if metrics.LastError != "" {
			a.logger.Warn("Collector %s has errors: %s", collector.Name(), metrics.LastError)
		}
	}

	// Check server connection
	if a.client != nil {
		if err := a.client.HealthCheck(a.ctx); err != nil {
			return fmt.Errorf("server health check failed: %w", err)
		}
	}

	return nil
}

// metricsReportingRoutine reports metrics periodically
func (a *Agent) metricsReportingRoutine() {
	defer a.wg.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.reportMetrics()
		}
	}
}

// reportMetrics reports agent metrics
func (a *Agent) reportMetrics() {
	status := a.GetStatus()
	a.logger.Debug("Agent metrics - Status: %s, Uptime: %s", status.State, status.Uptime)

	// Report collector metrics
	for _, collector := range a.collectors {
		metrics := collector.GetMetrics()
		a.logger.Debug("Collector %s - Events: %d, Errors: %d",
			collector.Name(), metrics.EventsCollected, metrics.ErrorCount)
	}
}

// buildAgentInfo builds agent information for registration
func (a *Agent) buildAgentInfo() *common.AgentInfo {
	hostname, _ := os.Hostname()

	return &common.AgentInfo{
		AgentId:      "", // Will be assigned by server
		Hostname:     hostname,
		Os:           runtime.GOOS,
		OsVersion:    "", // TODO: Get actual OS version
		Architecture: runtime.GOARCH,
		AgentVersion: a.config.Version,
		IpAddress:    "", // TODO: Get actual IP address
		MacAddress:   "", // TODO: Get actual MAC address
		Tags:         make(map[string]string),
	}
}

// handleCommand handles commands from the server
func (a *Agent) handleCommand(cmd *agent.AgentCommand) error {
	a.logger.Info("Received command: %s (ID: %s)", cmd.CommandType, cmd.CommandId)

	switch cmd.CommandType {
	case "restart":
		return a.handleRestartCommand(cmd)
	case "update_config":
		return a.handleUpdateConfigCommand(cmd)
	case "collect_info":
		return a.handleCollectInfoCommand(cmd)
	case "isolate":
		return a.handleIsolateCommand(cmd)
	default:
		return fmt.Errorf("unknown command type: %s", cmd.CommandType)
	}
}

// handleRestartCommand handles restart command
func (a *Agent) handleRestartCommand(cmd *agent.AgentCommand) error {
	a.logger.Info("Executing restart command")
	// TODO: Implement graceful restart
	return fmt.Errorf("restart command not implemented yet")
}

// handleUpdateConfigCommand handles config update command
func (a *Agent) handleUpdateConfigCommand(cmd *agent.AgentCommand) error {
	a.logger.Info("Executing update config command")
	// TODO: Implement config update
	return fmt.Errorf("update config command not implemented yet")
}

// handleCollectInfoCommand handles collect info command
func (a *Agent) handleCollectInfoCommand(cmd *agent.AgentCommand) error {
	a.logger.Info("Executing collect info command")
	// TODO: Implement info collection
	return fmt.Errorf("collect info command not implemented yet")
}

// handleIsolateCommand handles isolate command
func (a *Agent) handleIsolateCommand(cmd *agent.AgentCommand) error {
	a.logger.Info("Executing isolate command")
	// TODO: Implement isolation
	return fmt.Errorf("isolate command not implemented yet")
}
