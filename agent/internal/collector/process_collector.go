package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/XXXXD-cation/OpenEDR/agent/internal/config"
	"github.com/XXXXD-cation/OpenEDR/shared/logger"
)

// ProcessCollector collects process events using eBPF
type ProcessCollector struct {
	name      string
	logger    logger.Logger
	config    config.CollectorConfig
	manager   *EBPFManager
	ctx       context.Context
	cancel    context.CancelFunc
	eventChan chan ProcessEvent
	metrics   CollectorMetrics
}

// ProcessEvent represents a process event
type ProcessEvent struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	UID       uint32    `json:"uid"`
	GID       uint32    `json:"gid"`
	Comm      string    `json:"comm"`
	Filename  string    `json:"filename,omitempty"`
	Args      string    `json:"args,omitempty"`
	ExitCode  uint32    `json:"exit_code,omitempty"`
}

// CollectorMetrics represents collector metrics
type CollectorMetrics struct {
	EventsCollected uint64
	ErrorCount      uint64
	LastError       string
	LastEventTime   time.Time
}

// ProcessCollectorDebugInfo contains detailed debug information
type ProcessCollectorDebugInfo struct {
	CollectorMetrics   CollectorMetrics       `json:"collector_metrics"`
	EBPFDebugStats     *DebugStats            `json:"ebpf_debug_stats"`
	PerformanceMetrics map[string]interface{} `json:"performance_metrics"`
}

// NewProcessCollector creates a new process collector
func NewProcessCollector(cfg config.CollectorConfig, logger logger.Logger) *ProcessCollector {
	ctx, cancel := context.WithCancel(context.Background())

	return &ProcessCollector{
		name:      "process",
		logger:    logger,
		config:    cfg,
		ctx:       ctx,
		cancel:    cancel,
		eventChan: make(chan ProcessEvent, 1000),
	}
}

// Name returns the collector name
func (c *ProcessCollector) Name() string {
	return c.name
}

// Start starts the process collector
func (c *ProcessCollector) Start(ctx context.Context) error {
	if !c.config.Enabled {
		c.logger.Info("Process collector is disabled")
		return nil
	}

	c.logger.Info("Starting process collector")

	// Create eBPF manager
	c.manager = NewEBPFManager(c.logger)

	// Configure eBPF
	ebpfConfig := &Config{
		EnableProcessMonitoring: true,
		EnableNetworkMonitoring: false,
		EnableFileMonitoring:    false,
		EnableSyscallMonitoring: false,
		SamplingRate:            uint32(c.config.SamplingRate * 100),
	}

	// Start eBPF manager
	if err := c.manager.Start(ebpfConfig); err != nil {
		return fmt.Errorf("failed to start eBPF manager: %w", err)
	}

	// Start event processing
	go c.processEvents(ctx)

	c.logger.Info("Process collector started")
	return nil
}

// Stop stops the process collector
func (c *ProcessCollector) Stop() error {
	c.logger.Info("Stopping process collector")

	c.cancel()

	if c.manager != nil {
		if err := c.manager.Stop(); err != nil {
			c.logger.Error("Failed to stop eBPF manager: %v", err)
		}
	}

	close(c.eventChan)

	c.logger.Info("Process collector stopped")
	return nil
}

// GetMetrics returns collector metrics
func (c *ProcessCollector) GetMetrics() CollectorMetrics {
	return c.metrics
}

// GetEventChannel returns the event channel
func (c *ProcessCollector) GetEventChannel() <-chan ProcessEvent {
	return c.eventChan
}

// processEvents processes events from eBPF
func (c *ProcessCollector) processEvents(ctx context.Context) {
	eventChan := c.manager.GetEventChannel()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.ctx.Done():
			return
		case event, ok := <-eventChan:
			if !ok {
				return
			}

			// Filter process events
			if event.Type != EventProcessExec && event.Type != EventProcessExit {
				continue
			}

			processEvent := c.convertEvent(event)
			if processEvent != nil {
				select {
				case c.eventChan <- *processEvent:
					c.metrics.EventsCollected++
					c.metrics.LastEventTime = time.Now()
				default:
					c.logger.Warn("Process event channel full, dropping event")
				}
			}
		}
	}
}

// convertEvent converts eBPF event to process event
func (c *ProcessCollector) convertEvent(event *Event) *ProcessEvent {
	processData, ok := event.Data.(*ProcessEventData)
	if !ok {
		c.metrics.ErrorCount++
		c.metrics.LastError = "invalid process event data"
		return nil
	}

	processEvent := &ProcessEvent{
		Timestamp: event.Timestamp,
		PID:       event.PID,
		PPID:      processData.PPID,
		UID:       event.UID,
		GID:       event.GID,
		Comm:      event.Comm,
		Filename:  processData.Filename,
		Args:      processData.Args,
		ExitCode:  processData.ExitCode,
	}

	switch event.Type {
	case EventProcessExec:
		processEvent.Type = "exec"
	case EventProcessExit:
		processEvent.Type = "exit"
	default:
		return nil
	}

	return processEvent
}

// GetDebugInfo returns comprehensive debug information including eBPF statistics
func (c *ProcessCollector) GetDebugInfo() (*ProcessCollectorDebugInfo, error) {
	if c.manager == nil {
		return nil, fmt.Errorf("eBPF manager not initialized")
	}

	// Get eBPF debug statistics
	ebpfStats, err := c.manager.GetDebugStats()
	if err != nil {
		return nil, fmt.Errorf("failed to get eBPF debug stats: %w", err)
	}

	// Get performance metrics
	perfMetrics, err := c.manager.GetPerformanceMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to get performance metrics: %w", err)
	}

	debugInfo := &ProcessCollectorDebugInfo{
		CollectorMetrics:   c.metrics,
		EBPFDebugStats:     ebpfStats,
		PerformanceMetrics: perfMetrics,
	}

	return debugInfo, nil
}

// LogDebugInfo logs comprehensive debug information
func (c *ProcessCollector) LogDebugInfo() {
	debugInfo, err := c.GetDebugInfo()
	if err != nil {
		c.logger.Error("Failed to get debug info: %v", err)
		return
	}

	c.logger.Info("Process Collector Debug Information:")
	c.logger.Info("  Collector Events Collected: %d", debugInfo.CollectorMetrics.EventsCollected)
	c.logger.Info("  Collector Error Count: %d", debugInfo.CollectorMetrics.ErrorCount)
	if debugInfo.CollectorMetrics.LastError != "" {
		c.logger.Info("  Collector Last Error: %s", debugInfo.CollectorMetrics.LastError)
	}

	if debugInfo.EBPFDebugStats != nil {
		stats := debugInfo.EBPFDebugStats
		c.logger.Info("  eBPF Events Processed: %d", stats.EventsProcessed)
		c.logger.Info("  eBPF Exec Events: %d", stats.ExecEvents)
		c.logger.Info("  eBPF Exit Events: %d", stats.ExitEvents)
		c.logger.Info("  eBPF Events Dropped: %d", stats.EventsDropped)
		c.logger.Info("  eBPF Allocation Failures: %d", stats.AllocationFailures)
		c.logger.Info("  eBPF Config Errors: %d", stats.ConfigErrors)
		c.logger.Info("  eBPF Data Read Errors: %d", stats.DataReadErrors)
		c.logger.Info("  eBPF Tracepoint Errors: %d", stats.TracepointErrors)
		c.logger.Info("  eBPF Sampling Skipped: %d", stats.SamplingSkipped)
		c.logger.Info("  eBPF PID Filtered: %d", stats.PidFiltered)
	}

	if debugInfo.PerformanceMetrics != nil {
		if errorRate, ok := debugInfo.PerformanceMetrics["error_rate"].(float64); ok {
			c.logger.Info("  Error Rate: %.2f%%", errorRate*100)
		}
		if allocFailureRate, ok := debugInfo.PerformanceMetrics["allocation_failure_rate"].(float64); ok {
			c.logger.Info("  Allocation Failure Rate: %.2f%%", allocFailureRate*100)
		}
	}
}

// ResetDebugStats resets eBPF debug statistics
func (c *ProcessCollector) ResetDebugStats() error {
	if c.manager == nil {
		return fmt.Errorf("eBPF manager not initialized")
	}

	if err := c.manager.ResetDebugStats(); err != nil {
		return fmt.Errorf("failed to reset eBPF debug stats: %w", err)
	}

	// Reset collector metrics as well
	c.metrics.EventsCollected = 0
	c.metrics.ErrorCount = 0
	c.metrics.LastError = ""

	c.logger.Info("Process collector debug statistics reset")
	return nil
}

// StartDebugMonitoring starts periodic debug statistics monitoring
func (c *ProcessCollector) StartDebugMonitoring(interval time.Duration) {
	if c.manager == nil {
		c.logger.Error("Cannot start debug monitoring: eBPF manager not initialized")
		return
	}

	// Start eBPF debug stats monitoring
	c.manager.StartDebugStatsMonitoring(interval)

	// Start collector-level debug monitoring
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				c.LogDebugInfo()
			}
		}
	}()

	c.logger.Info("Process collector debug monitoring started with interval: %v", interval)
}

// GetEBPFDebugStats returns eBPF debug statistics directly
func (c *ProcessCollector) GetEBPFDebugStats() (*DebugStats, error) {
	if c.manager == nil {
		return nil, fmt.Errorf("eBPF manager not initialized")
	}

	return c.manager.GetDebugStats()
}

// GetPerformanceMetrics returns performance metrics
func (c *ProcessCollector) GetPerformanceMetrics() (map[string]interface{}, error) {
	if c.manager == nil {
		return nil, fmt.Errorf("eBPF manager not initialized")
	}

	return c.manager.GetPerformanceMetrics()
}

// ProcessCollectorMonitoringInterface provides advanced monitoring capabilities
type ProcessCollectorMonitoringInterface struct {
	collector      *ProcessCollector
	debugInterface *DebugInterface
	logger         logger.Logger
}

// NewMonitoringInterface creates a new monitoring interface
func (c *ProcessCollector) NewMonitoringInterface() *ProcessCollectorMonitoringInterface {
	var debugInterface *DebugInterface
	if c.manager != nil {
		debugInterface = c.manager.NewDebugInterface()
	}

	return &ProcessCollectorMonitoringInterface{
		collector:      c,
		debugInterface: debugInterface,
		logger:         c.logger,
	}
}

// GetDetailedStatus returns comprehensive status information
func (m *ProcessCollectorMonitoringInterface) GetDetailedStatus() map[string]interface{} {
	status := make(map[string]interface{})

	// Basic collector info
	status["collector_name"] = m.collector.Name()
	status["collector_enabled"] = m.collector.config.Enabled
	status["sampling_rate"] = m.collector.config.SamplingRate

	// Collector metrics
	metrics := m.collector.GetMetrics()
	status["collector_metrics"] = map[string]interface{}{
		"events_collected": metrics.EventsCollected,
		"error_count":      metrics.ErrorCount,
		"last_error":       metrics.LastError,
		"last_event_time":  metrics.LastEventTime,
	}

	// eBPF metrics if available
	if m.debugInterface != nil {
		ebpfMetrics, err := m.debugInterface.GetComprehensiveMetrics()
		if err == nil {
			status["ebpf_metrics"] = ebpfMetrics
		} else {
			status["ebpf_metrics_error"] = err.Error()
		}
	}

	return status
}

// GenerateHealthReport generates a comprehensive health report
func (m *ProcessCollectorMonitoringInterface) GenerateHealthReport() map[string]interface{} {
	report := make(map[string]interface{})

	// Overall health status
	health := "healthy"
	issues := []string{}

	// Check collector metrics
	metrics := m.collector.GetMetrics()
	if metrics.ErrorCount > 0 {
		errorRate := float64(metrics.ErrorCount) / float64(metrics.EventsCollected+metrics.ErrorCount)
		if errorRate > 0.05 { // More than 5% error rate
			health = "degraded"
			issues = append(issues, fmt.Sprintf("High error rate: %.2f%%", errorRate*100))
		}
	}

	// Check eBPF health if available
	if m.debugInterface != nil {
		ebpfMetrics, err := m.debugInterface.GetComprehensiveMetrics()
		if err != nil {
			health = "unhealthy"
			issues = append(issues, "Cannot retrieve eBPF metrics")
		} else {
			// Check for allocation failures
			if ebpfMetrics.AllocationFailures > 0 {
				totalEvents := ebpfMetrics.EventsProcessed + ebpfMetrics.EventsDropped
				if totalEvents > 0 {
					failureRate := float64(ebpfMetrics.AllocationFailures) / float64(totalEvents)
					if failureRate > 0.01 { // More than 1% allocation failure rate
						health = "degraded"
						issues = append(issues, fmt.Sprintf("High allocation failure rate: %.2f%%", failureRate*100))
					}
				}
			}

			// Check ring buffer usage
			if ebpfMetrics.RingBufferUsage > 80.0 {
				health = "degraded"
				issues = append(issues, fmt.Sprintf("High ring buffer usage: %.2f%%", ebpfMetrics.RingBufferUsage))
			}
		}
	}

	report["health_status"] = health
	report["issues"] = issues
	report["timestamp"] = time.Now()
	report["detailed_status"] = m.GetDetailedStatus()

	return report
}

// ExportDiagnostics exports comprehensive diagnostic information
func (m *ProcessCollectorMonitoringInterface) ExportDiagnostics(format string) ([]byte, error) {
	diagnostics := map[string]interface{}{
		"timestamp": time.Now(),
		"collector_info": map[string]interface{}{
			"name":   m.collector.Name(),
			"config": m.collector.config,
		},
		"health_report":   m.GenerateHealthReport(),
		"detailed_status": m.GetDetailedStatus(),
	}

	// Add metrics history if available
	if m.debugInterface != nil {
		diagnostics["metrics_history"] = m.debugInterface.GetMetricsHistory()
	}

	switch format {
	case "json":
		return json.MarshalIndent(diagnostics, "", "  ")
	case "csv":
		if m.debugInterface != nil {
			return m.debugInterface.ExportMetricsCSV()
		}
		return nil, fmt.Errorf("CSV export requires debug interface")
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}
