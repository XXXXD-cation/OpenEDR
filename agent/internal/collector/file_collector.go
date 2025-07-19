package collector

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/XXXXD-cation/OpenEDR/agent/internal/config"
	"github.com/XXXXD-cation/OpenEDR/shared/logger"
)

// FileCollector collects file system events using eBPF
type FileCollector struct {
	name      string
	logger    logger.Logger
	config    config.CollectorConfig
	manager   *EBPFManager
	ctx       context.Context
	cancel    context.CancelFunc
	eventChan chan FileEvent
	metrics   CollectorMetrics
}

// FileEvent represents a file system event
type FileEvent struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	UID       uint32    `json:"uid"`
	GID       uint32    `json:"gid"`
	Comm      string    `json:"comm"`
	Filename  string    `json:"filename"`
	Flags     uint32    `json:"flags,omitempty"`
	Mode      uint16    `json:"mode,omitempty"`
	FD        int32     `json:"fd,omitempty"`
	Size      uint64    `json:"size,omitempty"`
	Offset    uint64    `json:"offset,omitempty"`
}

// NewFileCollector creates a new file collector
func NewFileCollector(cfg config.CollectorConfig, logger logger.Logger) *FileCollector {
	ctx, cancel := context.WithCancel(context.Background())

	return &FileCollector{
		name:      "file",
		logger:    logger,
		config:    cfg,
		ctx:       ctx,
		cancel:    cancel,
		eventChan: make(chan FileEvent, 1000),
	}
}

// Name returns the collector name
func (c *FileCollector) Name() string {
	return c.name
}

// Start starts the file collector
func (c *FileCollector) Start(ctx context.Context) error {
	if !c.config.Enabled {
		c.logger.Info("File collector is disabled")
		return nil
	}

	c.logger.Info("Starting file collector")

	// Create eBPF manager
	c.manager = NewEBPFManager(c.logger)

	// Configure eBPF
	ebpfConfig := &Config{
		EnableProcessMonitoring: false,
		EnableNetworkMonitoring: false,
		EnableFileMonitoring:    true,
		EnableSyscallMonitoring: false,
		SamplingRate:            uint32(c.config.SamplingRate * 100),
	}

	// Start eBPF manager
	if err := c.manager.Start(ebpfConfig); err != nil {
		return fmt.Errorf("failed to start eBPF manager: %w", err)
	}

	// Start event processing
	go c.processEvents(ctx)

	c.logger.Info("File collector started")
	return nil
}

// Stop stops the file collector
func (c *FileCollector) Stop() error {
	c.logger.Info("Stopping file collector")

	c.cancel()

	if c.manager != nil {
		if err := c.manager.Stop(); err != nil {
			c.logger.Error("Failed to stop eBPF manager: %v", err)
		}
	}

	close(c.eventChan)

	c.logger.Info("File collector stopped")
	return nil
}

// GetMetrics returns collector metrics
func (c *FileCollector) GetMetrics() CollectorMetrics {
	return c.metrics
}

// GetEventChannel returns the event channel
func (c *FileCollector) GetEventChannel() <-chan FileEvent {
	return c.eventChan
}

// processEvents processes events from eBPF
func (c *FileCollector) processEvents(ctx context.Context) {
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

			// Filter file events
			if event.Type != EventFileOpen && event.Type != EventFileWrite && event.Type != EventFileUnlink {
				continue
			}

			fileEvent := c.convertEvent(event)
			if fileEvent != nil && c.shouldIncludeFile(fileEvent.Filename) {
				select {
				case c.eventChan <- *fileEvent:
					c.metrics.EventsCollected++
					c.metrics.LastEventTime = time.Now()
				default:
					c.logger.Warn("File event channel full, dropping event")
				}
			}
		}
	}
}

// convertEvent converts eBPF event to file event
func (c *FileCollector) convertEvent(event *Event) *FileEvent {
	fileData, ok := event.Data.(*FileEventData)
	if !ok {
		c.metrics.ErrorCount++
		c.metrics.LastError = "invalid file event data"
		return nil
	}

	fileEvent := &FileEvent{
		Timestamp: event.Timestamp,
		PID:       event.PID,
		UID:       event.UID,
		GID:       event.GID,
		Comm:      event.Comm,
		Filename:  fileData.Filename,
		Flags:     fileData.Flags,
		Mode:      fileData.Mode,
		FD:        fileData.FD,
		Size:      fileData.Size,
		Offset:    fileData.Offset,
	}

	// Set event type
	switch event.Type {
	case EventFileOpen:
		fileEvent.Type = "open"
	case EventFileWrite:
		fileEvent.Type = "write"
	case EventFileUnlink:
		fileEvent.Type = "unlink"
	default:
		return nil
	}

	return fileEvent
}

// shouldIncludeFile checks if a file should be included based on configuration
func (c *FileCollector) shouldIncludeFile(filename string) bool {
	// Check exclude paths
	for _, excludePath := range c.config.ExcludePaths {
		if matched, _ := filepath.Match(excludePath, filename); matched {
			return false
		}
		if strings.HasPrefix(filename, excludePath) {
			return false
		}
	}

	// Check include paths (if specified)
	if len(c.config.IncludePaths) > 0 {
		for _, includePath := range c.config.IncludePaths {
			if matched, _ := filepath.Match(includePath, filename); matched {
				return true
			}
			if strings.HasPrefix(filename, includePath) {
				return true
			}
		}
		return false
	}

	return true
}
