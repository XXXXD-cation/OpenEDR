package collector

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/XXXXD-cation/OpenEDR/agent/internal/config"
	"github.com/XXXXD-cation/OpenEDR/shared/logger"
)

// NetworkCollector collects network events using eBPF
type NetworkCollector struct {
	name      string
	logger    logger.Logger
	config    config.CollectorConfig
	manager   *EBPFManager
	ctx       context.Context
	cancel    context.CancelFunc
	eventChan chan NetworkEvent
	metrics   CollectorMetrics
}

// NetworkEvent represents a network event
type NetworkEvent struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	UID       uint32    `json:"uid"`
	GID       uint32    `json:"gid"`
	Comm      string    `json:"comm"`
	Family    string    `json:"family"`
	Protocol  string    `json:"protocol"`
	SrcAddr   string    `json:"src_addr"`
	DstAddr   string    `json:"dst_addr"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
}

// NewNetworkCollector creates a new network collector
func NewNetworkCollector(cfg config.CollectorConfig, logger logger.Logger) *NetworkCollector {
	ctx, cancel := context.WithCancel(context.Background())

	return &NetworkCollector{
		name:      "network",
		logger:    logger,
		config:    cfg,
		ctx:       ctx,
		cancel:    cancel,
		eventChan: make(chan NetworkEvent, 1000),
	}
}

// Name returns the collector name
func (c *NetworkCollector) Name() string {
	return c.name
}

// Start starts the network collector
func (c *NetworkCollector) Start(ctx context.Context) error {
	if !c.config.Enabled {
		c.logger.Info("Network collector is disabled")
		return nil
	}

	c.logger.Info("Starting network collector")

	// Create eBPF manager
	c.manager = NewEBPFManager(c.logger)

	// Configure eBPF
	ebpfConfig := &Config{
		EnableProcessMonitoring: false,
		EnableNetworkMonitoring: true,
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

	c.logger.Info("Network collector started")
	return nil
}

// Stop stops the network collector
func (c *NetworkCollector) Stop() error {
	c.logger.Info("Stopping network collector")

	c.cancel()

	if c.manager != nil {
		if err := c.manager.Stop(); err != nil {
			c.logger.Error("Failed to stop eBPF manager: %v", err)
		}
	}

	close(c.eventChan)

	c.logger.Info("Network collector stopped")
	return nil
}

// GetMetrics returns collector metrics
func (c *NetworkCollector) GetMetrics() CollectorMetrics {
	return c.metrics
}

// GetEventChannel returns the event channel
func (c *NetworkCollector) GetEventChannel() <-chan NetworkEvent {
	return c.eventChan
}

// processEvents processes events from eBPF
func (c *NetworkCollector) processEvents(ctx context.Context) {
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

			// Filter network events
			if event.Type != EventNetworkConnect && event.Type != EventNetworkAccept {
				continue
			}

			networkEvent := c.convertEvent(event)
			if networkEvent != nil {
				select {
				case c.eventChan <- *networkEvent:
					c.metrics.EventsCollected++
					c.metrics.LastEventTime = time.Now()
				default:
					c.logger.Warn("Network event channel full, dropping event")
				}
			}
		}
	}
}

// convertEvent converts eBPF event to network event
func (c *NetworkCollector) convertEvent(event *Event) *NetworkEvent {
	networkData, ok := event.Data.(*NetworkEventData)
	if !ok {
		c.metrics.ErrorCount++
		c.metrics.LastError = "invalid network event data"
		return nil
	}

	networkEvent := &NetworkEvent{
		Timestamp: event.Timestamp,
		PID:       event.PID,
		UID:       event.UID,
		GID:       event.GID,
		Comm:      event.Comm,
		SrcPort:   networkData.SPort,
		DstPort:   networkData.DPort,
	}

	// Set event type
	switch event.Type {
	case EventNetworkConnect:
		networkEvent.Type = "connect"
	case EventNetworkAccept:
		networkEvent.Type = "accept"
	default:
		return nil
	}

	// Set family
	switch networkData.Family {
	case 2: // AF_INET
		networkEvent.Family = "ipv4"
		if len(networkData.SAddr) >= 4 {
			networkEvent.SrcAddr = net.IP(networkData.SAddr[:4]).String()
		}
		if len(networkData.DAddr) >= 4 {
			networkEvent.DstAddr = net.IP(networkData.DAddr[:4]).String()
		}
	case 10: // AF_INET6
		networkEvent.Family = "ipv6"
		if len(networkData.SAddr) >= 16 {
			networkEvent.SrcAddr = net.IP(networkData.SAddr[:16]).String()
		}
		if len(networkData.DAddr) >= 16 {
			networkEvent.DstAddr = net.IP(networkData.DAddr[:16]).String()
		}
	default:
		networkEvent.Family = "unknown"
	}

	// Set protocol
	switch networkData.Protocol {
	case 6: // IPPROTO_TCP
		networkEvent.Protocol = "tcp"
	case 17: // IPPROTO_UDP
		networkEvent.Protocol = "udp"
	default:
		networkEvent.Protocol = "unknown"
	}

	return networkEvent
}
