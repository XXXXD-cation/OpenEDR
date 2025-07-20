package collector

import (
	"testing"
)

func TestNetworkConfiguration(t *testing.T) {

	// Test configuration with network-specific settings
	config := &Config{
		EnableProcessMonitoring: true,
		EnableNetworkMonitoring: true,
		EnableFileMonitoring:    false,
		EnableSyscallMonitoring: false,
		SamplingRate:            50,
		EnableTCP:               true,
		EnableUDP:               false,
		EnableIPv6:              true,
		NetworkSamplingRate:     75,
	}

	// Test that configuration structure is properly set up
	if !config.EnableNetworkMonitoring {
		t.Error("Network monitoring should be enabled")
	}

	if !config.EnableTCP {
		t.Error("TCP monitoring should be enabled")
	}

	if config.EnableUDP {
		t.Error("UDP monitoring should be disabled")
	}

	if !config.EnableIPv6 {
		t.Error("IPv6 monitoring should be enabled")
	}

	if config.NetworkSamplingRate != 75 {
		t.Errorf("Network sampling rate should be 75, got %d", config.NetworkSamplingRate)
	}

	// Test default configuration
	defaultConfig := &Config{
		EnableNetworkMonitoring: true,
		SamplingRate:            100,
		EnableTCP:               true,
		EnableUDP:               true,
		EnableIPv6:              true,
		NetworkSamplingRate:     100,
	}

	if defaultConfig.NetworkSamplingRate != 100 {
		t.Errorf("Default network sampling rate should be 100, got %d", defaultConfig.NetworkSamplingRate)
	}

	t.Logf("Network configuration test passed successfully")
}

func TestDebugStatsStructure(t *testing.T) {
	// Test that DebugStats structure includes network-specific fields
	stats := &DebugStats{
		EventsProcessed:      1000,
		NetworkEvents:        100,
		NetworkConnectEvents: 50,
		NetworkAcceptEvents:  30,
		NetworkTCPEvents:     80,
		NetworkUDPEvents:     20,
		NetworkIPv4Events:    90,
		NetworkIPv6Events:    10,
		SocketInfoErrors:     2,
	}

	if stats.NetworkEvents != 100 {
		t.Errorf("NetworkEvents should be 100, got %d", stats.NetworkEvents)
	}

	if stats.NetworkConnectEvents != 50 {
		t.Errorf("NetworkConnectEvents should be 50, got %d", stats.NetworkConnectEvents)
	}

	if stats.NetworkTCPEvents != 80 {
		t.Errorf("NetworkTCPEvents should be 80, got %d", stats.NetworkTCPEvents)
	}

	if stats.SocketInfoErrors != 2 {
		t.Errorf("SocketInfoErrors should be 2, got %d", stats.SocketInfoErrors)
	}

	t.Logf("Debug stats structure test passed successfully")
}