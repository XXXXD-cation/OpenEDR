package collector

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/XXXXD-cation/OpenEDR/shared/logger"
	"github.com/XXXXD-cation/OpenEDR/shared/security"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// EBPFManager manages eBPF programs and maps
type EBPFManager struct {
	logger    logger.Logger
	programs  map[string]*ebpf.Program
	links     map[string]link.Link
	maps      map[string]*ebpf.Map
	readers   map[string]*ringbuf.Reader
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	eventChan chan *Event
	startTime time.Time
}

// Event represents a generic eBPF event
type Event struct {
	Type      EventType
	Timestamp time.Time
	PID       uint32
	TGID      uint32
	UID       uint32
	GID       uint32
	CPU       uint32
	Comm      string
	Data      interface{}
}

// EventType represents the type of event
type EventType uint32

const (
	EventProcessExec EventType = iota + 1
	EventProcessExit
	EventNetworkConnect
	EventNetworkAccept
	EventFileOpen
	EventFileWrite
	EventFileUnlink
	EventSyscall
)

// ProcessEventData contains process-specific event data
type ProcessEventData struct {
	PPID     uint32
	ExitCode uint32
	Filename string
	Args     string
}

// NetworkEventData contains network-specific event data
type NetworkEventData struct {
	Family   uint16
	Protocol uint16
	SPort    uint16
	DPort    uint16
	SAddr    []byte
	DAddr    []byte
}

// FileEventData contains file-specific event data
type FileEventData struct {
	Flags    uint32
	Mode     uint16
	FD       int32
	Size     uint64
	Offset   uint64
	Filename string
}

// SyscallEventData contains syscall-specific event data
type SyscallEventData struct {
	SyscallNr uint64
	Args      [6]uint64
	Ret       int64
}

// DebugStats contains eBPF debug and error statistics
type DebugStats struct {
	EventsProcessed    uint64 `json:"events_processed"`
	EventsDropped      uint64 `json:"events_dropped"`
	AllocationFailures uint64 `json:"allocation_failures"`
	ConfigErrors       uint64 `json:"config_errors"`
	DataReadErrors     uint64 `json:"data_read_errors"`
	TracepointErrors   uint64 `json:"tracepoint_errors"`
	ExecEvents         uint64 `json:"exec_events"`
	ExitEvents         uint64 `json:"exit_events"`
	SamplingSkipped    uint64 `json:"sampling_skipped"`
	PidFiltered        uint64 `json:"pid_filtered"`
	LastErrorTimestamp uint64 `json:"last_error_timestamp"`
	LastErrorType      uint32 `json:"last_error_type"`
	LastErrorPid       uint32 `json:"last_error_pid"`
}

// Config represents eBPF configuration
type Config struct {
	EnableProcessMonitoring bool
	EnableNetworkMonitoring bool
	EnableFileMonitoring    bool
	EnableSyscallMonitoring bool
	SamplingRate            uint32
}

// NewEBPFManager creates a new eBPF manager
func NewEBPFManager(logger logger.Logger) *EBPFManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &EBPFManager{
		logger:    logger,
		programs:  make(map[string]*ebpf.Program),
		links:     make(map[string]link.Link),
		maps:      make(map[string]*ebpf.Map),
		readers:   make(map[string]*ringbuf.Reader),
		ctx:       ctx,
		cancel:    cancel,
		eventChan: make(chan *Event, 10000),
		startTime: time.Now(),
	}
}

// Start initializes and starts eBPF programs
func (m *EBPFManager) Start(config *Config) error {
	m.logger.Info("Starting eBPF manager")

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Load eBPF programs
	if err := m.loadPrograms(); err != nil {
		return fmt.Errorf("failed to load eBPF programs: %w", err)
	}

	// Configure programs
	if err := m.configurePrograms(config); err != nil {
		return fmt.Errorf("failed to configure eBPF programs: %w", err)
	}

	// Attach programs
	if err := m.attachPrograms(config); err != nil {
		return fmt.Errorf("failed to attach eBPF programs: %w", err)
	}

	// Start event readers
	if err := m.startEventReaders(); err != nil {
		return fmt.Errorf("failed to start event readers: %w", err)
	}

	m.logger.Info("eBPF manager started successfully")
	return nil
}

// Stop stops all eBPF programs and cleans up resources
func (m *EBPFManager) Stop() error {
	m.logger.Info("Stopping eBPF manager")

	// Cancel context to stop all goroutines
	m.cancel()

	// Wait for all goroutines to finish
	m.wg.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Close ring buffer readers
	for name, reader := range m.readers {
		if err := reader.Close(); err != nil {
			m.logger.Error("Failed to close ring buffer reader %s: %v", name, err)
		}
	}

	// Detach links
	for name, l := range m.links {
		if err := l.Close(); err != nil {
			m.logger.Error("Failed to close link %s: %v", name, err)
		}
	}

	// Close maps
	for name, mapObj := range m.maps {
		if err := mapObj.Close(); err != nil {
			m.logger.Error("Failed to close map %s: %v", name, err)
		}
	}

	// Close programs
	for name, prog := range m.programs {
		if err := prog.Close(); err != nil {
			m.logger.Error("Failed to close program %s: %v", name, err)
		}
	}

	// Close event channel
	close(m.eventChan)

	m.logger.Info("eBPF manager stopped")
	return nil
}

// GetEventChannel returns the event channel
func (m *EBPFManager) GetEventChannel() <-chan *Event {
	return m.eventChan
}

// ProcessMonitorVersion represents the version of process monitor to use
type ProcessMonitorVersion int

const (
	ProcessMonitorV1 ProcessMonitorVersion = iota // kprobe-based (fallback)
	ProcessMonitorV2                              // tracepoint-based (optimized)
)

// KernelCapabilities represents detected kernel capabilities
type KernelCapabilities struct {
	SupportsTracepoints   bool
	SupportsRingBuffer    bool
	KernelVersion         string
	HasSchedProcessExec   bool
	HasSchedProcessExit   bool
	HasSyscallTracepoints bool
}

// detectKernelCapabilities detects kernel capabilities for eBPF features
func (m *EBPFManager) detectKernelCapabilities() (*KernelCapabilities, error) {
	caps := &KernelCapabilities{}

	// Get kernel version
	if data, err := os.ReadFile("/proc/version"); err == nil {
		caps.KernelVersion = strings.TrimSpace(string(data))
	}

	// Check for BTF support (indicates modern kernel)
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		caps.SupportsTracepoints = true
		caps.SupportsRingBuffer = true
	}

	// Check for specific tracepoints
	tracepointDir := "/sys/kernel/debug/tracing/events"

	// Check for sched_process_exec tracepoint
	if _, err := os.Stat(filepath.Join(tracepointDir, "sched", "sched_process_exec")); err == nil {
		caps.HasSchedProcessExec = true
	}

	// Check for sched_process_exit tracepoint
	if _, err := os.Stat(filepath.Join(tracepointDir, "sched", "sched_process_exit")); err == nil {
		caps.HasSchedProcessExit = true
	}

	// Check for syscall tracepoints
	if _, err := os.Stat(filepath.Join(tracepointDir, "syscalls")); err == nil {
		caps.HasSyscallTracepoints = true
	}

	// Check for ring buffer support (available in newer kernels)
	if _, err := os.Stat("/sys/fs/bpf"); err == nil {
		caps.SupportsRingBuffer = true
	}

	m.logger.Info("Detected kernel capabilities:")
	m.logger.Info("  Kernel Version: %s", caps.KernelVersion)
	m.logger.Info("  Tracepoints Support: %v", caps.SupportsTracepoints)
	m.logger.Info("  Ring Buffer Support: %v", caps.SupportsRingBuffer)
	m.logger.Info("  sched_process_exec: %v", caps.HasSchedProcessExec)
	m.logger.Info("  sched_process_exit: %v", caps.HasSchedProcessExit)
	m.logger.Info("  Syscall Tracepoints: %v", caps.HasSyscallTracepoints)

	return caps, nil
}

// selectProcessMonitorVersion selects the appropriate process monitor version
func (m *EBPFManager) selectProcessMonitorVersion(caps *KernelCapabilities) ProcessMonitorVersion {
	// Prefer V2 (tracepoint-based) if kernel supports it
	if caps.SupportsTracepoints && caps.HasSchedProcessExec && caps.HasSchedProcessExit {
		m.logger.Info("Selected process monitor V2 (tracepoint-based)")
		return ProcessMonitorV2
	}

	// Fallback to V1 (kprobe-based) for older kernels
	m.logger.Info("Selected process monitor V1 (kprobe-based) - fallback mode")
	return ProcessMonitorV1
}

// loadPrograms loads eBPF programs from object files with version selection
func (m *EBPFManager) loadPrograms() error {
	programDir := "/opt/openedr/ebpf"
	if _, err := os.Stat(programDir); os.IsNotExist(err) {
		// Fallback to local build directory
		programDir = "agent/ebpf/build"
	}

	// Detect kernel capabilities
	caps, err := m.detectKernelCapabilities()
	if err != nil {
		m.logger.Warn("Failed to detect kernel capabilities: %v, using fallback", err)
		caps = &KernelCapabilities{} // Use empty capabilities (will select V1)
	}

	// Select process monitor version based on capabilities
	version := m.selectProcessMonitorVersion(caps)

	// Determine which process monitor file to load
	var processMonitorFile string
	switch version {
	case ProcessMonitorV2:
		processMonitorFile = "process_monitor_v2.o"
	case ProcessMonitorV1:
		processMonitorFile = "process_monitor.o"
	default:
		processMonitorFile = "process_monitor.o" // Default fallback
	}

	programs := []string{
		processMonitorFile,
		"network_monitor.o",
		"file_monitor.o",
	}

	for _, progFile := range programs {
		progPath := filepath.Join(programDir, progFile)
		if _, err := os.Stat(progPath); os.IsNotExist(err) {
			m.logger.Warn("eBPF program not found: %s", progPath)

			// If V2 is not available, try to fallback to V1
			if progFile == "process_monitor_v2.o" {
				m.logger.Info("Process monitor V2 not found, falling back to V1")
				progFile = "process_monitor.o"
				progPath = filepath.Join(programDir, progFile)

				if _, err := os.Stat(progPath); os.IsNotExist(err) {
					m.logger.Error("Process monitor V1 also not found: %s", progPath)
					continue
				}
			} else {
				continue
			}
		}

		spec, err := ebpf.LoadCollectionSpec(progPath)
		if err != nil {
			// If V2 fails to load, try V1 as fallback
			if progFile == "process_monitor_v2.o" {
				m.logger.Warn("Failed to load process monitor V2: %v, trying V1", err)
				progFile = "process_monitor.o"
				progPath = filepath.Join(programDir, progFile)

				spec, err = ebpf.LoadCollectionSpec(progPath)
				if err != nil {
					return fmt.Errorf("failed to load both V2 and V1 process monitors: %w", err)
				}
			} else {
				return fmt.Errorf("failed to load spec for %s: %w", progFile, err)
			}
		}

		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			// Similar fallback logic for collection creation
			if progFile == "process_monitor_v2.o" {
				m.logger.Warn("Failed to create collection for process monitor V2: %v, trying V1", err)
				progFile = "process_monitor.o"
				progPath = filepath.Join(programDir, progFile)

				spec, err = ebpf.LoadCollectionSpec(progPath)
				if err != nil {
					return fmt.Errorf("failed to load V1 spec after V2 failure: %w", err)
				}

				coll, err = ebpf.NewCollection(spec)
				if err != nil {
					return fmt.Errorf("failed to create collection for both V2 and V1: %w", err)
				}
			} else {
				return fmt.Errorf("failed to create collection for %s: %w", progFile, err)
			}
		}

		// Store programs and maps
		for name, prog := range coll.Programs {
			m.programs[name] = prog
			m.logger.Debug("Loaded eBPF program: %s from %s", name, progFile)
		}

		for name, mapObj := range coll.Maps {
			m.maps[name] = mapObj
			m.logger.Debug("Loaded eBPF map: %s from %s", name, progFile)
		}
	}

	return nil
}

// configurePrograms configures eBPF programs with runtime settings
func (m *EBPFManager) configurePrograms(config *Config) error {
	configMap, exists := m.maps["config_map"]
	if !exists {
		return fmt.Errorf("config_map not found")
	}

	// Create configuration structure
	type ebpfConfig struct {
		EnableProcessMonitoring uint32
		EnableNetworkMonitoring uint32
		EnableFileMonitoring    uint32
		EnableSyscallMonitoring uint32
		SamplingRate            uint32
	}

	cfg := ebpfConfig{
		SamplingRate: config.SamplingRate,
	}

	if config.EnableProcessMonitoring {
		cfg.EnableProcessMonitoring = 1
	}
	if config.EnableNetworkMonitoring {
		cfg.EnableNetworkMonitoring = 1
	}
	if config.EnableFileMonitoring {
		cfg.EnableFileMonitoring = 1
	}
	if config.EnableSyscallMonitoring {
		cfg.EnableSyscallMonitoring = 1
	}

	// Update configuration in eBPF map
	key := uint32(0)
	if err := configMap.Update(key, cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update config map: %w", err)
	}

	m.logger.Info("eBPF programs configured successfully")
	return nil
}

// attachPrograms attaches eBPF programs to kernel hooks
func (m *EBPFManager) attachPrograms(config *Config) error {
	// Attach process monitoring programs
	if config.EnableProcessMonitoring {
		if err := m.attachProcessPrograms(); err != nil {
			return fmt.Errorf("failed to attach process programs: %w", err)
		}
	}

	// Attach network monitoring programs
	if config.EnableNetworkMonitoring {
		if err := m.attachNetworkPrograms(); err != nil {
			return fmt.Errorf("failed to attach network programs: %w", err)
		}
	}

	// Attach file monitoring programs
	if config.EnableFileMonitoring {
		if err := m.attachFilePrograms(); err != nil {
			return fmt.Errorf("failed to attach file programs: %w", err)
		}
	}

	return nil
}

// attachProcessPrograms attaches process monitoring programs with version support
func (m *EBPFManager) attachProcessPrograms() error {
	// Try to attach V2 (tracepoint-based) programs first
	if err := m.attachProcessProgramsV2(); err == nil {
		m.logger.Info("Successfully attached process monitor V2 programs")
		return nil
	} else {
		m.logger.Warn("Failed to attach process monitor V2 programs: %v, trying V1", err)
	}

	// Fallback to V1 (kprobe-based) programs
	if err := m.attachProcessProgramsV1(); err != nil {
		return fmt.Errorf("failed to attach both V2 and V1 process programs: %w", err)
	}

	m.logger.Info("Successfully attached process monitor V1 programs (fallback)")
	return nil
}

// attachProcessProgramsV2 attaches V2 tracepoint-based process programs
func (m *EBPFManager) attachProcessProgramsV2() error {
	attached := 0

	// Attach process exec tracepoint (V2)
	if prog, exists := m.programs["trace_process_exec_v2"]; exists {
		l, err := link.Tracepoint("sched", "sched_process_exec", prog, nil)
		if err != nil {
			return fmt.Errorf("failed to attach process exec tracepoint V2: %w", err)
		}
		m.links["trace_process_exec_v2"] = l
		m.logger.Debug("Attached process exec tracepoint V2")
		attached++
	}

	// Attach process exit tracepoint (V2)
	if prog, exists := m.programs["trace_process_exit_v2"]; exists {
		l, err := link.Tracepoint("sched", "sched_process_exit", prog, nil)
		if err != nil {
			return fmt.Errorf("failed to attach process exit tracepoint V2: %w", err)
		}
		m.links["trace_process_exit_v2"] = l
		m.logger.Debug("Attached process exit tracepoint V2")
		attached++
	}

	// Attach syscall exit tracepoints for exit code capture (V2)
	if prog, exists := m.programs["trace_sys_exit_v2"]; exists {
		l, err := link.Tracepoint("syscalls", "sys_exit_exit", prog, nil)
		if err != nil {
			m.logger.Warn("Failed to attach sys_exit tracepoint V2: %v", err)
		} else {
			m.links["trace_sys_exit_v2"] = l
			m.logger.Debug("Attached sys_exit tracepoint V2")
			attached++
		}
	}

	if prog, exists := m.programs["trace_sys_exit_group_v2"]; exists {
		l, err := link.Tracepoint("syscalls", "sys_exit_exit_group", prog, nil)
		if err != nil {
			m.logger.Warn("Failed to attach sys_exit_group tracepoint V2: %v", err)
		} else {
			m.links["trace_sys_exit_group_v2"] = l
			m.logger.Debug("Attached sys_exit_group tracepoint V2")
			attached++
		}
	}

	if attached == 0 {
		return fmt.Errorf("no V2 process programs found or attached")
	}

	return nil
}

// attachProcessProgramsV1 attaches V1 kprobe-based process programs
func (m *EBPFManager) attachProcessProgramsV1() error {
	attached := 0

	// Note: Deprecated kprobe implementations have been removed from process_monitor.c
	// Only the optimized tracepoint-based V2 implementation is now supported
	m.logger.Info("V1 kprobe-based process monitoring has been deprecated and removed")

	if attached == 0 {
		return fmt.Errorf("no V1 process programs found or attached")
	}

	return nil
}

// attachNetworkPrograms attaches network monitoring programs
func (m *EBPFManager) attachNetworkPrograms() error {
	// Attach TCP v4 connect kprobe
	if prog, exists := m.programs["trace_tcp_v4_connect"]; exists {
		l, err := link.Kprobe("tcp_v4_connect", prog, nil)
		if err != nil {
			m.logger.Warn("Failed to attach tcp_v4_connect kprobe: %v", err)
		} else {
			m.links["trace_tcp_v4_connect"] = l
			m.logger.Debug("Attached tcp_v4_connect kprobe")
		}
	}

	// Attach inet_csk_accept kprobe
	if prog, exists := m.programs["trace_inet_csk_accept"]; exists {
		l, err := link.Kprobe("inet_csk_accept", prog, nil)
		if err != nil {
			m.logger.Warn("Failed to attach inet_csk_accept kprobe: %v", err)
		} else {
			m.links["trace_inet_csk_accept"] = l
			m.logger.Debug("Attached inet_csk_accept kprobe")
		}
	}

	// Attach inet_csk_accept kretprobe
	if prog, exists := m.programs["trace_inet_csk_accept_ret"]; exists {
		l, err := link.Kretprobe("inet_csk_accept", prog, nil)
		if err != nil {
			m.logger.Warn("Failed to attach inet_csk_accept kretprobe: %v", err)
		} else {
			m.links["trace_inet_csk_accept_ret"] = l
			m.logger.Debug("Attached inet_csk_accept kretprobe")
		}
	}

	return nil
}

// attachFilePrograms attaches file monitoring programs
func (m *EBPFManager) attachFilePrograms() error {
	// Attach file open tracepoint
	if prog, exists := m.programs["trace_sys_enter_openat"]; exists {
		l, err := link.Tracepoint("syscalls", "sys_enter_openat", prog, nil)
		if err != nil {
			m.logger.Warn("Failed to attach sys_enter_openat tracepoint: %v", err)
		} else {
			m.links["trace_sys_enter_openat"] = l
			m.logger.Debug("Attached sys_enter_openat tracepoint")
		}
	}

	// Attach VFS write kprobe
	if prog, exists := m.programs["trace_vfs_write"]; exists {
		l, err := link.Kprobe("vfs_write", prog, nil)
		if err != nil {
			m.logger.Warn("Failed to attach vfs_write kprobe: %v", err)
		} else {
			m.links["trace_vfs_write"] = l
			m.logger.Debug("Attached vfs_write kprobe")
		}
	}

	// Attach VFS unlink kprobe
	if prog, exists := m.programs["trace_vfs_unlink"]; exists {
		l, err := link.Kprobe("vfs_unlink", prog, nil)
		if err != nil {
			m.logger.Warn("Failed to attach vfs_unlink kprobe: %v", err)
		} else {
			m.links["trace_vfs_unlink"] = l
			m.logger.Debug("Attached vfs_unlink kprobe")
		}
	}

	return nil
}

// startEventReaders starts ring buffer readers for events
func (m *EBPFManager) startEventReaders() error {
	eventsMap, exists := m.maps["events"]
	if !exists {
		return fmt.Errorf("events ring buffer map not found")
	}

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("failed to create ring buffer reader: %w", err)
	}

	m.readers["events"] = reader

	// Start event processing goroutine
	m.wg.Add(1)
	go m.processEvents(reader)

	return nil
}

// processEvents processes events from the ring buffer
func (m *EBPFManager) processEvents(reader *ringbuf.Reader) {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return
		default:
			record, err := reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				m.logger.Error("Failed to read from ring buffer: %v", err)
				continue
			}

			event := m.parseEvent(record.RawSample)
			if event != nil {
				select {
				case m.eventChan <- event:
				case <-m.ctx.Done():
					return
				default:
					// Channel is full, drop event
					m.logger.Warn("Event channel full, dropping event")
				}
			}
		}
	}
}

// parseEvent parses raw event data into structured event
func (m *EBPFManager) parseEvent(data []byte) *Event {
	if len(data) < 32 { // Minimum size for event header
		return nil
	}

	// Parse event header (simplified)
	timestamp := *(*uint64)(unsafe.Pointer(&data[0]))
	pid := *(*uint32)(unsafe.Pointer(&data[8]))
	tgid := *(*uint32)(unsafe.Pointer(&data[12]))
	uid := *(*uint32)(unsafe.Pointer(&data[16]))
	gid := *(*uint32)(unsafe.Pointer(&data[20]))
	eventType := *(*uint32)(unsafe.Pointer(&data[24]))
	cpu := *(*uint32)(unsafe.Pointer(&data[28]))

	// Extract comm (process name)
	comm := string(data[32:48])
	if idx := strings.IndexByte(comm, 0); idx != -1 {
		comm = comm[:idx]
	}

	// Safely convert timestamp to avoid integer overflow
	eventTimestamp, err := security.SafeTimestampConversion(timestamp)
	if err != nil {
		m.logger.Warn("Timestamp conversion failed for event type %d: %v, using current time", eventType, err)
		eventTimestamp = time.Now()
	}

	event := &Event{
		Type:      EventType(eventType),
		Timestamp: eventTimestamp,
		PID:       pid,
		TGID:      tgid,
		UID:       uid,
		GID:       gid,
		CPU:       cpu,
		Comm:      comm,
	}

	// Parse event-specific data
	switch EventType(eventType) {
	case EventProcessExec, EventProcessExit:
		event.Data = m.parseProcessEvent(data[48:])
	case EventNetworkConnect, EventNetworkAccept:
		event.Data = m.parseNetworkEvent(data[48:])
	case EventFileOpen, EventFileWrite, EventFileUnlink:
		event.Data = m.parseFileEvent(data[48:])
	case EventSyscall:
		event.Data = m.parseSyscallEvent(data[48:])
	}

	return event
}

// parseProcessEvent parses process event data
func (m *EBPFManager) parseProcessEvent(data []byte) *ProcessEventData {
	if len(data) < 8 {
		return nil
	}

	ppid := *(*uint32)(unsafe.Pointer(&data[0]))
	exitCode := *(*uint32)(unsafe.Pointer(&data[4]))

	// Extract filename and args (simplified)
	filename := ""
	args := ""
	if len(data) > 8 {
		remaining := data[8:]
		if len(remaining) >= 256 {
			filename = string(remaining[:256])
			if idx := strings.IndexByte(filename, 0); idx != -1 {
				filename = filename[:idx]
			}
		}
		if len(remaining) >= 768 {
			args = string(remaining[256:768])
			if idx := strings.IndexByte(args, 0); idx != -1 {
				args = args[:idx]
			}
		}
	}

	return &ProcessEventData{
		PPID:     ppid,
		ExitCode: exitCode,
		Filename: filename,
		Args:     args,
	}
}

// parseNetworkEvent parses network event data
func (m *EBPFManager) parseNetworkEvent(data []byte) *NetworkEventData {
	if len(data) < 24 {
		return nil
	}

	family := *(*uint16)(unsafe.Pointer(&data[0]))
	protocol := *(*uint16)(unsafe.Pointer(&data[2]))
	sport := *(*uint16)(unsafe.Pointer(&data[4]))
	dport := *(*uint16)(unsafe.Pointer(&data[6]))

	var saddr, daddr []byte
	if family == 2 { // AF_INET
		saddr = make([]byte, 4)
		daddr = make([]byte, 4)
		copy(saddr, data[8:12])
		copy(daddr, data[12:16])
	} else if family == 10 { // AF_INET6
		saddr = make([]byte, 16)
		daddr = make([]byte, 16)
		copy(saddr, data[8:24])
		copy(daddr, data[24:40])
	}

	return &NetworkEventData{
		Family:   family,
		Protocol: protocol,
		SPort:    sport,
		DPort:    dport,
		SAddr:    saddr,
		DAddr:    daddr,
	}
}

// parseFileEvent parses file event data
func (m *EBPFManager) parseFileEvent(data []byte) *FileEventData {
	if len(data) < 24 {
		return nil
	}

	flags := *(*uint32)(unsafe.Pointer(&data[0]))
	mode := *(*uint16)(unsafe.Pointer(&data[4]))
	fd := *(*int32)(unsafe.Pointer(&data[6]))
	size := *(*uint64)(unsafe.Pointer(&data[8]))
	offset := *(*uint64)(unsafe.Pointer(&data[16]))

	filename := ""
	if len(data) > 24 {
		filename = string(data[24:])
		if idx := strings.IndexByte(filename, 0); idx != -1 {
			filename = filename[:idx]
		}
	}

	return &FileEventData{
		Flags:    flags,
		Mode:     mode,
		FD:       fd,
		Size:     size,
		Offset:   offset,
		Filename: filename,
	}
}

// parseSyscallEvent parses syscall event data
func (m *EBPFManager) parseSyscallEvent(data []byte) *SyscallEventData {
	if len(data) < 56 {
		return nil
	}

	syscallNr := *(*uint64)(unsafe.Pointer(&data[0]))
	var args [6]uint64
	for i := 0; i < 6; i++ {
		args[i] = *(*uint64)(unsafe.Pointer(&data[8+i*8]))
	}
	ret := *(*int64)(unsafe.Pointer(&data[48]))

	return &SyscallEventData{
		SyscallNr: syscallNr,
		Args:      args,
		Ret:       ret,
	}
}

// GetDebugStats reads debug statistics from eBPF maps
func (m *EBPFManager) GetDebugStats() (*DebugStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	debugStatsMap, exists := m.maps["debug_stats_map"]
	if !exists {
		return nil, fmt.Errorf("debug_stats_map not found")
	}

	// Read debug statistics from eBPF map
	key := uint32(0)
	var rawStats struct {
		EventsProcessed    uint64
		EventsDropped      uint64
		AllocationFailures uint64
		ConfigErrors       uint64
		DataReadErrors     uint64
		TracepointErrors   uint64
		ExecEvents         uint64
		ExitEvents         uint64
		SamplingSkipped    uint64
		PidFiltered        uint64
		LastErrorTimestamp uint64
		LastErrorType      uint32
		LastErrorPid       uint32
	}

	if err := debugStatsMap.Lookup(key, &rawStats); err != nil {
		return nil, fmt.Errorf("failed to read debug stats: %w", err)
	}

	stats := &DebugStats{
		EventsProcessed:    rawStats.EventsProcessed,
		EventsDropped:      rawStats.EventsDropped,
		AllocationFailures: rawStats.AllocationFailures,
		ConfigErrors:       rawStats.ConfigErrors,
		DataReadErrors:     rawStats.DataReadErrors,
		TracepointErrors:   rawStats.TracepointErrors,
		ExecEvents:         rawStats.ExecEvents,
		ExitEvents:         rawStats.ExitEvents,
		SamplingSkipped:    rawStats.SamplingSkipped,
		PidFiltered:        rawStats.PidFiltered,
		LastErrorTimestamp: rawStats.LastErrorTimestamp,
		LastErrorType:      rawStats.LastErrorType,
		LastErrorPid:       rawStats.LastErrorPid,
	}

	return stats, nil
}

// ResetDebugStats resets debug statistics in eBPF maps
func (m *EBPFManager) ResetDebugStats() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	debugStatsMap, exists := m.maps["debug_stats_map"]
	if !exists {
		return fmt.Errorf("debug_stats_map not found")
	}

	// Reset debug statistics in eBPF map
	key := uint32(0)
	var zeroStats struct {
		EventsProcessed    uint64
		EventsDropped      uint64
		AllocationFailures uint64
		ConfigErrors       uint64
		DataReadErrors     uint64
		TracepointErrors   uint64
		ExecEvents         uint64
		ExitEvents         uint64
		SamplingSkipped    uint64
		PidFiltered        uint64
		LastErrorTimestamp uint64
		LastErrorType      uint32
		LastErrorPid       uint32
	}

	if err := debugStatsMap.Update(key, zeroStats, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to reset debug stats: %w", err)
	}

	m.logger.Info("Debug statistics reset successfully")
	return nil
}

// GetPerformanceMetrics calculates performance metrics from debug statistics
func (m *EBPFManager) GetPerformanceMetrics() (map[string]interface{}, error) {
	stats, err := m.GetDebugStats()
	if err != nil {
		return nil, err
	}

	metrics := make(map[string]interface{})

	// Basic event counts
	metrics["total_events"] = stats.EventsProcessed
	metrics["exec_events"] = stats.ExecEvents
	metrics["exit_events"] = stats.ExitEvents

	// Error rates
	totalEvents := stats.EventsProcessed
	if totalEvents > 0 {
		metrics["error_rate"] = float64(stats.EventsDropped+stats.AllocationFailures+stats.ConfigErrors+stats.DataReadErrors+stats.TracepointErrors) / float64(totalEvents)
		metrics["allocation_failure_rate"] = float64(stats.AllocationFailures) / float64(totalEvents)
		metrics["config_error_rate"] = float64(stats.ConfigErrors) / float64(totalEvents)
		metrics["data_read_error_rate"] = float64(stats.DataReadErrors) / float64(totalEvents)
	} else {
		metrics["error_rate"] = 0.0
		metrics["allocation_failure_rate"] = 0.0
		metrics["config_error_rate"] = 0.0
		metrics["data_read_error_rate"] = 0.0
	}

	// Filtering statistics
	metrics["sampling_skipped"] = stats.SamplingSkipped
	metrics["pid_filtered"] = stats.PidFiltered

	// Last error information
	if stats.LastErrorTimestamp > 0 {
		// Convert nanoseconds to time
		lastErrorTime := time.Unix(0, int64(stats.LastErrorTimestamp))
		metrics["last_error_time"] = lastErrorTime.Format(time.RFC3339)
		metrics["last_error_type"] = stats.LastErrorType
		metrics["last_error_pid"] = stats.LastErrorPid
	}

	return metrics, nil
}

// LogDebugStats logs current debug statistics
func (m *EBPFManager) LogDebugStats() {
	stats, err := m.GetDebugStats()
	if err != nil {
		m.logger.Error("Failed to get debug stats: %v", err)
		return
	}

	m.logger.Info("eBPF Debug Statistics:")
	m.logger.Info("  Events Processed: %d", stats.EventsProcessed)
	m.logger.Info("  Exec Events: %d", stats.ExecEvents)
	m.logger.Info("  Exit Events: %d", stats.ExitEvents)
	m.logger.Info("  Events Dropped: %d", stats.EventsDropped)
	m.logger.Info("  Allocation Failures: %d", stats.AllocationFailures)
	m.logger.Info("  Config Errors: %d", stats.ConfigErrors)
	m.logger.Info("  Data Read Errors: %d", stats.DataReadErrors)
	m.logger.Info("  Tracepoint Errors: %d", stats.TracepointErrors)
	m.logger.Info("  Sampling Skipped: %d", stats.SamplingSkipped)
	m.logger.Info("  PID Filtered: %d", stats.PidFiltered)

	if stats.LastErrorTimestamp > 0 {
		lastErrorTime := time.Unix(0, int64(stats.LastErrorTimestamp))
		m.logger.Info("  Last Error: Type=%d, PID=%d, Time=%s",
			stats.LastErrorType, stats.LastErrorPid, lastErrorTime.Format(time.RFC3339))
	}
}

// StartDebugStatsMonitoring starts a goroutine to periodically log debug statistics
func (m *EBPFManager) StartDebugStatsMonitoring(interval time.Duration) {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-m.ctx.Done():
				return
			case <-ticker.C:
				m.LogDebugStats()
			}
		}
	}()
}

// MonitoringMetrics contains comprehensive monitoring metrics
type MonitoringMetrics struct {
	// Basic counters
	EventsProcessed uint64  `json:"events_processed"`
	EventsDropped   uint64  `json:"events_dropped"`
	EventsPerSecond float64 `json:"events_per_second"`

	// Error metrics
	AllocationFailures uint64 `json:"allocation_failures"`
	ConfigErrors       uint64 `json:"config_errors"`
	DataReadErrors     uint64 `json:"data_read_errors"`
	TracepointErrors   uint64 `json:"tracepoint_errors"`

	// Performance metrics
	AvgProcessingTime float64 `json:"avg_processing_time_ns"`
	RingBufferUsage   float64 `json:"ring_buffer_usage_percent"`
	CPUUsage          float64 `json:"cpu_usage_percent"`
	MemoryUsage       uint64  `json:"memory_usage_bytes"`

	// Event type breakdown
	ExecEvents    uint64 `json:"exec_events"`
	ExitEvents    uint64 `json:"exit_events"`
	NetworkEvents uint64 `json:"network_events"`
	FileEvents    uint64 `json:"file_events"`

	// Filtering statistics
	SamplingSkipped uint64 `json:"sampling_skipped"`
	PidFiltered     uint64 `json:"pid_filtered"`

	// Timing information
	StartTime     time.Time `json:"start_time"`
	LastEventTime time.Time `json:"last_event_time"`
	Uptime        float64   `json:"uptime_seconds"`
}

// DebugInterface provides comprehensive debugging capabilities
type DebugInterface struct {
	manager *EBPFManager
	logger  logger.Logger

	// Metrics collection
	metricsHistory []MonitoringMetrics
	maxHistorySize int

	// Performance tracking
	lastMetricsTime time.Time
	lastEventCount  uint64

	mu sync.RWMutex
}

// NewDebugInterface creates a new debug interface
func (m *EBPFManager) NewDebugInterface() *DebugInterface {
	return &DebugInterface{
		manager:         m,
		logger:          m.logger,
		metricsHistory:  make([]MonitoringMetrics, 0),
		maxHistorySize:  100, // Keep last 100 metrics snapshots
		lastMetricsTime: time.Now(),
	}
}

// GetComprehensiveMetrics returns detailed monitoring metrics
func (d *DebugInterface) GetComprehensiveMetrics() (*MonitoringMetrics, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Get basic eBPF stats
	stats, err := d.manager.GetDebugStats()
	if err != nil {
		return nil, fmt.Errorf("failed to get debug stats: %w", err)
	}

	now := time.Now()

	// Calculate events per second
	timeDiff := now.Sub(d.lastMetricsTime).Seconds()
	eventDiff := stats.EventsProcessed - d.lastEventCount
	eventsPerSecond := 0.0
	if timeDiff > 0 {
		eventsPerSecond = float64(eventDiff) / timeDiff
	}

	// Get ring buffer usage (simplified estimation)
	ringBufferUsage := d.estimateRingBufferUsage()

	// Get system resource usage
	cpuUsage, memUsage := d.getSystemResourceUsage()

	metrics := &MonitoringMetrics{
		EventsProcessed:    stats.EventsProcessed,
		EventsDropped:      stats.EventsDropped,
		EventsPerSecond:    eventsPerSecond,
		AllocationFailures: stats.AllocationFailures,
		ConfigErrors:       stats.ConfigErrors,
		DataReadErrors:     stats.DataReadErrors,
		TracepointErrors:   stats.TracepointErrors,
		ExecEvents:         stats.ExecEvents,
		ExitEvents:         stats.ExitEvents,
		SamplingSkipped:    stats.SamplingSkipped,
		PidFiltered:        stats.PidFiltered,
		RingBufferUsage:    ringBufferUsage,
		CPUUsage:           cpuUsage,
		MemoryUsage:        memUsage,
		StartTime:          d.manager.startTime,
		LastEventTime:      time.Unix(0, int64(stats.LastErrorTimestamp)),
		Uptime:             time.Since(d.manager.startTime).Seconds(),
	}

	// Update tracking variables
	d.lastMetricsTime = now
	d.lastEventCount = stats.EventsProcessed

	// Add to history
	d.addToHistory(*metrics)

	return metrics, nil
}

// Helper methods
func (d *DebugInterface) addToHistory(metrics MonitoringMetrics) {
	d.metricsHistory = append(d.metricsHistory, metrics)
	if len(d.metricsHistory) > d.maxHistorySize {
		d.metricsHistory = d.metricsHistory[1:]
	}
}

func (d *DebugInterface) estimateRingBufferUsage() float64 {
	// This is a simplified estimation
	// In a real implementation, you would need to access ring buffer internals
	return 0.0 // Placeholder
}

func (d *DebugInterface) getSystemResourceUsage() (float64, uint64) {
	// This would integrate with system monitoring
	// For now, return placeholder values
	return 0.0, 0 // CPU usage, Memory usage
}

// GetMetricsHistory returns historical metrics data
func (d *DebugInterface) GetMetricsHistory() []MonitoringMetrics {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Return a copy of the history
	history := make([]MonitoringMetrics, len(d.metricsHistory))
	copy(history, d.metricsHistory)
	return history
}

// ExportMetricsJSON exports metrics in JSON format
func (d *DebugInterface) ExportMetricsJSON() ([]byte, error) {
	metrics, err := d.GetComprehensiveMetrics()
	if err != nil {
		return nil, err
	}

	return json.Marshal(metrics)
}

// ExportMetricsCSV exports metrics in CSV format
func (d *DebugInterface) ExportMetricsCSV() ([]byte, error) {
	history := d.GetMetricsHistory()
	if len(history) == 0 {
		return nil, fmt.Errorf("no metrics history available")
	}

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write header
	header := []string{
		"timestamp", "events_processed", "events_dropped", "events_per_second",
		"allocation_failures", "config_errors", "data_read_errors", "tracepoint_errors",
		"exec_events", "exit_events", "sampling_skipped", "pid_filtered",
		"ring_buffer_usage", "cpu_usage", "memory_usage", "uptime",
	}
	writer.Write(header)

	// Write data
	for _, metrics := range history {
		record := []string{
			time.Now().Format(time.RFC3339),
			fmt.Sprintf("%d", metrics.EventsProcessed),
			fmt.Sprintf("%d", metrics.EventsDropped),
			fmt.Sprintf("%.2f", metrics.EventsPerSecond),
			fmt.Sprintf("%d", metrics.AllocationFailures),
			fmt.Sprintf("%d", metrics.ConfigErrors),
			fmt.Sprintf("%d", metrics.DataReadErrors),
			fmt.Sprintf("%d", metrics.TracepointErrors),
			fmt.Sprintf("%d", metrics.ExecEvents),
			fmt.Sprintf("%d", metrics.ExitEvents),
			fmt.Sprintf("%d", metrics.SamplingSkipped),
			fmt.Sprintf("%d", metrics.PidFiltered),
			fmt.Sprintf("%.2f", metrics.RingBufferUsage),
			fmt.Sprintf("%.2f", metrics.CPUUsage),
			fmt.Sprintf("%d", metrics.MemoryUsage),
			fmt.Sprintf("%.2f", metrics.Uptime),
		}
		writer.Write(record)
	}

	writer.Flush()
	return buf.Bytes(), writer.Error()
}

// StartMetricsCollection starts periodic metrics collection
func (d *DebugInterface) StartMetricsCollection(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-d.manager.ctx.Done():
				return
			case <-ticker.C:
				_, err := d.GetComprehensiveMetrics()
				if err != nil {
					d.logger.Error("Failed to collect metrics: %v", err)
				}
			}
		}
	}()
}
