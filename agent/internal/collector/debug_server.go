package collector

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/XXXXD-cation/OpenEDR/shared/logger"
)

// DebugServer provides HTTP endpoints for debugging and monitoring
type DebugServer struct {
	logger              logger.Logger
	processCollector    *ProcessCollector
	monitoringInterface *ProcessCollectorMonitoringInterface
	server              *http.Server
}

// NewDebugServer creates a new debug server
func NewDebugServer(port int, processCollector *ProcessCollector, logger logger.Logger) *DebugServer {
	mux := http.NewServeMux()

	ds := &DebugServer{
		logger:              logger,
		processCollector:    processCollector,
		monitoringInterface: processCollector.NewMonitoringInterface(),
		server: &http.Server{
			Addr:    fmt.Sprintf(":%d", port),
			Handler: mux,
		},
	}

	// Register endpoints
	mux.HandleFunc("/debug/status", ds.handleStatus)
	mux.HandleFunc("/debug/metrics", ds.handleMetrics)
	mux.HandleFunc("/debug/health", ds.handleHealth)
	mux.HandleFunc("/debug/export", ds.handleExport)
	mux.HandleFunc("/debug/reset", ds.handleReset)

	return ds
}

// Start starts the debug server
func (ds *DebugServer) Start() error {
	ds.logger.Info("Starting debug server on %s", ds.server.Addr)
	return ds.server.ListenAndServe()
}

// Stop stops the debug server
func (ds *DebugServer) Stop() error {
	ds.logger.Info("Stopping debug server")
	return ds.server.Close()
}

// HTTP handlers
func (ds *DebugServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := ds.monitoringInterface.GetDetailedStatus()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (ds *DebugServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if ds.monitoringInterface.debugInterface == nil {
		http.Error(w, "Debug interface not available", http.StatusServiceUnavailable)
		return
	}

	metrics, err := ds.monitoringInterface.debugInterface.GetComprehensiveMetrics()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

func (ds *DebugServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	report := ds.monitoringInterface.GenerateHealthReport()

	// Set HTTP status based on health
	status := http.StatusOK
	if healthStatus, ok := report["health_status"].(string); ok {
		switch healthStatus {
		case "degraded":
			status = http.StatusPartialContent
		case "unhealthy":
			status = http.StatusServiceUnavailable
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(report)
}

func (ds *DebugServer) handleExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	data, err := ds.monitoringInterface.ExportDiagnostics(format)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=metrics.csv")
	}

	w.Write(data)
}

func (ds *DebugServer) handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := ds.processCollector.ResetDebugStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reset successful"})
}
