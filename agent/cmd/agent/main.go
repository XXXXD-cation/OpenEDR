package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/XXXXD-cation/OpenEDR/agent/internal/config"
	"github.com/XXXXD-cation/OpenEDR/agent/internal/core"
	"github.com/XXXXD-cation/OpenEDR/agent/internal/updater"
	"github.com/XXXXD-cation/OpenEDR/shared/logger"
)

var (
	// Build variables (set by ldflags)
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	// Parse command line flags
	var (
		configFile  = flag.String("config", getDefaultConfigPath(), "configuration file path")
		showVersion = flag.Bool("version", false, "show version information")
		checkUpdate = flag.Bool("check-update", false, "check for updates")
		install     = flag.Bool("install", false, "install agent as system service")
		uninstall   = flag.Bool("uninstall", false, "uninstall agent service")
		logLevel    = flag.String("log-level", "", "override log level")
	)
	flag.Parse()

	// Show version information
	if *showVersion {
		fmt.Printf("OpenEDR Agent\n")
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		fmt.Printf("Git Commit: %s\n", GitCommit)
		fmt.Printf("Go Version: %s\n", runtime.Version())
		fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Override log level if specified
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}

	// Initialize logger
	logConfig := logger.LogConfig{
		Level:      cfg.LogLevel,
		File:       cfg.LogFile,
		MaxSize:    100, // 100MB
		MaxBackups: 5,
		MaxAge:     30, // 30 days
		Compress:   true,
	}

	log, err := logger.New(logConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	// Set global logger
	logger.SetGlobalLogger(log)

	// Log startup information
	log.Info("Starting OpenEDR Agent v%s", Version)
	log.Info("Build: %s (commit: %s)", BuildTime, GitCommit)
	log.Info("Platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	log.Info("PID: %d", os.Getpid())

	// Handle service installation/uninstallation
	if *install {
		if err := installService(); err != nil {
			log.Fatal("Failed to install service: %v", err)
		}
		log.Info("Service installed successfully")
		os.Exit(0)
	}

	if *uninstall {
		if err := uninstallService(); err != nil {
			log.Fatal("Failed to uninstall service: %v", err)
		}
		log.Info("Service uninstalled successfully")
		os.Exit(0)
	}

	// Check for updates if requested
	if *checkUpdate {
		checkForUpdates(cfg, log)
		os.Exit(0)
	}

	// Set version in config
	cfg.Version = Version

	// Create agent instance
	agent, err := core.New(cfg, log)
	if err != nil {
		log.Fatal("Failed to create agent: %v", err)
	}

	// Register collectors based on configuration
	registerCollectors(agent, cfg, log)

	// Start agent
	if err := agent.Start(); err != nil {
		log.Fatal("Failed to start agent: %v", err)
	}

	// Start update checker in background
	if cfg.Update.Enabled {
		go func() {
			upd := updater.New(cfg, log)
			upd.StartUpdateRoutine()
		}()
	}

	// Watch for configuration changes
	if err := cfg.Watch(func(newCfg *config.Config) {
		log.Info("Configuration changed, reloading...")
		// Handle configuration reload
		// This could involve restarting collectors, updating log level, etc.
	}); err != nil {
		log.Error("Failed to start configuration watcher: %v", err)
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	log.Info("Received signal: %v", sig)

	// Stop agent
	if err := agent.Stop(); err != nil {
		log.Error("Error stopping agent: %v", err)
	}

	log.Info("Agent shutdown complete")
}

// getDefaultConfigPath returns the default configuration file path
func getDefaultConfigPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "OpenEDR", "agent", "config.yaml")
	case "darwin":
		return "/Library/Application Support/OpenEDR/agent/config.yaml"
	default:
		return "/etc/openedr/agent/config.yaml"
	}
}

// registerCollectors registers enabled collectors
func registerCollectors(agent *core.Agent, cfg *config.Config, log logger.Logger) {
	// TODO: Register actual collectors based on configuration
	// For now, we'll add placeholder comments

	/*
		// Process collector
		if cfg.Collectors.Process.Enabled {
			collector := collectors.NewProcessCollector(cfg.Collectors.Process, log)
			agent.RegisterCollector(collector)
		}

		// Network collector
		if cfg.Collectors.Network.Enabled {
			collector := collectors.NewNetworkCollector(cfg.Collectors.Network, log)
			agent.RegisterCollector(collector)
		}

		// File collector
		if cfg.Collectors.File.Enabled {
			collector := collectors.NewFileCollector(cfg.Collectors.File, log)
			agent.RegisterCollector(collector)
		}

		// Registry collector (Windows only)
		if runtime.GOOS == "windows" && cfg.Collectors.Registry.Enabled {
			collector := collectors.NewRegistryCollector(cfg.Collectors.Registry, log)
			agent.RegisterCollector(collector)
		}
	*/
}

// checkForUpdates checks for available updates
func checkForUpdates(cfg *config.Config, log logger.Logger) {
	upd := updater.New(cfg, log)
	info, err := upd.CheckForUpdates()
	if err != nil {
		log.Error("Failed to check for updates: %v", err)
		return
	}

	if info == nil {
		log.Info("No updates available")
		return
	}

	log.Info("Update available:")
	log.Info("  Current version: %s", cfg.Version)
	log.Info("  Latest version: %s", info.Version)
	log.Info("  Release date: %s", info.ReleaseDate.Format("2006-01-02"))
	log.Info("  Description: %s", info.Description)
	if info.Critical {
		log.Warn("  This is a CRITICAL update!")
	}
}

// Service installation functions (platform-specific implementations)

// installService installs the agent as a system service
func installService() error {
	// Platform-specific implementation
	switch runtime.GOOS {
	case "windows":
		return installWindowsService()
	case "linux":
		return installLinuxService()
	case "darwin":
		return installDarwinService()
	default:
		return fmt.Errorf("service installation not supported on %s", runtime.GOOS)
	}
}

// uninstallService removes the agent service
func uninstallService() error {
	// Platform-specific implementation
	switch runtime.GOOS {
	case "windows":
		return uninstallWindowsService()
	case "linux":
		return uninstallLinuxService()
	case "darwin":
		return uninstallDarwinService()
	default:
		return fmt.Errorf("service uninstallation not supported on %s", runtime.GOOS)
	}
}

// Platform-specific service functions (to be implemented)

func installWindowsService() error {
	// TODO: Implement Windows service installation
	return fmt.Errorf("Windows service installation not yet implemented")
}

func uninstallWindowsService() error {
	// TODO: Implement Windows service uninstallation
	return fmt.Errorf("Windows service uninstallation not yet implemented")
}

func installLinuxService() error {
	// TODO: Implement systemd service installation
	return fmt.Errorf("Linux service installation not yet implemented")
}

func uninstallLinuxService() error {
	// TODO: Implement systemd service uninstallation
	return fmt.Errorf("Linux service uninstallation not yet implemented")
}

func installDarwinService() error {
	// TODO: Implement launchd service installation
	return fmt.Errorf("macOS service installation not yet implemented")
}

func uninstallDarwinService() error {
	// TODO: Implement launchd service uninstallation
	return fmt.Errorf("macOS service uninstallation not yet implemented")
}
