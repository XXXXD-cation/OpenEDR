package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Level represents log level
type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
)

// Logger interface
type Logger interface {
	Debug(format string, args ...interface{})
	Info(format string, args ...interface{})
	Warn(format string, args ...interface{})
	Error(format string, args ...interface{})
	Fatal(format string, args ...interface{})

	SetLevel(level Level)
	SetOutput(output io.Writer)
	Close() error
	GetMetrics() map[string]int64
}

// ZapLogger implements the Logger interface using zap
type ZapLogger struct {
	logger *zap.SugaredLogger
	atom   zap.AtomicLevel
	mu     sync.RWMutex

	// Metrics
	logCount   map[Level]int64
	errorCount int64
}

// LogConfig represents logger configuration
type LogConfig struct {
	Level      string
	File       string
	MaxSize    int // megabytes
	MaxBackups int // number of backups
	MaxAge     int // days
	Compress   bool
}

// New creates a new logger instance using zap
func New(config LogConfig) (Logger, error) {
	level := parseZapLevel(config.Level)
	atom := zap.NewAtomicLevelAt(level)

	var core zapcore.Core

	if config.File != "" {
		// File output with rotation using lumberjack
		writer := &lumberjack.Logger{
			Filename:   config.File,
			MaxSize:    config.MaxSize, // megabytes
			MaxBackups: config.MaxBackups,
			MaxAge:     config.MaxAge, // days
			Compress:   config.Compress,
		}

		// Ensure directory exists
		dir := filepath.Dir(config.File)
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}

		// Create encoder config
		encoderConfig := zapcore.EncoderConfig{
			TimeKey:        "timestamp",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			MessageKey:     "msg",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.CapitalLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		}

		core = zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderConfig),
			zapcore.AddSync(writer),
			atom,
		)
	} else {
		// Console output
		encoderConfig := zap.NewDevelopmentEncoderConfig()
		core = zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			zapcore.AddSync(os.Stdout),
			atom,
		)
	}

	zapLogger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	sugar := zapLogger.Sugar()

	return &ZapLogger{
		logger:   sugar,
		atom:     atom,
		logCount: make(map[Level]int64),
	}, nil
}

// Debug logs a debug message
func (l *ZapLogger) Debug(format string, args ...interface{}) {
	l.updateMetrics(DebugLevel)
	l.logger.Debugf(format, args...)
}

// Info logs an info message
func (l *ZapLogger) Info(format string, args ...interface{}) {
	l.updateMetrics(InfoLevel)
	l.logger.Infof(format, args...)
}

// Warn logs a warning message
func (l *ZapLogger) Warn(format string, args ...interface{}) {
	l.updateMetrics(WarnLevel)
	l.logger.Warnf(format, args...)
}

// Error logs an error message
func (l *ZapLogger) Error(format string, args ...interface{}) {
	l.updateMetrics(ErrorLevel)
	l.logger.Errorf(format, args...)
}

// Fatal logs a fatal message and exits
func (l *ZapLogger) Fatal(format string, args ...interface{}) {
	l.updateMetrics(FatalLevel)
	l.logger.Fatalf(format, args...)
}

// SetLevel sets the log level
func (l *ZapLogger) SetLevel(level Level) {
	zapLevel := parseZapLevel(levelString(level))
	l.atom.SetLevel(zapLevel)
}

// SetOutput sets the log output (not fully supported with zap, but kept for interface compatibility)
func (l *ZapLogger) SetOutput(output io.Writer) {
	// Note: This is limited with zap as it requires core reconfiguration
	// For now, we'll just log a warning
	l.logger.Warn("SetOutput is not fully supported with zap logger")
}

// Close closes the logger
func (l *ZapLogger) Close() error {
	return l.logger.Sync()
}

// GetMetrics returns logger metrics
func (l *ZapLogger) GetMetrics() map[string]int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()

	metrics := make(map[string]int64)
	for level, count := range l.logCount {
		metrics[levelString(level)] = count
	}
	metrics["errors"] = l.errorCount

	return metrics
}

// updateMetrics updates internal metrics
func (l *ZapLogger) updateMetrics(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.logCount[level]++
	if level >= ErrorLevel {
		l.errorCount++
	}
}

// parseLevel parses log level from string
func parseLevel(level string) Level {
	switch strings.ToLower(level) {
	case "debug":
		return DebugLevel
	case "info":
		return InfoLevel
	case "warn", "warning":
		return WarnLevel
	case "error":
		return ErrorLevel
	case "fatal":
		return FatalLevel
	default:
		return InfoLevel
	}
}

// parseZapLevel parses log level string to zap level
func parseZapLevel(level string) zapcore.Level {
	switch strings.ToLower(level) {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn", "warning":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	case "fatal":
		return zapcore.FatalLevel
	default:
		return zapcore.InfoLevel
	}
}

// levelString returns string representation of log level
func levelString(level Level) string {
	switch level {
	case DebugLevel:
		return "DEBUG"
	case InfoLevel:
		return "INFO"
	case WarnLevel:
		return "WARN"
	case ErrorLevel:
		return "ERROR"
	case FatalLevel:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Global logger instance
var globalLogger Logger

// init initializes the global logger
func init() {
	globalLogger, _ = New(LogConfig{
		Level: "info",
	})
}

// SetGlobalLogger sets the global logger
func SetGlobalLogger(logger Logger) {
	globalLogger = logger
}

// Global logging functions
func Debug(format string, args ...interface{}) {
	globalLogger.Debug(format, args...)
}

func Info(format string, args ...interface{}) {
	globalLogger.Info(format, args...)
}

func Warn(format string, args ...interface{}) {
	globalLogger.Warn(format, args...)
}

func Error(format string, args ...interface{}) {
	globalLogger.Error(format, args...)
}

func Fatal(format string, args ...interface{}) {
	globalLogger.Fatal(format, args...)
}
