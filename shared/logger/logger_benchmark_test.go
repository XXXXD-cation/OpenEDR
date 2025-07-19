package logger

import (
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkLogger_Info(b *testing.B) {
	tempDir := b.TempDir()
	logFile := filepath.Join(tempDir, "bench.log")

	config := LogConfig{
		Level: "info",
		File:  logFile,
	}

	log, err := New(config)
	if err != nil {
		b.Fatal(err)
	}
	defer log.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			log.Info("benchmark message: %d", 12345)
		}
	})
}

func BenchmarkLogger_Debug_Filtered(b *testing.B) {
	tempDir := b.TempDir()
	logFile := filepath.Join(tempDir, "bench.log")

	config := LogConfig{
		Level: "info", // Debug messages should be filtered out
		File:  logFile,
	}

	log, err := New(config)
	if err != nil {
		b.Fatal(err)
	}
	defer log.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			log.Debug("debug message that should be filtered: %d", 12345)
		}
	})
}

func BenchmarkLogger_Error(b *testing.B) {
	tempDir := b.TempDir()
	logFile := filepath.Join(tempDir, "bench.log")

	config := LogConfig{
		Level: "error",
		File:  logFile,
	}

	log, err := New(config)
	if err != nil {
		b.Fatal(err)
	}
	defer log.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			log.Error("error message: %s", "benchmark error")
		}
	})
}

func BenchmarkLogger_Console(b *testing.B) {
	config := LogConfig{
		Level: "info",
		// No file specified, should use console
	}

	log, err := New(config)
	if err != nil {
		b.Fatal(err)
	}
	defer log.Close()

	// Redirect stdout to discard output for benchmarking
	oldStdout := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = oldStdout }()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			log.Info("console benchmark message: %d", 12345)
		}
	})
}

func BenchmarkLogger_WithFormatting(b *testing.B) {
	tempDir := b.TempDir()
	logFile := filepath.Join(tempDir, "bench.log")

	config := LogConfig{
		Level: "info",
		File:  logFile,
	}

	log, err := New(config)
	if err != nil {
		b.Fatal(err)
	}
	defer log.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			log.Info("complex message with multiple args: %s, %d, %f, %t",
				"string", 12345, 3.14159, true)
		}
	})
}

func BenchmarkLogger_GetMetrics(b *testing.B) {
	config := LogConfig{
		Level: "info",
	}

	log, err := New(config)
	if err != nil {
		b.Fatal(err)
	}
	defer log.Close()

	// Log some messages first
	for i := 0; i < 1000; i++ {
		log.Info("setup message %d", i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = log.GetMetrics()
	}
}

func BenchmarkLogger_SetLevel(b *testing.B) {
	config := LogConfig{
		Level: "info",
	}

	log, err := New(config)
	if err != nil {
		b.Fatal(err)
	}
	defer log.Close()

	levels := []Level{
		DebugLevel,
		InfoLevel,
		WarnLevel,
		ErrorLevel,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.SetLevel(levels[i%len(levels)])
	}
}

// Benchmark comparison between different log levels
func BenchmarkLogger_LevelComparison(b *testing.B) {
	tempDir := b.TempDir()

	levels := []struct {
		name  string
		level string
	}{
		{"Debug", "debug"},
		{"Info", "info"},
		{"Warn", "warn"},
		{"Error", "error"},
	}

	for _, level := range levels {
		b.Run(level.name, func(b *testing.B) {
			logFile := filepath.Join(tempDir, "bench_"+level.name+".log")
			config := LogConfig{
				Level: level.level,
				File:  logFile,
			}

			log, err := New(config)
			if err != nil {
				b.Fatal(err)
			}
			defer log.Close()

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					log.Info("benchmark message for level %s: %d", level.name, 12345)
				}
			})
		})
	}
}

// Benchmark memory allocations
func BenchmarkLogger_Allocations(b *testing.B) {
	config := LogConfig{
		Level: "info",
	}

	log, err := New(config)
	if err != nil {
		b.Fatal(err)
	}
	defer log.Close()

	// Redirect stdout to discard output
	oldStdout := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = oldStdout }()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		log.Info("allocation test message: %d", i)
	}
}
