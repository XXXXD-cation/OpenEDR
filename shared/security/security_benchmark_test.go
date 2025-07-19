package security

import (
	"testing"
)

func BenchmarkSafeUint64ToInt64(b *testing.B) {
	testValues := []uint64{
		0,
		12345,
		1<<32 - 1,
		1<<63 - 1,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, val := range testValues {
			_, _ = SafeUint64ToInt64(val)
		}
	}
}

func BenchmarkSafeTimestampConversion(b *testing.B) {
	testTimestamps := []uint64{
		0,
		1640995200000000000, // 2022-01-01 00:00:00 UTC in nanoseconds
		1<<62 - 1,           // Large but valid timestamp
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, ts := range testTimestamps {
			_, _ = SafeTimestampConversion(ts)
		}
	}
}
