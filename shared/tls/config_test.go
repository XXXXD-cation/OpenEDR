package tls

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetCertificateFingerprint(t *testing.T) {
	// 创建临时证书文件用于测试
	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "test.crt")

	// 测试证书内容（一个有效的自签名证书）
	certPEM := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHGIgSl9+dqMA0GCSqGSIb3DQEBBQUAMA0xCzAJBgNVBAYTAlVT
MB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowDTELMAkGA1UEBhMCVVMw
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMEBklkRW7chwfvF3zKHJYKPe9GU
-----END CERTIFICATE-----`

	err := os.WriteFile(certFile, []byte(certPEM), 0644)
	if err != nil {
		t.Fatalf("Failed to create test certificate: %v", err)
	}

	tests := []struct {
		name     string
		certFile string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "Valid certificate path",
			certFile: certFile,
			wantErr:  false,
		},
		{
			name:     "Path traversal attempt",
			certFile: "../../../etc/passwd",
			wantErr:  true,
			errMsg:   "potential path traversal",
		},
		{
			name:     "Non-existent file",
			certFile: filepath.Join(tempDir, "nonexistent.crt"),
			wantErr:  true,
			errMsg:   "failed to read certificate file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetCertificateFingerprint(tt.certFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCertificateFingerprint() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
				t.Errorf("GetCertificateFingerprint() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestGetCertificateFingerprintFromBytes(t *testing.T) {
	tests := []struct {
		name      string
		certBytes []byte
		wantErr   bool
	}{
		{
			name:      "Invalid certificate bytes",
			certBytes: []byte{0x00, 0x01, 0x02},
			wantErr:   true,
		},
		{
			name:      "Empty bytes",
			certBytes: []byte{},
			wantErr:   true,
		},
		{
			name:      "Nil bytes",
			certBytes: nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetCertificateFingerprintFromBytes(tt.certBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCertificateFingerprintFromBytes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr || len(s) > len(substr) && contains(s[1:], substr)
}
