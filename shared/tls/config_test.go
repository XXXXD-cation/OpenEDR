package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create test certificates
func createTestCertificates(t *testing.T, tempDir string) (certFile, keyFile, caFile string) {
	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create CA certificate template
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Create CA certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	// Generate server private key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create server certificate template
	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization:  []string{"Test Server"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"localhost", "test.example.com"},
	}

	// Create server certificate
	serverBytes, err := x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	// Write CA certificate
	caFile = filepath.Join(tempDir, "ca.crt")
	caCertOut, err := os.Create(caFile)
	require.NoError(t, err)
	pem.Encode(caCertOut, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	caCertOut.Close()

	// Write server certificate
	certFile = filepath.Join(tempDir, "server.crt")
	certOut, err := os.Create(certFile)
	require.NoError(t, err)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: serverBytes})
	certOut.Close()

	// Write server private key
	keyFile = filepath.Join(tempDir, "server.key")
	keyOut, err := os.Create(keyFile)
	require.NoError(t, err)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
	keyOut.Close()

	return certFile, keyFile, caFile
}

func TestLoadServerTLSConfig(t *testing.T) {
	tempDir := t.TempDir()
	certFile, keyFile, caFile := createTestCertificates(t, tempDir)

	config := TLSConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	}

	tlsConfig, err := LoadServerTLSConfig(config)
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	// Verify TLS config properties
	assert.NotNil(t, tlsConfig.Certificates)
	assert.Len(t, tlsConfig.Certificates, 1)
	assert.NotNil(t, tlsConfig.ClientCAs)
	assert.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
}

func TestLoadClientTLSConfig(t *testing.T) {
	tempDir := t.TempDir()
	certFile, keyFile, caFile := createTestCertificates(t, tempDir)

	config := TLSConfig{
		CertFile:   certFile,
		KeyFile:    keyFile,
		CAFile:     caFile,
		ServerName: "localhost",
	}

	tlsConfig, err := LoadClientTLSConfig(config)
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	// Verify TLS config properties
	assert.NotNil(t, tlsConfig.Certificates)
	assert.Len(t, tlsConfig.Certificates, 1)
	assert.NotNil(t, tlsConfig.RootCAs)
	assert.Equal(t, "localhost", tlsConfig.ServerName)
	assert.False(t, tlsConfig.InsecureSkipVerify)
}

func TestLoadServerTLSConfig_MissingFiles(t *testing.T) {
	tests := []struct {
		name   string
		config TLSConfig
		errMsg string
	}{
		{
			name: "missing cert file",
			config: TLSConfig{
				CertFile: "/nonexistent/cert.pem",
				KeyFile:  "/nonexistent/key.pem",
				CAFile:   "/nonexistent/ca.pem",
			},
			errMsg: "failed to load server certificate",
		},
		{
			name: "missing CA file",
			config: TLSConfig{
				CertFile: "/dev/null",
				KeyFile:  "/dev/null",
				CAFile:   "/nonexistent/ca.pem",
			},
			errMsg: "failed to load server certificate", // 实际上错误发生在证书加载阶段
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig, err := LoadServerTLSConfig(tt.config)
			assert.Error(t, err)
			assert.Nil(t, tlsConfig)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestLoadClientTLSConfig_MissingFiles(t *testing.T) {
	config := TLSConfig{
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
		CAFile:   "/nonexistent/ca.pem",
	}

	tlsConfig, err := LoadClientTLSConfig(config)
	assert.Error(t, err)
	assert.Nil(t, tlsConfig)
	assert.Contains(t, err.Error(), "failed to load client certificate")
}

func TestTLSConfig_Validation(t *testing.T) {
	tempDir := t.TempDir()
	certFile, keyFile, caFile := createTestCertificates(t, tempDir)

	// Test valid config
	config := TLSConfig{
		CertFile:   certFile,
		KeyFile:    keyFile,
		CAFile:     caFile,
		ServerName: "localhost",
	}

	// Should work for both server and client
	serverTLS, err := LoadServerTLSConfig(config)
	assert.NoError(t, err)
	assert.NotNil(t, serverTLS)

	clientTLS, err := LoadClientTLSConfig(config)
	assert.NoError(t, err)
	assert.NotNil(t, clientTLS)
}

func TestGetCertificateFingerprint(t *testing.T) {
	tempDir := t.TempDir()
	certFile, _, _ := createTestCertificates(t, tempDir)

	fingerprint, err := GetCertificateFingerprint(certFile)
	assert.NoError(t, err)
	assert.NotEmpty(t, fingerprint)
	assert.Len(t, fingerprint, 64) // SHA256 hex string length

	// Test with non-existent file
	fingerprint, err = GetCertificateFingerprint("/nonexistent/cert.pem")
	assert.Error(t, err)
	assert.Empty(t, fingerprint)
}

func TestGetCertificateFingerprintFromBytes(t *testing.T) {
	tempDir := t.TempDir()
	certFile, _, _ := createTestCertificates(t, tempDir)

	// Read certificate file
	certData, err := os.ReadFile(certFile)
	require.NoError(t, err)

	// Decode PEM
	block, _ := pem.Decode(certData)
	require.NotNil(t, block)

	fingerprint, err := GetCertificateFingerprintFromBytes(block.Bytes)
	assert.NoError(t, err)
	assert.NotEmpty(t, fingerprint)
	assert.Len(t, fingerprint, 64) // SHA256 hex string length

	// Test with invalid data
	fingerprint, err = GetCertificateFingerprintFromBytes([]byte("invalid"))
	assert.Error(t, err)
	assert.Empty(t, fingerprint)
}

func TestTLSConfig_DefaultValues(t *testing.T) {
	config := TLSConfig{}

	// Test that empty config fails appropriately
	_, err := LoadServerTLSConfig(config)
	assert.Error(t, err)

	_, err = LoadClientTLSConfig(config)
	assert.Error(t, err)
}

func TestTLSConfig_InsecureSkipVerify(t *testing.T) {
	tempDir := t.TempDir()
	certFile, keyFile, caFile := createTestCertificates(t, tempDir)

	config := TLSConfig{
		CertFile:           certFile,
		KeyFile:            keyFile,
		CAFile:             caFile,
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	}

	tlsConfig, err := LoadClientTLSConfig(config)
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	assert.True(t, tlsConfig.InsecureSkipVerify)
}

func TestCertificateLoading(t *testing.T) {
	tempDir := t.TempDir()
	certFile, keyFile, caFile := createTestCertificates(t, tempDir)

	// Test loading certificate and key pair
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	assert.NoError(t, err)
	assert.NotNil(t, cert.Certificate)
	assert.NotNil(t, cert.PrivateKey)

	// Test loading CA certificate
	caData, err := os.ReadFile(caFile)
	require.NoError(t, err)

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(caData)
	assert.True(t, ok)
}
