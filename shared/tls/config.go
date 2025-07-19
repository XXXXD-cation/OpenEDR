package tls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TLSConfig TLS配置结构
type TLSConfig struct {
	CertFile   string // 证书文件路径
	KeyFile    string // 私钥文件路径
	CAFile     string // CA证书文件路径
	ServerName string // 服务器名称
}

// LoadServerTLSConfig 加载服务器端TLS配置（双向认证）
func LoadServerTLSConfig(config TLSConfig) (*tls.Config, error) {
	// 加载服务器证书和私钥
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	// 加载CA证书
	caCert, err := os.ReadFile(config.CAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// 创建CA证书池
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificate")
	}

	// 配置TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
	}

	return tlsConfig, nil
}

// LoadClientTLSConfig 加载客户端TLS配置（双向认证）
func LoadClientTLSConfig(config TLSConfig) (*tls.Config, error) {
	// 加载客户端证书和私钥
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	// 加载CA证书
	caCert, err := os.ReadFile(config.CAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// 创建CA证书池
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificate")
	}

	// 配置TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ServerName:   config.ServerName,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
	}

	return tlsConfig, nil
}

// GetCertificateFingerprint 获取证书指纹
func GetCertificateFingerprint(certFile string) (string, error) {
	// 验证文件路径，防止路径遍历攻击
	cleanPath := filepath.Clean(certFile)
	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("invalid certificate path: potential path traversal")
	}

	certPEM, err := os.ReadFile(cleanPath)
	if err != nil {
		return "", fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	return fmt.Sprintf("%x", cert.Signature), nil
}

// GetCertificateFingerprintFromBytes 从证书字节数据获取指纹
func GetCertificateFingerprintFromBytes(certBytes []byte) (string, error) {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	return fmt.Sprintf("%x", cert.Signature), nil
}
