package tls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/XXXXD-cation/OpenEDR/shared/logger"
)

// Environment represents the deployment environment
type Environment string

const (
	EnvironmentProduction  Environment = "production"
	EnvironmentStaging     Environment = "staging"
	EnvironmentDevelopment Environment = "development"
	EnvironmentTest        Environment = "test"
)

// TLSConfig TLS配置结构
type TLSConfig struct {
	CertFile           string      // 证书文件路径
	KeyFile            string      // 私钥文件路径
	CAFile             string      // CA证书文件路径
	ServerName         string      // 服务器名称
	InsecureSkipVerify bool        // 跳过证书验证（仅用于测试）
	Environment        Environment // 部署环境
}

// ValidationResult represents the result of TLS configuration validation
type ValidationResult struct {
	Valid    bool     // 配置是否有效
	Errors   []string // 错误列表
	Warnings []string // 警告列表
}

// SecurityError represents a TLS security configuration error
type SecurityError struct {
	Code    string
	Message string
}

func (e SecurityError) Error() string {
	return fmt.Sprintf("TLS security error [%s]: %s", e.Code, e.Message)
}

var (
	ErrUnsafeTLSConfig = SecurityError{
		Code:    "UNSAFE_TLS_CONFIG",
		Message: "unsafe TLS configuration detected",
	}
	ErrProductionInsecureSkip = SecurityError{
		Code:    "PRODUCTION_INSECURE_SKIP",
		Message: "InsecureSkipVerify cannot be enabled in production environment",
	}
)

// ValidateTLSConfig validates TLS configuration for security issues
func ValidateTLSConfig(config TLSConfig) ValidationResult {
	result := ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}

	// Check for InsecureSkipVerify in production
	if config.InsecureSkipVerify {
		if config.Environment == EnvironmentProduction {
			result.Valid = false
			result.Errors = append(result.Errors, ErrProductionInsecureSkip.Message)
			logger.Error("TLS security violation: InsecureSkipVerify enabled in production environment")
		} else {
			result.Warnings = append(result.Warnings, "TLS certificate verification is disabled - only use in development/test environments")
			logger.Warn("TLS certificate verification is disabled in %s environment", string(config.Environment))
		}
	}

	// Validate required certificate files exist
	if config.CertFile == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "certificate file path is required")
	} else if !fileExists(config.CertFile) {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("certificate file not found: %s", config.CertFile))
	}

	if config.KeyFile == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "private key file path is required")
	} else if !fileExists(config.KeyFile) {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("private key file not found: %s", config.KeyFile))
	}

	if config.CAFile == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "CA certificate file path is required")
	} else if !fileExists(config.CAFile) {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("CA certificate file not found: %s", config.CAFile))
	}

	// Validate environment
	if config.Environment == "" {
		result.Warnings = append(result.Warnings, "environment not specified, assuming development")
		logger.Warn("TLS configuration environment not specified, assuming development")
	}

	// Additional security checks for production
	if config.Environment == EnvironmentProduction {
		if config.ServerName == "" && !config.InsecureSkipVerify {
			result.Warnings = append(result.Warnings, "server name not specified for production environment")
			logger.Warn("TLS server name not specified in production environment")
		}
	}

	return result
}

// ValidateAndLogTLSConfig validates TLS configuration and logs security issues
func ValidateAndLogTLSConfig(config TLSConfig) error {
	result := ValidateTLSConfig(config)

	// Log warnings
	for _, warning := range result.Warnings {
		logger.Warn("TLS configuration warning: %s", warning)
	}

	// Log errors and return if invalid
	if !result.Valid {
		for _, err := range result.Errors {
			logger.Error("TLS configuration error: %s", err)
		}
		return ErrUnsafeTLSConfig
	}

	logger.Info("TLS configuration validation passed for %s environment", string(config.Environment))
	return nil
}

// IsProductionEnvironment checks if the environment is production
func IsProductionEnvironment(env Environment) bool {
	return env == EnvironmentProduction
}

// IsDevelopmentEnvironment checks if the environment is development or test
func IsDevelopmentEnvironment(env Environment) bool {
	return env == EnvironmentDevelopment || env == EnvironmentTest
}

// fileExists checks if a file exists
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
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
	// 验证TLS配置安全性
	if err := ValidateAndLogTLSConfig(config); err != nil {
		return nil, fmt.Errorf("TLS configuration validation failed: %w", err)
	}

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

	// 强制在生产环境中禁用InsecureSkipVerify
	insecureSkipVerify := config.InsecureSkipVerify
	if IsProductionEnvironment(config.Environment) {
		insecureSkipVerify = false
		if config.InsecureSkipVerify {
			logger.Error("Forcing InsecureSkipVerify to false in production environment")
		}
	}

	// 配置TLS
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		ServerName:         config.ServerName,
		InsecureSkipVerify: insecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
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

	// 使用SHA256计算证书指纹
	hash := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", hash), nil
}

// GetCertificateFingerprintFromBytes 从证书字节数据获取指纹
func GetCertificateFingerprintFromBytes(certBytes []byte) (string, error) {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	// 使用SHA256计算证书指纹
	hash := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", hash), nil
}
