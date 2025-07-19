package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	internalgrpc "github.com/XXXXD-cation/OpenEDR/server/internal/grpc"
	"github.com/XXXXD-cation/OpenEDR/shared/proto/agent"
	sharedTLS "github.com/XXXXD-cation/OpenEDR/shared/tls"
)

func main() {
	// 配置
	serverAddr := "localhost:8443"
	tlsConfig := sharedTLS.TLSConfig{
		CertFile:   "certs/server.crt",
		KeyFile:    "certs/server.key",
		CAFile:     "certs/ca.crt",
		ServerName: "localhost",
	}

	// 加载TLS配置
	creds, err := loadTLSCredentials(tlsConfig)
	if err != nil {
		log.Fatalf("Failed to load TLS credentials: %v", err)
	}

	// 创建gRPC服务器
	server := grpc.NewServer(grpc.Creds(creds))

	// 注册Agent服务
	agentService := internalgrpc.NewAgentServiceServer()
	agent.RegisterAgentServiceServer(server, agentService)

	// 启动事件处理协程
	go handleEvents(agentService)
	go handleLogs(agentService)

	// 监听端口
	listener, err := net.Listen("tcp", serverAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", serverAddr, err)
	}

	log.Printf("OpenEDR Server starting on %s", serverAddr)
	log.Printf("TLS enabled with mutual authentication")

	// 启动服务器
	go func() {
		if err := server.Serve(listener); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	// 优雅关闭
	gracefulShutdown(server)
}

func loadTLSCredentials(config sharedTLS.TLSConfig) (credentials.TransportCredentials, error) {
	tlsConfig, err := sharedTLS.LoadServerTLSConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to load server TLS config: %w", err)
	}

	return credentials.NewTLS(tlsConfig), nil
}

func handleEvents(service *internalgrpc.AgentServiceServer) {
	eventsChan := service.GetEventsChan()
	for eventsReq := range eventsChan {
		log.Printf("Processing %d events from agent %s",
			len(eventsReq.EventBatch.Events), eventsReq.AgentId)

		// TODO: 实际的事件处理逻辑
		// - 存储到Elasticsearch
		// - 运行检测规则
		// - 生成告警
		// - 更新统计信息
	}
}

func handleLogs(service *internalgrpc.AgentServiceServer) {
	logsChan := service.GetLogsChan()
	for logsReq := range logsChan {
		log.Printf("Processing %d log entries", len(logsReq.Logs))

		// TODO: 实际的日志处理逻辑
		// - 存储到日志系统
		// - 分析日志模式
		// - 生成指标
	}
}

func gracefulShutdown(server *grpc.Server) {
	// 等待中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Println("Shutting down server...")

	// 优雅关闭
	server.GracefulStop()
	log.Println("Server stopped")
}
