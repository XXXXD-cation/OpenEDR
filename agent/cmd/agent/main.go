package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/XXXXD-cation/OpenEDR/agent/internal/grpc"
	"github.com/XXXXD-cation/OpenEDR/shared/proto/agent"
	"github.com/XXXXD-cation/OpenEDR/shared/proto/common"
	"github.com/XXXXD-cation/OpenEDR/shared/proto/events"
	sharedTLS "github.com/XXXXD-cation/OpenEDR/shared/tls"
)

func main() {
	// 配置
	serverAddr := "localhost:8443"
	tlsConfig := sharedTLS.TLSConfig{
		CertFile:   "certs/agent.crt",
		KeyFile:    "certs/agent.key",
		CAFile:     "certs/ca.crt",
		ServerName: "localhost",
	}

	// 创建Agent信息
	agentInfo := &common.AgentInfo{
		AgentId:      "test-agent-001",
		Hostname:     getHostname(),
		Os:           runtime.GOOS,
		OsVersion:    "Unknown", // TODO: 获取实际OS版本
		Architecture: runtime.GOARCH,
		AgentVersion: "1.0.0",
		LastSeen:     timestamppb.Now(),
		IpAddress:    "127.0.0.1",         // TODO: 获取实际IP地址
		MacAddress:   "00:00:00:00:00:00", // TODO: 获取实际MAC地址
		Tags:         make(map[string]string),
	}

	// 创建gRPC客户端
	clientConfig := grpc.ClientConfig{
		ServerAddr: serverAddr,
		TLSConfig:  tlsConfig,
		AgentInfo:  agentInfo,
		OnCommand:  handleCommand,
	}

	client, err := grpc.NewClient(clientConfig)
	if err != nil {
		log.Fatalf("Failed to create gRPC client: %v", err)
	}

	// 连接到服务器
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Printf("Connecting to server: %s", serverAddr)
	if err := client.Connect(ctx); err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}

	// 注册Agent
	if err := client.Register(ctx); err != nil {
		log.Fatalf("Failed to register agent: %v", err)
	}

	log.Printf("Agent registered with ID: %s", client.GetAgentID())

	// 启动事件生成器（测试用）
	go eventGenerator(client)

	// 启动健康检查
	go healthChecker(client)

	// 等待中断信号
	gracefulShutdown(client)
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func handleCommand(cmd *agent.AgentCommand) error {
	log.Printf("Received command: %s (%s)", cmd.CommandType, cmd.CommandId)

	// TODO: 实现实际的命令处理逻辑
	switch cmd.CommandType {
	case "restart":
		log.Printf("Handling restart command")
	case "update_config":
		log.Printf("Handling config update command")
	case "collect_info":
		log.Printf("Handling info collection command")
	case "isolate":
		log.Printf("Handling isolation command")
	default:
		log.Printf("Unknown command type: %s", cmd.CommandType)
	}

	return nil
}

func eventGenerator(client *grpc.Client) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	eventID := 1
	for range ticker.C {
		// 生成测试事件
		event := &events.Event{
			EventId:   fmt.Sprintf("event-%d", eventID),
			AgentId:   client.GetAgentID(),
			EventType: common.EventType_EVENT_TYPE_PROCESS,
			Timestamp: timestamppb.Now(),
			Hostname:  getHostname(),
			EventData: &events.Event_ProcessEvent{
				ProcessEvent: &events.ProcessEvent{
					ProcessId:        fmt.Sprintf("pid-%d", eventID),
					ParentProcessId:  "pid-0",
					ProcessName:      "test-process",
					CommandLine:      "test-process --arg1 --arg2",
					ExecutablePath:   "/usr/bin/test-process",
					WorkingDirectory: "/tmp",
					User:             "testuser",
					StartTime:        timestamppb.Now(),
					ProcessHash:      "abc123def456",
				},
			},
			Metadata:    make(map[string]string),
			ThreatLevel: common.ThreatLevel_THREAT_LEVEL_INFO,
			Tags:        []string{"test", "generated"},
		}

		// 创建事件批次
		eventBatch := &events.EventBatch{
			Events:         []*events.Event{event},
			BatchId:        fmt.Sprintf("batch-%d", eventID),
			BatchTimestamp: timestamppb.Now(),
			AgentId:        client.GetAgentID(),
		}

		// 发送事件
		if err := client.SendEvents(eventBatch); err != nil {
			log.Printf("Failed to send events: %v", err)
		} else {
			log.Printf("Sent event batch with %d events", len(eventBatch.Events))
		}

		eventID++
	}
}

func healthChecker(client *grpc.Client) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := client.HealthCheck(ctx); err != nil {
			log.Printf("Health check failed: %v", err)
		} else {
			log.Printf("Health check passed")
		}
		cancel()
	}
}

func gracefulShutdown(client *grpc.Client) {
	// 等待中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Println("Shutting down agent...")

	// 关闭客户端连接
	if err := client.Close(); err != nil {
		log.Printf("Error closing client: %v", err)
	}

	log.Println("Agent stopped")
}
