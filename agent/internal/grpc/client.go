package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/XXXXD-cation/OpenEDR/shared/proto/agent"
	"github.com/XXXXD-cation/OpenEDR/shared/proto/common"
	"github.com/XXXXD-cation/OpenEDR/shared/proto/events"
	sharedTLS "github.com/XXXXD-cation/OpenEDR/shared/tls"
)

// Client Agent gRPC客户端
type Client struct {
	// 连接配置
	serverAddr string
	tlsConfig  *tls.Config

	// gRPC连接和客户端
	conn   *grpc.ClientConn
	client agent.AgentServiceClient

	// Agent信息
	agentInfo *common.AgentInfo
	agentID   string
	config    *agent.AgentConfig

	// 状态管理
	connected bool
	mu        sync.RWMutex

	// 心跳管理
	heartbeatTicker *time.Ticker
	stopChan        chan struct{}

	// 事件流
	eventsStream agent.AgentService_ReportEventsClient
	eventsChan   chan *events.EventBatch

	// 回调函数
	onCommand func(*agent.AgentCommand) error
}

// ClientConfig 客户端配置
type ClientConfig struct {
	ServerAddr string
	TLSConfig  sharedTLS.TLSConfig
	AgentInfo  *common.AgentInfo
	OnCommand  func(*agent.AgentCommand) error
}

// NewClient 创建新的gRPC客户端
func NewClient(config ClientConfig) (*Client, error) {
	// 加载TLS配置
	tlsConfig, err := sharedTLS.LoadClientTLSConfig(config.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS config: %w", err)
	}

	return &Client{
		serverAddr: config.ServerAddr,
		tlsConfig:  tlsConfig,
		agentInfo:  config.AgentInfo,
		eventsChan: make(chan *events.EventBatch, 100),
		stopChan:   make(chan struct{}),
		onCommand:  config.OnCommand,
	}, nil
}

// Connect 连接到服务器
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	// 创建gRPC连接
	creds := credentials.NewTLS(c.tlsConfig)

	// 配置keepalive参数
	kacp := keepalive.ClientParameters{
		Time:                10 * time.Second, // 10秒发送一次keepalive ping
		Timeout:             time.Second,      // 1秒超时
		PermitWithoutStream: true,
	}

	conn, err := grpc.DialContext(ctx, c.serverAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(kacp),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}

	c.conn = conn
	c.client = agent.NewAgentServiceClient(conn)
	c.connected = true

	log.Printf("Connected to server: %s", c.serverAddr)
	return nil
}

// Register 向服务器注册Agent
func (c *Client) Register(ctx context.Context) error {
	if !c.connected {
		return fmt.Errorf("not connected to server")
	}

	// 获取证书指纹
	fingerprint, err := sharedTLS.GetCertificateFingerprintFromBytes(c.tlsConfig.Certificates[0].Certificate[0])
	if err != nil {
		log.Printf("Warning: failed to get certificate fingerprint: %v", err)
		fingerprint = ""
	}

	// 发送注册请求
	req := &agent.RegisterRequest{
		AgentInfo:              c.agentInfo,
		CertificateFingerprint: fingerprint,
	}

	resp, err := c.client.Register(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}

	if resp.Response.Status != common.Status_STATUS_SUCCESS {
		return fmt.Errorf("registration failed: %s", resp.Response.Message)
	}

	// 保存注册信息
	c.agentID = resp.AgentId
	c.config = resp.Config

	log.Printf("Agent registered successfully with ID: %s", c.agentID)

	// 启动心跳
	c.startHeartbeat()

	// 启动事件流
	if err := c.startEventsStream(ctx); err != nil {
		log.Printf("Warning: failed to start events stream: %v", err)
	}

	return nil
}

// startHeartbeat 启动心跳
func (c *Client) startHeartbeat() {
	if c.heartbeatTicker != nil {
		c.heartbeatTicker.Stop()
	}

	interval := time.Duration(c.config.HeartbeatInterval) * time.Second
	c.heartbeatTicker = time.NewTicker(interval)

	go func() {
		for {
			select {
			case <-c.heartbeatTicker.C:
				if err := c.sendHeartbeat(); err != nil {
					log.Printf("Heartbeat failed: %v", err)
				}
			case <-c.stopChan:
				return
			}
		}
	}()
}

// sendHeartbeat 发送心跳
func (c *Client) sendHeartbeat() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 构造心跳请求
	req := &agent.HeartbeatRequest{
		AgentId:   c.agentID,
		Timestamp: timestamppb.Now(),
		Status: &agent.AgentStatus{
			Version:          c.agentInfo.AgentVersion,
			Uptime:           timestamppb.Now(), // TODO: 计算实际运行时间
			Status:           "running",
			ActiveCollectors: c.config.EnabledCollectors,
			EventsProcessed:  0, // TODO: 统计实际处理的事件数
			EventsSent:       0, // TODO: 统计实际发送的事件数
		},
		Metrics: &agent.AgentMetrics{
			CpuUsage:        0.0, // TODO: 获取实际CPU使用率
			MemoryUsage:     0,   // TODO: 获取实际内存使用量
			DiskUsage:       0,   // TODO: 获取实际磁盘使用量
			EventsPerSecond: 0,   // TODO: 计算实际事件处理速率
		},
	}

	resp, err := c.client.Heartbeat(ctx, req)
	if err != nil {
		return fmt.Errorf("heartbeat request failed: %w", err)
	}

	if resp.Response.Status != common.Status_STATUS_SUCCESS {
		return fmt.Errorf("heartbeat failed: %s", resp.Response.Message)
	}

	// 处理服务器命令
	for _, command := range resp.Commands {
		if c.onCommand != nil {
			go func(cmd *agent.AgentCommand) {
				if err := c.onCommand(cmd); err != nil {
					log.Printf("Command execution failed: %v", err)
					// TODO: 上报命令执行失败结果
				}
			}(command)
		}
	}

	// 更新配置（如果有）
	if resp.UpdatedConfig != nil {
		c.config = resp.UpdatedConfig
		log.Printf("Agent configuration updated")
	}

	return nil
}

// startEventsStream 启动事件流
func (c *Client) startEventsStream(ctx context.Context) error {
	stream, err := c.client.ReportEvents(ctx)
	if err != nil {
		return fmt.Errorf("failed to create events stream: %w", err)
	}

	c.eventsStream = stream

	// 启动事件发送协程
	go c.eventsSender()

	// 启动响应接收协程
	go c.eventsReceiver()

	return nil
}

// eventsSender 事件发送协程
func (c *Client) eventsSender() {
	for {
		select {
		case eventBatch := <-c.eventsChan:
			req := &agent.ReportEventsRequest{
				AgentId:    c.agentID,
				EventBatch: eventBatch,
			}

			if err := c.eventsStream.Send(req); err != nil {
				log.Printf("Failed to send events: %v", err)
				// TODO: 实现重连逻辑
				return
			}

		case <-c.stopChan:
			return
		}
	}
}

// eventsReceiver 事件响应接收协程
func (c *Client) eventsReceiver() {
	for {
		resp, err := c.eventsStream.Recv()
		if err != nil {
			log.Printf("Failed to receive events response: %v", err)
			// TODO: 实现重连逻辑
			return
		}

		if resp.Response.Status != common.Status_STATUS_SUCCESS {
			log.Printf("Events processing failed: %s", resp.Response.Message)
		} else {
			log.Printf("Events processed: %d/%d", resp.EventsProcessed, resp.EventsReceived)
		}
	}
}

// SendEvents 发送事件批次
func (c *Client) SendEvents(eventBatch *events.EventBatch) error {
	if !c.connected {
		return fmt.Errorf("not connected to server")
	}

	select {
	case c.eventsChan <- eventBatch:
		return nil
	default:
		return fmt.Errorf("events channel is full")
	}
}

// ReportLogs 上报日志
func (c *Client) ReportLogs(ctx context.Context, logs []*agent.LogEntry) error {
	if !c.connected {
		return fmt.Errorf("not connected to server")
	}

	req := &agent.ReportLogsRequest{
		Logs: logs,
	}

	resp, err := c.client.ReportLogs(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to report logs: %w", err)
	}

	if resp.Response.Status != common.Status_STATUS_SUCCESS {
		return fmt.Errorf("log reporting failed: %s", resp.Response.Message)
	}

	return nil
}

// GetConfig 获取配置
func (c *Client) GetConfig(ctx context.Context) (*agent.AgentConfig, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected to server")
	}

	req := &agent.GetConfigRequest{
		AgentId:       c.agentID,
		ConfigVersion: "1.0", // TODO: 实现配置版本管理
	}

	resp, err := c.client.GetConfig(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %w", err)
	}

	if resp.Response.Status != common.Status_STATUS_SUCCESS {
		return nil, fmt.Errorf("get config failed: %s", resp.Response.Message)
	}

	return resp.Config, nil
}

// HealthCheck 健康检查
func (c *Client) HealthCheck(ctx context.Context) error {
	if !c.connected {
		return fmt.Errorf("not connected to server")
	}

	resp, err := c.client.HealthCheck(ctx, &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	if resp.Status != common.Status_STATUS_SUCCESS {
		return fmt.Errorf("server unhealthy: %s", resp.Message)
	}

	return nil
}

// Close 关闭连接
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil
	}

	// 停止心跳
	if c.heartbeatTicker != nil {
		c.heartbeatTicker.Stop()
	}

	// 发送停止信号
	close(c.stopChan)

	// 关闭事件流
	if c.eventsStream != nil {
		if err := c.eventsStream.CloseSend(); err != nil {
			log.Printf("Error closing events stream: %v", err)
		}
	}

	// 关闭连接
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			log.Printf("Error closing connection: %v", err)
		}
	}

	c.connected = false
	log.Printf("Disconnected from server")

	return nil
}

// IsConnected 检查连接状态
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// GetAgentID 获取Agent ID
func (c *Client) GetAgentID() string {
	return c.agentID
}

// GetConfig 获取当前配置
func (c *Client) GetCurrentConfig() *agent.AgentConfig {
	return c.config
}
