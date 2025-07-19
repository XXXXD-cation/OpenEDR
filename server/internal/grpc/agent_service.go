package grpc

import (
	"context"
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/XXXXD-cation/OpenEDR/shared/proto/agent"
	"github.com/XXXXD-cation/OpenEDR/shared/proto/common"
)

// AgentServiceServer Agent服务实现
type AgentServiceServer struct {
	agent.UnimplementedAgentServiceServer

	// Agent管理
	agents    map[string]*AgentInfo
	agentsMux sync.RWMutex

	// 配置管理
	defaultConfig *agent.AgentConfig

	// 事件处理通道
	eventsChan chan *agent.ReportEventsRequest

	// 日志处理通道
	logsChan chan *agent.ReportLogsRequest
}

// AgentInfo Agent信息结构
type AgentInfo struct {
	Info        *common.AgentInfo
	LastSeen    time.Time
	Status      *agent.AgentStatus
	Metrics     *agent.AgentMetrics
	Config      *agent.AgentConfig
	Commands    []*agent.AgentCommand
	commandsMux sync.RWMutex
}

// NewAgentServiceServer 创建新的Agent服务
func NewAgentServiceServer() *AgentServiceServer {
	return &AgentServiceServer{
		agents:     make(map[string]*AgentInfo),
		eventsChan: make(chan *agent.ReportEventsRequest, 1000),
		logsChan:   make(chan *agent.ReportLogsRequest, 1000),
		defaultConfig: &agent.AgentConfig{
			HeartbeatInterval:    60,  // 60秒
			EventBatchSize:       100, // 100个事件一批
			EventBatchTimeout:    30,  // 30秒超时
			EnabledCollectors:    []string{"process", "network", "file"},
			EnableRealTimeEvents: true,
			CollectorConfigs:     make(map[string]string),
			BlockedProcesses:     []string{},
			BlockedDomains:       []string{},
			LogConfig: &agent.LogConfig{
				Level:       common.LogLevel_LOG_LEVEL_INFO,
				Output:      "file",
				FilePath:    "/var/log/openedr-agent.log",
				MaxFileSize: 100, // 100MB
				MaxBackups:  5,
				MaxAge:      30, // 30天
			},
		},
	}
}

// Register Agent注册
func (s *AgentServiceServer) Register(ctx context.Context, req *agent.RegisterRequest) (*agent.RegisterResponse, error) {
	// 获取客户端信息
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "failed to get peer info")
	}

	log.Printf("Agent registration from %s", p.Addr.String())

	// 验证Agent信息
	if req.AgentInfo == nil {
		return nil, status.Error(codes.InvalidArgument, "agent info is required")
	}

	if req.AgentInfo.AgentId == "" {
		return nil, status.Error(codes.InvalidArgument, "agent ID is required")
	}

	// 生成或验证Agent ID
	agentID := req.AgentInfo.AgentId

	// 创建Agent信息
	agentInfo := &AgentInfo{
		Info:     req.AgentInfo,
		LastSeen: time.Now(),
		Config:   s.defaultConfig,
		Commands: []*agent.AgentCommand{},
	}

	// 存储Agent信息
	s.agentsMux.Lock()
	s.agents[agentID] = agentInfo
	s.agentsMux.Unlock()

	log.Printf("Agent %s registered successfully", agentID)

	// 返回注册响应
	return &agent.RegisterResponse{
		Response: &common.Response{
			Status:    common.Status_STATUS_SUCCESS,
			Message:   "Agent registered successfully",
			Timestamp: timestamppb.Now(),
		},
		AgentId:       agentID,
		Config:        s.defaultConfig,
		NextHeartbeat: timestamppb.New(time.Now().Add(time.Duration(s.defaultConfig.HeartbeatInterval) * time.Second)),
	}, nil
}

// Heartbeat 心跳检查
func (s *AgentServiceServer) Heartbeat(ctx context.Context, req *agent.HeartbeatRequest) (*agent.HeartbeatResponse, error) {
	if req.AgentId == "" {
		return nil, status.Error(codes.InvalidArgument, "agent ID is required")
	}

	// 获取Agent信息
	s.agentsMux.RLock()
	agentInfo, exists := s.agents[req.AgentId]
	s.agentsMux.RUnlock()

	if !exists {
		return nil, status.Error(codes.NotFound, "agent not found")
	}

	// 更新Agent状态
	s.agentsMux.Lock()
	agentInfo.LastSeen = time.Now()
	if req.Status != nil {
		agentInfo.Status = req.Status
	}
	if req.Metrics != nil {
		agentInfo.Metrics = req.Metrics
	}
	s.agentsMux.Unlock()

	// 获取待执行的命令
	agentInfo.commandsMux.RLock()
	commands := make([]*agent.AgentCommand, len(agentInfo.Commands))
	copy(commands, agentInfo.Commands)
	agentInfo.commandsMux.RUnlock()

	// 清空已发送的命令
	agentInfo.commandsMux.Lock()
	agentInfo.Commands = []*agent.AgentCommand{}
	agentInfo.commandsMux.Unlock()

	log.Printf("Heartbeat from agent %s, status: %s", req.AgentId, req.Status.Status)

	return &agent.HeartbeatResponse{
		Response: &common.Response{
			Status:    common.Status_STATUS_SUCCESS,
			Message:   "Heartbeat received",
			Timestamp: timestamppb.Now(),
		},
		NextHeartbeat: timestamppb.New(time.Now().Add(time.Duration(agentInfo.Config.HeartbeatInterval) * time.Second)),
		Commands:      commands,
		UpdatedConfig: nil, // 只有配置更新时才返回
	}, nil
}

// ReportEvents 事件上报 (流式)
func (s *AgentServiceServer) ReportEvents(stream agent.AgentService_ReportEventsServer) error {
	for {
		req, err := stream.Recv()
		if err != nil {
			log.Printf("Error receiving events: %v", err)
			return err
		}

		if req.AgentId == "" {
			return status.Error(codes.InvalidArgument, "agent ID is required")
		}

		// 验证Agent是否存在
		s.agentsMux.RLock()
		_, exists := s.agents[req.AgentId]
		s.agentsMux.RUnlock()

		if !exists {
			return status.Error(codes.NotFound, "agent not found")
		}

		// 处理事件批次
		eventsReceived := len(req.EventBatch.Events)
		log.Printf("Received %d events from agent %s", eventsReceived, req.AgentId)

		// 将事件发送到处理通道
		select {
		case s.eventsChan <- req:
			// 事件已发送到处理通道
		default:
			log.Printf("Warning: events channel is full, dropping events from agent %s", req.AgentId)
		}

		// 发送响应
		response := &agent.ReportEventsResponse{
			Response: &common.Response{
				Status:    common.Status_STATUS_SUCCESS,
				Message:   fmt.Sprintf("Received %d events", eventsReceived),
				Timestamp: timestamppb.Now(),
			},
			EventsReceived:  safeIntToInt32(eventsReceived),
			EventsProcessed: safeIntToInt32(eventsReceived),
			FailedEventIds:  []string{},
		}

		if err := stream.Send(response); err != nil {
			log.Printf("Error sending events response: %v", err)
			return err
		}
	}
}

// GetConfig 获取配置
func (s *AgentServiceServer) GetConfig(ctx context.Context, req *agent.GetConfigRequest) (*agent.GetConfigResponse, error) {
	if req.AgentId == "" {
		return nil, status.Error(codes.InvalidArgument, "agent ID is required")
	}

	// 获取Agent配置
	s.agentsMux.RLock()
	agentInfo, exists := s.agents[req.AgentId]
	s.agentsMux.RUnlock()

	if !exists {
		return nil, status.Error(codes.NotFound, "agent not found")
	}

	return &agent.GetConfigResponse{
		Response: &common.Response{
			Status:    common.Status_STATUS_SUCCESS,
			Message:   "Config retrieved successfully",
			Timestamp: timestamppb.Now(),
		},
		Config:        agentInfo.Config,
		ConfigVersion: "1.0", // TODO: 实现配置版本管理
	}, nil
}

// ReportCommandResult 命令执行结果上报
func (s *AgentServiceServer) ReportCommandResult(ctx context.Context, req *agent.CommandResult) (*common.Response, error) {
	if req.AgentId == "" {
		return nil, status.Error(codes.InvalidArgument, "agent ID is required")
	}

	if req.CommandId == "" {
		return nil, status.Error(codes.InvalidArgument, "command ID is required")
	}

	log.Printf("Command result from agent %s: command=%s, status=%s",
		req.AgentId, req.CommandId, req.Status.String())

	// TODO: 存储命令执行结果

	return &common.Response{
		Status:    common.Status_STATUS_SUCCESS,
		Message:   "Command result received",
		Timestamp: timestamppb.Now(),
	}, nil
}

// ReportLogs 日志上报
func (s *AgentServiceServer) ReportLogs(ctx context.Context, req *agent.ReportLogsRequest) (*agent.ReportLogsResponse, error) {
	logsReceived := len(req.Logs)
	log.Printf("Received %d log entries", logsReceived)

	// 将日志发送到处理通道
	select {
	case s.logsChan <- req:
		// 日志已发送到处理通道
	default:
		log.Printf("Warning: logs channel is full, dropping logs")
	}

	return &agent.ReportLogsResponse{
		Response: &common.Response{
			Status:    common.Status_STATUS_SUCCESS,
			Message:   fmt.Sprintf("Received %d logs", logsReceived),
			Timestamp: timestamppb.Now(),
		},
		LogsReceived: safeIntToInt32(logsReceived),
	}, nil
}

// HealthCheck 健康检查
func (s *AgentServiceServer) HealthCheck(ctx context.Context, req *emptypb.Empty) (*common.Response, error) {
	return &common.Response{
		Status:    common.Status_STATUS_SUCCESS,
		Message:   "Service is healthy",
		Timestamp: timestamppb.Now(),
	}, nil
}

// GetAgents 获取所有Agent信息
func (s *AgentServiceServer) GetAgents() map[string]*AgentInfo {
	s.agentsMux.RLock()
	defer s.agentsMux.RUnlock()

	agents := make(map[string]*AgentInfo)
	for id, info := range s.agents {
		agents[id] = info
	}
	return agents
}

// SendCommand 向Agent发送命令
func (s *AgentServiceServer) SendCommand(agentID string, command *agent.AgentCommand) error {
	s.agentsMux.RLock()
	agentInfo, exists := s.agents[agentID]
	s.agentsMux.RUnlock()

	if !exists {
		return fmt.Errorf("agent %s not found", agentID)
	}

	agentInfo.commandsMux.Lock()
	agentInfo.Commands = append(agentInfo.Commands, command)
	agentInfo.commandsMux.Unlock()

	log.Printf("Command %s queued for agent %s", command.CommandId, agentID)
	return nil
}

// GetEventsChan 获取事件处理通道
func (s *AgentServiceServer) GetEventsChan() <-chan *agent.ReportEventsRequest {
	return s.eventsChan
}

// GetLogsChan 获取日志处理通道
func (s *AgentServiceServer) GetLogsChan() <-chan *agent.ReportLogsRequest {
	return s.logsChan
}

// safeIntToInt32 安全地将 int 转换为 int32
func safeIntToInt32(n int) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	if n < math.MinInt32 {
		return math.MinInt32
	}
	return int32(n)
}
