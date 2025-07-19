# OpenEDR API 参考文档

## 概述

OpenEDR提供RESTful API和gRPC API两种接口方式：
- **RESTful API**: 用于Web控制台和第三方集成
- **gRPC API**: 用于Agent与服务器之间的高性能通信

### 基础URL
```
https://api.openedr.com/v1
```

### 认证
所有API请求需要在Header中包含JWT令牌：
```
Authorization: Bearer <token>
```

### 响应格式
```json
{
  "success": true,
  "data": {},
  "error": null,
  "metadata": {
    "request_id": "uuid",
    "timestamp": "2024-01-01T00:00:00Z"
  }
}
```

## RESTful API

### 认证接口

#### POST /auth/login
用户登录

**请求体**
```json
{
  "username": "string",
  "password": "string",
  "mfa_code": "string" // 可选
}
```

**响应**
```json
{
  "success": true,
  "data": {
    "token": "jwt_token",
    "refresh_token": "refresh_token",
    "expires_at": "2024-01-01T00:00:00Z",
    "user": {
      "id": "uuid",
      "username": "string",
      "email": "string",
      "roles": ["admin"]
    }
  }
}
```

#### POST /auth/refresh
刷新访问令牌

**请求体**
```json
{
  "refresh_token": "string"
}
```

#### POST /auth/logout
用户登出

### Agent管理接口

#### GET /agents
获取Agent列表

**查询参数**
- `page` (int): 页码，默认1
- `limit` (int): 每页数量，默认20，最大100
- `status` (string): 状态过滤 (online|offline|all)
- `os` (string): 操作系统过滤
- `version` (string): 版本过滤
- `search` (string): 搜索关键词

**响应**
```json
{
  "success": true,
  "data": {
    "agents": [
      {
        "id": "uuid",
        "hostname": "server-01",
        "fqdn": "server-01.example.com",
        "ip_addresses": ["192.168.1.100"],
        "mac_addresses": ["00:11:22:33:44:55"],
        "os": {
          "platform": "linux",
          "distro": "ubuntu",
          "version": "20.04",
          "arch": "x86_64"
        },
        "agent_version": "1.0.0",
        "status": "online",
        "last_seen": "2024-01-01T00:00:00Z",
        "enrolled_at": "2024-01-01T00:00:00Z",
        "tags": ["production", "web-server"],
        "policies": ["default-policy"]
      }
    ],
    "pagination": {
      "total": 100,
      "page": 1,
      "limit": 20,
      "pages": 5
    }
  }
}
```

#### GET /agents/{id}
获取单个Agent详情

**响应**
```json
{
  "success": true,
  "data": {
    "id": "uuid",
    "hostname": "server-01",
    "system_info": {
      "cpu": {
        "model": "Intel Core i7",
        "cores": 8,
        "threads": 16
      },
      "memory": {
        "total": 16384,
        "available": 8192
      },
      "disks": [
        {
          "device": "/dev/sda",
          "mount": "/",
          "total": 512000,
          "used": 256000
        }
      ]
    },
    "network_interfaces": [
      {
        "name": "eth0",
        "ip": "192.168.1.100",
        "mac": "00:11:22:33:44:55"
      }
    ]
  }
}
```

#### PUT /agents/{id}
更新Agent配置

**请求体**
```json
{
  "tags": ["production", "database"],
  "policies": ["strict-policy"],
  "collection_config": {
    "process_monitoring": true,
    "network_monitoring": true,
    "file_monitoring": true
  }
}
```

#### POST /agents/{id}/isolate
隔离Agent

**请求体**
```json
{
  "type": "network", // network|full
  "reason": "Suspicious activity detected",
  "duration": 3600 // 秒，0表示永久
}
```

#### DELETE /agents/{id}/isolate
解除Agent隔离

#### DELETE /agents/{id}
删除Agent

### 事件查询接口

#### POST /events/search
搜索事件

**请求体**
```json
{
  "query": {
    "agent_ids": ["uuid1", "uuid2"],
    "event_types": ["process_create", "network_connection"],
    "severity": ["high", "critical"],
    "time_range": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-01-02T00:00:00Z"
    },
    "process": {
      "name": "cmd.exe",
      "command_line": "*powershell*"
    },
    "network": {
      "remote_ip": "1.2.3.4",
      "remote_port": 443
    }
  },
  "aggregations": {
    "by_type": {
      "field": "event_type"
    },
    "by_time": {
      "field": "timestamp",
      "interval": "1h"
    }
  },
  "sort": [
    {
      "field": "timestamp",
      "order": "desc"
    }
  ],
  "page": 1,
  "limit": 100
}
```

**响应**
```json
{
  "success": true,
  "data": {
    "events": [
      {
        "id": "uuid",
        "timestamp": "2024-01-01T00:00:00Z",
        "agent_id": "uuid",
        "hostname": "server-01",
        "event_type": "process_create",
        "severity": "high",
        "data": {
          "process": {
            "pid": 1234,
            "ppid": 1000,
            "name": "powershell.exe",
            "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "powershell.exe -enc <base64>",
            "user": "SYSTEM",
            "hash": {
              "md5": "abc123",
              "sha256": "def456"
            }
          }
        }
      }
    ],
    "aggregations": {
      "by_type": {
        "buckets": [
          {
            "key": "process_create",
            "count": 150
          }
        ]
      }
    },
    "total": 1000,
    "took": 45
  }
}
```

#### GET /events/{id}
获取事件详情

#### GET /events/{id}/context
获取事件上下文（前后相关事件）

### 告警管理接口

#### GET /alerts
获取告警列表

**查询参数**
- `status` (string): open|closed|all
- `severity` (string): low|medium|high|critical
- `assigned_to` (string): 用户ID
- `time_range` (string): 1h|24h|7d|30d|custom

#### GET /alerts/{id}
获取告警详情

#### PUT /alerts/{id}
更新告警状态

**请求体**
```json
{
  "status": "investigating", // open|investigating|closed
  "assigned_to": "user_id",
  "notes": "Initial investigation shows...",
  "tags": ["false-positive", "malware"]
}
```

#### POST /alerts/{id}/comments
添加告警评论

### 检测规则接口

#### GET /rules
获取规则列表

#### GET /rules/{id}
获取规则详情

#### POST /rules
创建新规则

**请求体**
```json
{
  "name": "Suspicious PowerShell Execution",
  "description": "Detects encoded PowerShell commands",
  "severity": "high",
  "enabled": true,
  "rule_type": "detection",
  "logic": {
    "conditions": [
      {
        "field": "process.name",
        "operator": "equals",
        "value": "powershell.exe"
      },
      {
        "field": "process.command_line",
        "operator": "contains",
        "value": "-enc"
      }
    ],
    "logic": "AND"
  },
  "actions": [
    {
      "type": "alert",
      "severity": "high"
    },
    {
      "type": "isolate",
      "duration": 300
    }
  ]
}
```

#### PUT /rules/{id}
更新规则

#### DELETE /rules/{id}
删除规则

### 响应动作接口

#### POST /responses/execute
执行响应动作

**请求体**
```json
{
  "agent_id": "uuid",
  "action_type": "kill_process", // kill_process|isolate_file|block_network
  "parameters": {
    "process_id": 1234
  },
  "reason": "Malicious process detected",
  "automated": false
}
```

#### GET /responses/{id}
获取响应动作状态

### 报告接口

#### GET /reports/types
获取可用报告类型

#### POST /reports/generate
生成报告

**请求体**
```json
{
  "report_type": "executive_summary", // executive_summary|threat_analysis|compliance
  "time_range": {
    "start": "2024-01-01T00:00:00Z",
    "end": "2024-01-31T23:59:59Z"
  },
  "filters": {
    "severity": ["high", "critical"],
    "agent_tags": ["production"]
  },
  "format": "pdf" // pdf|html|csv
}
```

#### GET /reports/{id}
下载生成的报告

### 系统管理接口

#### GET /system/status
获取系统状态

**响应**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "version": "1.0.0",
    "uptime": 864000,
    "components": {
      "api": "healthy",
      "database": "healthy",
      "message_queue": "healthy",
      "detection_engine": "healthy"
    },
    "metrics": {
      "agents_online": 450,
      "agents_total": 500,
      "events_per_second": 1250,
      "alerts_open": 23
    }
  }
}
```

#### GET /system/config
获取系统配置

#### PUT /system/config
更新系统配置

## gRPC API

### Protocol Buffers定义

```protobuf
syntax = "proto3";
package openedr.v1;

import "google/protobuf/timestamp.proto";

// Agent服务定义
service AgentService {
  // Agent注册
  rpc Register(RegisterRequest) returns (RegisterResponse);
  
  // 发送事件流
  rpc SendEvents(stream Event) returns (SendEventsResponse);
  
  // 获取配置
  rpc GetConfiguration(GetConfigRequest) returns (Configuration);
  
  // 心跳
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
  
  // 接收命令
  rpc ReceiveCommands(ReceiveCommandsRequest) returns (stream Command);
}

// 消息定义
message RegisterRequest {
  string hostname = 1;
  string fqdn = 2;
  SystemInfo system_info = 3;
  string agent_version = 4;
  bytes certificate = 5;
}

message RegisterResponse {
  string agent_id = 1;
  string token = 2;
  Configuration initial_config = 3;
}

message Event {
  string event_id = 1;
  google.protobuf.Timestamp timestamp = 2;
  EventType type = 3;
  Severity severity = 4;
  oneof data {
    ProcessEvent process = 5;
    NetworkEvent network = 6;
    FileEvent file = 7;
  }
}

message ProcessEvent {
  uint32 pid = 1;
  uint32 ppid = 2;
  string name = 3;
  string path = 4;
  string command_line = 5;
  string user = 6;
  Hash hash = 7;
}

message NetworkEvent {
  string protocol = 1;
  string local_address = 2;
  uint32 local_port = 3;
  string remote_address = 4;
  uint32 remote_port = 5;
  uint32 pid = 6;
  Direction direction = 7;
}

message FileEvent {
  string path = 1;
  string operation = 2;
  uint32 pid = 3;
  Hash hash = 4;
  uint64 size = 5;
}

// 枚举定义
enum EventType {
  EVENT_TYPE_UNKNOWN = 0;
  EVENT_TYPE_PROCESS_CREATE = 1;
  EVENT_TYPE_PROCESS_TERMINATE = 2;
  EVENT_TYPE_NETWORK_CONNECTION = 3;
  EVENT_TYPE_FILE_CREATE = 4;
  EVENT_TYPE_FILE_MODIFY = 5;
  EVENT_TYPE_FILE_DELETE = 6;
}

enum Severity {
  SEVERITY_UNKNOWN = 0;
  SEVERITY_LOW = 1;
  SEVERITY_MEDIUM = 2;
  SEVERITY_HIGH = 3;
  SEVERITY_CRITICAL = 4;
}
```

### gRPC客户端示例

#### Go客户端
```go
package main

import (
    "context"
    "log"
    
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    pb "github.com/openedr/api/proto/v1"
)

func main() {
    // 加载TLS证书
    creds, err := credentials.NewClientTLSFromFile("ca.crt", "")
    if err != nil {
        log.Fatal(err)
    }
    
    // 连接服务器
    conn, err := grpc.Dial("server:9090", grpc.WithTransportCredentials(creds))
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    
    client := pb.NewAgentServiceClient(conn)
    
    // 注册Agent
    resp, err := client.Register(context.Background(), &pb.RegisterRequest{
        Hostname:     "agent-01",
        AgentVersion: "1.0.0",
    })
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Registered with ID: %s", resp.AgentId)
    
    // 发送事件流
    stream, err := client.SendEvents(context.Background())
    if err != nil {
        log.Fatal(err)
    }
    
    // 发送事件
    event := &pb.Event{
        Type:     pb.EventType_EVENT_TYPE_PROCESS_CREATE,
        Severity: pb.Severity_SEVERITY_HIGH,
        Data: &pb.Event_Process{
            Process: &pb.ProcessEvent{
                Pid:         1234,
                Name:        "suspicious.exe",
                CommandLine: "suspicious.exe -malicious",
            },
        },
    }
    
    if err := stream.Send(event); err != nil {
        log.Fatal(err)
    }
}
```

## WebSocket API

### 实时事件订阅

**连接URL**
```
wss://api.openedr.com/v1/ws
```

**认证**
```json
{
  "type": "auth",
  "token": "jwt_token"
}
```

**订阅事件**
```json
{
  "type": "subscribe",
  "channels": [
    "events:high-severity",
    "alerts:new",
    "agents:status-change"
  ],
  "filters": {
    "agent_ids": ["uuid1", "uuid2"],
    "event_types": ["process_create"]
  }
}
```

**事件推送格式**
```json
{
  "type": "event",
  "channel": "events:high-severity",
  "data": {
    "id": "uuid",
    "timestamp": "2024-01-01T00:00:00Z",
    "event_type": "process_create",
    "severity": "high",
    "agent_id": "uuid",
    "data": {}
  }
}
```

## 错误处理

### 错误响应格式
```json
{
  "success": false,
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Invalid request parameters",
    "details": {
      "field": "agent_id",
      "reason": "Invalid UUID format"
    }
  },
  "metadata": {
    "request_id": "uuid",
    "timestamp": "2024-01-01T00:00:00Z"
  }
}
```

### 错误代码

| 代码 | HTTP状态码 | 说明 |
|------|------------|------|
| UNAUTHORIZED | 401 | 未认证或令牌无效 |
| FORBIDDEN | 403 | 无权限访问资源 |
| NOT_FOUND | 404 | 资源不存在 |
| INVALID_REQUEST | 400 | 请求参数无效 |
| CONFLICT | 409 | 资源冲突 |
| RATE_LIMITED | 429 | 请求频率超限 |
| INTERNAL_ERROR | 500 | 服务器内部错误 |
| SERVICE_UNAVAILABLE | 503 | 服务暂时不可用 |

## 速率限制

API实施以下速率限制：
- 认证接口: 10次/分钟
- 查询接口: 100次/分钟
- 写入接口: 50次/分钟

超出限制时返回429状态码，响应头包含：
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1641024000
```

## SDK使用示例

### Python SDK
```python
from openedr import Client

# 初始化客户端
client = Client(
    base_url="https://api.openedr.com/v1",
    api_key="your_api_key"
)

# 获取Agent列表
agents = client.agents.list(status="online")

# 搜索事件
events = client.events.search(
    event_types=["process_create"],
    severity=["high", "critical"],
    time_range={"start": "2024-01-01", "end": "2024-01-02"}
)

# 创建告警
alert = client.alerts.create(
    title="Suspicious Activity",
    description="Detected malicious process",
    severity="high",
    agent_id="uuid"
)
```

### JavaScript SDK
```javascript
import { OpenEDRClient } from '@openedr/sdk';

// 初始化客户端
const client = new OpenEDRClient({
  baseURL: 'https://api.openedr.com/v1',
  apiKey: 'your_api_key'
});

// 获取Agent列表
const agents = await client.agents.list({ status: 'online' });

// 实时事件订阅
const subscription = client.events.subscribe({
  channels: ['events:high-severity'],
  onEvent: (event) => {
    console.log('New event:', event);
  }
});

// 执行响应动作
await client.responses.execute({
  agentId: 'uuid',
  action: 'isolate',
  duration: 3600
});
```

## API版本控制

API使用URL路径进行版本控制：
- 当前版本: `/v1`
- 版本支持策略: 每个主版本支持至少12个月
- 废弃通知: 新版本发布后，旧版本标记为废弃但继续支持6个月

## 更多信息

- [完整API规范(OpenAPI)](https://api.openedr.com/docs/openapi.yaml)
- [Postman集合](https://api.openedr.com/docs/postman.json)
- [API更新日志](https://docs.openedr.com/api/changelog) 