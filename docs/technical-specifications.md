# OpenEDR 技术规范

## 1. 数据模型规范

### 1.1 事件数据模型

#### 基础事件结构
```json
{
  "event_id": "string (UUID)",
  "timestamp": "ISO 8601",
  "agent_id": "string",
  "hostname": "string",
  "event_type": "enum",
  "severity": "enum (low|medium|high|critical)",
  "data": {
    // 特定事件类型的数据
  },
  "metadata": {
    "version": "string",
    "os": "string",
    "architecture": "string"
  }
}
```

#### 进程事件
```json
{
  "event_type": "process_create|process_terminate",
  "data": {
    "process_id": "integer",
    "parent_process_id": "integer",
    "process_name": "string",
    "process_path": "string",
    "command_line": "string",
    "user": "string",
    "hash": {
      "md5": "string",
      "sha256": "string"
    },
    "signature": {
      "signed": "boolean",
      "verified": "boolean",
      "signer": "string"
    }
  }
}
```

#### 网络事件
```json
{
  "event_type": "network_connection",
  "data": {
    "protocol": "tcp|udp",
    "direction": "inbound|outbound",
    "local_address": "string",
    "local_port": "integer",
    "remote_address": "string",
    "remote_port": "integer",
    "process_id": "integer",
    "bytes_sent": "integer",
    "bytes_received": "integer"
  }
}
```

#### 文件事件
```json
{
  "event_type": "file_create|file_modify|file_delete",
  "data": {
    "file_path": "string",
    "file_name": "string",
    "operation": "string",
    "process_id": "integer",
    "hash": {
      "md5": "string",
      "sha256": "string"
    },
    "size": "integer",
    "permissions": "string"
  }
}
```

### 1.2 配置数据模型

#### Agent配置
```yaml
agent:
  id: "auto-generated"
  version: "1.0.0"
  
server:
  endpoint: "grpc://server:443"
  tls:
    cert: "/path/to/cert"
    key: "/path/to/key"
    ca: "/path/to/ca"
  
collection:
  process:
    enabled: true
    include_command_line: true
    hash_executables: true
  
  network:
    enabled: true
    capture_packets: false
    
  filesystem:
    enabled: true
    watch_paths:
      - "/etc"
      - "/var/log"
      - "/home"
    exclude_patterns:
      - "*.tmp"
      - "*.cache"
      
performance:
  max_cpu_percent: 5
  max_memory_mb: 200
  event_rate_limit: 1000
  
logging:
  level: "info"
  max_size_mb: 100
  max_files: 5
```

### 1.3 检测规则格式

#### YARA规则示例
```yara
rule SuspiciousProcess {
    meta:
        description = "Detects suspicious process behavior"
        severity = "high"
        
    strings:
        $a = "cmd.exe" nocase
        $b = "powershell" nocase
        $c = "-enc" nocase
        
    condition:
        ($a or $b) and $c
}
```

#### 自定义规则语言
```yaml
rule:
  name: "Suspicious Network Connection"
  description: "Detects connections to known malicious IPs"
  severity: "high"
  
  conditions:
    - event_type: "network_connection"
    - direction: "outbound"
    - remote_address:
        in_list: "threat_intel_ips"
    - process_name:
        not_in: ["chrome.exe", "firefox.exe"]
        
  actions:
    - alert: true
    - isolate_network: true
    - collect_memory: true
```

## 2. API规范

### 2.1 RESTful API

#### 认证端点
```
POST /api/v1/auth/login
Request:
{
  "username": "string",
  "password": "string"
}

Response:
{
  "token": "JWT",
  "expires_at": "ISO 8601"
}
```

#### Agent管理
```
GET /api/v1/agents
Response:
{
  "agents": [
    {
      "id": "string",
      "hostname": "string",
      "ip_address": "string",
      "os": "string",
      "version": "string",
      "status": "online|offline",
      "last_seen": "ISO 8601"
    }
  ],
  "total": "integer",
  "page": "integer"
}

GET /api/v1/agents/{id}
PUT /api/v1/agents/{id}/isolate
DELETE /api/v1/agents/{id}
```

#### 事件查询
```
POST /api/v1/events/search
Request:
{
  "query": {
    "event_type": ["process_create"],
    "severity": ["high", "critical"],
    "time_range": {
      "start": "ISO 8601",
      "end": "ISO 8601"
    }
  },
  "page": 1,
  "size": 100
}

Response:
{
  "events": [...],
  "total": "integer",
  "took": "integer (ms)"
}
```

### 2.2 gRPC API

#### Protocol Buffers定义
```protobuf
syntax = "proto3";
package openedr;

service AgentService {
  rpc Register(RegisterRequest) returns (RegisterResponse);
  rpc SendEvents(stream Event) returns (SendEventsResponse);
  rpc GetConfiguration(GetConfigRequest) returns (Configuration);
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
}

message Event {
  string event_id = 1;
  int64 timestamp = 2;
  EventType type = 3;
  bytes data = 4;
}

message RegisterRequest {
  string hostname = 1;
  string os = 2;
  string version = 3;
  bytes certificate = 4;
}

message RegisterResponse {
  string agent_id = 1;
  string token = 2;
  Configuration initial_config = 3;
}
```

## 3. 安全规范

### 3.1 加密标准

#### 传输加密
- TLS 1.3最低要求
- 支持的密码套件:
  - TLS_AES_256_GCM_SHA384
  - TLS_CHACHA20_POLY1305_SHA256
  - TLS_AES_128_GCM_SHA256

#### 存储加密
- 敏感数据: AES-256-GCM
- 密钥管理: PKCS#11或KMS集成
- 密钥轮换: 每90天

### 3.2 认证和授权

#### Agent认证
- 双向TLS证书认证
- 唯一Agent ID和Token
- 证书有效期: 1年
- 自动证书更新

#### 用户认证
- 密码要求:
  - 最小长度: 12字符
  - 复杂度: 大小写+数字+特殊字符
  - 历史记录: 不能使用最近5个密码
- MFA支持: TOTP/U2F

#### RBAC模型
```yaml
roles:
  admin:
    permissions:
      - "*"
  
  analyst:
    permissions:
      - "events:read"
      - "agents:read"
      - "alerts:*"
      - "reports:read"
  
  viewer:
    permissions:
      - "events:read"
      - "agents:read"
      - "dashboard:read"
```

### 3.3 审计日志

#### 审计事件格式
```json
{
  "timestamp": "ISO 8601",
  "user": "string",
  "action": "string",
  "resource": "string",
  "result": "success|failure",
  "details": {},
  "source_ip": "string"
}
```

## 4. 性能规范

### 4.1 Agent性能要求

| 指标 | 目标值 | 最大值 |
|------|--------|--------|
| CPU使用率 | < 3% | 5% |
| 内存使用 | < 150MB | 200MB |
| 磁盘I/O | < 5MB/s | 10MB/s |
| 网络带宽 | < 1Mbps | 2Mbps |
| 启动时间 | < 5s | 10s |

### 4.2 服务器性能要求

| 指标 | 目标值 | 最小要求 |
|------|--------|----------|
| 事件处理速度 | 100k/秒 | 50k/秒 |
| API响应时间(P50) | < 50ms | < 100ms |
| API响应时间(P99) | < 200ms | < 500ms |
| 并发连接数 | 10k | 5k |
| 数据保留期 | 90天 | 30天 |

### 4.3 扩展性要求

- 水平扩展: 支持添加节点线性扩展
- Agent数量: 单集群支持50k agents
- 数据分片: 基于时间和Agent ID
- 负载均衡: 支持多种算法

## 5. 数据收集规范

### 5.1 Linux eBPF程序

#### 支持的内核版本
- 最低: 4.14 (有限功能)
- 推荐: 5.4+
- 完整功能: 5.10+

#### eBPF程序类型
```c
// 进程监控
SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // 收集进程执行信息
}

// 网络监控
SEC("kprobe/tcp_connect")
int trace_connect(struct pt_regs *ctx) {
    // 收集TCP连接信息
}

// 文件监控
SEC("kprobe/vfs_open")
int trace_open(struct pt_regs *ctx) {
    // 收集文件打开信息
}
```

### 5.2 Windows驱动规范

#### 驱动类型
- 文件系统微过滤驱动
- 网络过滤驱动(WFP)
- 进程/线程通知回调

#### 支持的Windows版本
- Windows 10 1809+
- Windows Server 2016+
- Windows 11

## 6. 部署规范

### 6.1 硬件要求

#### Agent最低要求
- CPU: 1核
- 内存: 512MB
- 磁盘: 1GB
- 网络: 1Mbps

#### 服务器最低要求(1000 agents)
- CPU: 8核
- 内存: 32GB
- 磁盘: 1TB SSD
- 网络: 1Gbps

### 6.2 容器化规范

#### Docker镜像
```dockerfile
# Agent镜像
FROM alpine:3.18
RUN apk add --no-cache libc6-compat
COPY agent /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/agent"]

# 服务器镜像
FROM golang:1.21-alpine AS builder
# 构建步骤...
FROM alpine:3.18
COPY --from=builder /app/server /usr/local/bin/
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/server"]
```

#### Kubernetes部署
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openedr-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: openedr-server
  template:
    metadata:
      labels:
        app: openedr-server
    spec:
      containers:
      - name: server
        image: openedr/server:latest
        resources:
          requests:
            memory: "4Gi"
            cpu: "2"
          limits:
            memory: "8Gi"
            cpu: "4"
```

## 7. 集成规范

### 7.1 SIEM集成

#### Syslog格式
```
<priority>version timestamp hostname app-name procid msgid structured-data msg
```

#### CEF格式
```
CEF:0|OpenEDR|EDR|1.0|process_create|Process Creation|3|...
```

### 7.2 威胁情报集成

#### STIX 2.1支持
- 支持的对象类型:
  - Indicator
  - Malware
  - Attack Pattern
  - Threat Actor

#### TAXII 2.1客户端
- 轮询和订阅模式
- 自动更新间隔: 可配置
- 支持多个源

## 8. 合规性要求

### 8.1 数据隐私
- GDPR合规
- 数据最小化原则
- 用户数据删除权
- 数据可移植性

### 8.2 日志保留
- 默认保留期: 90天
- 可配置范围: 7-365天
- 自动清理机制
- 归档选项

### 8.3 合规报告
- PCI-DSS报告模板
- HIPAA合规检查
- SOC 2审计支持
- 自定义合规框架

## 9. 测试规范

### 9.1 单元测试
- 覆盖率要求: > 80%
- 测试框架:
  - Go: testing + testify
  - C/C++: Google Test
  - TypeScript: Jest

### 9.2 集成测试
- API测试: Postman/Newman
- 端到端测试: Cypress
- 性能测试: JMeter/Locust

### 9.3 安全测试
- 静态分析: SonarQube
- 动态分析: OWASP ZAP
- 依赖扫描: Snyk/Dependabot
- 渗透测试: 每季度

## 10. 维护规范

### 10.1 版本策略
- 语义化版本: MAJOR.MINOR.PATCH
- LTS版本: 每年一个
- 安全更新: 立即发布
- 功能更新: 每月

### 10.2 升级机制
- Agent自动升级
- 滚动升级支持
- 版本兼容性矩阵
- 回滚机制

### 10.3 监控指标
- 可用性: > 99.9%
- MTTR: < 30分钟
- 告警响应: < 5分钟
- 备份验证: 每周 