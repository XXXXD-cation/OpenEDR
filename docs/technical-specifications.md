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

| 指标 | 目标值 (优化后) | 最大值 | 优化前 |
|------|----------------|--------|--------|
| CPU使用率 | < 3% | 5% | < 5% |
| 内存使用 | < 150MB | 200MB | < 200MB |
| 磁盘I/O | < 5MB/s | 10MB/s | < 8MB/s |
| 网络带宽 | < 1Mbps | 2Mbps | < 1.5Mbps |
| 启动时间 | < 5s | 10s | < 8s |
| 事件延迟 | < 0.5s | 1s | < 1s |

### 4.1.1 eBPF 性能优化配置

#### Tracepoint 优化参数
```yaml
# Agent 配置文件中的性能优化设置
performance:
  ebpf:
    # 优先使用 tracepoint，降级使用 kprobe
    prefer_tracepoint: true
    
    # 事件批处理大小 (减少用户空间切换)
    batch_size: 64
    
    # Ring buffer 大小 (内核 5.4+)
    ring_buffer_size: "4MB"
    
    # Perf event buffer 大小 (内核 < 5.4)
    perf_buffer_size: "2MB"
    
    # 事件过滤在内核空间进行
    kernel_filtering: true
    
    # CPU 亲和性设置
    cpu_affinity: "auto"  # 或指定 CPU 核心
    
  # 采样率配置
  sampling:
    # 进程事件采样率 (1-100)
    process_events: 100
    
    # 网络事件采样率
    network_events: 80
    
    # 文件事件采样率
    file_events: 60
    
  # 内存优化
  memory:
    # 事件缓冲区大小
    event_buffer_size: "1MB"
    
    # 最大内存使用限制
    max_memory_mb: 150
    
    # 内存压力时的降级策略
    memory_pressure_action: "reduce_sampling"
```

#### 内核版本特定优化
```yaml
# 根据内核版本自动调整的优化参数
kernel_optimizations:
  "5.10+":
    use_ring_buffer: true
    use_bpf_core: true
    batch_processing: true
    
  "5.4-5.9":
    use_ring_buffer: true
    use_bpf_core: false
    batch_processing: true
    
  "4.9-5.3":
    use_ring_buffer: false
    use_perf_events: true
    batch_processing: false
    
  "4.4-4.8":
    use_ring_buffer: false
    use_perf_events: true
    fallback_to_kprobe: true
```

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

#### 支持的内核版本 (优化后)
- **最低支持**: 4.4 (兼容性模式，使用 kprobe 降级)
- **基础支持**: 4.9+ (稳定的 tracepoint 支持)
- **推荐版本**: 5.4+ (完整功能，最佳性能)
- **最优版本**: 5.10+ (所有优化功能)

#### 内核版本兼容性策略
- **Tracepoint 优先**: 优先使用稳定的 `sched_process_exec` 和 `sched_process_exit` tracepoint
- **Kprobe 降级**: 在 tracepoint 不可用时自动降级到 kprobe 实现
- **运行时检测**: 自动检测内核功能并选择最优实现方式
- **性能优化**: 在支持的内核上获得 20-30% 的性能提升

#### 生产环境内核版本建议

| 内核版本范围 | 支持级别 | 功能特性 | 性能提升 | 推荐使用 |
|-------------|----------|----------|----------|----------|
| 5.10+ | 完整支持 | 所有优化功能 | 30%+ | ✅ 强烈推荐 |
| 5.4 - 5.9 | 完整支持 | 大部分优化功能 | 25%+ | ✅ 推荐 |
| 4.9 - 5.3 | 基础支持 | 核心功能 | 20%+ | ⚠️ 可用 |
| 4.4 - 4.8 | 兼容性支持 | 基础功能 | 10%+ | ⚠️ 有限支持 |
| < 4.4 | 不支持 | 降级到 kprobe | 0% | ❌ 不推荐 |

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

## 11. 监控和告警配置 (优化后)

### 11.1 eBPF 性能监控指标

#### 核心性能指标
```yaml
# Prometheus 监控指标配置
ebpf_metrics:
  # Tracepoint vs Kprobe 性能对比
  - name: ebpf_tracepoint_events_total
    help: "Total number of tracepoint events processed"
    labels: ["event_type", "kernel_version"]
    
  - name: ebpf_kprobe_events_total
    help: "Total number of kprobe events processed (fallback)"
    labels: ["event_type", "kernel_version"]
    
  - name: ebpf_event_processing_duration_seconds
    help: "Time spent processing eBPF events"
    labels: ["implementation_type"]  # tracepoint, kprobe
    
  - name: ebpf_memory_usage_bytes
    help: "Memory usage by eBPF programs"
    labels: ["program_type", "kernel_version"]
    
  - name: ebpf_cpu_usage_percent
    help: "CPU usage by eBPF programs"
    labels: ["program_type"]
    
  - name: ebpf_kernel_compatibility_info
    help: "Kernel compatibility information"
    labels: ["kernel_version", "tracepoint_support", "feature_level"]
```

#### 优化效果监控
```yaml
optimization_metrics:
  # 性能提升指标
  - name: ebpf_performance_improvement_ratio
    help: "Performance improvement ratio (tracepoint vs kprobe)"
    labels: ["metric_type"]  # cpu, memory, latency
    
  - name: ebpf_event_drop_rate
    help: "Event drop rate due to performance issues"
    labels: ["cause"]  # buffer_full, cpu_pressure, memory_pressure
    
  - name: ebpf_fallback_usage_total
    help: "Number of times fallback to kprobe was used"
    labels: ["reason"]  # tracepoint_unavailable, kernel_incompatible
```

### 11.2 告警规则配置

#### 性能告警规则
```yaml
# Prometheus 告警规则
groups:
  - name: ebpf_performance
    rules:
      # CPU 使用率告警
      - alert: eBPF_HighCPUUsage
        expr: ebpf_cpu_usage_percent > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "eBPF CPU usage is high"
          description: "eBPF CPU usage is {{ $value }}% on {{ $labels.instance }}"
          
      # 内存使用告警
      - alert: eBPF_HighMemoryUsage
        expr: ebpf_memory_usage_bytes > 200 * 1024 * 1024
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "eBPF memory usage is high"
          description: "eBPF memory usage is {{ $value | humanizeBytes }} on {{ $labels.instance }}"
          
      # 事件丢失告警
      - alert: eBPF_HighEventDropRate
        expr: rate(ebpf_event_drop_rate[5m]) > 0.01
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High eBPF event drop rate"
          description: "Event drop rate is {{ $value | humanizePercentage }} on {{ $labels.instance }}"
          
      # 降级使用告警
      - alert: eBPF_FallbackToKprobe
        expr: increase(ebpf_fallback_usage_total[1h]) > 0
        for: 0m
        labels:
          severity: info
        annotations:
          summary: "eBPF fallback to kprobe detected"
          description: "Agent on {{ $labels.instance }} fell back to kprobe due to {{ $labels.reason }}"
```

#### 兼容性告警规则
```yaml
  - name: ebpf_compatibility
    rules:
      # 内核版本兼容性告警
      - alert: eBPF_UnsupportedKernel
        expr: ebpf_kernel_compatibility_info{feature_level="unsupported"} == 1
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Unsupported kernel version detected"
          description: "Kernel {{ $labels.kernel_version }} on {{ $labels.instance }} is not supported"
          
      # Tracepoint 不可用告警
      - alert: eBPF_TracepointUnavailable
        expr: ebpf_kernel_compatibility_info{tracepoint_support="false"} == 1
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "Tracepoint support unavailable"
          description: "Tracepoint support is unavailable on {{ $labels.instance }}, using kprobe fallback"
```

### 11.3 Grafana 仪表板配置

#### eBPF 性能仪表板
```json
{
  "dashboard": {
    "title": "OpenEDR eBPF Performance Dashboard",
    "panels": [
      {
        "title": "eBPF Implementation Distribution",
        "type": "piechart",
        "targets": [
          {
            "expr": "sum by (implementation_type) (ebpf_tracepoint_events_total + ebpf_kprobe_events_total)"
          }
        ]
      },
      {
        "title": "Performance Improvement Over Time",
        "type": "graph",
        "targets": [
          {
            "expr": "ebpf_performance_improvement_ratio",
            "legendFormat": "{{ metric_type }} improvement"
          }
        ]
      },
      {
        "title": "Event Processing Latency",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, ebpf_event_processing_duration_seconds)",
            "legendFormat": "95th percentile"
          },
          {
            "expr": "histogram_quantile(0.50, ebpf_event_processing_duration_seconds)",
            "legendFormat": "50th percentile"
          }
        ]
      },
      {
        "title": "Resource Usage by Kernel Version",
        "type": "table",
        "targets": [
          {
            "expr": "avg by (kernel_version) (ebpf_cpu_usage_percent)",
            "format": "table"
          },
          {
            "expr": "avg by (kernel_version) (ebpf_memory_usage_bytes)",
            "format": "table"
          }
        ]
      }
    ]
  }
}
```

### 11.4 日志监控配置

#### 结构化日志格式
```yaml
# 优化相关的日志配置
logging:
  ebpf_optimization:
    # 内核兼容性检测日志
    kernel_detection:
      level: info
      format: |
        {
          "timestamp": "{{ .Time }}",
          "level": "info",
          "component": "ebpf_manager",
          "event": "kernel_detection",
          "kernel_version": "{{ .KernelVersion }}",
          "tracepoint_support": {{ .TracepointSupport }},
          "feature_level": "{{ .FeatureLevel }}",
          "selected_implementation": "{{ .Implementation }}"
        }
    
    # 性能优化日志
    performance_optimization:
      level: debug
      format: |
        {
          "timestamp": "{{ .Time }}",
          "level": "debug",
          "component": "ebpf_optimizer",
          "event": "optimization_applied",
          "optimization_type": "{{ .OptimizationType }}",
          "before_value": {{ .BeforeValue }},
          "after_value": {{ .AfterValue }},
          "improvement_percent": {{ .ImprovementPercent }}
        }
    
    # 降级事件日志
    fallback_events:
      level: warning
      format: |
        {
          "timestamp": "{{ .Time }}",
          "level": "warning",
          "component": "ebpf_manager",
          "event": "fallback_triggered",
          "reason": "{{ .Reason }}",
          "from_implementation": "{{ .FromImplementation }}",
          "to_implementation": "{{ .ToImplementation }}",
          "impact": "{{ .Impact }}"
        }
```

### 11.5 自动化运维配置

#### 自动优化脚本
```bash
#!/bin/bash
# 自动性能优化脚本

# 检测内核版本并应用最优配置
optimize_ebpf_config() {
    local kernel_version=$(uname -r)
    local config_file="/etc/openedr/agent.yaml"
    
    # 根据内核版本选择最优配置
    case $kernel_version in
        5.1[0-9].*|6.*)
            # 最新内核，启用所有优化
            yq eval '.performance.ebpf.prefer_tracepoint = true' -i $config_file
            yq eval '.performance.ebpf.use_ring_buffer = true' -i $config_file
            yq eval '.performance.ebpf.batch_size = 64' -i $config_file
            ;;
        5.[4-9].*)
            # 较新内核，启用大部分优化
            yq eval '.performance.ebpf.prefer_tracepoint = true' -i $config_file
            yq eval '.performance.ebpf.use_ring_buffer = true' -i $config_file
            yq eval '.performance.ebpf.batch_size = 32' -i $config_file
            ;;
        4.9.*|5.[0-3].*)
            # 基础支持内核
            yq eval '.performance.ebpf.prefer_tracepoint = true' -i $config_file
            yq eval '.performance.ebpf.use_ring_buffer = false' -i $config_file
            yq eval '.performance.ebpf.batch_size = 16' -i $config_file
            ;;
        *)
            # 降级到 kprobe
            yq eval '.performance.ebpf.prefer_tracepoint = false' -i $config_file
            yq eval '.performance.ebpf.fallback_to_kprobe = true' -i $config_file
            ;;
    esac
    
    # 重启 agent 以应用新配置
    systemctl restart openedr-agent
}

# 性能监控和自动调优
monitor_and_tune() {
    # 获取当前性能指标
    local cpu_usage=$(curl -s "http://localhost:9090/api/v1/query?query=ebpf_cpu_usage_percent" | jq -r '.data.result[0].value[1]')
    local memory_usage=$(curl -s "http://localhost:9090/api/v1/query?query=ebpf_memory_usage_bytes" | jq -r '.data.result[0].value[1]')
    
    # 如果性能超出阈值，自动调整采样率
    if (( $(echo "$cpu_usage > 4.0" | bc -l) )); then
        echo "High CPU usage detected, reducing sampling rate"
        yq eval '.performance.sampling.process_events = 80' -i /etc/openedr/agent.yaml
        systemctl reload openedr-agent
    fi
    
    if (( $(echo "$memory_usage > 180000000" | bc -l) )); then
        echo "High memory usage detected, reducing buffer size"
        yq eval '.performance.memory.event_buffer_size = "512KB"' -i /etc/openedr/agent.yaml
        systemctl reload openedr-agent
    fi
}

# 定期执行优化检查
optimize_ebpf_config
monitor_and_tune
```

### 11.6 容量规划指导

#### 基于内核版本的容量规划
```yaml
capacity_planning:
  kernel_5_10_plus:
    agents_per_server: 15000
    cpu_cores_required: 16
    memory_gb_required: 64
    network_bandwidth_mbps: 1000
    
  kernel_5_4_to_5_9:
    agents_per_server: 12000
    cpu_cores_required: 20
    memory_gb_required: 80
    network_bandwidth_mbps: 1200
    
  kernel_4_9_to_5_3:
    agents_per_server: 8000
    cpu_cores_required: 24
    memory_gb_required: 96
    network_bandwidth_mbps: 1500
    
  kernel_4_4_to_4_8:
    agents_per_server: 5000
    cpu_cores_required: 32
    memory_gb_required: 128
    network_bandwidth_mbps: 2000
``` 