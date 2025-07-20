# OpenEDR 部署配置指南

## 概述

本文档提供了 OpenEDR 系统的详细部署配置指南，包括内核版本兼容性要求、性能调优建议、监控告警配置等内容。

## 目录

1. [内核版本兼容性要求](#1-内核版本兼容性要求)
2. [Agent 性能优化配置](#2-agent-性能优化配置)
3. [监控和告警配置](#3-监控和告警配置)
4. [部署架构配置](#4-部署架构配置)
5. [自动化运维配置](#5-自动化运维配置)
6. [容量规划指导](#6-容量规划指导)

---

## 1. 内核版本兼容性要求

### 1.1 支持的内核版本

OpenEDR 采用分层支持策略，根据内核版本提供不同级别的功能支持：

#### 第一层：完整支持 (推荐)
- **内核版本**: 5.10+
- **功能特性**: 所有优化功能
- **性能提升**: 30%+
- **目标环境**: 现代生产环境
- **推荐使用**: ✅ 强烈推荐

#### 第二层：基础支持
- **内核版本**: 5.4 - 5.9
- **功能特性**: 大部分优化功能
- **性能提升**: 25%+
- **目标环境**: 较新的生产环境
- **推荐使用**: ✅ 推荐

#### 第三层：兼容性支持
- **内核版本**: 4.9 - 5.3
- **功能特性**: 核心功能
- **性能提升**: 20%+
- **目标环境**: 较老的生产环境
- **推荐使用**: ⚠️ 可用

#### 第四层：有限支持
- **内核版本**: 4.4 - 4.8
- **功能特性**: 基础功能，降级实现
- **性能提升**: 10%+
- **目标环境**: 遗留系统
- **推荐使用**: ⚠️ 有限支持

#### 不支持
- **内核版本**: < 4.4
- **建议**: 升级内核或使用传统监控方案
- **推荐使用**: ❌ 不推荐

### 1.2 主要发行版兼容性

| 发行版 | 版本 | 内核版本 | 支持级别 | LTS 支持 | 推荐使用 |
|--------|------|----------|----------|----------|----------|
| Ubuntu 24.04 LTS | Noble | 6.8.x | 完整支持 | 2034年 | ✅ |
| Ubuntu 22.04 LTS | Jammy | 5.15.x | 完整支持 | 2032年 | ✅ |
| Ubuntu 20.04 LTS | Focal | 5.4.x | 完整支持 | 2030年 | ✅ |
| Ubuntu 18.04 LTS | Bionic | 4.15.x | 兼容性支持 | 2028年 | ⚠️ |
| RHEL 9 | 9.x | 5.14.x | 完整支持 | 2032年 | ✅ |
| RHEL 8 | 8.x | 4.18.x | 兼容性支持 | 2029年 | ⚠️ |
| Debian 12 | Bookworm | 6.1.x | 完整支持 | 2028年 | ✅ |
| Debian 11 | Bullseye | 5.10.x | 完整支持 | 2026年 | ✅ |

### 1.3 云平台兼容性

| 云平台 | 服务 | 内核版本范围 | 支持级别 | 推荐使用 |
|--------|------|-------------|----------|----------|
| AWS | EC2 | 4.14.x - 6.x.x | 完整支持 | ✅ |
| Azure | VM | 4.15.x - 6.x.x | 完整支持 | ✅ |
| GCP | Compute Engine | 4.19.x - 6.x.x | 完整支持 | ✅ |
| 阿里云 | ECS | 4.19.x - 6.x.x | 完整支持 | ✅ |
| 腾讯云 | CVM | 4.14.x - 6.x.x | 完整支持 | ✅ |

### 1.4 内核功能检测

#### 运行时检测脚本
```bash
#!/bin/bash
# 内核兼容性检测脚本

detect_kernel_compatibility() {
    local kernel_version=$(uname -r)
    local major=$(echo $kernel_version | cut -d. -f1)
    local minor=$(echo $kernel_version | cut -d. -f2)
    
    echo "检测到内核版本: $kernel_version"
    
    # 检测 tracepoint 支持
    if [ -d "/sys/kernel/debug/tracing/events/sched" ]; then
        echo "✅ Tracepoint 支持: 可用"
        tracepoint_support=true
    else
        echo "❌ Tracepoint 支持: 不可用"
        tracepoint_support=false
    fi
    
    # 检测 eBPF 支持
    if [ -f "/proc/sys/kernel/unprivileged_bpf_disabled" ]; then
        echo "✅ eBPF 支持: 可用"
        ebpf_support=true
    else
        echo "❌ eBPF 支持: 不可用"
        ebpf_support=false
    fi
    
    # 确定支持级别
    if [ $major -gt 5 ] || ([ $major -eq 5 ] && [ $minor -ge 10 ]); then
        echo "🎯 支持级别: 完整支持 (推荐)"
        support_level="full"
    elif [ $major -eq 5 ] && [ $minor -ge 4 ]; then
        echo "🎯 支持级别: 基础支持 (推荐)"
        support_level="basic"
    elif [ $major -eq 4 ] && [ $minor -ge 9 ]; then
        echo "🎯 支持级别: 兼容性支持 (可用)"
        support_level="compatibility"
    elif [ $major -eq 4 ] && [ $minor -ge 4 ]; then
        echo "🎯 支持级别: 有限支持 (不推荐)"
        support_level="limited"
    else
        echo "🎯 支持级别: 不支持"
        support_level="unsupported"
    fi
    
    # 生成配置建议
    generate_config_recommendations $support_level $tracepoint_support
}

generate_config_recommendations() {
    local support_level=$1
    local tracepoint_support=$2
    
    echo ""
    echo "=== 配置建议 ==="
    
    case $support_level in
        "full")
            echo "prefer_tracepoint: true"
            echo "use_ring_buffer: true"
            echo "batch_size: 64"
            echo "cpu_optimization: aggressive"
            ;;
        "basic")
            echo "prefer_tracepoint: true"
            echo "use_ring_buffer: true"
            echo "batch_size: 32"
            echo "cpu_optimization: moderate"
            ;;
        "compatibility")
            echo "prefer_tracepoint: $tracepoint_support"
            echo "use_ring_buffer: false"
            echo "batch_size: 16"
            echo "cpu_optimization: conservative"
            ;;
        "limited")
            echo "prefer_tracepoint: false"
            echo "fallback_to_kprobe: true"
            echo "batch_size: 8"
            echo "cpu_optimization: minimal"
            ;;
        *)
            echo "❌ 当前内核版本不支持，建议升级内核"
            exit 1
            ;;
    esac
}

# 执行检测
detect_kernel_compatibility
```

---

## 2. Agent 性能优化配置

### 2.1 基础性能配置

#### Agent 配置文件 (agent.yaml)
```yaml
# OpenEDR Agent 配置文件
agent:
  id: "auto-generated"
  version: "2.0.0"
  
# 服务器连接配置
server:
  endpoint: "grpc://server:443"
  tls:
    cert: "/etc/openedr/certs/agent.crt"
    key: "/etc/openedr/certs/agent.key"
    ca: "/etc/openedr/certs/ca.crt"
  
# 性能优化配置
performance:
  # eBPF 优化设置
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
    cpu_affinity: "auto"  # 或指定 CPU 核心 "0,1,2,3"
    
    # 内存映射优化
    memory_mapping:
      use_hugepages: true
      prefault_pages: true
    
  # 采样率配置
  sampling:
    # 进程事件采样率 (1-100)
    process_events: 100
    
    # 网络事件采样率
    network_events: 80
    
    # 文件事件采样率
    file_events: 60
    
    # 系统调用采样率
    syscall_events: 40
    
  # 内存优化
  memory:
    # 事件缓冲区大小
    event_buffer_size: "1MB"
    
    # 最大内存使用限制
    max_memory_mb: 150
    
    # 内存压力时的降级策略
    memory_pressure_action: "reduce_sampling"
    
    # 垃圾回收优化
    gc_target_percent: 50
    
  # CPU 优化
  cpu:
    # 最大 CPU 使用率限制
    max_cpu_percent: 3
    
    # CPU 压力时的降级策略
    cpu_pressure_action: "reduce_batch_size"
    
    # 工作线程数量
    worker_threads: "auto"  # 或指定数量
    
# 数据收集配置
collection:
  process:
    enabled: true
    include_command_line: true
    hash_executables: true
    monitor_injections: true
    
  network:
    enabled: true
    capture_packets: false
    monitor_dns: true
    track_connections: true
    
  filesystem:
    enabled: true
    watch_paths:
      - "/etc"
      - "/var/log"
      - "/home"
      - "/tmp"
    exclude_patterns:
      - "*.tmp"
      - "*.cache"
      - "*.log"
    hash_files: true
    
  registry:  # Windows only
    enabled: true
    monitor_keys:
      - "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
      - "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
      
# 日志配置
logging:
  level: "info"
  max_size_mb: 100
  max_files: 5
  compress: true
  
  # 性能相关日志
  performance_logging:
    enabled: true
    interval: "5m"
    metrics:
      - "cpu_usage"
      - "memory_usage"
      - "event_rate"
      - "buffer_utilization"
```

### 2.2 内核版本特定优化

#### 内核 5.10+ 优化配置
```yaml
# 最新内核优化配置
performance:
  ebpf:
    prefer_tracepoint: true
    use_ring_buffer: true
    use_bpf_core: true
    batch_processing: true
    batch_size: 64
    ring_buffer_size: "8MB"
    cpu_optimization: "aggressive"
    memory_optimization: "advanced"
    
  sampling:
    process_events: 100
    network_events: 90
    file_events: 80
    
  advanced_features:
    co_re_enabled: true
    btf_enabled: true
    jit_enabled: true
```

#### 内核 5.4-5.9 优化配置
```yaml
# 较新内核优化配置
performance:
  ebpf:
    prefer_tracepoint: true
    use_ring_buffer: true
    use_bpf_core: false
    batch_processing: true
    batch_size: 32
    ring_buffer_size: "4MB"
    cpu_optimization: "moderate"
    memory_optimization: "standard"
    
  sampling:
    process_events: 100
    network_events: 80
    file_events: 70
```

#### 内核 4.9-5.3 优化配置
```yaml
# 基础支持内核配置
performance:
  ebpf:
    prefer_tracepoint: true
    use_ring_buffer: false
    use_perf_events: true
    batch_processing: false
    batch_size: 16
    perf_buffer_size: "2MB"
    cpu_optimization: "conservative"
    memory_optimization: "basic"
    
  sampling:
    process_events: 90
    network_events: 70
    file_events: 60
```

#### 内核 4.4-4.8 兼容配置
```yaml
# 兼容性支持配置
performance:
  ebpf:
    prefer_tracepoint: false
    fallback_to_kprobe: true
    use_perf_events: true
    batch_processing: false
    batch_size: 8
    perf_buffer_size: "1MB"
    cpu_optimization: "minimal"
    memory_optimization: "conservative"
    
  sampling:
    process_events: 80
    network_events: 60
    file_events: 50
```

### 2.3 自动配置脚本

#### 配置生成脚本
```bash
#!/bin/bash
# 自动生成优化配置脚本

generate_optimized_config() {
    local kernel_version=$(uname -r)
    local config_file="/etc/openedr/agent.yaml"
    local template_dir="/etc/openedr/templates"
    
    echo "正在为内核 $kernel_version 生成优化配置..."
    
    # 检测内核版本并选择模板
    case $kernel_version in
        5.1[0-9].*|6.*)
            echo "使用最新内核优化模板"
            cp "$template_dir/agent-kernel-5.10+.yaml" "$config_file"
            ;;
        5.[4-9].*)
            echo "使用较新内核优化模板"
            cp "$template_dir/agent-kernel-5.4-5.9.yaml" "$config_file"
            ;;
        4.9.*|5.[0-3].*)
            echo "使用基础支持模板"
            cp "$template_dir/agent-kernel-4.9-5.3.yaml" "$config_file"
            ;;
        4.[4-8].*)
            echo "使用兼容性模板"
            cp "$template_dir/agent-kernel-4.4-4.8.yaml" "$config_file"
            ;;
        *)
            echo "❌ 不支持的内核版本: $kernel_version"
            exit 1
            ;;
    esac
    
    # 应用系统特定优化
    apply_system_optimizations "$config_file"
    
    echo "✅ 配置生成完成: $config_file"
}

apply_system_optimizations() {
    local config_file=$1
    local cpu_cores=$(nproc)
    local memory_gb=$(free -g | awk '/^Mem:/{print $2}')
    
    # 根据系统资源调整配置
    if [ $cpu_cores -ge 8 ]; then
        yq eval '.performance.cpu.worker_threads = 4' -i "$config_file"
        yq eval '.performance.ebpf.batch_size *= 2' -i "$config_file"
    elif [ $cpu_cores -ge 4 ]; then
        yq eval '.performance.cpu.worker_threads = 2' -i "$config_file"
    else
        yq eval '.performance.cpu.worker_threads = 1' -i "$config_file"
        yq eval '.performance.ebpf.batch_size /= 2' -i "$config_file"
    fi
    
    # 根据内存调整缓冲区大小
    if [ $memory_gb -ge 16 ]; then
        yq eval '.performance.memory.event_buffer_size = "2MB"' -i "$config_file"
        yq eval '.performance.memory.max_memory_mb = 200' -i "$config_file"
    elif [ $memory_gb -ge 8 ]; then
        yq eval '.performance.memory.event_buffer_size = "1MB"' -i "$config_file"
        yq eval '.performance.memory.max_memory_mb = 150' -i "$config_file"
    else
        yq eval '.performance.memory.event_buffer_size = "512KB"' -i "$config_file"
        yq eval '.performance.memory.max_memory_mb = 100' -i "$config_file"
    fi
}

# 执行配置生成
generate_optimized_config
```

---

## 3. 监控和告警配置

### 3.1 Prometheus 监控指标

#### eBPF 性能指标配置
```yaml
# prometheus.yml 配置片段
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "openedr_rules.yml"

scrape_configs:
  - job_name: 'openedr-agents'
    static_configs:
      - targets: ['agent1:9090', 'agent2:9090']
    scrape_interval: 10s
    metrics_path: /metrics
    
  - job_name: 'openedr-server'
    static_configs:
      - targets: ['server:9090']
    scrape_interval: 15s
```

#### 核心监控指标
```yaml
# 自定义指标配置
custom_metrics:
  # eBPF 性能指标
  ebpf_metrics:
    - name: ebpf_tracepoint_events_total
      help: "Total tracepoint events processed"
      type: counter
      labels: ["event_type", "kernel_version", "agent_id"]
      
    - name: ebpf_kprobe_events_total
      help: "Total kprobe events processed (fallback)"
      type: counter
      labels: ["event_type", "kernel_version", "agent_id"]
      
    - name: ebpf_event_processing_duration_seconds
      help: "Event processing duration"
      type: histogram
      labels: ["implementation_type", "agent_id"]
      buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
      
    - name: ebpf_memory_usage_bytes
      help: "eBPF program memory usage"
      type: gauge
      labels: ["program_type", "kernel_version", "agent_id"]
      
    - name: ebpf_cpu_usage_percent
      help: "eBPF CPU usage percentage"
      type: gauge
      labels: ["program_type", "agent_id"]
      
  # 系统兼容性指标
  compatibility_metrics:
    - name: ebpf_kernel_compatibility_info
      help: "Kernel compatibility information"
      type: gauge
      labels: ["kernel_version", "tracepoint_support", "feature_level", "agent_id"]
      
    - name: ebpf_fallback_usage_total
      help: "Fallback to kprobe usage count"
      type: counter
      labels: ["reason", "agent_id"]
      
  # 性能优化指标
  optimization_metrics:
    - name: ebpf_performance_improvement_ratio
      help: "Performance improvement ratio"
      type: gauge
      labels: ["metric_type", "agent_id"]
      
    - name: ebpf_event_drop_rate
      help: "Event drop rate"
      type: gauge
      labels: ["cause", "agent_id"]
```

### 3.2 告警规则配置

#### Prometheus 告警规则文件 (openedr_rules.yml)
```yaml
groups:
  - name: ebpf_performance
    rules:
      # CPU 使用率告警
      - alert: eBPF_HighCPUUsage
        expr: ebpf_cpu_usage_percent > 5
        for: 5m
        labels:
          severity: warning
          component: ebpf
        annotations:
          summary: "eBPF CPU usage is high"
          description: "eBPF CPU usage is {{ $value }}% on {{ $labels.agent_id }}"
          runbook_url: "https://docs.openedr.org/troubleshooting/high-cpu"
          
      # 内存使用告警
      - alert: eBPF_HighMemoryUsage
        expr: ebpf_memory_usage_bytes > 200 * 1024 * 1024
        for: 5m
        labels:
          severity: warning
          component: ebpf
        annotations:
          summary: "eBPF memory usage is high"
          description: "eBPF memory usage is {{ $value | humanizeBytes }} on {{ $labels.agent_id }}"
          runbook_url: "https://docs.openedr.org/troubleshooting/high-memory"
          
      # 事件丢失告警
      - alert: eBPF_HighEventDropRate
        expr: rate(ebpf_event_drop_rate[5m]) > 0.01
        for: 2m
        labels:
          severity: critical
          component: ebpf
        annotations:
          summary: "High eBPF event drop rate detected"
          desn: "Event drop rate is {{ $value | humanizePercentage }} on {{ $labels.agent_id }}"
          runbook_url: "https://docs.openedr.org/troubleshooting/event-drops"
          
      # 处理延迟告警
      - alert: eBPF_HighProcessingLatency
        expr: histogram_quantile(0.95, ebpf_event_processing_duration_seconds) > 0.1
        for: 3m
        labels:
          severity: warning
          component: ebpf
        annotations:
          summary: "High eBPF event processing latency"
          description: "95th percentile processing latency is {{ $value }}s on {{ $labels.agent_id }}"

  - name: ebpf_compatibility
    rules:
      # 不支持的内核版本告警
      - alert: eBPF_UnsupportedKernel
        expr: ebpf_kernel_compatibility_info{feature_level="unsupported"} == 1
        for: 0m
        labels:
          severity: critical
          component: compatibility
        annotations:
          summary: "Unsupported kernel version detected"
          description: "Kernel {{ $labels.kernel_version }} on {{ $labels.agent_id }} is not supported"
          runbook_url: "https://docs.openedr.org/compatibility/kernel-upgrade"
          
      # Tracepoint 不可用告警
      - alert: eBPF_TracepointUnavailable
        expr: ebpf_kernel_compatibility_info{tracepoint_support="false"} == 1
        for: 0m
        labels:
          severity: warning
          component: compatibility
        annotations:
          summary: "Tracepoint support unavailable"
          description: "Tracepoint support unavailable on {{ $labels.agent_id }}, using kprobe fallback"
          
      # 频繁降级告警
      - alert: eBPF_FrequentFallback
        expr: rate(ebpf_fallback_usage_total[1h]) > 0.1
        for: 5m
        labels:
          severity: warning
          component: compatibility
        annotations:
          summary: "Frequent eBPF fallback detected"
          description: "Agent {{ $labels.agent_id }} is frequently falling back to kprobe"

  - name: agent_health
    rules:
      # Agent 离线告警
      - alert: Agent_Offline
        expr: up{job="openedr-agents"} == 0
        for: 2m
        labels:
          severity: critical
          component: agent
        annotations:
          summary: "OpenEDR Agent is offline"
          description: "Agent {{ $labels.instance }} has been offline for more than 2 minutes"
          
      # Agent 性能下降告警
      - alert: Agent_PerformanceDegradation
        expr: |
          (
            ebpf_performance_improvement_ratio{metric_type="cpu"} < 0.8 or
            ebpf_performance_improvement_ratio{metric_type="memory"} < 0.8 or
            ebpf_performance_improvement_ratio{metric_type="latency"} < 0.8
          )
        for: 10m
        labels:
          severity: warning
          component: performance
        annotations:
          summary: "Agent performance degradation detected"
          description: "Performance improvement ratio dropped below 80% on {{ $labels.agent_id }}"
```

### 3.3 Grafana 仪表板配置

#### eBPF 性能监控仪表板
```json
{
  "dashboard": {
    "id": null,
    "title": "OpenEDR eBPF Performance Dashboard",
    "tags": ["openedr", "ebpf", "performance"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "eBPF Implementation Distribution",
        "type": "piechart",
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
        "targets": [
          {
            "expr": "sum by (implementation_type) (ebpf_tracepoint_events_total + ebpf_kprobe_events_total)",
            "legendFormat": "{{ implementation_type }}"
          }
        ],
        "options": {
          "legend": {"displayMode": "table", "placement": "right"},
          "pieType": "pie"
        }
      },
      {
        "id": 2,
        "title": "CPU Usage by Agent",
        "type": "graph",
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
        "targets": [
          {
            "expr": "ebpf_cpu_usage_percent",
            "legendFormat": "{{ agent_id }}"
          }
        ],
        "yAxes": [
          {"label": "CPU %", "max": 10, "min": 0}
        ],
        "alert": {
          "conditions": [
            {
              "query": {"params": ["A", "5m", "now"]},
              "reducer": {"params": [], "type": "avg"},
              "evaluator": {"params": [5], "type": "gt"}
            }
          ],
          "executionErrorState": "alerting",
          "for": "5m",
          "frequency": "10s",
          "handler": 1,
          "name": "High CPU Usage",
          "noDataState": "no_data"
        }
      },
      {
        "id": 3,
        "title": "Memory Usage by Agent",
        "type": "graph",
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
        "targets": [
          {
            "expr": "ebpf_memory_usage_bytes / 1024 / 1024",
            "legendFormat": "{{ agent_id }}"
          }
        ],
        "yAxes": [
          {"label": "Memory (MB)", "max": 250, "min": 0}
        ]
      },
      {
        "id": 4,
        "title": "Event Processing Latency",
        "type": "graph",
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8},
        "targets": [
          {
            "expr": "histogram_quantile(0.95, ebpf_event_processing_duration_seconds)",
            "legendFormat": "95th percentile"
          },
          {
            "expr": "histogram_quantile(0.50, ebpf_event_processing_duration_seconds)",
            "legendFormat": "50th percentile"
          }
        ],
        "yAxes": [
          {"label": "Latency (s)", "logBase": 10}
        ]
      }
    ],
    "time": {"from": "now-1h", "to": "now"},
    "refresh": "30s"
  }
}
```