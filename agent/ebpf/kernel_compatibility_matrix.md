# 内核版本兼容性矩阵

## 概述

本文档提供了详细的内核版本兼容性矩阵，用于指导 eBPF tracepoint 实现的版本支持策略。

## 主要 Linux 发行版内核版本

### 企业级发行版

| 发行版 | 版本 | 内核版本 | LTS支持 | tracepoint支持 | 推荐使用 |
|--------|------|----------|---------|----------------|----------|
| RHEL 7 | 7.x | 3.10.x | 2024年 | 基础支持 | ⚠️ |
| RHEL 8 | 8.x | 4.18.x | 2029年 | 完整支持 | ✅ |
| RHEL 9 | 9.x | 5.14.x | 2032年 | 完整支持 | ✅ |
| CentOS 7 | 7.x | 3.10.x | EOL | 基础支持 | ❌ |
| CentOS 8 | 8.x | 4.18.x | EOL | 完整支持 | ⚠️ |
| Ubuntu 16.04 LTS | Xenial | 4.4.x | EOL | 基础支持 | ❌ |
| Ubuntu 18.04 LTS | Bionic | 4.15.x | 2028年 | 完整支持 | ✅ |
| Ubuntu 20.04 LTS | Focal | 5.4.x | 2030年 | 完整支持 | ✅ |
| Ubuntu 22.04 LTS | Jammy | 5.15.x | 2032年 | 完整支持 | ✅ |
| Ubuntu 24.04 LTS | Noble | 6.8.x | 2034年 | 完整支持 | ✅ |
| SLES 12 | SP5 | 4.12.x | 2027年 | 完整支持 | ✅ |
| SLES 15 | SP4+ | 5.3.x+ | 2031年 | 完整支持 | ✅ |
| Debian 9 | Stretch | 4.9.x | EOL | 完整支持 | ❌ |
| Debian 10 | Buster | 4.19.x | 2024年 | 完整支持 | ⚠️ |
| Debian 11 | Bullseye | 5.10.x | 2026年 | 完整支持 | ✅ |
| Debian 12 | Bookworm | 6.1.x | 2028年 | 完整支持 | ✅ |

### 云平台内核版本

| 云平台 | 服务 | 内核版本范围 | tracepoint支持 | 推荐使用 |
|--------|------|-------------|----------------|----------|
| AWS | EC2 | 4.14.x - 6.x.x | 完整支持 | ✅ |
| Azure | VM | 4.15.x - 6.x.x | 完整支持 | ✅ |
| GCP | Compute Engine | 4.19.x - 6.x.x | 完整支持 | ✅ |
| 阿里云 | ECS | 4.19.x - 6.x.x | 完整支持 | ✅ |
| 腾讯云 | CVM | 4.14.x - 6.x.x | 完整支持 | ✅ |

## Tracepoint 功能支持矩阵

### sched_process_exec Tracepoint

| 内核版本 | 结构可用性 | old_pid字段 | __data_loc_filename | 稳定性 | 推荐 |
|----------|-----------|-------------|---------------------|--------|------|
| 2.6.32+ | ❌ | ❌ | ❌ | 不稳定 | ❌ |
| 3.10+ | ⚠️ | ⚠️ | ⚠️ | 不稳定 | ❌ |
| 4.4+ | ✅ | ✅ | ✅ | 基础稳定 | ⚠️ |
| 4.9+ | ✅ | ✅ | ✅ | 稳定 | ✅ |
| 5.0+ | ✅ | ✅ | ✅ | 很稳定 | ✅ |
| 5.4+ | ✅ | ✅ | ✅ | 非常稳定 | ✅ |

### sched_process_exit Tracepoint

| 内核版本 | 结构可用性 | comm字段 | pid字段 | prio字段 | 稳定性 | 推荐 |
|----------|-----------|----------|---------|----------|--------|------|
| 2.6.32+ | ❌ | ❌ | ❌ | ❌ | 不稳定 | ❌ |
| 3.10+ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | 不稳定 | ❌ |
| 4.4+ | ✅ | ✅ | ✅ | ✅ | 基础稳定 | ⚠️ |
| 4.9+ | ✅ | ✅ | ✅ | ✅ | 稳定 | ✅ |
| 5.0+ | ✅ | ✅ | ✅ | ✅ | 很稳定 | ✅ |
| 5.4+ | ✅ | ✅ | ✅ | ✅ | 非常稳定 | ✅ |

## eBPF 功能支持

### 核心 eBPF 功能

| 功能 | 4.4+ | 4.9+ | 5.0+ | 5.4+ | 说明 |
|------|------|------|------|------|------|
| 基础 tracepoint | ✅ | ✅ | ✅ | ✅ | 所有版本支持 |
| bpf_probe_read_kernel | ❌ | ⚠️ | ✅ | ✅ | 5.0+ 推荐使用 |
| bpf_probe_read_kernel_str | ❌ | ⚠️ | ✅ | ✅ | 5.0+ 推荐使用 |
| Ring buffer | ❌ | ❌ | ⚠️ | ✅ | 5.4+ 稳定支持 |
| BPF_CORE | ❌ | ❌ | ⚠️ | ✅ | CO-RE 支持 |
| BTF | ❌ | ❌ | ⚠️ | ✅ | 类型信息支持 |

### 辅助函数支持

| 辅助函数 | 4.4+ | 4.9+ | 5.0+ | 5.4+ | 用途 |
|----------|------|------|------|------|------|
| bpf_get_current_pid_tgid | ✅ | ✅ | ✅ | ✅ | 获取进程ID |
| bpf_get_current_uid_gid | ✅ | ✅ | ✅ | ✅ | 获取用户ID |
| bpf_get_current_comm | ✅ | ✅ | ✅ | ✅ | 获取进程名 |
| bpf_ktime_get_ns | ✅ | ✅ | ✅ | ✅ | 获取时间戳 |
| bpf_ringbuf_reserve | ❌ | ❌ | ⚠️ | ✅ | Ring buffer 操作 |
| bpf_ringbuf_submit | ❌ | ❌ | ⚠️ | ✅ | Ring buffer 操作 |

## 推荐的支持策略

### 分层支持策略

#### 第一层：完整支持 (推荐)
- **内核版本**: 5.4+
- **功能**: 所有优化功能
- **目标**: 现代生产环境

#### 第二层：基础支持
- **内核版本**: 4.9 - 5.3
- **功能**: 核心功能，部分优化
- **目标**: 较老的生产环境

#### 第三层：兼容性支持
- **内核版本**: 4.4 - 4.8
- **功能**: 基础功能，降级实现
- **目标**: 遗留系统

#### 不支持
- **内核版本**: < 4.4
- **建议**: 使用 kprobe 降级实现

### 实现优先级

1. **高优先级**: 5.4+ (现代 LTS 内核)
2. **中优先级**: 4.9+ (稳定内核)
3. **低优先级**: 4.4+ (最低兼容)

## 测试矩阵

### 必须测试的内核版本

| 内核版本 | 测试优先级 | 测试范围 | 原因 |
|----------|-----------|----------|------|
| 5.15.x | 高 | 完整测试 | 当前 LTS |
| 5.10.x | 高 | 完整测试 | 前一个 LTS |
| 5.4.x | 高 | 完整测试 | 广泛使用的 LTS |
| 4.19.x | 中 | 核心功能 | Debian 10 |
| 4.18.x | 中 | 核心功能 | RHEL 8 |
| 4.15.x | 中 | 核心功能 | Ubuntu 18.04 |
| 4.9.x | 低 | 基础功能 | 最低推荐版本 |
| 4.4.x | 低 | 兼容性测试 | 最低支持版本 |

### 测试环境建议

```bash
# Docker 测试环境
docker run --privileged -v /lib/modules:/lib/modules:ro \
  ubuntu:18.04  # 4.15.x
docker run --privileged -v /lib/modules:/lib/modules:ro \
  ubuntu:20.04  # 5.4.x
docker run --privileged -v /lib/modules:/lib/modules:ro \
  ubuntu:22.04  # 5.15.x
```

## 部署建议

### 生产环境
- **推荐**: 5.4+ 内核
- **最低**: 4.9+ 内核
- **避免**: < 4.4 内核

### 开发环境
- **推荐**: 5.15+ 内核 (最新 LTS)
- **测试**: 多版本并行测试

### CI/CD 环境
- **核心测试**: 5.15, 5.10, 5.4
- **兼容性测试**: 4.19, 4.18, 4.15
- **边界测试**: 4.9, 4.4

## 版本检测代码示例

### 编译时检测
```c
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
    #define USE_MODERN_TRACEPOINT 1
    #define USE_RINGBUF 1
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
    #define USE_BASIC_TRACEPOINT 1
    #define USE_PERF_EVENT 1
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
    #define USE_COMPAT_TRACEPOINT 1
    #define USE_PERF_EVENT 1
#else
    #define USE_KPROBE_FALLBACK 1
#endif
```

### 运行时检测
```c
static int detect_kernel_features(void) {
    // 检测 tracepoint 可用性
    if (access("/sys/kernel/debug/tracing/events/sched/sched_process_exec", F_OK) == 0) {
        return FEATURE_TRACEPOINT_AVAILABLE;
    }
    return FEATURE_KPROBE_ONLY;
}
```

## 总结

1. **推荐最低版本**: 4.9 (稳定的 tracepoint 支持)
2. **目标版本**: 5.4+ (完整功能支持)
3. **测试重点**: LTS 版本 (5.15, 5.10, 5.4)
4. **部署策略**: 分层支持，优雅降级
5. **风险控制**: 全面测试，版本检测，降级机制