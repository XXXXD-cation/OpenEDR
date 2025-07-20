# eBPF 故障排除指南

## 概述

本指南提供了 OpenEDR 系统中 eBPF 程序常见问题的诊断和解决方法，包括 tracepoint 和 kprobe 相关的故障排除步骤。

## 常见问题分类

### 1. 加载和附加问题
### 2. 运行时错误
### 3. 性能问题
### 4. 兼容性问题
### 5. 数据收集问题

## 1. 加载和附加问题

### 1.1 eBPF 程序加载失败

#### 症状
- 程序启动时报错：`Failed to load eBPF program`
- 日志显示验证器错误

#### 可能原因
- 内核版本不支持所需的 eBPF 功能
- 程序超过复杂度限制
- 权限不足

#### 诊断步骤

```bash
# 检查内核版本
uname -r

# 检查 eBPF 支持
cat /proc/sys/kernel/unprivileged_bpf_disabled

# 检查权限
id
```

#### 解决方案

```bash
# 1. 确保以 root 权限运行
sudo ./agent

# 2. 检查内核配置
grep CONFIG_BPF /boot/config-$(uname -r)

# 3. 启用 eBPF（如果被禁用）
echo 0 | sudo tee /proc/sys/kernel/unprivileged_bpf_disabled
```

### 1.2 Tracepoint 附加失败

#### 症状
- 错误信息：`Failed to attach to tracepoint`
- 程序回退到 kprobe 模式

#### 可能原因
- Tracepoint 不存在或名称错误
- 内核版本过低
- 权限问题

#### 诊断步骤

```bash
# 检查可用的 tracepoint
ls /sys/kernel/debug/tracing/events/sched/
cat /sys/kernel/debug/tracing/available_events | grep sched

# 检查特定 tracepoint
cat /sys/kernel/debug/tracing/events/sched/sched_process_exec/format
```

#### 解决方案

```bash
# 1. 挂载 debugfs（如果未挂载）
sudo mount -t debugfs none /sys/kernel/debug

# 2. 检查权限
sudo chmod 755 /sys/kernel/debug/tracing

# 3. 验证 tracepoint 格式
sudo cat /sys/kernel/debug/tracing/events/sched/sched_process_exec/enable
```
## 2. 运行时错误

### 2.1 数据读取失败

#### 症状
- 事件数据不完整或为空
- 日志显示 `bpf_probe_read_kernel_str` 失败

#### 可能原因
- 内存地址无效
- 数据结构偏移错误
- 权限问题

#### 诊断步骤

```c
// 在 eBPF 程序中添加调试信息
int ret = bpf_probe_read_kernel_str(filename, sizeof(filename), ptr);
if (ret < 0) {
    bpf_printk("Failed to read string: %d\n", ret);
    return 0;
}
```

#### 解决方案

```c
// 1. 添加边界检查
if (!ptr) {
    bpf_printk("Null pointer detected\n");
    return 0;
}

// 2. 使用安全的读取函数
static __always_inline int safe_read_str(char *dest, size_t size, const void *src) {
    if (!src || !dest || size == 0) {
        return -1;
    }
    
    int ret = bpf_probe_read_kernel_str(dest, size, src);
    if (ret < 0) {
        dest[0] = '\0';  // 设置默认值
    }
    return ret;
}
```

### 2.2 事件丢失

#### 症状
- 事件计数不匹配
- 性能监控显示事件丢失

#### 可能原因
- Perf buffer 满了
- 用户空间处理太慢
- 内核缓冲区不足

#### 诊断步骤

```bash
# 检查 perf buffer 统计
cat /sys/kernel/debug/tracing/per_cpu/cpu*/stats

# 监控事件速率
bpftool prog show
bpftool map show
```

#### 解决方案

```c
// 1. 增加 perf buffer 大小
struct perf_buffer *pb = perf_buffer__new(
    bpf_map__fd(skel->maps.events), 
    128,  // 增加页面数
    handle_event, NULL, NULL, NULL);

// 2. 实现批量处理
#define BATCH_SIZE 64
struct event_batch {
    int count;
    struct process_event events[BATCH_SIZE];
};
```

## 3. 性能问题

### 3.1 CPU 使用率过高

#### 症状
- Agent CPU 使用率超过 5%
- 系统响应变慢

#### 可能原因
- 事件过滤不充分
- 频繁的内存分配
- 复杂的处理逻辑

#### 诊断步骤

```bash
# 监控 CPU 使用率
top -p $(pgrep agent)

# 检查 eBPF 程序统计
bpftool prog show --json | jq '.[] | {id, run_cnt, run_time_ns}'
```

#### 解决方案

```c
// 1. 早期过滤
SEC("tracepoint/sched/sched_process_exec")
int trace_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // 跳过内核线程
    if (ctx->pid <= 0) return 0;
    
    // 跳过系统进程
    if (ctx->pid < 100) return 0;
    
    // 继续处理...
}

// 2. 减少字符串操作
// 避免频繁的字符串复制和比较
```

### 3.2 内存使用过高

#### 症状
- Agent 内存使用超过 200MB
- 内存泄漏警告

#### 可能原因
- Map 大小设置过大
- 未清理的 Map 条目
- 用户空间缓冲区积累

#### 诊断步骤

```bash
# 检查内存使用
ps aux | grep agent
cat /proc/$(pgrep agent)/status | grep -E "VmRSS|VmSize"

# 检查 BPF map 使用
bpftool map show
bpftool map dump id <map_id>
```

#### 解决方案

```c
// 1. 设置合理的 map 大小
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);  // 根据实际需求调整
    __type(key, u32);
    __type(value, struct process_info);
} process_map SEC(".maps");

// 2. 实现定期清理
static void cleanup_old_entries(void) {
    // 定期清理过期条目
}
```## 4
. 兼容性问题

### 4.1 内核版本兼容性

#### 症状
- 在某些内核版本上程序无法运行
- 结构体字段访问错误

#### 可能原因
- 内核版本过低
- 结构体定义变化
- eBPF 功能不支持

#### 诊断步骤

```bash
# 检查内核版本
uname -r
cat /proc/version

# 检查 eBPF 功能支持
ls /sys/fs/bpf/
cat /proc/kallsyms | grep bpf
```

#### 解决方案

```c
// 1. 版本检测和降级
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
    // 使用现代 tracepoint
    SEC("tracepoint/sched/sched_process_exec")
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
    // 使用兼容 tracepoint
    SEC("tracepoint/sched/sched_process_exec")
#else
    // 降级到 kprobe
    SEC("kprobe/do_execve")
#endif

// 2. 运行时检测
static int detect_kernel_features(void) {
    // 检测可用功能
    return 0;
}
```

### 4.2 发行版差异

#### 症状
- 在不同 Linux 发行版上行为不一致
- 某些发行版上功能缺失

#### 可能原因
- 内核配置差异
- 安全策略不同
- 包版本差异

#### 诊断步骤

```bash
# 检查发行版信息
cat /etc/os-release
lsb_release -a

# 检查内核配置
zcat /proc/config.gz | grep BPF
cat /boot/config-$(uname -r) | grep BPF
```

#### 解决方案

```bash
# 1. 检查必需的内核配置
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y

# 2. 适配不同发行版
if [ -f /etc/debian_version ]; then
    # Debian/Ubuntu 特定处理
elif [ -f /etc/redhat-release ]; then
    # RHEL/CentOS 特定处理
fi
```

## 5. 数据收集问题

### 5.1 事件数据不准确

#### 症状
- 进程 PID/PPID 错误
- 文件路径不完整
- 时间戳异常

#### 可能原因
- 数据结构理解错误
- 竞态条件
- 内核数据结构变化

#### 诊断步骤

```c
// 添加数据验证
SEC("tracepoint/sched/sched_process_exec")
int trace_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // 验证数据合理性
    if (ctx->pid <= 0 || ctx->pid > 4194304) {
        bpf_printk("Invalid PID: %d\n", ctx->pid);
        return 0;
    }
    
    // 验证父进程 ID
    if (ctx->old_pid < 0) {
        bpf_printk("Invalid PPID: %d\n", ctx->old_pid);
    }
    
    return 0;
}
```

#### 解决方案

```c
// 1. 使用正确的字段
struct process_event event = {};
event.pid = ctx->pid;
event.ppid = ctx->old_pid;  // 注意：使用 old_pid 而不是 ent.pid

// 2. 安全的字符串提取
static __always_inline int extract_filename_safe(
    struct trace_event_raw_sched_process_exec *ctx,
    char *dest, size_t dest_size) {
    
    u32 data_loc = ctx->__data_loc_filename;
    u32 offset = data_loc & 0xFFFF;
    u32 length = (data_loc >> 16) & 0xFFFF;
    
    // 边界检查
    if (offset > 4096 || length > dest_size - 1) {
        dest[0] = '\0';
        return -1;
    }
    
    return bpf_probe_read_kernel_str(dest, length + 1, 
                                   (char *)ctx + offset);
}
```

### 5.2 事件时序问题

#### 症状
- 事件顺序混乱
- 时间戳不连续
- 父子进程关系错误

#### 可能原因
- 多核并发处理
- 缓冲区延迟
- 时钟同步问题

#### 诊断步骤

```c
// 添加时序调试信息
struct process_event event = {};
event.timestamp = bpf_ktime_get_ns();
event.cpu_id = bpf_get_smp_processor_id();

bpf_printk("Event: PID=%d, CPU=%d, TS=%llu\n", 
           event.pid, event.cpu_id, event.timestamp);
```

#### 解决方案

```c
// 1. 使用单调时钟
u64 timestamp = bpf_ktime_get_ns();

// 2. 添加序列号
static u64 seq_num = 0;
event.seq_num = __sync_fetch_and_add(&seq_num, 1);

// 3. 在用户空间排序
// 根据时间戳和序列号对事件进行排序
```

## 6. 调试工具和技巧

### 6.1 内核调试

```bash
# 启用 eBPF 调试
echo 1 > /sys/kernel/debug/tracing/events/bpf/enable

# 查看 eBPF 日志
cat /sys/kernel/debug/tracing/trace_pipe

# 监控 eBPF 程序
bpftool prog tracelog
```

### 6.2 用户空间调试

```c
// 启用详细日志
#define DEBUG 1

// 统计收集
struct stats {
    u64 events_processed;
    u64 events_dropped;
    u64 errors;
};

// 性能监控
static void print_stats(void) {
    printf("Events: processed=%llu, dropped=%llu, errors=%llu\n",
           stats.events_processed, stats.events_dropped, stats.errors);
}
```

### 6.3 常用诊断命令

```bash
# 检查 eBPF 程序状态
bpftool prog list
bpftool prog show id <prog_id>

# 检查 Map 状态
bpftool map list
bpftool map show id <map_id>
bpftool map dump id <map_id>

# 监控系统调用
strace -e bpf ./agent

# 检查内核消息
dmesg | grep -i bpf
journalctl -k | grep -i bpf
```

## 7. 预防措施

### 7.1 代码最佳实践

- 始终检查返回值
- 实现适当的错误处理
- 添加边界检查
- 使用安全的内存访问函数

### 7.2 测试策略

- 多内核版本测试
- 压力测试
- 长时间运行测试
- 不同工作负载测试

### 7.3 监控和告警

- 实时性能监控
- 错误率告警
- 资源使用监控
- 自动故障恢复

## 8. 获取帮助

### 8.1 日志收集

```bash
# 收集系统信息
uname -a > debug_info.txt
cat /proc/version >> debug_info.txt
cat /etc/os-release >> debug_info.txt

# 收集 eBPF 信息
bpftool prog list >> debug_info.txt
bpftool map list >> debug_info.txt

# 收集内核日志
dmesg > kernel.log
journalctl -k > journal.log
```

### 8.2 问题报告模板

```
**环境信息:**
- 操作系统: 
- 内核版本: 
- Agent 版本: 

**问题描述:**
- 症状: 
- 重现步骤: 
- 预期行为: 
- 实际行为: 

**日志和错误信息:**
- 错误消息: 
- 相关日志: 

**已尝试的解决方案:**
- 
```

通过本指南，您应该能够诊断和解决大多数 eBPF 相关问题。如果问题仍然存在，请收集相关信息并寻求技术支持。