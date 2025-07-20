# eBPF Tracepoint 使用指南

## 概述

本指南详细介绍了 OpenEDR 系统中 eBPF tracepoint 的使用方法，包括从传统 kprobe 迁移到 tracepoint 的最佳实践、性能优化技巧和故障排除方法。

## 什么是 Tracepoint

Tracepoint 是 Linux 内核中的静态跟踪点，相比 kprobe 具有以下优势：

- **稳定性更高**: 内核 API 稳定，不会因内核版本变化而失效
- **性能更好**: 预解析的数据结构，减少运行时开销
- **兼容性强**: 跨内核版本兼容性好
- **数据完整**: 提供结构化的事件数据

## 支持的 Tracepoint 类型

### 1. 进程监控 Tracepoint

#### sched_process_exec
- **用途**: 监控进程执行事件
- **触发时机**: 进程调用 execve() 系统调用时
- **数据结构**: `trace_event_raw_sched_process_exec`

```c
struct trace_event_raw_sched_process_exec {
    struct trace_entry ent;         // 通用跟踪条目头部
    u32 __data_loc_filename;        // 文件名数据位置偏移
    pid_t pid;                      // 当前进程ID
    pid_t old_pid;                  // 父进程ID
    char __data[0];                 // 可变长度数据区域
};
```

#### sched_process_exit
- **用途**: 监控进程退出事件
- **触发时机**: 进程终止时
- **数据结构**: `trace_event_raw_sched_process_template`

```c
struct trace_event_raw_sched_process_template {
    struct trace_entry ent;         // 通用跟踪条目头部
    char comm[16];                  // 进程命令名
    pid_t pid;                      // 进程ID
    int prio;                       // 进程优先级
    char __data[0];                 // 可变长度数据区域
};
```

### 2. 系统调用 Tracepoint

#### sys_enter_* / sys_exit_*
- **用途**: 监控系统调用进入和退出
- **触发时机**: 系统调用执行前后
- **数据结构**: `trace_event_raw_sys_enter` / `trace_event_raw_sys_exit`

## 实现示例

### 1. 进程执行监控

```c
SEC("tracepoint/sched/sched_process_exec")
int trace_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct process_event event = {};
    
    // 基本信息
    event.pid = ctx->pid;
    event.ppid = ctx->old_pid;  // 正确的父进程ID
    event.timestamp = bpf_ktime_get_ns();
    
    // 提取文件名
    u32 filename_offset = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(event.filename, sizeof(event.filename),
                             (char *)ctx + filename_offset);
    
    // 获取进程信息
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_get_current_comm(event.comm, sizeof(event.comm));
    
    // 发送事件
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
                         &event, sizeof(event));
    
    return 0;
}
```

### 2. 进程退出监控

```c
SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    struct process_exit_event event = {};
    
    // 基本信息
    event.pid = ctx->pid;
    event.timestamp = bpf_ktime_get_ns();
    event.priority = ctx->prio;
    
    // 进程名称
    bpf_probe_read_kernel_str(event.comm, sizeof(event.comm), ctx->comm);
    
    // 获取退出码（需要从 task_struct 获取）
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&event.exit_code, sizeof(event.exit_code),
                         &task->exit_code);
    
    // 发送事件
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                         &event, sizeof(event));
    
    return 0;
}
```

## 数据提取最佳实践

### 1. 字符串数据提取

```c
// 安全的字符串提取函数
static __always_inline int extract_string_data(
    void *ctx, u32 data_loc, char *dest, size_t dest_size) {
    
    // 获取偏移量和长度
    u32 offset = data_loc & 0xFFFF;
    u32 length = (data_loc >> 16) & 0xFFFF;
    
    // 边界检查
    if (length > dest_size - 1) {
        length = dest_size - 1;
    }
    
    // 读取字符串
    int ret = bpf_probe_read_kernel_str(dest, length + 1, 
                                       (char *)ctx + offset);
    return ret;
}
```

### 2. 结构体数据访问

```c
// 安全的结构体字段访问
static __always_inline int read_task_field(
    struct task_struct *task, void *dest, size_t size, size_t offset) {
    
    return bpf_probe_read_kernel(dest, size, (char *)task + offset);
}
```

## 版本兼容性处理

### 1. 编译时版本检测

```c
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
    #define USE_MODERN_TRACEPOINT
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
    #define USE_STABLE_TRACEPOINT
#else
    #define USE_KPROBE_FALLBACK
#endif
```

### 2. 运行时兼容性检查

```c
// 检查 tracepoint 可用性
static int check_tracepoint_availability(void) {
    // 尝试附加到 tracepoint
    int fd = bpf_program__fd(skel->progs.trace_process_exec);
    if (fd < 0) {
        return -1;  // tracepoint 不可用
    }
    return 0;
}
```

## 性能优化技巧

### 1. 事件过滤

```c
SEC("tracepoint/sched/sched_process_exec")
int trace_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // 早期过滤，减少不必要的处理
    pid_t pid = ctx->pid;
    
    // 跳过内核线程
    if (pid <= 0) {
        return 0;
    }
    
    // 跳过系统进程
    if (pid < 100) {
        return 0;
    }
    
    // 继续处理...
}
```

### 2. 批量数据处理

```c
// 使用 BPF_MAP_TYPE_PERF_EVENT_ARRAY 进行批量传输
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");
```

### 3. 内存使用优化

```c
// 使用栈变量而不是堆分配
struct process_event event = {};  // 栈分配
// 避免: struct process_event *event = bpf_map_lookup_elem(...);
```

## 错误处理和调试

### 1. 返回值检查

```c
int ret = bpf_probe_read_kernel_str(event.filename, sizeof(event.filename),
                                   (char *)ctx + filename_offset);
if (ret < 0) {
    // 记录错误或使用默认值
    bpf_printk("Failed to read filename: %d\n", ret);
    strncpy(event.filename, "<unknown>", sizeof(event.filename));
}
```

### 2. 调试输出

```c
// 使用 bpf_printk 进行调试（仅开发环境）
#ifdef DEBUG
    bpf_printk("Process exec: pid=%d, ppid=%d, filename=%s\n",
               event.pid, event.ppid, event.filename);
#endif
```

### 3. 统计信息收集

```c
// 统计 map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, u32);
    __type(value, u64);
} stats SEC(".maps");

// 更新统计
static void update_stats(u32 stat_type) {
    u64 *count = bpf_map_lookup_elem(&stats, &stat_type);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}
```

## 用户空间集成

### 1. 事件接收

```c
// 用户空间事件处理回调
static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct process_event *event = data;
    
    printf("Process exec: PID=%d, PPID=%d, CMD=%s, FILE=%s\n",
           event->pid, event->ppid, event->comm, event->filename);
    
    return 0;
}

// 设置 perf buffer
struct perf_buffer *pb = perf_buffer__new(
    bpf_map__fd(skel->maps.events), 64, handle_event, NULL, NULL, NULL);
```

### 2. 配置管理

```c
// 动态配置更新
int update_filter_config(struct bpf_object *obj, struct filter_config *config) {
    int map_fd = bpf_object__find_map_fd_by_name(obj, "config");
    if (map_fd < 0) {
        return -1;
    }
    
    u32 key = 0;
    return bpf_map_update_elem(map_fd, &key, config, BPF_ANY);
}
```

## 迁移指南

### 从 Kprobe 迁移到 Tracepoint

#### 1. 识别对应的 tracepoint

- `kprobe/do_execve` → `tracepoint/sched/sched_process_exec`
- `kprobe/do_exit` → `tracepoint/sched/sched_process_exit`

#### 2. 更新数据访问方式

```c
// Kprobe 方式（旧）
struct pt_regs *regs = (struct pt_regs *)ctx;
char *filename = (char *)PT_REGS_PARM1(regs);

// Tracepoint 方式（新）
u32 offset = ctx->__data_loc_filename & 0xFFFF;
char *filename = (char *)ctx + offset;
```

#### 3. 测试和验证

- **功能测试**：确保事件正确捕获
- **性能测试**：验证性能提升
- **兼容性测试**：多内核版本测试

## 最佳实践总结

- **优先使用 tracepoint**: 稳定性和性能更好
- **实现降级机制**: 不支持时回退到 kprobe
- **早期过滤**: 在 eBPF 程序中过滤不需要的事件
- **错误处理**: 始终检查返回值
- **性能监控**: 监控 eBPF 程序的性能影响
- **版本兼容**: 支持多个内核版本
- **调试友好**: 提供充分的调试信息

## 参考资源

- [Linux Kernel Tracepoint Documentation](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)
- [BPF and XDP Reference Guide](https://docs.cilium.io/en/latest/bpf/)
- [libbpf Documentation](https://libbpf.readthedocs.io/)
