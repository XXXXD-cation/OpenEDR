# OpenEDR eBPF 进程监控迁移指南

## 概述

本文档提供从旧版本 eBPF 进程监控实现（V1）迁移到新版本优化实现（V2）的详细指南。V2 版本采用基于 tracepoint 的稳定实现，替代了不稳定的 kprobe 实现，提供更好的性能、稳定性和兼容性。

## 版本对比

### V1 版本（已弃用）
- **实现方式**: 基于 kprobe 的系统调用监控
- **稳定性**: 依赖不稳定的内核接口，容易因内核更新而失效
- **性能**: 存在代码重复和冗余实现
- **维护性**: 复杂的错误处理和调试机制

### V2 版本（推荐）
- **实现方式**: 基于 tracepoint 的稳定内核接口
- **稳定性**: 使用稳定的内核 API，跨内核版本兼容性好
- **性能**: 优化的代码结构，消除重复实现
- **维护性**: 简化的架构和增强的调试功能

## 迁移前准备

### 系统要求检查

#### 内核版本要求
```bash
# 检查内核版本
uname -r

# 检查 BTF 支持（推荐）
ls -la /sys/kernel/btf/vmlinux

# 检查 tracepoint 支持
ls -la /sys/kernel/debug/tracing/events/sched/
```

#### 必需的 tracepoint 检查
```bash
# 检查进程执行 tracepoint
ls -la /sys/kernel/debug/tracing/events/sched/sched_process_exec

# 检查进程退出 tracepoint  
ls -la /sys/kernel/debug/tracing/events/sched/sched_process_exit

# 检查系统调用 tracepoint
ls -la /sys/kernel/debug/tracing/events/syscalls/
```

#### 依赖工具检查
```bash
# 运行依赖检查
cd agent/ebpf
make check-deps

# 检查内核信息
make kernel-info
```

### 备份当前配置

#### 备份 eBPF 程序
```bash
# 备份当前运行的程序
sudo mkdir -p /opt/openedr/backup/$(date +%Y%m%d)
sudo cp /opt/openedr/ebpf/*.o /opt/openedr/backup/$(date +%Y%m%d)/ 2>/dev/null || true
```

#### 备份配置文件
```bash
# 备份代理配置
sudo cp /etc/openedr/agent/config.yaml /etc/openedr/agent/config.yaml.backup.$(date +%Y%m%d)

# 备份日志文件
sudo cp /var/log/openedr/agent.log /var/log/openedr/agent.log.backup.$(date +%Y%m%d) 2>/dev/null || true
```
## 迁移步骤

### 步骤 1: 停止当前服务

```bash
# 停止 OpenEDR 代理服务
sudo systemctl stop openedr-agent

# 确认服务已停止
sudo systemctl status openedr-agent

# 卸载当前 eBPF 程序
cd agent/ebpf
make unload
```

### 步骤 2: 构建新版本

#### 构建 V2 版本（推荐）
```bash
# 进入 eBPF 目录
cd agent/ebpf

# 清理旧的构建文件
make clean

# 构建 V2 版本（默认）
make build-v2

# 验证构建结果
make verify

# 显示当前版本
make show-version
```

#### 构建 V1 版本（兼容性后备）
```bash
# 如果需要 V1 作为后备
make build-v1

# 注意：会显示弃用警告
# "Process monitor V1 contains deprecated kprobe implementations. Use V2 for production."
```

### 步骤 3: 安装新版本

```bash
# 安装编译好的程序
make install

# 验证安装
ls -la /opt/openedr/ebpf/

# 检查程序信息
make info
```

### 步骤 4: 配置更新

#### 检查配置兼容性
```bash
# 验证当前配置
cd agent
go run cmd/agent/main.go -config /etc/openedr/agent/config.yaml -validate-config
```

#### 更新配置（如需要）
V2 版本与现有配置完全兼容，通常不需要修改配置文件。如果需要调整性能参数：

```yaml
# /etc/openedr/agent/config.yaml
collectors:
  process:
    enabled: true
    sampling_rate: 1.0  # V2 版本性能更好，可以使用更高采样率
    
performance:
  event_buffer_size: 10000  # V2 版本可以处理更大的缓冲区
  batch_size: 100
  flush_interval_seconds: 10
```

### 步骤 5: 启动和验证

#### 启动服务
```bash
# 启动 OpenEDR 代理服务
sudo systemctl start openedr-agent

# 检查服务状态
sudo systemctl status openedr-agent

# 设置开机自启
sudo systemctl enable openedr-agent
```

#### 验证功能
```bash
# 检查日志
sudo tail -f /var/log/openedr/agent.log

# 查看 eBPF 程序状态
sudo bpftool prog list | grep openedr

# 检查事件统计
sudo bpftool map dump name debug_stats_map
```

### 步骤 6: 性能验证

#### 运行性能测试
```bash
# 进入测试目录
cd agent/ebpf/tests

# 运行单元测试
make test

# 运行性能测试
./run_performance_tests.sh

# 检查测试报告
cat performance_test_report.txt
```

#### 监控系统资源
```bash
# 监控 CPU 使用率
top -p $(pgrep openedr-agent)

# 监控内存使用
ps aux | grep openedr-agent

# 检查 eBPF 统计信息
cd agent/ebpf
make info
```

## 配置变更和兼容性

### 构建系统变更

#### Makefile 变更
- **新增版本选择**: 支持 `PROCESS_MONITOR_VERSION` 环境变量
- **默认版本**: V2 为默认版本，V1 显示弃用警告
- **新增目标**: `build-v1`, `build-v2`, `show-version`

```bash
# 新的构建命令
make build-v2                    # 构建 V2 版本
make build-v1                    # 构建 V1 版本（显示警告）
make PROCESS_MONITOR_VERSION=v1  # 指定版本构建
make show-version                # 显示当前选择的版本
```

#### 程序文件变更
- **V1 文件**: `process_monitor.c` → `process_monitor.o`
- **V2 文件**: `process_monitor_v2.c` → `process_monitor_v2.o`
- **自动选择**: 系统根据内核能力自动选择合适版本

### 代码架构变更

#### 移除的功能
```c
// V1 中已移除的 kprobe 实现
// trace_sys_execve()     - 不稳定的系统调用 kprobe
// trace_sys_exit()       - 不稳定的系统调用 kprobe  
// trace_sys_exit_group() - 冗余的进程组退出 kprobe
```

#### V2 中简化的实现
```c
// V2 中移除的冗余实现
// trace_sys_exit_v2()       - 不必要的退出代码捕获
// trace_sys_exit_group_v2() - 重复的退出组监控
// debug_stats_reader()      - 未使用的调试函数
```

#### 保留的核心功能
- ✅ 进程执行监控 (`sched_process_exec` tracepoint)
- ✅ 进程退出监控 (`sched_process_exit` tracepoint)  
- ✅ 错误处理和统计
- ✅ 配置管理
- ✅ 调试和性能监控

### 兼容性矩阵

#### 内核版本兼容性
| 内核版本 | V1 支持 | V2 支持 | 推荐版本 |
|---------|---------|---------|----------|
| < 4.7   | ✅      | ❌      | V1       |
| 4.7-5.0 | ✅      | ⚠️      | V1       |
| 5.0+    | ✅      | ✅      | V2       |
| 5.8+    | ✅      | ✅      | V2       |

#### 功能兼容性
| 功能 | V1 | V2 | 变更说明 |
|------|----|----|----------|
| 进程执行监控 | ✅ | ✅ | 实现方式改变 |
| 进程退出监控 | ✅ | ✅ | 简化实现 |
| 退出代码捕获 | ✅ | ✅ | 通过 tracepoint |
| 父进程 PID | ✅ | ✅ | 更准确的提取 |
| 错误统计 | ✅ | ✅ | 增强的统计 |
| 调试功能 | ✅ | ✅ | 简化的接口 |

### 配置文件兼容性

#### 完全兼容的配置
现有的配置文件无需修改，以下配置保持完全兼容：

```yaml
# 进程监控配置（无需修改）
collectors:
  process:
    enabled: true
    sampling_rate: 1.0
    exclude_paths: []
    include_paths: []

# 性能配置（无需修改）  
performance:
  max_cpu_percent: 5
  max_memory_mb: 200
  event_buffer_size: 10000
  batch_size: 100
  flush_interval_seconds: 10

# TLS 配置（无需修改）
tls:
  cert_file: "/etc/openedr/agent/agent.crt"
  key_file: "/etc/openedr/agent/agent.key"
  ca_file: "/etc/openedr/agent/ca.crt"
```

#### 可选的性能优化配置
V2 版本性能更好，可以考虑以下优化：

```yaml
# 可选的性能优化
performance:
  event_buffer_size: 20000  # V2 可以处理更大缓冲区
  batch_size: 200           # 更大的批处理大小
  
collectors:
  process:
    sampling_rate: 1.0      # V2 可以使用更高采样率
```

## 回滚方案


### 快速回滚到 V1

如果 V2 版本出现问题，可以快速回滚到 V1 版本：

#### 方法 1: 重新构建 V1
```bash
# 停止服务
sudo systemctl stop openedr-agent

# 构建 V1 版本
cd agent/ebpf
make clean
make build-v1

# 重新安装
make install

# 启动服务
sudo systemctl start openedr-agent
```

#### 方法 2: 使用备份文件
```bash
# 停止服务
sudo systemctl stop openedr-agent

# 恢复备份的程序文件
sudo cp /opt/openedr/backup/$(date +%Y%m%d)/*.o /opt/openedr/ebpf/

# 恢复配置文件
sudo cp /etc/openedr/agent/config.yaml.backup.$(date +%Y%m%d) /etc/openedr/agent/config.yaml

# 启动服务
sudo systemctl start openedr-agent
```

#### 方法 3: 运行时切换
```bash
# 在运行时强制使用 V1
export PROCESS_MONITOR_VERSION=v1
sudo systemctl restart openedr-agent
```

### 完整回滚步骤

#### 1. 停止所有相关服务
```bash
# 停止代理服务
sudo systemctl stop openedr-agent

# 卸载 eBPF 程序
cd agent/ebpf
make unload

# 检查是否有残留程序
sudo bpftool prog list | grep openedr
```

#### 2. 恢复旧版本文件
```bash
# 恢复程序文件
sudo rm -f /opt/openedr/ebpf/process_monitor_v2.o
sudo cp /opt/openedr/backup/$(date +%Y%m%d)/process_monitor.o /opt/openedr/ebpf/

# 恢复配置文件
sudo cp /etc/openedr/agent/config.yaml.backup.$(date +%Y%m%d) /etc/openedr/agent/config.yaml

# 恢复日志文件（可选）
sudo cp /var/log/openedr/agent.log.backup.$(date +%Y%m%d) /var/log/openedr/agent.log
```

#### 3. 验证回滚
```bash
# 启动服务
sudo systemctl start openedr-agent

# 检查服务状态
sudo systemctl status openedr-agent

# 检查日志
sudo tail -f /var/log/openedr/agent.log

# 验证功能
cd agent/ebpf/tests
./run_tests.sh
```

## 故障排除指南

### 常见问题和解决方案

#### 问题 1: V2 版本无法加载
**症状**: 
```
Failed to load process monitor V2: invalid argument
```

**原因**: 内核不支持所需的 tracepoint

**解决方案**:
```bash
# 检查内核支持
make kernel-info

# 如果不支持，回滚到 V1
make build-v1
make install
sudo systemctl restart openedr-agent
```

#### 问题 2: 性能下降
**症状**: CPU 使用率异常高或事件丢失

**诊断步骤**:
```bash
# 检查 eBPF 统计
sudo bpftool map dump name debug_stats_map

# 检查系统资源
top -p $(pgrep openedr-agent)

# 查看详细日志
sudo journalctl -u openedr-agent -f
```

**解决方案**:
```bash
# 调整采样率
# 编辑 /etc/openedr/agent/config.yaml
collectors:
  process:
    sampling_rate: 0.5  # 降低采样率

# 增加缓冲区大小
performance:
  event_buffer_size: 20000
  
# 重启服务
sudo systemctl restart openedr-agent
```

#### 问题 3: 编译错误
**症状**: 
```
clang: error: unknown target CPU 'v3'
```

**解决方案**:
```bash
# 检查编译器版本
clang --version

# 如果版本过低，修改 Makefile
# 将 -mcpu=v3 改为 -mcpu=v2 或移除该选项

# 或者安装更新的编译器
sudo apt update
sudo apt install clang-12 llvm-12
```

#### 问题 4: 权限问题
**症状**: 
```
Permission denied: /sys/fs/bpf
```

**解决方案**:
```bash
# 检查 BPF 文件系统挂载
mount | grep bpf

# 如果未挂载，手动挂载
sudo mount -t bpf bpf /sys/fs/bpf

# 检查权限
ls -la /sys/fs/bpf

# 确保服务以 root 权限运行
sudo systemctl status openedr-agent
```

### 调试工具和命令

#### eBPF 程序调试
```bash
# 列出加载的程序
sudo bpftool prog list

# 查看程序详细信息
sudo bpftool prog show id <ID>

# 查看程序字节码
sudo bpftool prog dump xlated id <ID>

# 查看 JIT 编译结果
sudo bpftool prog dump jited id <ID>
```

#### 映射调试
```bash
# 列出所有映射
sudo bpftool map list

# 查看配置映射
sudo bpftool map dump name config_map

# 查看统计映射
sudo bpftool map dump name debug_stats_map

# 查看事件映射
sudo bpftool map dump name events
```

#### 日志分析
```bash
# 查看系统日志
sudo dmesg | grep -i bpf

# 查看代理日志
sudo journalctl -u openedr-agent --since "1 hour ago"

# 查看内核跟踪日志
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### 性能监控

#### 关键指标监控
```bash
# 事件处理统计
sudo bpftool map lookup name debug_stats_map key 0

# CPU 使用率监控
pidstat -p $(pgrep openedr-agent) 1

# 内存使用监控
pmap $(pgrep openedr-agent)

# 网络统计
ss -tuln | grep openedr
```

#### 性能基准测试
```bash
# 运行性能测试套件
cd agent/ebpf/tests
./run_performance_tests.sh

# 比较 V1 和 V2 性能
make build-v1
./run_performance_tests.sh > v1_results.txt

make build-v2  
./run_performance_tests.sh > v2_results.txt

# 分析结果
diff v1_results.txt v2_results.txt
```

## 最佳实践

### 迁移前最佳实践

#### 1. 测试环境验证
```bash
# 在测试环境中完整测试迁移流程
# 1. 设置测试环境
cp -r /etc/openedr /etc/openedr.test
export OPENEDR_CONFIG_DIR=/etc/openedr.test

# 2. 测试 V2 构建和运行
cd agent/ebpf
make build-v2
make verify

# 3. 运行完整测试套件
cd tests
./run_tests.sh
./run_performance_tests.sh

# 4. 验证功能完整性
# 测试进程监控、网络监控、文件监控等功能
```

#### 2. 分阶段迁移
```bash
# 阶段 1: 非生产环境迁移
# - 开发环境
# - 测试环境  
# - 预生产环境

# 阶段 2: 生产环境小规模试点
# - 选择 1-2 台服务器进行试点
# - 监控 24-48 小时
# - 收集性能和稳定性数据

# 阶段 3: 全面生产环境迁移
# - 批量迁移剩余服务器
# - 持续监控和优化
```

#### 3. 监控和告警设置
```bash
# 设置关键指标监控
# - eBPF 程序加载状态
# - 事件处理速率
# - 错误率和丢包率
# - 系统资源使用率

# 配置告警规则
# - 程序加载失败
# - 事件处理异常
# - 性能指标异常
```

### 迁移后最佳实践

#### 1. 持续监控
```bash
# 设置定期检查脚本
#!/bin/bash
# /opt/openedr/scripts/health_check.sh

echo "=== OpenEDR eBPF Health Check ==="
echo "Date: $(date)"

# 检查服务状态
systemctl is-active openedr-agent

# 检查 eBPF 程序状态
bpftool prog list | grep -c openedr

# 检查统计信息
cd /opt/openedr/agent/ebpf
make info

# 检查错误率
bpftool map dump name debug_stats_map | grep -E "(events_dropped|allocation_failures)"
```

#### 2. 性能优化
```yaml
# 根据实际负载调整配置
# /etc/openedr/agent/config.yaml

performance:
  # 高负载环境
  event_buffer_size: 50000
  batch_size: 500
  flush_interval_seconds: 5
  
  # 低负载环境
  event_buffer_size: 5000
  batch_size: 50
  flush_interval_seconds: 30

collectors:
  process:
    # 根据需求调整采样率
    sampling_rate: 1.0    # 完整监控
    # sampling_rate: 0.1  # 轻量监控
```

#### 3. 定期维护
```bash
# 每周维护任务
#!/bin/bash
# /opt/openedr/scripts/weekly_maintenance.sh

# 清理旧日志
find /var/log/openedr -name "*.log.*" -mtime +30 -delete

# 重置统计信息
cd /opt/openedr/agent/ebpf
make reset-stats

# 检查程序更新
make check-updates

# 生成健康报告
./health_check.sh > /var/log/openedr/health_$(date +%Y%m%d).log
```

### 安全考虑

#### 1. 权限管理
```bash
# 确保最小权限原则
# eBPF 程序文件权限
sudo chmod 644 /opt/openedr/ebpf/*.o
sudo chown root:root /opt/openedr/ebpf/*.o

# 配置文件权限
sudo chmod 600 /etc/openedr/agent/config.yaml
sudo chown root:root /etc/openedr/agent/config.yaml

# 日志文件权限
sudo chmod 640 /var/log/openedr/*.log
sudo chown root:adm /var/log/openedr/*.log
```

#### 2. 网络安全
```yaml
# 确保 TLS 配置正确
tls:
  cert_file: "/etc/openedr/agent/agent.crt"
  key_file: "/etc/openedr/agent/agent.key"
  ca_file: "/etc/openedr/agent/ca.crt"
  server_name: "openedr-server.example.com"
  
# 验证证书有效性
```

```bash
# 定期检查证书
openssl x509 -in /etc/openedr/agent/agent.crt -text -noout | grep "Not After"
```

## 总结

### 迁移收益

#### 1. 稳定性提升
- ✅ 使用稳定的 tracepoint API，减少内核更新导致的兼容性问题
- ✅ 消除了不稳定的 kprobe 实现
- ✅ 简化的错误处理机制

#### 2. 性能优化
- ✅ 减少代码重复，提高执行效率
- ✅ 优化的内存使用和事件处理
- ✅ 更好的多核扩展性

#### 3. 维护性改善
- ✅ 清晰的代码结构和文档
- ✅ 增强的调试和监控功能
- ✅ 简化的构建和部署流程

### 关键成功因素

1. **充分的测试**: 在非生产环境进行完整测试
2. **分阶段迁移**: 避免一次性大规模迁移的风险
3. **持续监控**: 迁移后密切关注系统状态
4. **快速回滚**: 准备好快速回滚方案
5. **团队培训**: 确保运维团队了解新版本特性

### 后续计划

#### 短期（1-3 个月）
- 完成所有生产环境迁移
- 优化性能配置
- 建立监控和告警体系

#### 中期（3-6 个月）
- 移除 V1 版本支持
- 基于 V2 开发新功能
- 完善文档和培训材料

#### 长期（6-12 个月）
- 探索更多 eBPF 优化机会
- 集成新的内核特性
- 持续性能和安全改进

## 支持和联系

### 技术支持
- **文档**: 参考 `agent/ebpf/README.md` 和相关技术文档
- **测试**: 使用 `agent/ebpf/tests/` 中的测试套件
- **调试**: 参考本文档的故障排除部分

### 反馈渠道
- **问题报告**: 通过项目 Issue 系统报告问题
- **功能建议**: 提交功能改进建议
- **文档改进**: 协助完善文档内容

---

**注意**: 本迁移指南基于 OpenEDR eBPF 进程监控优化项目。在执行迁移前，请确保已阅读并理解所有步骤，并在测试环境中验证迁移流程。