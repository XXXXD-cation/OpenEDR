# OpenEDR 项目概览

## 项目简介

OpenEDR是一个从零开始构建的开源端点检测与响应（EDR）系统，旨在提供企业级的端点安全监控、威胁检测和自动化响应能力。

## 项目结构

```
OpenEDR/
├── README.md                 # 项目主页和快速入门
├── CONTRIBUTING.md           # 贡献指南
├── Makefile                  # 构建和开发自动化
├── .gitignore               # Git忽略文件配置
│
├── docs/                     # 项目文档
│   ├── architecture.md       # 系统架构设计
│   ├── roadmap.md           # 开发路线图
│   ├── technical-specifications.md  # 技术规范
│   ├── security-design.md    # 安全设计
│   ├── development-guide.md  # 开发指南
│   ├── api-reference.md      # API参考文档
│   └── project-overview.md   # 项目概览（本文档）
│
├── agent/                    # EDR Agent源代码
│   ├── cmd/                 # 命令行程序入口
│   ├── internal/            # 内部实现
│   ├── pkg/                 # 可复用的包
│   └── ebpf/                # eBPF程序
│
├── server/                   # 中央服务器源代码
│   ├── cmd/                 # 服务器程序入口
│   ├── internal/            # 内部实现
│   └── pkg/                 # 可复用的包
│
├── web/                      # Web控制台源代码
│   ├── src/                 # React源代码
│   ├── public/              # 静态资源
│   └── package.json         # Node.js依赖
│
├── shared/                   # 共享代码和定义
│   ├── proto/               # Protocol Buffers定义
│   └── models/              # 共享数据模型
│
├── scripts/                  # 工具脚本
├── tests/                    # 测试代码
│   ├── integration/         # 集成测试
│   ├── e2e/                 # 端到端测试
│   └── performance/         # 性能测试
│
└── docker/                   # Docker相关配置
    └── docker-compose.dev.yml # 开发环境配置
```

## 核心文档索引

### 1. 架构和设计文档

#### [系统架构设计](./architecture.md)
- 系统整体架构
- 核心组件详解
- 数据流设计
- 部署架构
- 技术栈选择

#### [安全设计](./security-design.md)
- 安全架构原则
- 身份认证与授权
- 数据加密和保护
- 安全监控和响应
- 合规性设计

#### [技术规范](./technical-specifications.md)
- 数据模型定义
- API规范
- 性能指标
- 部署要求
- 集成标准

### 2. 开发相关文档

#### [开发指南](./development-guide.md)
- 开发环境搭建
- 代码组织结构
- 核心组件开发示例
- 测试策略
- 调试技巧

#### [API参考](./api-reference.md)
- RESTful API详细文档
- gRPC API定义
- WebSocket实时API
- SDK使用示例

#### [贡献指南](../CONTRIBUTING.md)
- 如何参与贡献
- 代码规范
- 提交流程
- 测试要求

### 3. 项目管理文档

#### [开发路线图](./roadmap.md)
- 项目阶段规划
- 版本发布计划
- 功能里程碑
- 长期愿景

## 快速开始

### 1. 环境准备

```bash
# 克隆项目
git clone https://github.com/yourusername/OpenEDR.git
cd OpenEDR

# 安装开发工具
make install-tools
```

### 2. 启动开发环境

```bash
# 启动所有依赖服务
make dev

# 查看服务状态
docker-compose -f docker/docker-compose.dev.yml ps
```

### 3. 构建项目

```bash
# 构建所有组件
make build

# 运行测试
make test
```

## 技术栈概览

### Agent端
- **核心语言**: C/C++, Go
- **内核技术**: Linux eBPF, Windows WDF
- **通信协议**: gRPC over TLS

### 服务器端
- **主要语言**: Go
- **Web框架**: Gin
- **数据存储**: PostgreSQL, Elasticsearch
- **消息队列**: Apache Kafka
- **缓存**: Redis

### Web前端
- **框架**: React + TypeScript
- **UI库**: Ant Design
- **状态管理**: Redux Toolkit

## 开发工作流

```mermaid
graph LR
    A[创建Issue] --> B[Fork项目]
    B --> C[创建分支]
    C --> D[本地开发]
    D --> E[运行测试]
    E --> F[提交代码]
    F --> G[创建PR]
    G --> H[代码审查]
    H --> I[合并到主分支]
```

## 部署选项

### 开发环境
- Docker Compose一键部署
- 本地开发服务器

### 生产环境
- Kubernetes集群部署
- 云原生架构支持
- 高可用配置

## 监控和运维

### 可观测性
- Prometheus指标收集
- Grafana可视化面板
- Jaeger分布式追踪
- ELK日志聚合

### 运维工具
- 自动化部署脚本
- 健康检查接口
- 备份恢复机制
- 性能调优指南

## 社区资源

- **GitHub仓库**: https://github.com/yourusername/OpenEDR
- **文档站点**: https://docs.openedr.org
- **社区论坛**: https://forum.openedr.org
- **Discord频道**: https://discord.gg/openedr

## 获取帮助

1. 查看[常见问题](./faq.md)
2. 搜索[GitHub Issues](https://github.com/yourusername/OpenEDR/issues)
3. 加入社区讨论
4. 提交新的Issue

## 下一步

- 阅读[系统架构](./architecture.md)了解设计理念
- 查看[开发指南](./development-guide.md)开始编码
- 参考[API文档](./api-reference.md)进行集成
- 了解[路线图](./roadmap.md)跟踪项目进展

---

*本文档持续更新中，最后更新时间：2024年1月* 