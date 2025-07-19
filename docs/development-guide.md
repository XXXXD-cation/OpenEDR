# OpenEDR 开发指南

## 1. 开发环境设置

### 1.1 系统要求

#### 开发机器要求
- **操作系统**: Linux (Ubuntu 20.04+), macOS 12+, Windows 10+ (WSL2)
- **CPU**: 4核以上
- **内存**: 16GB以上
- **磁盘**: 50GB可用空间

#### 软件依赖
- **Go**: 1.21+
- **Node.js**: 18+ (LTS)
- **Docker**: 20.10+
- **Docker Compose**: 2.0+
- **Git**: 2.30+
- **Make**: GNU Make 4.0+

### 1.2 环境搭建

#### 克隆仓库
```bash
git clone https://github.com/yourusername/OpenEDR.git
cd OpenEDR
```

#### 安装开发工具
```bash
# 安装Go工具链
make install-go-tools

# 安装前端依赖
cd web && npm install

# 安装pre-commit hooks
pip install pre-commit
pre-commit install
```

#### 配置IDE

##### VS Code
```json
{
  "go.useLanguageServer": true,
  "go.lintTool": "golangci-lint",
  "go.lintFlags": [
    "--fast"
  ],
  "editor.formatOnSave": true,
  "[go]": {
    "editor.codeActionsOnSave": {
      "source.organizeImports": true
    }
  }
}
```

##### GoLand/IntelliJ
- 安装Go插件
- 配置GOPATH和模块
- 启用格式化和导入优化

## 2. 项目结构详解

### 2.1 目录布局
```
OpenEDR/
├── agent/                  # Agent源代码
│   ├── cmd/               # 命令行入口
│   ├── internal/          # 内部包
│   │   ├── collector/     # 数据收集器
│   │   ├── detector/      # 检测引擎
│   │   ├── responder/     # 响应模块
│   │   └── transport/     # 通信层
│   ├── pkg/               # 公共包
│   └── ebpf/              # eBPF程序
│
├── server/                 # 服务器源代码
│   ├── cmd/               # 服务入口
│   ├── internal/          # 内部服务
│   │   ├── api/          # API处理
│   │   ├── engine/       # 检测引擎
│   │   ├── storage/      # 存储层
│   │   └── stream/       # 数据流处理
│   └── pkg/               # 公共包
│
├── web/                    # Web前端
│   ├── src/
│   │   ├── components/   # React组件
│   │   ├── pages/        # 页面组件
│   │   ├── services/     # API服务
│   │   └── store/        # Redux存储
│   └── public/           # 静态资源
│
├── shared/                 # 共享代码
│   ├── proto/            # Protocol Buffers
│   └── models/           # 共享数据模型
│
├── docs/                   # 文档
├── scripts/               # 脚本工具
├── tests/                 # 测试代码
│   ├── integration/      # 集成测试
│   ├── e2e/              # 端到端测试
│   └── performance/      # 性能测试
└── docker/                # Docker配置
```

### 2.2 代码组织原则

- **internal/**: 私有包，不对外暴露
- **pkg/**: 公共包，可被其他项目使用
- **cmd/**: 可执行文件入口
- **按功能分层**: 收集、检测、响应、存储等

## 3. 核心组件开发

### 3.1 Agent开发

#### 数据收集器接口
```go
// collector/interface.go
package collector

import "context"

type Event struct {
    ID        string
    Type      EventType
    Timestamp time.Time
    Data      interface{}
}

type Collector interface {
    // 启动收集器
    Start(ctx context.Context) error
    
    // 停止收集器
    Stop() error
    
    // 获取事件通道
    Events() <-chan Event
    
    // 获取收集器名称
    Name() string
}
```

#### 实现进程收集器
```go
// collector/process.go
package collector

import (
    "context"
    "github.com/openedr/agent/internal/ebpf"
)

type ProcessCollector struct {
    events chan Event
    prog   *ebpf.Program
}

func NewProcessCollector() *ProcessCollector {
    return &ProcessCollector{
        events: make(chan Event, 1000),
    }
}

func (p *ProcessCollector) Start(ctx context.Context) error {
    // 加载eBPF程序
    prog, err := ebpf.LoadProgram("process_monitor.o")
    if err != nil {
        return err
    }
    p.prog = prog
    
    // 启动事件读取
    go p.readEvents(ctx)
    
    return nil
}

func (p *ProcessCollector) readEvents(ctx context.Context) {
    reader := p.prog.NewReader()
    defer reader.Close()
    
    for {
        select {
        case <-ctx.Done():
            return
        default:
            event, err := reader.Read()
            if err != nil {
                continue
            }
            
            p.events <- Event{
                Type: ProcessCreate,
                Data: event,
            }
        }
    }
}
```

#### eBPF程序示例
```c
// ebpf/process_monitor.c
#include <linux/bpf.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>

struct process_event {
    u32 pid;
    u32 ppid;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct process_event event = {};
    struct task_struct *task;
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    
    bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), 
                          &task->real_parent->tgid);
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 3.2 服务器开发

#### API路由设置
```go
// api/router.go
package api

import (
    "github.com/gin-gonic/gin"
    "github.com/openedr/server/internal/api/handlers"
)

func SetupRouter() *gin.Engine {
    r := gin.New()
    
    // 中间件
    r.Use(gin.Logger())
    r.Use(gin.Recovery())
    r.Use(CORSMiddleware())
    
    // API版本组
    v1 := r.Group("/api/v1")
    {
        // 认证路由
        auth := v1.Group("/auth")
        {
            auth.POST("/login", handlers.Login)
            auth.POST("/logout", handlers.Logout)
            auth.POST("/refresh", handlers.RefreshToken)
        }
        
        // 需要认证的路由
        authorized := v1.Group("/")
        authorized.Use(JWTAuthMiddleware())
        {
            // Agent管理
            agents := authorized.Group("/agents")
            {
                agents.GET("", handlers.ListAgents)
                agents.GET("/:id", handlers.GetAgent)
                agents.PUT("/:id", handlers.UpdateAgent)
                agents.DELETE("/:id", handlers.DeleteAgent)
            }
            
            // 事件查询
            events := authorized.Group("/events")
            {
                events.POST("/search", handlers.SearchEvents)
                events.GET("/:id", handlers.GetEvent)
            }
        }
    }
    
    return r
}
```

#### 数据处理管道
```go
// stream/pipeline.go
package stream

import (
    "context"
    "github.com/Shopify/sarama"
)

type Pipeline struct {
    consumer sarama.ConsumerGroup
    producer sarama.SyncProducer
    handlers []EventHandler
}

type EventHandler interface {
    Process(event *Event) error
}

func (p *Pipeline) Start(ctx context.Context) error {
    topics := []string{"agent-events"}
    
    handler := consumerGroupHandler{
        pipeline: p,
    }
    
    for {
        select {
        case <-ctx.Done():
            return nil
        default:
            err := p.consumer.Consume(ctx, topics, handler)
            if err != nil {
                return err
            }
        }
    }
}

func (p *Pipeline) processEvent(message *sarama.ConsumerMessage) error {
    event := &Event{}
    if err := json.Unmarshal(message.Value, event); err != nil {
        return err
    }
    
    // 执行处理链
    for _, handler := range p.handlers {
        if err := handler.Process(event); err != nil {
            return err
        }
    }
    
    return nil
}
```

### 3.3 前端开发

#### 组件开发示例
```typescript
// components/AgentList.tsx
import React, { useEffect, useState } from 'react';
import { Table, Tag, Space, Button } from 'antd';
import { useAppDispatch, useAppSelector } from '../hooks';
import { fetchAgents, selectAgents } from '../store/agentsSlice';

interface Agent {
  id: string;
  hostname: string;
  ip: string;
  status: 'online' | 'offline';
  version: string;
  lastSeen: string;
}

export const AgentList: React.FC = () => {
  const dispatch = useAppDispatch();
  const { agents, loading } = useAppSelector(selectAgents);
  
  useEffect(() => {
    dispatch(fetchAgents());
  }, [dispatch]);
  
  const columns = [
    {
      title: 'Hostname',
      dataIndex: 'hostname',
      key: 'hostname',
    },
    {
      title: 'IP Address',
      dataIndex: 'ip',
      key: 'ip',
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => (
        <Tag color={status === 'online' ? 'green' : 'red'}>
          {status.toUpperCase()}
        </Tag>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record: Agent) => (
        <Space size="middle">
          <Button type="link">View</Button>
          <Button type="link">Isolate</Button>
        </Space>
      ),
    },
  ];
  
  return (
    <Table
      columns={columns}
      dataSource={agents}
      loading={loading}
      rowKey="id"
    />
  );
};
```

#### API服务
```typescript
// services/api.ts
import axios, { AxiosInstance } from 'axios';

class ApiService {
  private client: AxiosInstance;
  
  constructor() {
    this.client = axios.create({
      baseURL: process.env.REACT_APP_API_URL || '/api/v1',
      headers: {
        'Content-Type': 'application/json',
      },
    });
    
    // 请求拦截器
    this.client.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );
    
    // 响应拦截器
    this.client.interceptors.response.use(
      (response) => response,
      async (error) => {
        if (error.response?.status === 401) {
          // 处理认证失败
          await this.refreshToken();
        }
        return Promise.reject(error);
      }
    );
  }
  
  async getAgents() {
    const response = await this.client.get('/agents');
    return response.data;
  }
  
  async searchEvents(query: EventQuery) {
    const response = await this.client.post('/events/search', query);
    return response.data;
  }
}

export default new ApiService();
```

## 4. 测试策略

### 4.1 单元测试

#### Go测试示例
```go
// collector/process_test.go
package collector

import (
    "context"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
)

func TestProcessCollector_Start(t *testing.T) {
    collector := NewProcessCollector()
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    err := collector.Start(ctx)
    assert.NoError(t, err)
    
    // 等待事件
    select {
    case event := <-collector.Events():
        assert.Equal(t, ProcessCreate, event.Type)
        assert.NotEmpty(t, event.ID)
    case <-ctx.Done():
        t.Fatal("timeout waiting for event")
    }
}

// Mock对象
type MockCollector struct {
    mock.Mock
}

func (m *MockCollector) Start(ctx context.Context) error {
    args := m.Called(ctx)
    return args.Error(0)
}
```

#### React测试示例
```typescript
// components/__tests__/AgentList.test.tsx
import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { Provider } from 'react-redux';
import { AgentList } from '../AgentList';
import { store } from '../../store';
import * as api from '../../services/api';

jest.mock('../../services/api');

describe('AgentList', () => {
  it('should display agents', async () => {
    const mockAgents = [
      {
        id: '1',
        hostname: 'test-host',
        ip: '192.168.1.1',
        status: 'online',
        version: '1.0.0',
      },
    ];
    
    (api.getAgents as jest.Mock).mockResolvedValue(mockAgents);
    
    render(
      <Provider store={store}>
        <AgentList />
      </Provider>
    );
    
    await waitFor(() => {
      expect(screen.getByText('test-host')).toBeInTheDocument();
      expect(screen.getByText('ONLINE')).toBeInTheDocument();
    });
  });
});
```

### 4.2 集成测试

```go
// tests/integration/api_test.go
package integration

import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    
    "github.com/openedr/server/internal/api"
    "github.com/stretchr/testify/assert"
)

func TestAgentAPI(t *testing.T) {
    router := api.SetupRouter()
    
    t.Run("List Agents", func(t *testing.T) {
        req := httptest.NewRequest("GET", "/api/v1/agents", nil)
        req.Header.Set("Authorization", "Bearer test-token")
        
        w := httptest.NewRecorder()
        router.ServeHTTP(w, req)
        
        assert.Equal(t, http.StatusOK, w.Code)
        
        var response map[string]interface{}
        err := json.Unmarshal(w.Body.Bytes(), &response)
        assert.NoError(t, err)
        assert.Contains(t, response, "agents")
    })
}
```

### 4.3 性能测试

```go
// tests/performance/load_test.go
package performance

import (
    "testing"
    "time"
    
    vegeta "github.com/tsenart/vegeta/v12/lib"
)

func TestAPILoad(t *testing.T) {
    rate := vegeta.Rate{Freq: 100, Per: time.Second}
    duration := 30 * time.Second
    
    targeter := vegeta.NewStaticTargeter(vegeta.Target{
        Method: "GET",
        URL:    "http://localhost:8080/api/v1/agents",
        Header: http.Header{
            "Authorization": []string{"Bearer test-token"},
        },
    })
    
    attacker := vegeta.NewAttacker()
    metrics := &vegeta.Metrics{}
    
    for res := range attacker.Attack(targeter, rate, duration, "Load Test") {
        metrics.Add(res)
    }
    
    metrics.Close()
    
    // 验证性能指标
    assert.Less(t, metrics.Latencies.P99, 200*time.Millisecond)
    assert.Greater(t, metrics.Success, 0.99)
}
```

## 5. 构建和部署

### 5.1 构建流程

#### Makefile
```makefile
.PHONY: all build test clean

VERSION := $(shell git describe --tags --always --dirty)
LDFLAGS := -X main.version=$(VERSION)

all: build

build: build-agent build-server build-web

build-agent:
	@echo "Building agent..."
	cd agent && go build -ldflags "$(LDFLAGS)" -o ../bin/agent ./cmd/agent

build-server:
	@echo "Building server..."
	cd server && go build -ldflags "$(LDFLAGS)" -o ../bin/server ./cmd/server

build-web:
	@echo "Building web..."
	cd web && npm run build

test:
	go test -v ./...
	cd web && npm test

docker:
	docker build -f docker/agent.Dockerfile -t openedr/agent:$(VERSION) .
	docker build -f docker/server.Dockerfile -t openedr/server:$(VERSION) .

clean:
	rm -rf bin/ web/build/
```

### 5.2 CI/CD配置

#### GitHub Actions
```yaml
# .github/workflows/build.yml
name: Build and Test

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.21'
    
    - name: Set up Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
    
    - name: Install dependencies
      run: |
        go mod download
        cd web && npm ci
    
    - name: Run tests
      run: |
        go test -v -race -coverprofile=coverage.out ./...
        cd web && npm test -- --coverage
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        files: ./coverage.out,./web/coverage/lcov.info
  
  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Build
      run: make build
    
    - name: Build Docker images
      run: make docker
    
    - name: Push images
      if: github.ref == 'refs/heads/main'
      run: |
        echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
        docker push openedr/agent:latest
        docker push openedr/server:latest
```

## 6. 调试技巧

### 6.1 Agent调试

#### 使用delve调试
```bash
# 安装delve
go install github.com/go-delve/delve/cmd/dlv@latest

# 调试agent
dlv debug ./cmd/agent -- --config=config.yaml

# 设置断点
(dlv) break collector.(*ProcessCollector).Start
(dlv) continue
```

#### eBPF调试
```bash
# 查看eBPF程序
bpftool prog list

# 查看map内容
bpftool map dump id <map_id>

# 跟踪eBPF日志
cat /sys/kernel/debug/tracing/trace_pipe
```

### 6.2 服务器调试

#### 启用pprof
```go
import _ "net/http/pprof"

func main() {
    // 启动pprof服务器
    go func() {
        log.Println(http.ListenAndServe("localhost:6060", nil))
    }()
    
    // 主服务器逻辑...
}
```

#### 性能分析
```bash
# CPU分析
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30

# 内存分析
go tool pprof http://localhost:6060/debug/pprof/heap

# 查看goroutine
curl http://localhost:6060/debug/pprof/goroutine?debug=1
```

### 6.3 前端调试

#### React DevTools
- 安装浏览器扩展
- 查看组件树和状态
- 性能分析

#### Redux DevTools
```typescript
// store/index.ts
export const store = configureStore({
  reducer: rootReducer,
  devTools: process.env.NODE_ENV !== 'production',
});
```

## 7. 最佳实践

### 7.1 代码规范

#### Go代码规范
- 遵循[Effective Go](https://golang.org/doc/effective_go.html)
- 使用`gofmt`和`goimports`
- 运行`golangci-lint`

#### TypeScript规范
- 使用ESLint和Prettier
- 严格的类型检查
- 避免any类型

### 7.2 Git工作流

#### 分支策略
- `main`: 生产就绪代码
- `develop`: 开发分支
- `feature/*`: 功能分支
- `hotfix/*`: 紧急修复

#### 提交规范
```
<type>(<scope>): <subject>

<body>

<footer>
```

类型:
- feat: 新功能
- fix: 修复bug
- docs: 文档更新
- style: 代码格式
- refactor: 重构
- test: 测试
- chore: 构建/工具

### 7.3 代码审查

#### 审查清单
- [ ] 代码符合规范
- [ ] 有适当的测试
- [ ] 文档已更新
- [ ] 没有安全漏洞
- [ ] 性能影响可接受
- [ ] 错误处理完善

## 8. 故障排查

### 8.1 常见问题

#### Agent无法连接服务器
```bash
# 检查网络连接
telnet server-address 9090

# 检查证书
openssl s_client -connect server-address:9090 -cert agent.crt -key agent.key

# 查看日志
tail -f /var/log/openedr/agent.log
```

#### 高CPU使用率
```bash
# 查看进程状态
top -p $(pgrep openedr-agent)

# 生成CPU profile
kill -USR1 $(pgrep openedr-agent)

# 分析profile
go tool pprof cpu.prof
```

### 8.2 日志分析

#### 结构化日志
```go
logger.Info("event processed",
    zap.String("event_id", event.ID),
    zap.String("type", event.Type),
    zap.Duration("duration", duration),
    zap.Error(err),
)
```

#### 日志聚合查询
```bash
# 使用jq分析JSON日志
cat agent.log | jq 'select(.level=="error") | .msg'

# 统计错误类型
cat agent.log | jq -r 'select(.level=="error") | .error' | sort | uniq -c
```

## 9. 贡献流程

### 9.1 提交PR

1. Fork项目
2. 创建feature分支
3. 编写代码和测试
4. 提交并推送
5. 创建Pull Request

### 9.2 代码质量要求

- 测试覆盖率 > 80%
- 无linter警告
- 文档完整
- 通过CI检查

## 10. 资源链接

### 官方资源
- [项目Wiki](https://github.com/yourusername/OpenEDR/wiki)
- [API文档](https://openedr.readthedocs.io)
- [开发者论坛](https://forum.openedr.org)

### 学习资源
- [eBPF教程](https://ebpf.io)
- [Go最佳实践](https://github.com/golang/go/wiki/CodeReviewComments)
- [React模式](https://reactpatterns.com)

### 工具推荐
- [BCC](https://github.com/iovisor/bcc): eBPF工具集
- [Delve](https://github.com/go-delve/delve): Go调试器
- [k6](https://k6.io): 负载测试工具 