# 贡献指南

感谢您对OpenEDR项目的关注！我们欢迎并感谢所有形式的贡献。

## 目录

- [行为准则](#行为准则)
- [如何贡献](#如何贡献)
- [开发流程](#开发流程)
- [提交规范](#提交规范)
- [代码规范](#代码规范)
- [测试要求](#测试要求)
- [文档贡献](#文档贡献)
- [问题反馈](#问题反馈)
- [安全漏洞](#安全漏洞)

## 行为准则

参与OpenEDR项目即表示您同意遵守我们的[行为准则](CODE_OF_CONDUCT.md)。请确保您的行为有助于创建一个开放、友好的社区环境。

## 如何贡献

### 贡献类型

- **错误修复**: 修复已知的bug
- **新功能**: 添加新的功能或改进
- **文档**: 改进或翻译文档
- **测试**: 添加缺失的测试
- **性能**: 优化性能
- **重构**: 改进代码结构

### 开始之前

1. 查看[Issues](https://github.com/yourusername/OpenEDR/issues)，看是否有人已经在处理相似的问题
2. 对于较大的改动，请先创建Issue讨论
3. Fork项目到您的GitHub账户
4. 创建您的特性分支

## 开发流程

### 1. 环境设置

```bash
# 克隆您的fork
git clone https://github.com/yourname/OpenEDR.git
cd OpenEDR

# 添加上游仓库
git remote add upstream https://github.com/yourusername/OpenEDR.git

# 安装依赖
make install-tools
```

### 2. 创建分支

```bash
# 从最新的develop分支创建
git checkout develop
git pull upstream develop
git checkout -b feature/your-feature-name
```

分支命名规范：
- `feature/` - 新功能
- `fix/` - 错误修复
- `docs/` - 文档更新
- `refactor/` - 代码重构
- `test/` - 测试相关

### 3. 开发

```bash
# 启动开发环境
make dev

# 运行测试
make test

# 检查代码规范
make lint
```

### 4. 提交更改

```bash
# 添加更改
git add .

# 提交（会触发commit lint）
git commit -m "feat: add new detection rule engine"

# 推送到您的fork
git push origin feature/your-feature-name
```

### 5. 创建Pull Request

1. 访问GitHub上您的fork
2. 点击"Compare & pull request"
3. 选择base分支为`develop`
4. 填写PR模板
5. 等待代码审查

## 提交规范

我们使用[Conventional Commits](https://www.conventionalcommits.org/)规范。

### 格式

```
<type>(<scope>): <subject>

<body>

<footer>
```

### 类型(type)

- **feat**: 新功能
- **fix**: 修复bug
- **docs**: 文档更新
- **style**: 代码格式调整（不影响功能）
- **refactor**: 重构（既不是新功能也不是修复bug）
- **perf**: 性能优化
- **test**: 添加或修改测试
- **chore**: 构建过程或辅助工具的变动
- **ci**: CI/CD相关的变动

### 范围(scope)

- **agent**: Agent相关
- **server**: 服务器相关
- **web**: Web前端相关
- **api**: API相关
- **docs**: 文档相关
- **build**: 构建系统相关

### 示例

```bash
# 功能添加
feat(agent): add process injection detection

# Bug修复
fix(server): resolve memory leak in event processing

# 文档更新
docs(api): update authentication documentation

# 破坏性变更
feat(api)!: change event schema

BREAKING CHANGE: The event schema has been updated to v2.
Old clients will need to be updated.
```

## 代码规范

### Go代码规范

- 遵循[Effective Go](https://golang.org/doc/effective_go.html)
- 使用`gofmt`格式化代码
- 使用`golangci-lint`进行静态检查
- 函数注释遵循GoDoc规范

```go
// ProcessEvent handles incoming process events from agents.
// It validates the event, enriches it with additional context,
// and forwards it to the detection engine.
func ProcessEvent(event *Event) error {
    // 实现...
}
```

### TypeScript/React规范

- 使用TypeScript严格模式
- 遵循React Hooks规则
- 使用函数组件和Hooks
- 使用ESLint和Prettier

```typescript
interface Props {
  agent: Agent;
  onUpdate: (agent: Agent) => void;
}

export const AgentCard: React.FC<Props> = ({ agent, onUpdate }) => {
  // 实现...
};
```

### 通用规范

- 变量和函数使用有意义的名称
- 避免魔法数字，使用常量
- 适当的错误处理
- 添加必要的注释
- 保持函数简洁（< 50行）

## 测试要求

### 单元测试

- 新功能必须包含单元测试
- 测试覆盖率目标：80%
- 使用表驱动测试（Go）

```go
func TestProcessEvent(t *testing.T) {
    tests := []struct {
        name    string
        event   *Event
        wantErr bool
    }{
        {
            name:    "valid event",
            event:   &Event{Type: "process_create"},
            wantErr: false,
        },
        // 更多测试用例...
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ProcessEvent(tt.event)
            if (err != nil) != tt.wantErr {
                t.Errorf("ProcessEvent() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

### 集成测试

- API端点必须有集成测试
- 使用测试数据库和模拟服务
- 清理测试数据

### E2E测试

- 关键用户流程需要E2E测试
- 使用Cypress进行前端E2E测试

## 文档贡献

### 文档类型

- **用户文档**: 面向最终用户
- **API文档**: API参考和示例
- **开发文档**: 架构和开发指南
- **运维文档**: 部署和运维指南

### 文档规范

- 使用清晰、简洁的语言
- 提供代码示例
- 保持文档与代码同步
- 中英文文档分别维护

### 文档结构

```markdown
# 标题

## 概述
简要说明文档内容

## 前提条件
- 列出所需的前提条件

## 步骤
1. 第一步
2. 第二步

## 示例
\```bash
# 代码示例
\```

## 常见问题
解答常见问题

## 相关链接
- [相关文档1](link1)
- [相关文档2](link2)
```

## 问题反馈

### 报告Bug

创建Issue时请包含：

1. **环境信息**
   - OpenEDR版本
   - 操作系统
   - 相关组件版本

2. **问题描述**
   - 期望行为
   - 实际行为
   - 错误信息

3. **复现步骤**
   - 详细的操作步骤
   - 最小复现代码

4. **日志和截图**
   - 相关日志
   - 错误截图

### 功能请求

1. 描述您想要的功能
2. 解释为什么需要这个功能
3. 提供使用场景示例
4. 考虑可能的实现方案

## 安全漏洞

**请勿在公开Issue中报告安全漏洞！**

如果您发现安全漏洞，请通过以下方式私下联系我们：

1. 发送邮件至: security@openedr.org
2. 使用PGP加密（公钥在项目根目录）
3. 包含详细的漏洞描述和复现步骤

我们会在24小时内响应，并在修复后公开致谢。

## Pull Request检查清单

提交PR前，请确保：

- [ ] 代码通过所有测试 `make test`
- [ ] 代码通过lint检查 `make lint`
- [ ] 添加了必要的测试
- [ ] 更新了相关文档
- [ ] 提交信息符合规范
- [ ] 没有包含敏感信息
- [ ] PR描述清晰完整

## 代码审查流程

1. **自动检查**: CI会自动运行测试和检查
2. **代码审查**: 至少需要一位维护者审查
3. **反馈处理**: 根据反馈进行修改
4. **合并**: 通过所有检查后合并

## 社区支持

- **Discord**: [加入我们的Discord](https://discord.gg/openedr)
- **论坛**: [社区论坛](https://forum.openedr.org)
- **邮件列表**: openedr-dev@googlegroups.com

## 贡献者协议

首次贡献时，您需要签署贡献者许可协议(CLA)。这是一个自动化流程，只需要进行一次。

## 致谢

我们感谢所有贡献者！您的名字将出现在：
- [贡献者列表](https://github.com/yourusername/OpenEDR/graphs/contributors)
- 项目README
- 发布说明

再次感谢您的贡献！🎉 