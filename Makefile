# OpenEDR Makefile

.PHONY: all build test clean help

# 版本信息
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go编译参数
GO := go
GOFLAGS := -v
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)"

# 目标平台
PLATFORMS := linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64

# 输出目录
BIN_DIR := bin
DIST_DIR := dist

# 默认目标
all: build

# 帮助信息
help:
	@echo "OpenEDR Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make build          - 构建所有组件"
	@echo "  make build-agent    - 构建Agent"
	@echo "  make build-server   - 构建服务器"
	@echo "  make build-web      - 构建Web前端"
	@echo "  make test           - 运行所有测试"
	@echo "  make docker         - 构建Docker镜像"
	@echo "  make clean          - 清理构建产物"
	@echo "  make dev            - 启动开发环境"
	@echo "  make proto          - 生成Protocol Buffers代码"
	@echo ""

# 构建所有组件
build: build-agent build-server build-web

# 构建Agent
build-agent:
	@echo "==> Building Agent..."
	@mkdir -p $(BIN_DIR)
	cd agent && $(GO) build $(GOFLAGS) $(LDFLAGS) -o ../$(BIN_DIR)/openedr-agent ./cmd/agent

# 构建eBPF程序
build-ebpf:
	@echo "==> Building eBPF programs..."
	cd agent/ebpf && make

# 构建服务器
build-server:
	@echo "==> Building Server..."
	@mkdir -p $(BIN_DIR)
	cd server && $(GO) build $(GOFLAGS) $(LDFLAGS) -o ../$(BIN_DIR)/openedr-server ./cmd/server

# 构建Web前端
build-web:
	@echo "==> Building Web UI..."
	cd web && npm install && npm run build

# 跨平台构建
build-cross:
	@echo "==> Building for multiple platforms..."
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} \
		$(GO) build $(LDFLAGS) -o $(DIST_DIR)/openedr-agent-$${platform//\//-} ./agent/cmd/agent; \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} \
		$(GO) build $(LDFLAGS) -o $(DIST_DIR)/openedr-server-$${platform//\//-} ./server/cmd/server; \
	done

# 运行测试
test:
	@echo "==> Running tests..."
	$(GO) test -v -race -coverprofile=coverage.out ./...
	cd web && npm test

# 运行基准测试
bench:
	@echo "==> Running benchmarks..."
	$(GO) test -bench=. -benchmem ./...

# 代码检查
lint:
	@echo "==> Running linters..."
	golangci-lint run ./...
	cd web && npm run lint

# 生成Protocol Buffers
proto:
	@echo "==> Generating Protocol Buffers..."
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		shared/proto/*.proto

# 构建Docker镜像
docker: docker-agent docker-server docker-web

docker-agent:
	@echo "==> Building Agent Docker image..."
	docker build -f docker/agent.Dockerfile -t openedr/agent:$(VERSION) .

docker-server:
	@echo "==> Building Server Docker image..."
	docker build -f docker/server.Dockerfile -t openedr/server:$(VERSION) .

docker-web:
	@echo "==> Building Web Docker image..."
	docker build -f docker/web.Dockerfile -t openedr/web:$(VERSION) .

# 推送Docker镜像
docker-push:
	@echo "==> Pushing Docker images..."
	docker push openedr/agent:$(VERSION)
	docker push openedr/server:$(VERSION)
	docker push openedr/web:$(VERSION)

# 启动开发环境
dev:
	@echo "==> Starting development environment..."
	docker-compose -f docker/docker-compose.dev.yml up -d

# 停止开发环境
dev-stop:
	@echo "==> Stopping development environment..."
	docker-compose -f docker/docker-compose.dev.yml down

# 查看开发环境日志
dev-logs:
	docker-compose -f docker/docker-compose.dev.yml logs -f

# 安装开发工具
install-tools:
	@echo "==> Installing development tools..."
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	$(GO) install github.com/go-delve/delve/cmd/dlv@latest
	npm install -g @commitlint/cli @commitlint/config-conventional

# 生成证书
gen-certs:
	@echo "==> Generating certificates..."
	@mkdir -p certs
	./scripts/generate-certs.sh

# 数据库迁移
migrate:
	@echo "==> Running database migrations..."
	cd server && $(GO) run ./cmd/migrate up

# 生成文档
docs:
	@echo "==> Generating documentation..."
	cd docs && mkdocs build

# 清理
clean:
	@echo "==> Cleaning..."
	rm -rf $(BIN_DIR) $(DIST_DIR)
	rm -rf web/build web/node_modules
	rm -f coverage.out
	find . -name "*.test" -delete
	find . -name "*.log" -delete

# CI/CD相关
ci-test:
	@echo "==> Running CI tests..."
	$(GO) test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	cd web && npm ci && npm test -- --coverage --watchAll=false

ci-build:
	@echo "==> Running CI build..."
	make build-cross
	make docker

# 发布
release:
	@echo "==> Creating release..."
	@if [ -z "$(TAG)" ]; then \
		echo "Error: TAG is not set. Use 'make release TAG=v1.0.0'"; \
		exit 1; \
	fi
	git tag $(TAG)
	git push origin $(TAG)
	make build-cross
	make docker
	make docker-push

# 性能分析
profile-cpu:
	@echo "==> Running CPU profiling..."
	$(GO) test -cpuprofile=cpu.prof -bench=. ./...
	$(GO) tool pprof cpu.prof

profile-mem:
	@echo "==> Running memory profiling..."
	$(GO) test -memprofile=mem.prof -bench=. ./...
	$(GO) tool pprof mem.prof

# 安全扫描
security-scan:
	@echo "==> Running security scan..."
	gosec ./...
	trivy fs .
	cd web && npm audit

# 代码格式化
fmt:
	@echo "==> Formatting code..."
	$(GO) fmt ./...
	cd web && npm run format

# 检查依赖更新
check-updates:
	@echo "==> Checking for dependency updates..."
	$(GO) list -u -m all
	cd web && npm outdated

# 本地集成测试
integration-test:
	@echo "==> Running integration tests..."
	make dev
	sleep 10
	cd tests/integration && $(GO) test -v ./...
	make dev-stop

# 端到端测试
e2e-test:
	@echo "==> Running E2E tests..."
	make dev
	sleep 10
	cd tests/e2e && npm test
	make dev-stop

# 压力测试
load-test:
	@echo "==> Running load tests..."
	cd tests/performance && k6 run load-test.js

# 生成变更日志
changelog:
	@echo "==> Generating changelog..."
	git-chglog -o CHANGELOG.md

# 统计代码行数
count:
	@echo "==> Counting lines of code..."
	@find . -name "*.go" -not -path "./vendor/*" | xargs wc -l
	@find . -name "*.ts" -name "*.tsx" -not -path "./node_modules/*" | xargs wc -l 