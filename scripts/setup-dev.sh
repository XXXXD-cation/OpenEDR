#!/bin/bash
set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 打印函数
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# 检查命令是否存在
check_command() {
    if ! command -v "$1" &> /dev/null; then
        print_error "$1 could not be found"
        return 1
    fi
    return 0
}

# 检查必要的工具
print_info "Checking required tools..."

MISSING_TOOLS=()

# 检查Go
if ! check_command go; then
    MISSING_TOOLS+=("Go (https://golang.org/dl/)")
else
    GO_VERSION=$(go version | awk '{print $3}')
    print_info "Found Go: $GO_VERSION"
fi

# 检查Node.js
if ! check_command node; then
    MISSING_TOOLS+=("Node.js (https://nodejs.org/)")
else
    NODE_VERSION=$(node --version)
    print_info "Found Node.js: $NODE_VERSION"
fi

# 检查npm
if ! check_command npm; then
    MISSING_TOOLS+=("npm (comes with Node.js)")
else
    NPM_VERSION=$(npm --version)
    print_info "Found npm: $NPM_VERSION"
fi

# 检查Docker
if ! check_command docker; then
    MISSING_TOOLS+=("Docker (https://docs.docker.com/get-docker/)")
else
    DOCKER_VERSION=$(docker --version)
    print_info "Found Docker: $DOCKER_VERSION"
fi

# 检查Docker Compose
if ! check_command docker-compose; then
    print_warning "docker-compose not found, checking docker compose (v2)..."
    if docker compose version &> /dev/null; then
        print_info "Found Docker Compose v2"
    else
        MISSING_TOOLS+=("Docker Compose (https://docs.docker.com/compose/install/)")
    fi
else
    COMPOSE_VERSION=$(docker-compose --version)
    print_info "Found Docker Compose: $COMPOSE_VERSION"
fi

# 检查Make
if ! check_command make; then
    MISSING_TOOLS+=("Make")
fi

# 如果有缺失的工具，退出
if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    print_error "Missing required tools:"
    for tool in "${MISSING_TOOLS[@]}"; do
        echo "  - $tool"
    done
    exit 1
fi

print_info "All required tools are installed!"

# 创建必要的目录
print_info "Creating necessary directories..."
mkdir -p bin
mkdir -p logs
mkdir -p certs
mkdir -p data

# 安装Go依赖
print_info "Installing Go dependencies..."
go mod download

# 安装Go开发工具
print_info "Installing Go development tools..."
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
go install github.com/go-delve/delve/cmd/dlv@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest

# 检查并安装前端依赖
print_info "Installing frontend dependencies..."
cd web
if [ -f "package.json" ]; then
    npm install
else
    print_warning "No package.json found in web directory, skipping npm install"
fi
cd ..

# 安装提交规范工具
print_info "Installing commit tools..."
npm install -g @commitlint/cli @commitlint/config-conventional

# 设置Git hooks
print_info "Setting up Git hooks..."
cat > .git/hooks/commit-msg << 'EOF'
#!/bin/sh
npx --no-install commitlint --edit $1
EOF
chmod +x .git/hooks/commit-msg

# 生成开发证书
print_info "Generating development certificates..."
if [ ! -f "certs/ca.crt" ]; then
    ./scripts/generate-certs.sh
else
    print_info "Certificates already exist, skipping generation"
fi

# 启动基础设施服务
print_info "Starting infrastructure services..."
cd docker
if command -v docker-compose &> /dev/null; then
    docker-compose -f docker-compose.dev.yml up -d
else
    docker compose -f docker-compose.dev.yml up -d
fi
cd ..

# 等待服务启动
print_info "Waiting for services to be ready..."
sleep 10

# 检查服务状态
print_info "Checking service status..."
SERVICES=("postgres:5432" "elasticsearch:9200" "redis:6379" "kafka:9092")

for service in "${SERVICES[@]}"; do
    IFS=':' read -r name port <<< "$service"
    if nc -z localhost "$port" 2>/dev/null; then
        print_info "$name is running on port $port"
    else
        print_warning "$name is not responding on port $port"
    fi
done

# 初始化数据库
print_info "Initializing database..."
# TODO: Run database migrations when available

# 显示环境信息
print_info "Development environment setup complete!"
echo ""
echo "Environment Variables for local development:"
echo "export DB_HOST=localhost"
echo "export DB_PORT=5432"
echo "export DB_USER=openedr"
echo "export DB_PASSWORD=openedr_dev_password"
echo "export DB_NAME=openedr"
echo "export REDIS_URL=redis://localhost:6379"
echo "export ELASTICSEARCH_URL=http://localhost:9200"
echo "export KAFKA_BROKERS=localhost:9092"
echo ""
echo "Services running:"
echo "- PostgreSQL: localhost:5432"
echo "- Elasticsearch: localhost:9200"
echo "- Kibana: localhost:5601"
echo "- Redis: localhost:6379"
echo "- Kafka: localhost:9092"
echo "- MinIO: localhost:9000 (console: localhost:9001)"
echo "- Prometheus: localhost:9090"
echo "- Grafana: localhost:3000 (admin/admin)"
echo "- Jaeger: localhost:16686"
echo ""
echo "To stop services: make dev-stop"
echo "To view logs: make dev-logs"
echo ""
print_info "Happy coding!" 