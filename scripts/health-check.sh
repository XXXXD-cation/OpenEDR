#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 打印函数
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}!${NC} $1"
}

# 检查服务函数
check_service() {
    local service_name=$1
    local host=$2
    local port=$3
    local check_command=$4
    
    echo -n "Checking $service_name... "
    
    if eval "$check_command" > /dev/null 2>&1; then
        print_success "$service_name is running on $host:$port"
        return 0
    else
        print_error "$service_name is not responding on $host:$port"
        return 1
    fi
}

# 健康检查总结
FAILED_SERVICES=()

echo "================================"
echo "OpenEDR Infrastructure Health Check"
echo "================================"
echo ""

# 检查PostgreSQL - 使用nc命令
if ! check_service "PostgreSQL" "localhost" "5432" "nc -zv localhost 5432"; then
    FAILED_SERVICES+=("PostgreSQL")
fi

# 检查Elasticsearch - 使用curl
if ! check_service "Elasticsearch" "localhost" "9200" "nc -zv localhost 9200"; then
    FAILED_SERVICES+=("Elasticsearch")
fi

# 检查Redis - 使用nc命令（redis-cli可能未安装）
if ! check_service "Redis" "localhost" "6379" "nc -zv localhost 6379"; then
    FAILED_SERVICES+=("Redis")
fi

# 检查Kafka
if ! check_service "Kafka" "localhost" "9092" "nc -zv localhost 9092"; then
    FAILED_SERVICES+=("Kafka")
fi

# 检查MinIO
if ! check_service "MinIO" "localhost" "9000" "curl -s -f -m 5 http://localhost:9000/minio/health/live"; then
    FAILED_SERVICES+=("MinIO")
fi

# 检查Prometheus
if ! check_service "Prometheus" "localhost" "9090" "curl -s -f -m 5 http://localhost:9090/-/healthy"; then
    FAILED_SERVICES+=("Prometheus")
fi

# 检查Grafana
if ! check_service "Grafana" "localhost" "3000" "curl -s -f -m 5 http://localhost:3000/api/health"; then
    FAILED_SERVICES+=("Grafana")
fi

# 检查Jaeger
if ! check_service "Jaeger" "localhost" "16686" "curl -s -f -m 5 http://localhost:16686/"; then
    FAILED_SERVICES+=("Jaeger")
fi

# 检查Docker容器状态
echo ""
echo "Docker Container Status:"
echo "------------------------"
docker ps --format "table {{.Names}}\t{{.Status}}" | grep openedr || echo "No OpenEDR containers found"

echo ""
echo "================================"
echo "Summary"
echo "================================"

if [ ${#FAILED_SERVICES[@]} -eq 0 ]; then
    print_success "All services are healthy!"
    echo ""
    echo "You can now:"
    echo "  - Start the server: cd server && go run ./cmd/server"
    echo "  - Start the web UI: cd web && npm start"
    echo "  - Run tests: make test"
    exit 0
else
    print_error "The following services are not healthy:"
    for service in "${FAILED_SERVICES[@]}"; do
        echo "  - $service"
    done
    echo ""
    echo "Try running:"
    echo "  make dev        # To start all services"
    echo "  make dev-logs   # To check service logs"
    exit 1
fi 