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

# 错误标志
HAS_ERROR=false

# 检查Go代码格式
print_info "Checking Go code formatting..."
if ! gofmt -l . | grep -v vendor | grep -v .git; then
    print_info "Go code is properly formatted"
else
    print_error "Go code formatting issues found. Run 'make fmt' to fix."
    HAS_ERROR=true
fi

# 运行Go linter
print_info "Running golangci-lint..."
if golangci-lint run ./...; then
    print_info "Go code passed linting"
else
    print_error "Go linting issues found"
    HAS_ERROR=true
fi

# 检查Go模块
print_info "Checking Go modules..."
if go mod tidy -v 2>&1 | grep -q "unused"; then
    print_warning "Found unused dependencies. Run 'go mod tidy' to clean up."
fi

if go mod verify; then
    print_info "Go modules verified"
else
    print_error "Go module verification failed"
    HAS_ERROR=true
fi

# 检查前端代码
if [ -d "web" ] && [ -f "web/package.json" ]; then
    print_info "Checking frontend code..."
    cd web
    
    # 运行ESLint
    print_info "Running ESLint..."
    if npm run lint; then
        print_info "Frontend code passed linting"
    else
        print_error "Frontend linting issues found"
        HAS_ERROR=true
    fi
    
    # 运行TypeScript类型检查
    print_info "Running TypeScript type check..."
    if npm run type-check; then
        print_info "TypeScript types are valid"
    else
        print_error "TypeScript type errors found"
        HAS_ERROR=true
    fi
    
    cd ..
fi

# 检查Dockerfile
print_info "Checking Dockerfiles..."
for dockerfile in docker/*.Dockerfile; do
    if [ -f "$dockerfile" ]; then
        if docker run --rm -i hadolint/hadolint < "$dockerfile"; then
            print_info "$(basename "$dockerfile") passed linting"
        else
            print_warning "$(basename "$dockerfile") has linting issues"
        fi
    fi
done

# 检查shell脚本
print_info "Checking shell scripts..."
for script in scripts/*.sh; do
    if [ -f "$script" ]; then
        if shellcheck "$script"; then
            print_info "$(basename "$script") passed shellcheck"
        else
            print_warning "$(basename "$script") has shellcheck issues"
        fi
    fi
done

# 检查提交消息格式
if command -v commitlint &> /dev/null; then
    print_info "Checking recent commit messages..."
    if git log --format=%B -n 5 | commitlint; then
        print_info "Recent commit messages follow convention"
    else
        print_warning "Some commit messages don't follow convention"
    fi
fi

# 检查安全问题
print_info "Running security checks..."
if gosec -quiet ./...; then
    print_info "No security issues found"
else
    print_warning "Security issues found. Review gosec output."
fi

# 总结
echo ""
if [ "$HAS_ERROR" = true ]; then
    print_error "Quality check failed! Please fix the issues above."
    exit 1
else
    print_info "All quality checks passed!"
fi 