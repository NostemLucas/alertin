#!/bin/bash
# Cleanup script for SOC Alerting System
# Removes temporary files, caches, and build artifacts

set -e

echo "🧹 Cleaning SOC Alerting System..."
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_step() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Navigate to project root
cd "$(dirname "$0")/.."

# 1. Clean Python cache files
echo "Cleaning Python cache files..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
find . -type f -name "*.pyo" -delete 2>/dev/null || true
find . -type f -name "*.py[cod]" -delete 2>/dev/null || true
find . -type f -name "*$py.class" -delete 2>/dev/null || true
print_step "Removed Python cache files"

# 2. Clean pytest cache
if [ -d ".pytest_cache" ]; then
    rm -rf .pytest_cache
    print_step "Removed pytest cache"
fi

# 3. Clean coverage reports
if [ -f ".coverage" ]; then
    rm -f .coverage
    print_step "Removed coverage reports"
fi
if [ -d "htmlcov" ]; then
    rm -rf htmlcov
    print_step "Removed coverage HTML reports"
fi

# 4. Clean mypy cache
if [ -d ".mypy_cache" ]; then
    rm -rf .mypy_cache
    print_step "Removed mypy cache"
fi

# 5. Clean ruff cache
if [ -d ".ruff_cache" ]; then
    rm -rf .ruff_cache
    print_step "Removed ruff cache"
fi

# 6. Clean egg-info
find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
print_step "Removed egg-info directories"

# 7. Clean build artifacts
if [ -d "build" ]; then
    rm -rf build
    print_step "Removed build directory"
fi
if [ -d "dist" ]; then
    rm -rf dist
    print_step "Removed dist directory"
fi

# 8. Clean temporary files
find . -type f -name "*.swp" -delete 2>/dev/null || true
find . -type f -name "*.swo" -delete 2>/dev/null || true
find . -type f -name "*~" -delete 2>/dev/null || true
find . -type f -name ".DS_Store" -delete 2>/dev/null || true
print_step "Removed temporary editor files"

# 9. Clean log files (optional - ask first)
if [ -d "logs" ]; then
    read -p "Remove log files? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf logs/*
        print_step "Removed log files"
    else
        print_warning "Skipped log files"
    fi
fi

# 10. Clean Docker volumes (optional - dangerous)
echo ""
read -p "Clean Docker volumes? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_warning "This will remove all Docker volumes including database data!"
    read -p "Are you sure? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker-compose down -v 2>/dev/null || true
        print_step "Removed Docker volumes"
    else
        print_warning "Skipped Docker volumes"
    fi
else
    print_warning "Skipped Docker volumes"
fi

echo ""
echo "✨ Cleanup complete!"
echo ""
echo "Summary:"
echo "  ✓ Python cache files"
echo "  ✓ Test cache and coverage"
echo "  ✓ Linter caches"
echo "  ✓ Build artifacts"
echo "  ✓ Temporary files"
echo ""
