# Makefile for SOC Alert System
# Simplifies Docker and development commands

.PHONY: help dev dev-build dev-up dev-down dev-logs prod prod-build prod-up prod-down test clean

# Default target
help:
	@echo "SOC Alert System - Available Commands"
	@echo "======================================"
	@echo ""
	@echo "Development:"
	@echo "  make dev         - Start development environment (with hot reload)"
	@echo "  make dev-build   - Build development images"
	@echo "  make dev-up      - Start dev containers in background"
	@echo "  make dev-down    - Stop and remove dev containers"
	@echo "  make dev-logs    - Show development logs (follow)"
	@echo "  make dev-shell   - Open shell in app container"
	@echo ""
	@echo "Production:"
	@echo "  make prod        - Start production environment"
	@echo "  make prod-build  - Build production images"
	@echo "  make prod-up     - Start prod containers in background"
	@echo "  make prod-down   - Stop and remove prod containers"
	@echo ""
	@echo "Database:"
	@echo "  make db          - Start only PostgreSQL"
	@echo "  make db-migrate  - Run Alembic migrations"
	@echo "  make db-shell    - Open PostgreSQL shell"
	@echo "  make db-backup   - Create database backup"
	@echo ""
	@echo "Utilities:"
	@echo "  make test        - Run tests"
	@echo "  make lint        - Run linters (black, ruff, mypy)"
	@echo "  make clean       - Remove containers, volumes, and cache"
	@echo "  make install     - Install Python dependencies locally"
	@echo ""

# ============================================================================
# Development
# ============================================================================

dev: dev-build dev-up

dev-build:
	@echo "Building development images..."
	docker compose -f docker-compose.dev.yml build

dev-up:
	@echo "Starting development environment..."
	docker compose -f docker-compose.dev.yml up

dev-up-d:
	@echo "Starting development environment (background)..."
	docker compose -f docker-compose.dev.yml up -d

dev-down:
	@echo "Stopping development environment..."
	docker compose -f docker-compose.dev.yml down

dev-logs:
	@echo "Following development logs..."
	docker compose -f docker-compose.dev.yml logs -f

dev-shell:
	@echo "Opening shell in app container..."
	docker compose -f docker-compose.dev.yml exec app /bin/bash

dev-restart:
	@echo "Restarting app container..."
	docker compose -f docker-compose.dev.yml restart app

# ============================================================================
# Production
# ============================================================================

prod: prod-build prod-up

prod-build:
	@echo "Building production images..."
	docker compose -f docker-compose.prod.yml build

prod-up:
	@echo "Starting production environment..."
	docker compose -f docker-compose.prod.yml up

prod-up-d:
	@echo "Starting production environment (background)..."
	docker compose -f docker-compose.prod.yml up -d

prod-down:
	@echo "Stopping production environment..."
	docker compose -f docker-compose.prod.yml down

prod-logs:
	@echo "Following production logs..."
	docker compose -f docker-compose.prod.yml logs -f

# ============================================================================
# Database
# ============================================================================

db:
	@echo "Starting PostgreSQL only..."
	docker compose up -d postgres

db-migrate:
	@echo "Running database migrations..."
	docker compose -f docker-compose.dev.yml exec app alembic upgrade head

db-shell:
	@echo "Opening PostgreSQL shell..."
	docker compose exec postgres psql -U soc_user -d soc_alerting

db-backup:
	@echo "Creating database backup..."
	@mkdir -p backups
	docker compose exec postgres pg_dump -U soc_user soc_alerting > backups/backup_$$(date +%Y%m%d_%H%M%S).sql
	@echo "Backup created in backups/"

db-restore:
	@echo "Restoring database from backup..."
	@read -p "Enter backup file name: " backup; \
	docker compose exec -T postgres psql -U soc_user -d soc_alerting < backups/$$backup

# ============================================================================
# Testing
# ============================================================================

test:
	@echo "Running tests..."
	docker compose -f docker-compose.dev.yml exec app pytest tests/ -v

test-cov:
	@echo "Running tests with coverage..."
	docker compose -f docker-compose.dev.yml exec app pytest tests/ -v --cov=src --cov-report=html

test-local:
	@echo "Running tests locally (no Docker)..."
	pytest tests/ -v

# ============================================================================
# Code Quality
# ============================================================================

lint:
	@echo "Running linters..."
	@echo "Black..."
	black src/ tests/
	@echo "Ruff..."
	ruff check src/ tests/ --fix
	@echo "MyPy..."
	mypy src/

lint-docker:
	@echo "Running linters in Docker..."
	docker compose -f docker-compose.dev.yml exec app black src/ tests/
	docker compose -f docker-compose.dev.yml exec app ruff check src/ tests/ --fix

# ============================================================================
# Utilities
# ============================================================================

install:
	@echo "Installing Python dependencies..."
	pip install -r requirements.txt

clean:
	@echo "Cleaning up..."
	docker compose -f docker-compose.dev.yml down -v
	docker compose -f docker-compose.prod.yml down -v
	docker compose down -v
	@echo "Removing Python cache..."
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "Cleanup complete"

clean-all: clean
	@echo "Removing Docker images..."
	docker images | grep soc_alerting | awk '{print $$3}' | xargs docker rmi -f 2>/dev/null || true
	@echo "Full cleanup complete"

# ============================================================================
# Monitoring
# ============================================================================

ps:
	@echo "Container status:"
	docker compose -f docker-compose.dev.yml ps

stats:
	@echo "Container stats:"
	docker stats $$(docker ps --format "{{.Names}}" | grep soc_alerting)

# ============================================================================
# Quick start commands
# ============================================================================

start: dev-up-d
	@echo "Development environment started in background"
	@echo "View logs: make dev-logs"
	@echo "Stop: make dev-down"

stop: dev-down

restart: dev-down dev-up-d
