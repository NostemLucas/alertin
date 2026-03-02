# Multi-stage Dockerfile for SOC Alert System
# Supports both development (hot reload) and production builds

# ============================================================================
# Base Stage - Common dependencies for all environments
# ============================================================================
FROM python:3.11-slim as base

# Prevent Python from writing pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ============================================================================
# Development Stage - Hot reload enabled
# ============================================================================
FROM base as development

# Install development tools
RUN pip install --no-cache-dir \
    ipython \
    ipdb \
    watchdog

# Create non-root user for development
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

USER appuser

# Source code will be mounted as volume (hot reload)
# No COPY needed in development

EXPOSE 8000

# Default command for development (can be overridden)
CMD ["python", "-m", "soc_alerting.main"]

# ============================================================================
# Production Stage - Optimized for deployment
# ============================================================================
FROM base as production

# Copy application code
COPY --chown=root:root . .

# Create non-root user for security
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

USER appuser

# Run Alembic migrations on startup (optional, can be done separately)
# and start application
EXPOSE 8000

# Use exec form for proper signal handling
CMD ["python", "-m", "soc_alerting.main"]

# ============================================================================
# Testing Stage - For CI/CD
# ============================================================================
FROM base as testing

COPY . .

# Install test dependencies
RUN pip install --no-cache-dir pytest pytest-asyncio pytest-cov

# Run tests
CMD ["pytest", "tests/", "-v", "--cov=src"]
