# ============================================================================
# API Gateway Service - Dockerfile
# ============================================================================
FROM python:3.11-slim

LABEL service="api-gateway"
LABEL description="API Gateway - FastAPI REST API for CVE queries"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Copy shared libraries
COPY shared/ /app/shared/

# Copy service code
COPY services/api-gateway/src/ /app/

# Install dependencies
RUN pip install --no-cache-dir \
    fastapi==0.104.1 \
    uvicorn[standard]==0.24.0 \
    psycopg2-binary==2.9.9 \
    sqlalchemy==2.0.23 \
    redis==5.0.1

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run API
CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
