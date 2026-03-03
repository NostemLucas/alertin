# ============================================================================
# SOC Alerting System - Dockerfile
# ============================================================================
FROM python:3.11-slim

# Metadatos
LABEL maintainer="SOC Team"
LABEL description="CVE Alerting System for SOC Operations"

# Variables de entorno
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    curl \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Crear directorio de trabajo
WORKDIR /app

# Copiar archivos de dependencias
COPY pyproject.toml poetry.lock* ./

# Instalar Poetry y dependencias
RUN pip install poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi --no-dev

# Copiar código fuente
COPY src/ ./src/
COPY alembic.ini ./

# Crear directorios necesarios
RUN mkdir -p logs backups

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Exponer puerto
EXPOSE 8000

# Comando por defecto (puede sobrescribirse en docker-compose)
CMD ["uvicorn", "soc_alerting.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
