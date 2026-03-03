# ============================================================================
# Alert Manager Service - Dockerfile
# ============================================================================
FROM python:3.11-slim

LABEL service="alert-manager"
LABEL description="Alert Manager - Evaluates CVEs and generates alerts"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Copy shared libraries
COPY shared/ /app/shared/

# Copy service code
COPY services/alert-manager/src/ /app/

# Install dependencies
RUN pip install --no-cache-dir \
    kafka-python==2.0.2

# Run manager
CMD ["python", "manager.py"]
