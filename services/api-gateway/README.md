# API Gateway Service

API REST con FastAPI para consultar CVEs, alertas y estadísticas.

## 📋 Responsabilidades

- API REST pública para consultas
- Query CVEs con filtros
- Búsqueda full-text
- Estadísticas agregadas
- Webhooks para notificaciones
- Rate limiting y autenticación (TODO)

## 🚀 Uso

### Con Docker

```bash
docker-compose up -d api-gateway
```

### Standalone (desarrollo)

```bash
cd services/api-gateway
poetry install
poetry run uvicorn api.app:app --reload
```

Acceder a: http://localhost:8000

## ⚙️ Variables de Entorno

```bash
# Database
DATABASE_URL=postgresql://user:pass@postgres:5432/soc_alerting

# Redis (cache)
REDIS_URL=redis://redis:6379/0

# API Config
API_PORT=8000
API_WORKERS=4
```

## 📚 API Endpoints

### Health

```bash
GET /health
```

### CVEs

```bash
# Listar CVEs con filtros
GET /api/v1/cves?severity=CRITICAL&is_in_kev=true&limit=100

# Obtener CVE específico
GET /api/v1/cves/CVE-2024-1234

# Buscar CVEs
GET /api/v1/search?q=remote+code+execution&limit=50
```

### Alertas

```bash
# Listar alertas recientes
GET /api/v1/alerts?priority=CRITICAL&hours_back=24

# Estadísticas
GET /api/v1/stats
```

### Webhooks

```bash
# Registrar webhook
POST /api/v1/webhooks
{
  "url": "https://your-server.com/webhook",
  "events": ["cve.alert", "cve.critical"],
  "filters": {
    "severity": ["CRITICAL", "HIGH"]
  }
}
```

## 📖 Documentación Interactiva

FastAPI proporciona documentación automática:

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

## 🔧 Ejemplos

### Listar CVEs críticos

```bash
curl "http://localhost:8000/api/v1/cves?severity=CRITICAL&limit=10"
```

### Obtener CVE específico

```bash
curl "http://localhost:8000/api/v1/cves/CVE-2024-1234"
```

### Buscar RCE

```bash
curl "http://localhost:8000/api/v1/search?q=remote+code+execution"
```

### Ver estadísticas

```bash
curl "http://localhost:8000/api/v1/stats"
```

## 🔐 Autenticación (TODO)

Agregar autenticación con JWT:
- API keys para clientes
- Rate limiting por cliente
- RBAC (admin, readonly, webhook)

## 📊 Performance

- Cache con Redis
- Query pagination
- Database indexes
- Connection pooling

## 🔗 Integración

Este API puede ser consumido por:
- **Frontend Dashboard** - React/Vue para visualización
- **CLI Tools** - Scripts Python/Bash
- **SIEM** - Integración con Splunk/ELK
- **Monitoring** - Prometheus metrics
