# Arquitectura - SOC Alerting System

Sistema de alertas de CVEs con arquitectura de microservicios y Kafka.

---

## 📐 Diagrama de Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                    EXTERNAL APIs                            │
│   ┌──────────────┐              ┌──────────────┐           │
│   │  NIST NVD    │              │  CISA KEV    │           │
│   │  (Rate       │              │  (Catalog)   │           │
│   │   Limited)   │              │              │           │
│   └──────┬───────┘              └──────┬───────┘           │
└──────────┼──────────────────────────────┼───────────────────┘
           │                              │
           └──────────────┬───────────────┘
                          │
                          ↓
┌──────────────────────────────────────────────────────────────┐
│              SERVICE 1: CVE SCRAPER                          │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  • Scheduler: Ejecuta cada 60 minutos (configurable)   │ │
│  │  • Rate Limiting: 6s sin API key, 0.6s con API key    │ │
│  │  • Parser: Extrae 17 campos críticos                   │ │
│  │  • CISA Check: Verifica si CVE está en KEV            │ │
│  │  • Output: CVEs crudos a Kafka                        │ │
│  └────────────────────────────────────────────────────────┘ │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ↓ Kafka Topic: cve.raw
                         │
┌────────────────────────┴─────────────────────────────────────┐
│              SERVICE 2: CVE PROCESSOR (3 replicas)           │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  • Consumer: Lee de cve.raw                            │ │
│  │  • NLP Enrichment: Análisis con DistilBERT            │ │
│  │    - Keywords extraction                               │ │
│  │    - Attack types detection                            │ │
│  │    - Risk indicators                                   │ │
│  │  • Risk Scoring: Calcula score 0-100                  │ │
│  │  • Database: Guarda en PostgreSQL                     │ │
│  │  • Output: CVEs enriquecidos a Kafka                  │ │
│  │  • DLQ: Errores a Dead Letter Queue                   │ │
│  └────────────────────────────────────────────────────────┘ │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ↓ Kafka Topic: cve.enriched
                         │
┌────────────────────────┴─────────────────────────────────────┐
│              SERVICE 3: ALERT MANAGER (2 replicas)           │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  • Consumer: Lee de cve.enriched                       │ │
│  │  • Rules Engine: Evalúa 7 reglas predefinidas         │ │
│  │    1. CISA_KEV         → CRITICAL                      │ │
│  │    2. HIGH_CVSS        → CRITICAL                      │ │
│  │    3. RCE              → CRITICAL                      │ │
│  │    4. ZERO_DAY         → CRITICAL                      │ │
│  │    5. NETWORK_NO_AUTH  → HIGH                          │ │
│  │    6. HIGH_RISK_SCORE  → HIGH                          │ │
│  │    7. CRITICAL_SEV     → CRITICAL                      │ │
│  │  • Deduplication: Evita alertas duplicadas            │ │
│  │  • Output: Alertas a Kafka                            │ │
│  └────────────────────────────────────────────────────────┘ │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ↓ Kafka Topic: cve.alerts
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ↓               ↓               ↓
    ┌─────────┐    ┌─────────┐    ┌─────────┐
    │  Email  │    │  Slack  │    │  SIEM   │
    │ Notifier│    │   Bot   │    │ Export  │
    │(Future) │    │(Future) │    │(Future) │
    └─────────┘    └─────────┘    └─────────┘

┌──────────────────────────────────────────────────────────────┐
│              SERVICE 4: API GATEWAY (FastAPI)                │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  • REST API: Query CVEs con filtros                   │ │
│  │  • Endpoints:                                          │ │
│  │    - GET /api/v1/cves                                  │ │
│  │    - GET /api/v1/cves/{id}                            │ │
│  │    - GET /api/v1/alerts                               │ │
│  │    - GET /api/v1/stats                                │ │
│  │    - GET /api/v1/search                               │ │
│  │  • Swagger UI: /docs                                   │ │
│  │  • Cache: Redis para performance                      │ │
│  │  • Webhooks: Configurables (future)                   │ │
│  └────────────────────────────────────────────────────────┘ │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ↓ HTTP/REST
                         │
                ┌────────┴─────────┐
                │   Frontend/CLI   │
                │   SIEM/Clients   │
                └──────────────────┘

╔══════════════════════════════════════════════════════════════╗
║                    INFRASTRUCTURE                            ║
╠══════════════════════════════════════════════════════════════╣
║  • Kafka + Zookeeper: Event streaming (5 topics)            ║
║  • PostgreSQL: CVE storage (versioned schema: Header+Versions) ║
║  • Redis: Cache + Celery backend                            ║
║  • Docker Network: Isolated soc-network                     ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 🔄 Flujo de Datos

### 1. Ingesta (Scraper)
```
NIST/CISA API → Scraper → Parse → cve.raw topic
                   ↓
               (Rate Limit: 6s/0.6s)
```

### 2. Procesamiento (Processor)
```
cve.raw topic → Processor → NLP → Risk Score → PostgreSQL
                                       ↓
                                 cve.enriched topic
```

### 3. Alerting (Alert Manager)
```
cve.enriched topic → Rules Engine → Filter → cve.alerts topic
                         ↓
                    (7 reglas configurables)
```

### 4. Consumo (API Gateway + Extensiones)
```
cve.alerts topic → Email/Slack/SIEM/etc.
PostgreSQL → API Gateway → REST API → Clients
```

---

## 📊 Kafka Topics

| Topic              | Descripción                     | Retention | Partitions |
|--------------------|--------------------------------|-----------|------------|
| `cve.raw`          | CVEs crudos desde NIST/CISA   | 7 días    | 3          |
| `cve.enriched`     | CVEs enriquecidos con NLP      | 7 días    | 3          |
| `cve.alerts`       | Alertas generadas              | 30 días   | 3          |
| `cve.notifications`| Notificaciones (email, Slack)  | 1 día     | 3          |
| `cve.dlq`          | Dead Letter Queue (errores)    | 30 días   | 1          |

---

## 🗄️ Base de Datos (PostgreSQL)

### Esquema Minimal (17 campos)

```sql
CREATE TABLE cves (
    -- Identity
    cve_id VARCHAR(20) PRIMARY KEY,

    -- Content
    description TEXT NOT NULL,
    cwe_id VARCHAR(20),

    -- Dates
    published_date TIMESTAMP,
    last_modified_date TIMESTAMP,

    -- Severity
    cvss_score FLOAT,
    cvss_vector VARCHAR(100),
    severity VARCHAR(20) NOT NULL,

    -- Attack Characteristics
    attack_vector VARCHAR(20),
    attack_complexity VARCHAR(20),
    requires_auth BOOLEAN,
    user_interaction_required BOOLEAN,

    -- Products (JSONB)
    affected_products JSONB NOT NULL DEFAULT '[]',
    references JSONB NOT NULL DEFAULT '[]',

    -- CISA KEV
    is_in_cisa_kev BOOLEAN DEFAULT FALSE,
    cisa_date_added TIMESTAMP,

    -- Metadata
    version INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_cves_severity ON cves(severity);
CREATE INDEX idx_cves_cvss_score ON cves(cvss_score DESC);
CREATE INDEX idx_cves_published_date ON cves(published_date DESC);
CREATE INDEX idx_cves_is_in_kev ON cves(is_in_cisa_kev);
CREATE INDEX idx_cves_attack_vector ON cves(attack_vector);
CREATE INDEX idx_cves_products ON cves USING GIN(affected_products);
```

---

## 🔌 Escalabilidad

### Escalar por Servicio

```bash
# Scraper: 1 instancia (rate-limited por NIST)
docker-compose up -d --scale cve-scraper=1

# Processor: Más instancias = Más throughput de NLP
docker-compose up -d --scale cve-processor=5

# Alert Manager: Más instancias = Más redundancia
docker-compose up -d --scale alert-manager=3

# API Gateway: Más workers = Más requests/segundo
API_WORKERS=8 docker-compose up -d api-gateway
```

### Performance por Servicio

| Servicio       | Throughput             | Bottleneck        |
|----------------|------------------------|-------------------|
| Scraper        | ~50 CVEs/min           | NIST rate limit   |
| Processor      | ~10 CVEs/sec (x worker)| NLP processing    |
| Alert Manager  | ~1000 CVEs/sec         | Rules evaluation  |
| API Gateway    | ~500 req/sec           | DB queries        |

---

## 🛡️ Resiliencia

### 1. Fault Tolerance
- Cada servicio puede fallar independientemente
- Kafka persiste mensajes (7-30 días)
- Consumer groups con auto-rebalancing
- Dead Letter Queue para errores

### 2. Retry Logic
- Kafka auto-retry en producers/consumers
- Exponential backoff en NIST API
- DLQ para mensajes no procesables

### 3. Health Checks
- Todos los servicios tienen health endpoints
- Docker healthchecks configurados
- Restart automático en fallo

---

## 🔐 Seguridad

### Network Isolation
```yaml
networks:
  soc-network:
    driver: bridge
```
- Servicios aislados en red privada
- Solo API Gateway expone puerto público (8000)

### Secrets Management
- `.env` para desarrollo (git-ignored)
- Docker Secrets para producción
- Variables sensibles: passwords, API keys

### Rate Limiting
- NIST API: 6s sin key, 0.6s con key
- Protección contra rate limit violations

---

## 📈 Monitoring (Future)

### Métricas Clave

**Scraper:**
- CVEs scraped/hour
- Rate limit usage
- NIST API errors

**Processor:**
- CVEs processed/sec
- NLP processing time
- Consumer lag
- DLQ messages

**Alert Manager:**
- Alerts generated/priority
- Rule match frequency
- Consumer lag

**API Gateway:**
- Request rate
- Response time p50/p95/p99
- Error rate

---

## 🔗 Extensiones Futuras

### 1. Email Notifier
```
services/email-notifier/
  - Consumer: cve.alerts
  - Action: Enviar emails a SOC team
```

### 2. Slack Bot
```
services/slack-bot/
  - Consumer: cve.alerts
  - Action: Notificaciones en Slack
```

### 3. SIEM Integration
```
services/siem-integration/
  - Consumer: cve.enriched
  - Action: Enviar a Splunk/ELK
```

### 4. Ticket Creator
```
services/ticket-creator/
  - Consumer: cve.alerts (CRITICAL only)
  - Action: Crear tickets en Jira/ServiceNow
```

---

## 📚 Referencias

- **Kafka:** https://kafka.apache.org/documentation/
- **FastAPI:** https://fastapi.tiangolo.com/
- **PostgreSQL:** https://www.postgresql.org/docs/
- **NIST NVD API:** https://nvd.nist.gov/developers
- **CISA KEV:** https://www.cisa.gov/known-exploited-vulnerabilities

---

**Versión:** 2.0 (Microservicios)
**Última actualización:** 2024-03-03
