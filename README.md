# SOC Alerting System - Microservices Architecture

Sistema de alertas de CVEs para operaciones SOC con arquitectura de microservicios y Kafka.

---

## 🏗️ Arquitectura

```
┌─────────────────┐
│  NIST/CISA API  │
└────────┬────────┘
         │
         ↓
┌────────────────────────────────────────────────────────────┐
│  SERVICE 1: CVE Scraper                                    │
│  - Obtiene CVEs de NIST NVD y CISA KEV                    │
│  - Rate limiting respetado                                 │
│  - Scheduler configurable (default: cada 60 min)          │
└──────────┬─────────────────────────────────────────────────┘
           │
           ↓ Kafka Topic: cve.raw
           │
┌──────────┴─────────────────────────────────────────────────┐
│  SERVICE 2: CVE Processor (3 replicas)                     │
│  - Enriquece CVEs con análisis NLP                        │
│  - Calcula risk score (0-100)                             │
│  - Guarda en PostgreSQL                                    │
└──────────┬─────────────────────────────────────────────────┘
           │
           ↓ Kafka Topic: cve.enriched
           │
┌──────────┴─────────────────────────────────────────────────┐
│  SERVICE 3: Alert Manager (2 replicas)                     │
│  - Evalúa CVEs contra reglas configurables                │
│  - Genera alertas por prioridad                            │
│  - Deduplicación automática                                │
└──────────┬─────────────────────────────────────────────────┘
           │
           ↓ Kafka Topic: cve.alerts
           │
┌──────────┴─────────────────────────────────────────────────┐
│  SERVICE 4: API Gateway (FastAPI)                          │
│  - API REST para consultas                                 │
│  - Query CVEs con filtros avanzados                        │
│  - Webhooks para notificaciones                            │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│  INFRASTRUCTURE                                            │
│  - PostgreSQL: CVE storage                                 │
│  - Redis: Cache + Celery                                   │
│  - Kafka: Event streaming                                  │
│  - Zookeeper: Kafka coordination                           │
└────────────────────────────────────────────────────────────┘
```

---

## ✨ Beneficios de Microservicios

### 1. **Separación Clara de Responsabilidades**
- **Scraper:** Solo obtiene datos de NIST/CISA
- **Processor:** Solo enriquece y procesa
- **Alert Manager:** Solo filtra y alerta
- **API Gateway:** Solo sirve queries

### 2. **Escalabilidad Independiente**
```bash
# Scraper: 1 instancia (rate-limited por NIST)
# Processor: 5 instancias (NLP es lento)
# Alert Manager: 2 instancias
# API Gateway: 4 workers

docker-compose -f docker-compose.yml up -d --scale cve-processor=5
```

### 3. **Flujo de Datos Claro (Kafka Topics)**
```
cve.raw         → CVEs crudos desde NIST/CISA
cve.enriched    → CVEs enriquecidos con NLP
cve.alerts      → Alertas generadas
cve.notifications → Notificaciones (extensión)
cve.dlq         → Dead Letter Queue (errores)
```

### 4. **Fácil de Extender**
Agregar nuevos consumidores sin tocar código existente:
```bash
# Nuevo servicio: Email Notifier
services/email-notifier/
  - Consume: cve.alerts
  - Acción: Enviar emails al SOC team

# Nuevo servicio: SIEM Integration
services/siem-integration/
  - Consume: cve.enriched
  - Acción: Enviar a Splunk/ELK
```

### 5. **Resiliencia**
- Si un servicio falla, los demás siguen funcionando
- Mensajes persisten en Kafka
- Dead Letter Queue para errores
- Retry automático

---

## 🚀 Inicio Rápido

### Prerequisitos

- Docker y Docker Compose
- 8GB RAM mínimo (recomendado: 16GB)
- 20GB espacio en disco

### 1. Configurar Variables de Entorno

```bash
cp .env.example .env
nano .env
```

**Mínimo requerido:**
```bash
POSTGRES_PASSWORD=tu-password-seguro
NIST_API_KEY=tu-api-key-de-nist  # Muy recomendado
```

### 2. Levantar TODO el Stack

```bash
# Levantar infraestructura + servicios
docker-compose -f docker-compose.yml up -d

# Ver logs en tiempo real
docker-compose -f docker-compose.yml logs -f

# Ver estado de servicios
docker-compose -f docker-compose.yml ps
```

### 3. Verificar que Todo Funcione

```bash
# 1. Verificar Kafka topics creados
docker exec soc-kafka kafka-topics --bootstrap-server localhost:9092 --list

# 2. Verificar API Gateway
curl http://localhost:8000/health

# 3. Ver logs del scraper (debe estar obteniendo CVEs)
docker-compose -f docker-compose.yml logs -f cve-scraper

# 4. Ver logs del processor (debe estar enriqueciendo)
docker-compose -f docker-compose.yml logs -f cve-processor

# 5. Ver alertas generadas
docker-compose -f docker-compose.yml logs -f alert-manager
```

---

## 📂 Estructura del Proyecto

```
soc-alerting/
├── docker-compose.yml    ← Orquestación completa
├── .env.example                        ← Template de configuración
├── README.md             ← Esta guía
│
├── services/                           ← Microservicios
│   ├── cve-scraper/                    ← SERVICE 1
│   │   ├── Dockerfile
│   │   ├── src/scraper.py
│   │   ├── src/scheduler.py
│   │   └── README.md
│   │
│   ├── cve-processor/                  ← SERVICE 2
│   │   ├── Dockerfile
│   │   ├── src/processor.py
│   │   └── README.md
│   │
│   ├── alert-manager/                  ← SERVICE 3
│   │   ├── Dockerfile
│   │   ├── src/manager.py
│   │   ├── src/rules/
│   │   └── README.md
│   │
│   └── api-gateway/                    ← SERVICE 4
│       ├── Dockerfile
│       ├── src/api/app.py
│       └── README.md
│
├── shared/                             ← Código compartido
│   ├── kafka/                          ← Kafka utils
│   ├── models/                         ← Domain models
│   └── database/                       ← DB access
│
└── infrastructure/                     ← Scripts de infra
    ├── kafka/create-topics.sh
    └── postgres/migrations/
```

---

## ⚙️ Configuración Avanzada

### Escalar Servicios

```bash
# Más procesadores (NLP es lento)
docker-compose -f docker-compose.yml up -d --scale cve-processor=5

# Más alert managers
docker-compose -f docker-compose.yml up -d --scale alert-manager=3
```

### Variables de Entorno Importantes

```bash
# === SCRAPER ===
NIST_API_KEY=                    # API key de NIST (muy recomendado)
SCRAPER_INTERVAL_MINUTES=60      # Frecuencia de scraping
SCRAPER_HOURS_BACK=24            # Horas hacia atrás

# === PROCESSOR ===
PROCESSOR_REPLICAS=3             # Número de instancias
ENABLE_ENRICHMENT=true           # Habilitar NLP
ENRICH_SEVERITY_THRESHOLD=HIGH   # Solo HIGH/CRITICAL
HF_MODEL_NAME=distilbert-base-uncased
HF_DEVICE=-1                     # -1=CPU, 0=GPU

# === ALERT MANAGER ===
ALERT_MANAGER_REPLICAS=2         # Número de instancias

# === API GATEWAY ===
API_PORT=8000                    # Puerto público
API_WORKERS=4                    # Workers de Uvicorn
```

---

## 📊 Monitoreo

### Ver Mensajes en Kafka

```bash
# Topic: cve.raw (CVEs crudos)
docker exec soc-kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic cve.raw \
  --from-beginning \
  --max-messages 10

# Topic: cve.enriched (CVEs enriquecidos)
docker exec soc-kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic cve.enriched \
  --from-beginning \
  --max-messages 10

# Topic: cve.alerts (Alertas)
docker exec soc-kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic cve.alerts \
  --from-beginning
```

### Ver Consumer Groups

```bash
# Estado del grupo de processors
docker exec soc-kafka kafka-consumer-groups \
  --bootstrap-server localhost:9092 \
  --describe \
  --group cve-processor-group

# Estado del grupo de alert managers
docker exec soc-kafka kafka-consumer-groups \
  --bootstrap-server localhost:9092 \
  --describe \
  --group alert-manager-group
```

### Logs de Servicios

```bash
# Ver todos los logs
docker-compose -f docker-compose.yml logs -f

# Logs de un servicio específico
docker-compose -f docker-compose.yml logs -f cve-scraper
docker-compose -f docker-compose.yml logs -f cve-processor
docker-compose -f docker-compose.yml logs -f alert-manager
docker-compose -f docker-compose.yml logs -f api-gateway
```

---

## 🔧 Comandos Útiles

### Reiniciar un Servicio

```bash
docker-compose -f docker-compose.yml restart cve-scraper
```

### Detener Todo

```bash
docker-compose -f docker-compose.yml down
```

### Borrar Volúmenes (Reset Completo)

```bash
# ¡CUIDADO! Pierdes todos los datos
docker-compose -f docker-compose.yml down -v
```

### Rebuild de un Servicio

```bash
# Rebuild después de cambiar código
docker-compose -f docker-compose.yml build cve-scraper
docker-compose -f docker-compose.yml up -d --force-recreate cve-scraper
```

---

## 🎯 API Endpoints

### Health Check

```bash
curl http://localhost:8000/health
```

### Listar CVEs

```bash
# Todos los CVEs
curl "http://localhost:8000/api/v1/cves?limit=100"

# Solo CRITICAL
curl "http://localhost:8000/api/v1/cves?severity=CRITICAL"

# Solo CISA KEV
curl "http://localhost:8000/api/v1/cves?is_in_kev=true"

# CVSS >= 9.0
curl "http://localhost:8000/api/v1/cves?min_cvss=9.0"
```

### Estadísticas

```bash
curl "http://localhost:8000/api/v1/stats"
```

### Documentación Interactiva

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

---

## 🔌 Extensiones Futuras

### Agregar Email Notifier

```python
# services/email-notifier/src/notifier.py
from shared.kafka import KafkaConsumerClient, KafkaTopics

consumer = KafkaConsumerClient(
    topics=[KafkaTopics.CVE_ALERTS],
    group_id="email-notifier-group"
)

def send_email(alert):
    # Enviar email al SOC team
    pass

consumer.consume(handler=send_email)
```

### Agregar Slack Bot

```python
# services/slack-bot/src/bot.py
from shared.kafka import KafkaConsumerClient, KafkaTopics
from slack_sdk import WebClient

consumer = KafkaConsumerClient(
    topics=[KafkaTopics.CVE_ALERTS],
    group_id="slack-bot-group"
)

def send_to_slack(alert):
    # Enviar a canal de Slack
    pass

consumer.consume(handler=send_to_slack)
```

---

## 📚 Documentación de Servicios

Cada servicio tiene su propio README con detalles:

- **[CVE Scraper](services/cve-scraper/README.md)** - Scraping de NIST/CISA
- **[CVE Processor](services/cve-processor/README.md)** - Enriquecimiento NLP
- **[Alert Manager](services/alert-manager/README.md)** - Reglas de alerting
- **[API Gateway](services/api-gateway/README.md)** - API REST

---

## 🛡️ Seguridad

- **Secrets:** Usar .env, no hardcodear
- **Passwords:** Mínimo 16 caracteres
- **API Keys:** Rotar cada 90 días
- **Network:** Aislar con docker networks
- **Producción:** Usar secrets management (Vault, AWS Secrets)

---

## 🐛 Troubleshooting

### "Out of memory" en Processor

```bash
# Reducir número de replicas
PROCESSOR_REPLICAS=2 docker-compose -f docker-compose.yml up -d
```

### "Kafka connection refused"

```bash
# Esperar a que Kafka esté listo (puede tardar 30s)
docker-compose -f docker-compose.yml logs -f kafka
```

### "Consumer lag alto"

```bash
# Agregar más replicas de processor
docker-compose -f docker-compose.yml up -d --scale cve-processor=5
```

---

## 📞 Soporte

Para más información, consulta los READMEs de cada servicio o abre un issue.

---

**¡Listo!** Ahora tienes un sistema de alertas de CVEs escalable, resiliente y fácil de extender. 🎉
