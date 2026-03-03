# Alert Manager Service

Servicio que evalúa CVEs enriquecidos contra reglas configurables y genera alertas.

## 📋 Responsabilidades

- Consumir CVEs desde Kafka topic `cve.enriched`
- Evaluar contra reglas de alerting
- Generar alertas con prioridad (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Enviar alertas a Kafka topic `cve.alerts`
- Deduplicación de alertas

## 🚀 Uso

### Con Docker

```bash
docker-compose up -d alert-manager
```

### Standalone (desarrollo)

```bash
cd services/alert-manager
poetry install
poetry run python src/manager.py
```

## ⚙️ Variables de Entorno

```bash
# Kafka
KAFKA_BOOTSTRAP_SERVERS=kafka:9092
KAFKA_CLIENT_ID=alert-manager
KAFKA_CONSUMER_GROUP_ID=alert-manager-group
```

## 📥 Input (Kafka Topic)

**Topic:** `cve.enriched`

## 📤 Output (Kafka Topic)

**Topic:** `cve.alerts`

**Message format:**
```json
{
  "rule_name": "CISA_KEV",
  "priority": "CRITICAL",
  "cve_id": "CVE-2024-1234",
  "description": "CVE is in CISA Known Exploited Vulnerabilities catalog",
  "cve_data": { ... },
  "generated_at": "2024-01-16T12:00:00Z"
}
```

## 🎯 Reglas de Alerting (Default)

### CRITICAL Priority

1. **CISA_KEV** - CVE en catálogo CISA KEV
2. **HIGH_CVSS** - CVSS >= 9.0
3. **REMOTE_CODE_EXECUTION** - RCE vulnerability
4. **ZERO_DAY** - Zero-day detectado
5. **CRITICAL_SEVERITY** - Severidad CRITICAL

### HIGH Priority

6. **NETWORK_NO_AUTH** - Network + No Auth
7. **HIGH_RISK_SCORE** - Risk score >= 85

## ➕ Agregar Reglas Personalizadas

```python
from rules.base_rule import AlertRule, AlertPriority

class CustomRule(AlertRule):
    def __init__(self):
        super().__init__(
            name="MY_RULE",
            priority=AlertPriority.HIGH,
            description="My custom rule"
        )

    def matches(self, cve_data):
        # Implementa tu lógica
        return cve_data.get("cvss_score", 0) > 8.0

# Agregar a manager
from manager import AlertManager
from rules import get_default_rules

rules = get_default_rules()
rules.append(CustomRule())
manager = AlertManager(rules=rules)
manager.run()
```

## 🔧 Comandos

```bash
# Ver logs
docker-compose logs -f alert-manager

# Ver estadísticas
docker-compose exec alert-manager python -c "from manager import AlertManager; print(AlertManager().alert_count)"

# Ver alertas generadas (leer topic)
kafka-console-consumer --bootstrap-server kafka:9092 \
  --topic cve.alerts --from-beginning
```

## 📊 Monitoring

Métricas importantes:
- Alertas generadas por prioridad
- Reglas más frecuentes
- CVEs sin alertas
- Latencia de evaluación

## 🔗 Integración con Notificaciones

Las alertas del topic `cve.alerts` pueden ser consumidas por:
- **Email Notifier** - Enviar emails a SOC team
- **Slack Bot** - Notificaciones en Slack
- **SIEM Integration** - Enviar a Splunk/ELK
- **Ticket Creator** - Crear tickets en Jira/ServiceNow
