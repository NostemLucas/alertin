# SOC Alert System - CVE Management Platform

Sistema de alerta SOC para gestión de vulnerabilidades (CVEs) con clasificación dual (NIST NVD + CISA KEV), enriquecimiento mediante NLP con HuggingFace, y almacenamiento en PostgreSQL.

## Características Principales

- **Clasificación Dual**: Combina datos de NIST NVD y CISA KEV para clasificación precisa
- **CISA KEV Override**: CVEs en CISA KEV se marcan automáticamente como CRITICAL
- **Enriquecimiento NLP**: Análisis de descripciones con HuggingFace para extraer contexto adicional
- **Actualización Automática**: Ejecución horaria para mantener datos actualizados
- **Tracking de Cambios**: Historial completo de modificaciones a CVEs
- **PostgreSQL**: Almacenamiento robusto con indexación optimizada

## Arquitectura

### Flujo de Datos

```
NIST NVD API → CISA KEV Check → Classification → Database → HuggingFace Enrichment → Logging
```

### Componentes

1. **NIST NVD**: Fuente primaria de CVEs (clasificación CVSS)
2. **CISA KEV**: Verificación de explotación en la vida real
3. **HuggingFace**: Enriquecimiento NLP (solo para CVEs HIGH/CRITICAL)
4. **PostgreSQL**: Persistencia con esquema normalizado
5. **Scheduler**: APScheduler para ejecuciones horarias

## Instalación

### Requisitos

- Python 3.10+ (o Docker)
- PostgreSQL 16+ (incluido en Docker Compose)
- Opcional: GPU para aceleración de HuggingFace

### Opción A: Docker (Recomendado) 🐳

**Setup completo en 2 comandos con Hot Reload:**

```bash
# 1. Configurar entorno
cp .env.example .env

# 2. Levantar todo (PostgreSQL + App con hot reload)
make dev
```

¡Listo! Puedes editar código en `src/` y los cambios se reflejan automáticamente.

Ver [DOCKER.md](DOCKER.md) para guía completa de Docker.

### Opción B: Instalación Local

### Paso 1: Clonar repositorio

```bash
git clone <repo-url>
cd soc-alertin
```

### Paso 2: Crear entorno virtual

```bash
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
```

### Paso 3: Instalar dependencias

```bash
pip install -r requirements.txt
```

### Paso 4: Configurar variables de entorno

```bash
cp .env.example .env
# Editar .env con tus credenciales
```

Variables importantes:
- `DATABASE_URL`: URL de conexión a PostgreSQL
- `NIST_API_KEY`: Clave API de NIST (opcional pero recomendado)
- `HF_MODEL_NAME`: Modelo de HuggingFace a usar

### Paso 5: Levantar base de datos (Docker)

```bash
docker-compose up -d postgres
```

### Paso 6: Ejecutar migraciones

```bash
alembic upgrade head
```

## Uso

### Ejecución Manual (Una vez)

```bash
python scripts/run_once.py
```

### Ejecución con Scheduler (Horario)

```bash
python src/soc_alerting/main.py
```

### Consultar Base de Datos

```sql
-- CVEs críticos
SELECT cve_id, final_severity, is_in_cisa_kev, cvss_v3_score
FROM cves
WHERE final_severity = 'CRITICAL'
ORDER BY published_date DESC
LIMIT 20;

-- CVEs con enriquecimiento
SELECT c.cve_id, c.final_severity, e.predicted_severity, e.severity_confidence
FROM cves c
JOIN cve_enrichments e ON c.cve_id = e.cve_id
WHERE c.is_in_cisa_kev = true;

-- Historial de cambios
SELECT cve_id, detected_at, severity_changed, cvss_changed
FROM cve_update_history
WHERE severity_changed = true
ORDER BY detected_at DESC;
```

## Estructura del Proyecto

```
soc-alertin/
├── src/soc_alerting/
│   ├── config/          # Configuración
│   ├── models/          # Modelos Pydantic y SQLAlchemy
│   ├── clients/         # Clientes API (NIST, CISA)
│   ├── services/        # Lógica de negocio
│   ├── database/        # Conexión y repositorios
│   ├── scheduler/       # APScheduler
│   └── main.py          # Entry point
├── tests/               # Tests unitarios e integración
├── scripts/             # Scripts de utilidad
├── requirements.txt
├── docker-compose.yml
└── alembic.ini
```

## Configuración Avanzada

### Rate Limiting NIST API

Sin API key: 5 requests/30s
Con API key: 50 requests/30s

Configurar en `.env`:
```bash
NIST_API_KEY=tu_api_key
NIST_RATE_LIMIT_DELAY=6.0  # segundos entre requests
```

### HuggingFace GPU

Para usar GPU:
```bash
HF_DEVICE=0  # 0 para primera GPU, -1 para CPU
```

### Threshold de Enriquecimiento

Solo enriquecer CVEs críticos:
```bash
ENRICH_SEVERITY_THRESHOLD=CRITICAL
```

## Esquema de Base de Datos

### Tabla `cves`
- Almacena estado actual de cada CVE
- Índices en: severity, published_date, cvss_score, is_in_cisa_kev

### Tabla `cve_enrichments`
- Datos de enriquecimiento NLP
- Relación 1:N con cves (puede haber múltiples enriquecimientos)

### Tabla `cve_update_history`
- Auditoría de cambios
- Tracking de modificaciones en CVSS, severidad, descripción

### Tabla `processing_logs`
- Métricas de cada ejecución
- Estado, CVEs procesados, errores

## Lógica de Clasificación

### Severidad NIST (basada en CVSS)
- NONE: 0.0
- LOW: 0.1-3.9
- MEDIUM: 4.0-6.9
- HIGH: 7.0-8.9
- CRITICAL: 9.0-10.0

### Override CISA KEV
```python
if cve in CISA_KEV:
    final_severity = CRITICAL
else:
    final_severity = severity_nist
```

## APIs Utilizadas

### NIST NVD API 2.0
- Endpoint: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Documentación: https://nvd.nist.gov/developers/vulnerabilities

### CISA KEV Catalog
- URL: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Documentación: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## Desarrollo

### Ejecutar Tests

```bash
pytest tests/
```

### Formatear Código

```bash
black src/
ruff check src/ --fix
```

### Type Checking

```bash
mypy src/
```

### Crear Nueva Migración

```bash
alembic revision --autogenerate -m "descripción del cambio"
```

## Próximas Fases

- [ ] Implementar clientes API (NIST, CISA)
- [ ] Implementar servicios de procesamiento
- [ ] Implementar servicio de enriquecimiento HuggingFace
- [ ] Agregar alertas (email, Slack, webhooks)
- [ ] Dashboard web (FastAPI + React)
- [ ] Fine-tuning de modelos HuggingFace
- [ ] Integración con inventario de activos

## Solución de Problemas

### Error de conexión a PostgreSQL
Verificar que el contenedor esté corriendo:
```bash
docker-compose ps
```

### Error "No module named 'soc_alerting'"
Asegurar que estás en el directorio raíz y:
```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

### HuggingFace out of memory
Reducir batch size o usar CPU:
```bash
HF_DEVICE=-1
```

## Licencia

MIT

## Soporte

Para issues y preguntas, abrir un ticket en el repositorio.
