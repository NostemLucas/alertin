# 🔍 SOC Alerting - CVE Scraper

Sistema de scraping automatizado de CVEs desde NIST NVD y CISA KEV con almacenamiento versionado y publicación a Kafka.

---

## 📋 Tabla de Contenidos

- [Descripción](#descripción)
- [Arquitectura](#arquitectura)
- [Entidades y Modelos](#entidades-y-modelos)
- [Configuración](#configuración)
- [Instalación](#instalación)
- [Uso](#uso)
- [Comandos Makefile](#comandos-makefile)
- [Flujo de Datos](#flujo-de-datos)
- [Troubleshooting](#troubleshooting)

---

## 📖 Descripción

El **CVE Scraper** es un servicio automatizado que:

1. 🔍 **Scraping**: Obtiene CVEs desde NIST NVD API 2.0 y CISA KEV catalog
2. 🗄️ **Almacenamiento**: Guarda CVEs con sistema de versiones (snapshots completos)
3. 📡 **Publicación**: Envía CVEs a Kafka para procesamiento downstream
4. ⏰ **Automatización**: Ejecuta periódicamente (configurable)

### Características

- ✅ **Rate Limiting Inteligente**: 50 req/30s con API key, 5 req/30s sin key
- ✅ **Versionamiento Automático**: Detecta cambios significativos y crea nuevas versiones
- ✅ **CISA KEV Integration**: Enriquece CVEs con metadata de Known Exploited Vulnerabilities
- ✅ **Retry & Backoff**: Manejo robusto de errores con reintentos exponenciales
- ✅ **Docker-First**: Fácil despliegue con docker-compose

---

## 🏗️ Arquitectura

### Componentes

```
┌─────────────────────────────────────────────────────────────┐
│                     CVE SCRAPER                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐      ┌──────────────┐                   │
│  │ NIST Client  │      │ CISA Client  │                   │
│  │ (NVD API)    │      │ (KEV JSON)   │                   │
│  └──────┬───────┘      └──────┬───────┘                   │
│         │                     │                            │
│         └──────────┬──────────┘                            │
│                    │                                        │
│         ┌──────────▼──────────┐                            │
│         │   CVE Processor     │                            │
│         │  (Conversion +      │                            │
│         │   Enrichment)       │                            │
│         └──────────┬──────────┘                            │
│                    │                                        │
│      ┌─────────────┴─────────────┐                         │
│      │                           │                         │
│      ▼                           ▼                         │
│ ┌─────────┐              ┌──────────────┐                 │
│ │ Postgres│              │    Kafka     │                 │
│ │ (Versioned)│            │  (cve-raw)   │                 │
│ └─────────┘              └──────────────┘                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Stack Tecnológico

| Componente           | Tecnología                         |
| -------------------- | ---------------------------------- |
| **Language**         | Python 3.11+                       |
| **HTTP Client**      | httpx (async)                      |
| **Database**         | PostgreSQL 15 + SQLAlchemy (async) |
| **Message Queue**    | Apache Kafka                       |
| **Validation**       | Pydantic v2                        |
| **Migrations**       | Alembic                            |
| **Containerization** | Docker + Docker Compose            |

---

## 🗂️ Entidades y Modelos

### 1. Modelo de Base de Datos (Versionado)

#### `CVE` (Tabla Cabecera)

```python
class CVE:
    cve_id: str              # PK - CVE-2024-12345
    first_seen: datetime     # Primera vez que se vio
    created_at: datetime     # Timestamp de creación
    current_version_id: UUID # FK a última versión

    # Relationship
    versions: List[CVEVersion]
```

**Propósito**: Identidad única de cada CVE. Solo guarda metadata de tracking.

---

#### `CVEVersion` (Tabla Versiones - Snapshots Completos)

```python
class CVEVersion:
    # === IDENTITY ===
    id: UUID                         # PK
    cve_id: str                      # FK a CVE
    version: int                     # 1, 2, 3...
    created_at: datetime             # Timestamp versión

    # === CONTENT ===
    description: str                 # Descripción del CVE
    cwe_id: str | None               # CWE-79, CWE-89...

    # === CRITICALITY ===
    cvss_score: float | None         # 0.0 - 10.0
    cvss_vector: str | None          # CVSS:3.1/AV:N/AC:L...
    severity: str                    # CRITICAL/HIGH/MEDIUM/LOW/NONE

    # === ATTACK VECTOR ===
    attack_vector: str | None        # NETWORK/ADJACENT/LOCAL/PHYSICAL
    attack_complexity: str | None    # LOW/HIGH
    requires_auth: bool | None       # ¿Requiere autenticación?
    user_interaction_required: bool  # ¿Requiere interacción usuario?

    # === AFFECTED PRODUCTS (JSONB) ===
    affected_products: list[dict]    # [{"vendor": "apache", "product": "log4j", "versions": ["2.0"]}]

    # === TRACKING ===
    status_nist: str                 # Analyzed/Undergoing Analysis/etc
    source: str                      # cna@apache.org
    published_date: datetime         # Fecha publicación original
    last_modified_date: datetime     # Última modificación en NIST

    # === CISA KEV ===
    is_in_cisa_kev: bool             # ¿Está en CISA KEV?
    cisa_date_added: datetime | None # Fecha añadido a KEV
    cisa_due_date: datetime | None   # Fecha límite remediación
    cisa_required_action: str | None # Acción requerida
    cisa_known_ransomware: bool      # ¿Usado en ransomware?

    # === REFERENCES ===
    primary_reference: str | None    # URL principal
    references: list[str]            # [urls...]
```

**Propósito**: Snapshot completo de un CVE en un momento dado. Cada actualización = nueva fila.

---

### 2. Modelo de Dominio (Pydantic)

#### `CVEMinimal`

```python
class CVEMinimal(BaseModel):
    """Modelo de dominio - Validación y lógica de negocio"""

    # Mismos campos que CVEVersion
    cve_id: str
    description: str
    # ... (17 campos totales)

    # === COMPUTED PROPERTIES ===
    @property
    def is_critical(self) -> bool:
        """¿Es CRITICAL severity?"""
        return self.severity == SeverityLevel.CRITICAL

    @property
    def risk_score(self) -> int:
        """
        Score de riesgo 0-100 basado en:
        - CVSS score (0-40 pts)
        - CISA KEV (+30 pts)
        - Network exploitable (+10 pts)
        - No auth required (+10 pts)
        - Low complexity (+10 pts)
        """
        # Implementation...

    @property
    def is_cisa_overdue(self) -> bool:
        """¿Pasó la fecha límite CISA?"""
        # Implementation...
```

---

### 3. Modelos de API Externa

#### `NISTVulnerability`

```python
class NISTVulnerability(BaseModel):
    """Respuesta de NIST NVD API 2.0"""
    id: str                    # CVE-2024-12345
    sourceIdentifier: str      # cna@apache.org
    published: datetime
    lastModified: datetime
    vulnStatus: str           # Analyzed/etc
    descriptions: list[dict]  # [{lang: "en", value: "..."}]
    metrics: dict             # CVSS v3 data
    weaknesses: list[dict]    # CWE IDs
    configurations: list      # CPE matches
    references: list[dict]    # URLs
```

#### `CISAVulnerability`

```python
class CISAVulnerability(BaseModel):
    """Entry del CISA KEV catalog"""
    cveID: str
    vendorProject: str
    product: str
    vulnerabilityName: str
    dateAdded: datetime
    shortDescription: str
    requiredAction: str
    dueDate: datetime
    knownRansomwareCampaignUse: str  # "Known" | "Unknown"
```

---

### 4. Enums

```python
class SeverityLevel(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AttackVector(str, Enum):
    NETWORK = "NETWORK"
    ADJACENT = "ADJACENT"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"

class AttackComplexity(str, Enum):
    LOW = "LOW"
    HIGH = "HIGH"
```

---

## ⚙️ Configuración

### Variables de Entorno (.env)

```bash
# NIST API
NIST_API_KEY=
NIST_RATE_LIMIT_DELAY=6.0

# Kafka
KAFKA_PORT=9092
KAFKA_BOOTSTRAP_SERVERS=localhost:9092

# PostgreSQL
POSTGRES_USER=soc_user
POSTGRES_PASSWORD=soc_password
POSTGRES_DB=soc_alerting
POSTGRES_PORT=5432

# Scraper
SCRAPER_INTERVAL_MINUTES=60        # Cada cuánto ejecutar
SCRAPER_HOURS_BACK=24              # Cuántas horas buscar hacia atrás

# Logging
LOG_LEVEL=INFO                     # DEBUG|INFO|WARNING|ERROR
```

---

## 🚀 Instalación

### Prerrequisitos

- Docker 20.10+
- Docker Compose 2.0+
- Make (opcional pero recomendado)
- Python 3.11+ (solo para desarrollo local)

### Setup Rápido

```bash
# 1. Clonar repo
git clone <repo-url>
cd soc-alertin

# 2. Setup inicial (crea .env)
make -f Makefile.scraper setup

# 3. Editar .env y añadir NIST_API_KEY (opcional pero recomendado)
nano .env

# 4. Levantar PostgreSQL
make -f Makefile.scraper db-up

# 5. Poblar BD con datos de prueba
make -f Makefile.scraper db-seed

# 6. Levantar todos los servicios
make -f Makefile.scraper up

# 7. Ver logs
make -f Makefile.scraper logs
```

---

## 🎮 Uso

### Setup Inicial Completo

```bash
# Todo en uno comando:
make -f Makefile.scraper init

# Esto ejecuta: setup + deps + db-up
# Luego manual: db-seed + up
```

### Operaciones Diarias

```bash
# Ver estado de servicios
make -f Makefile.scraper ps

# Ver logs en vivo
make -f Makefile.scraper logs

# Ejecutar scraper manualmente (últimas 24h)
make -f Makefile.scraper scrape

# Ejecutar scraper (última semana)
make -f Makefile.scraper scrape-week

# Reiniciar scraper
make -f Makefile.scraper restart
```

### Base de Datos

```bash
# Conectar a PostgreSQL
make -f Makefile.scraper db-shell

# Ver estado de migraciones
make -f Makefile.scraper db-status

# Aplicar migraciones
make -f Makefile.scraper db-migrate

# Crear backup
make -f Makefile.scraper db-backup

# Resetear BD (⚠️ elimina datos)
make -f Makefile.scraper db-reset
```

### Debugging

```bash
# Abrir shell en contenedor scraper
make -f Makefile.scraper shell-scraper

# Dentro del contenedor:
python scraper.py --hours-back 1  # Manual run
ls -la /app/                      # Ver archivos
env                               # Ver variables
```

---

## 📚 Comandos Makefile

### Categorías

| Categoría       | Comandos                                                  |
| --------------- | --------------------------------------------------------- |
| **Setup**       | `setup`, `check`, `deps`                                  |
| **Docker**      | `up`, `down`, `restart`, `ps`, `logs`                     |
| **Database**    | `db-up`, `db-seed`, `db-migrate`, `db-shell`, `db-backup` |
| **Scraper**     | `scrape`, `scrape-recent`, `scrape-week`                  |
| **Maintenance** | `clean`, `rebuild`, `clean-cache`                         |

### Comandos Útiles

```bash
# Ver todos los comandos disponibles
make -f Makefile.scraper help

# Setup completo inicial
make -f Makefile.scraper init

# Dev workflow (up + logs)
make -f Makefile.scraper dev

# Rebuild + restart
make -f Makefile.scraper refresh
```

---

## 🔄 Flujo de Datos

### 1. Scraping Flow

```
NIST NVD API
    ↓ fetch_cves_by_modified_date(hours=24)
NISTVulnerability[] (50+ campos)
    ↓ convert_to_domain_model()
CVE[] (17 campos críticos)
    ↓ enrich with CISA KEV data
CVE[] (enriquecido con CISA KEV)
    ↓ save() - Repository
┌──────────────────────────────┐
│ PostgreSQL (Versioned)       │
│ - CVE (header)               │
│ - CVEVersion (snapshot v1/v2)│
└──────────────────────────────┘
    ↓ publish to Kafka
┌──────────────────────────────┐
│ Kafka Topic: cve-raw         │
│ Message: CVERawMessage       │
└──────────────────────────────┘
```

### 2. Versionamiento Automático

```python
# Primera vez - CVE no existe
save(CVE-2024-12345) →
    ├─ CREATE CVE(cve_id="CVE-2024-12345", first_seen=now)
    ├─ CREATE CVEVersion(version=1, cvss_score=9.8, severity=CRITICAL)
    └─ UPDATE CVE.current_version_id = version_1.id

# Segunda vez - CVE existe, cambió CVSS
save(CVE-2024-12345) →
    ├─ DETECT changes: cvss_score 9.8 → 10.0
    ├─ CREATE CVEVersion(version=2, cvss_score=10.0, severity=CRITICAL)
    └─ UPDATE CVE.current_version_id = version_2.id

# Tercera vez - CVE existe, sin cambios significativos
save(CVE-2024-12345) →
    └─ NO CHANGES - Skip version creation
```

### 3. Queries Comunes

```sql
-- Obtener última versión de un CVE
SELECT v.* FROM cve_versions v
JOIN cves c ON c.current_version_id = v.id
WHERE c.cve_id = 'CVE-2024-12345';

-- Historial completo de un CVE
SELECT version, cvss_score, severity, created_at
FROM cve_versions
WHERE cve_id = 'CVE-2024-12345'
ORDER BY version;

-- CVEs CRITICAL en CISA KEV (última versión)
SELECT v.* FROM cve_versions v
JOIN cves c ON c.current_version_id = v.id
WHERE v.severity = 'CRITICAL'
  AND v.is_in_cisa_kev = true;

-- CVEs actualizados en últimas 24h
SELECT v.* FROM cve_versions v
WHERE v.created_at >= NOW() - INTERVAL '24 hours'
  AND v.version > 1  -- Solo updates, no v1
ORDER BY v.created_at DESC;
```

---

## 🐛 Troubleshooting

### Problema: Scraper no se conecta a NIST

**Síntomas:**

```
ERROR: Failed to fetch CVEs: Connection refused
```

**Solución:**

```bash
# 1. Verificar configuración
make -f Makefile.scraper check

# 2. Verificar API key (si tienes una)
grep NIST_API_KEY .env

# 3. Test manual
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-12345"
```

---

### Problema: PostgreSQL no inicia

**Síntomas:**

```
ERROR: Connection to database failed
```

**Solución:**

```bash
# 1. Ver logs de PostgreSQL
docker logs postgres

# 2. Verificar que esté corriendo
make -f Makefile.scraper ps

# 3. Reiniciar
docker-compose -f docker-compose.scraper.yml restart postgres

# 4. Si falla, recrear volumen
make -f Makefile.scraper clean
make -f Makefile.scraper db-up
make -f Makefile.scraper db-seed
```

---

### Problema: Rate Limit Exceeded

**Síntomas:**

```
WARNING: Rate limit exceeded, waiting 6s
```

**Solución:**

```bash
# Obtener NIST API key (50 req/30s en vez de 5 req/30s)
# https://nvd.nist.gov/developers/request-an-api-key

# Editar .env
NIST_API_KEY=<tu-key>
NIST_RATE_LIMIT_DELAY=0.6

# Reiniciar scraper
make -f Makefile.scraper restart
```

---

### Problema: Kafka no recibe mensajes

**Síntomas:**

```
INFO: Published CVE-2024-12345 to Kafka
# Pero no aparece en Kafka UI
```

**Solución:**

```bash
# 1. Verificar Kafka está corriendo
make -f Makefile.scraper ps

# 2. Ver Kafka UI
http://localhost:8080

# 3. Ver logs de Kafka
docker logs kafka

# 4. Verificar topic existe
docker exec -it kafka kafka-topics --bootstrap-server localhost:9092 --list
```

---

### Problema: Migraciones Alembic fallan

**Síntomas:**

```
ERROR: Can't locate revision identified by '...'
```

**Solución:**

```bash
# 1. Ver estado actual
make -f Makefile.scraper db-status

# 2. Ver historial
cd shared/database/migrations && alembic history

# 3. Si está corrupto, resetear
make -f Makefile.scraper db-reset

# 4. O manualmente
docker exec -it postgres psql -U soc_user -d soc_alerting -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
make -f Makefile.scraper db-seed
```

---

## 📊 Monitoreo

### Verificar Salud del Sistema

```bash
# 1. Estado de servicios
make -f Makefile.scraper ps

# 2. Logs recientes
make -f Makefile.scraper logs | tail -100

# 3. Estadísticas de BD
make -f Makefile.scraper db-shell
# Luego en psql:
SELECT COUNT(*) FROM cves;
SELECT severity, COUNT(*) FROM cve_versions
  JOIN cves ON cves.current_version_id = cve_versions.id
  GROUP BY severity;
```

### Métricas Importantes

- **CVEs totales**: `SELECT COUNT(*) FROM cves`
- **Versiones totales**: `SELECT COUNT(*) FROM cve_versions`
- **CISA KEV**: `SELECT COUNT(*) FROM cve_versions WHERE is_in_cisa_kev = true`
- **Últimas 24h**: `SELECT COUNT(*) FROM cves WHERE first_seen >= NOW() - INTERVAL '24 hours'`

---

## 📖 Documentación Adicional

- [IMPLEMENTATION_COMPLETE.md](IMPLEMENTATION_COMPLETE.md) - Estado de implementación del modelo versionado
- [EXAMPLES_VERSIONED_MODEL.md](EXAMPLES_VERSIONED_MODEL.md) - 10 ejemplos de uso del repositorio
- [MIGRATION_PLAN.md](MIGRATION_PLAN.md) - Plan de migración de BD existente

---

## 🤝 Contribuir

1. Fork el proyecto
2. Crear feature branch (`git checkout -b feature/nueva-funcionalidad`)
3. Commit cambios (`git commit -m 'feat: añadir nueva funcionalidad'`)
4. Push a branch (`git push origin feature/nueva-funcionalidad`)
5. Abrir Pull Request

---

## 📝 Licencia

[MIT License](LICENSE)

---

## 👥 Autores

- **SOC Team** - Initial work

---

## 🙏 Agradecimientos

- [NIST NVD](https://nvd.nist.gov/) - CVE data source
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - Known Exploited Vulnerabilities
