# Mejoras en la Base de Datos y Modelos

## Resumen de Cambios

Se han realizado mejoras significativas en los modelos de base de datos y la capa de conexión para mejorar la robustez, mantenibilidad y funcionalidad del sistema.

---

## 1. Modelos de Base de Datos (`models/database.py`)

### 1.1 Relaciones SQLAlchemy

**Añadidas relaciones bidireccionales** entre todos los modelos para facilitar la navegación:

```python
# En CVERecord
cisa_kev_metadata: Optional["CISAKEVMetadata"] = relationship(
    "CISAKEVMetadata",
    back_populates="cve",
    uselist=False,
    cascade="all, delete-orphan",
    lazy="selectin"  # Async-friendly eager loading
)
affected_products: List["AffectedProduct"] = relationship(...)
references: List["CVEReference"] = relationship(...)
enrichments: List["CVEEnrichmentRecord"] = relationship(...)
update_history: List["CVEUpdateHistory"] = relationship(...)
```

**Beneficios:**
- Acceso fácil a datos relacionados: `cve.cisa_kev_metadata.is_overdue`
- Cascade delete automático
- Lazy loading optimizado para async (selectin)

---

### 1.2 Validaciones de Datos

**Añadidos decoradores `@validates` y `CheckConstraint`:**

```python
# CVERecord
@validates('cvss_v3_score', 'cvss_v2_score')
def validate_cvss_score(self, key: str, value: Optional[float]) -> Optional[float]:
    """Validate CVSS score is in valid range."""
    if value is not None and (value < 0 or value > 10):
        raise ValueError(f"{key} must be between 0 and 10, got {value}")
    return value

__table_args__ = (
    CheckConstraint("cvss_v3_score IS NULL OR (cvss_v3_score >= 0 AND cvss_v3_score <= 10)"),
    CheckConstraint("severity_nist IN ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')"),
)
```

**Beneficios:**
- Validación a nivel de aplicación y base de datos
- Prevención de datos corruptos
- Mensajes de error claros

---

### 1.3 Propiedades Computadas

**Añadidas propiedades útiles para cada modelo:**

#### CVERecord:
```python
@property
def has_high_severity(self) -> bool:
    """Check if CVE is HIGH or CRITICAL severity."""
    return self.final_severity in ("HIGH", "CRITICAL")

@property
def is_recent(self, days: int = 30) -> bool:
    """Check if CVE was published recently."""
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(days=days)
    return self.published_date >= cutoff

@property
def latest_enrichment(self) -> Optional["CVEEnrichmentRecord"]:
    """Get most recent enrichment record."""
    return self.enrichments[0] if self.enrichments else None
```

#### CISAKEVMetadata:
```python
@property
def is_overdue(self) -> bool:
    """Check if CISA action is overdue."""
    if self.action_due is None:
        return False
    return datetime.utcnow() > self.action_due

@property
def days_until_due(self) -> Optional[int]:
    """Calculate days until action due date."""
    if self.action_due is None:
        return None
    delta = self.action_due - datetime.utcnow()
    return delta.days
```

#### AffectedProduct:
```python
@property
def full_product_name(self) -> str:
    """Get human-readable product name."""
    parts = [self.vendor, self.product]
    if self.version and self.version != "*":
        parts.append(self.version)
    if self.edition:
        parts.append(f"({self.edition})")
    return " ".join(parts)

def matches_product(self, vendor: str, product: str, version: Optional[str] = None) -> bool:
    """Check if this affected product matches given vendor/product/version."""
    # Implementación de matching
```

#### CVEReference:
```python
@property
def is_exploit(self) -> bool:
    """Check if reference is an exploit."""
    if self.reference_type and "exploit" in self.reference_type.lower():
        return True
    if self.tags:
        return any("exploit" in str(tag).lower() for tag in self.tags)
    return False

@property
def is_patch(self) -> bool:
    """Check if reference is a patch/fix."""
    # Similar implementation

@property
def is_vendor_advisory(self) -> bool:
    """Check if reference is a vendor advisory."""
    # Similar implementation
```

#### CVEEnrichmentRecord:
```python
@property
def is_high_confidence(self) -> bool:
    """Check if prediction has high confidence (>= 0.8)."""
    return self.severity_confidence >= 0.8

@property
def age_hours(self) -> float:
    """Get age of enrichment in hours."""
    delta = datetime.utcnow() - self.enriched_at
    return delta.total_seconds() / 3600

@property
def is_stale(self, max_age_days: int = 30) -> bool:
    """Check if enrichment is stale."""
    return self.age_hours > (max_age_days * 24)
```

#### CVEUpdateHistory:
```python
@property
def has_critical_changes(self) -> bool:
    """Check if update contains critical changes."""
    return self.severity_changed or self.added_to_cisa_kev

@property
def change_count(self) -> int:
    """Count number of fields that changed."""
    if not self.changes_summary:
        return 0
    return len(self.changes_summary)
```

#### ProcessingLog:
```python
@property
def duration_seconds(self) -> Optional[float]:
    """Calculate processing duration in seconds."""

@property
def processing_rate(self) -> Optional[float]:
    """Calculate CVEs processed per minute."""

@property
def new_cve_percentage(self) -> float:
    """Calculate percentage of new CVEs."""

@property
def update_percentage(self) -> float:
    """Calculate percentage of updated CVEs."""
```

---

### 1.4 Métodos to_dict()

**Añadido método `to_dict()` a cada modelo** para facilitar la serialización API:

```python
def to_dict(self) -> Dict[str, Any]:
    """Convert record to dictionary for API responses."""
    return {
        "cve_id": self.cve_id,
        "description": self.description,
        "published_date": self.published_date.isoformat() if self.published_date else None,
        "cvss_v3_score": self.cvss_v3_score,
        "severity_nist": self.severity_nist,
        "is_in_cisa_kev": self.is_in_cisa_kev,
        "final_severity": self.final_severity,
        # ... más campos
    }
```

**Beneficios:**
- Conversión fácil a JSON para API
- Manejo consistente de fechas (ISO format)
- Control sobre qué campos exponer

---

### 1.5 Mejores __repr__()

**Mejorados los métodos `__repr__()` para debugging:**

```python
# CVERecord
def __repr__(self):
    return f"<CVERecord(cve_id='{self.cve_id}', severity='{self.final_severity}', kev={self.is_in_cisa_kev})>"

# CVEUpdateHistory
def __repr__(self):
    flags = []
    if self.severity_changed:
        flags.append("severity")
    if self.added_to_cisa_kev:
        flags.append("KEV")
    changes_str = f", changes=[{','.join(flags)}]" if flags else ""
    return f"<CVEUpdateHistory(cve_id='{self.cve_id}', detected='{self.detected_at}'{changes_str})>"

# ProcessingLog
def __repr__(self):
    duration = f", duration={self.duration_minutes:.1f}m" if self.duration_minutes else ""
    return f"<ProcessingLog(status='{self.status}', processed={self.cves_processed}{duration})>"
```

---

## 2. Capa de Conexión (`database/connection.py`)

### 2.1 Pool de Conexiones Avanzado

**Configuración mejorada del pool:**

```python
self.engine = create_async_engine(
    self.database_url,
    poolclass=AsyncAdaptedQueuePool,
    pool_size=settings.database_pool_size,
    max_overflow=settings.database_max_overflow,
    pool_pre_ping=True,      # Test connections before using
    pool_recycle=3600,       # Recycle connections after 1 hour
    pool_timeout=30,         # Wait max 30s for connection
    echo=False,
    echo_pool=False,
    connect_args={
        "timeout": 60,
        "command_timeout": 60,
        "server_settings": {
            "application_name": "soc_alerting",
            "jit": "off",  # Disable JIT for better cold start
        }
    }
)
```

**Beneficios:**
- Reciclaje automático de conexiones stale
- Timeouts configurados para evitar hangs
- Pre-ping para detectar conexiones muertas
- Metadata de aplicación para monitoreo en PostgreSQL

---

### 2.2 Event Listeners para Monitoreo

**Añadidos listeners para el pool:**

```python
def _setup_pool_listeners(self):
    """Setup connection pool event listeners for monitoring."""

    @event.listens_for(self.engine.sync_engine.pool, "connect")
    def on_connect(dbapi_conn, connection_record):
        """Called when a new DB-API connection is created."""
        logger.debug("New database connection created")

    @event.listens_for(self.engine.sync_engine.pool, "checkout")
    def on_checkout(dbapi_conn, connection_record, connection_proxy):
        """Called when a connection is retrieved from the pool."""
        self._pool_stats["total_checkouts"] += 1
        self._pool_stats["current_checked_out"] += 1

    @event.listens_for(self.engine.sync_engine.pool, "checkin")
    def on_checkin(dbapi_conn, connection_record):
        """Called when a connection is returned to the pool."""
        self._pool_stats["total_checkins"] += 1
        self._pool_stats["current_checked_out"] -= 1
```

**Métricas recolectadas:**
- Total de checkouts/checkins
- Conexiones actualmente en uso
- Último error y timestamp
- Tamaño del pool y overflow

---

### 2.3 Gestión Mejorada de Sesiones

**Session manager con mejor manejo de errores:**

```python
@asynccontextmanager
async def get_session(self, auto_commit: bool = True) -> AsyncGenerator[AsyncSession, None]:
    """Get an async database session with automatic cleanup and error handling."""
    session = self.SessionLocal()
    try:
        yield session
        if auto_commit:
            await session.commit()
    except sa_exc.OperationalError as e:
        await session.rollback()
        self._pool_stats["last_error"] = str(e)
        logger.error(f"Database operational error: {e}", exc_info=True)
        raise
    except sa_exc.IntegrityError as e:
        await session.rollback()
        logger.error(f"Database integrity error: {e}", exc_info=True)
        raise
    except sa_exc.DataError as e:
        await session.rollback()
        logger.error(f"Database data error: {e}", exc_info=True)
        raise
    except Exception as e:
        await session.rollback()
        logger.error(f"Unexpected session error: {e}", exc_info=True)
        raise
    finally:
        await session.close()
```

**Beneficios:**
- Distinción entre tipos de errores
- Rollback automático en errores
- Logging detallado con stack traces
- Tracking de errores en métricas

---

### 2.4 Retry Logic

**Operaciones con reintentos automáticos:**

```python
async def execute_with_retry(
    self,
    operation,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    backoff_factor: float = 2.0
):
    """Execute a database operation with automatic retry on transient failures."""
    last_exception = None
    delay = retry_delay

    for attempt in range(max_retries + 1):
        try:
            async with self.get_session() as session:
                result = await operation(session)
                return result
        except (sa_exc.OperationalError, asyncio.TimeoutError) as e:
            last_exception = e
            if attempt < max_retries:
                logger.warning(
                    f"Database operation failed (attempt {attempt + 1}/{max_retries + 1}): {e}. "
                    f"Retrying in {delay}s..."
                )
                await asyncio.sleep(delay)
                delay *= backoff_factor
            else:
                raise
        except Exception as e:
            # Don't retry on non-transient errors
            logger.error(f"Non-retryable database error: {e}")
            raise
```

**Uso:**
```python
async def my_operation(session):
    result = await session.execute(select(CVERecord))
    return result.scalars().all()

cves = await db.execute_with_retry(my_operation)
```

**Beneficios:**
- Resiliente a errores transitorios (network glitches, deadlocks)
- Backoff exponencial para no sobrecargar la BD
- Solo reintenta errores recuperables

---

### 2.5 Health Checks Mejorados

**Health check con métricas detalladas:**

```python
async def health_check(self, detailed: bool = False) -> Dict[str, Any]:
    """Check database connectivity with optional detailed metrics."""
    start_time = datetime.utcnow()
    result = {
        "healthy": False,
        "latency_ms": None,
        "error": None,
        "timestamp": start_time.isoformat(),
    }

    try:
        async with self.get_session() as session:
            await session.execute(text("SELECT 1"))

        end_time = datetime.utcnow()
        latency = (end_time - start_time).total_seconds() * 1000

        result["healthy"] = True
        result["latency_ms"] = round(latency, 2)

        if detailed:
            result["pool_stats"] = self.get_pool_stats()
            result["database_url"] = self._get_safe_url()

        return result
    except Exception as e:
        result["error"] = str(e)
        result["error_type"] = type(e).__name__
        return result
```

**Verificación de tablas:**
```python
async def verify_tables_exist(self) -> Dict[str, bool]:
    """Verify that all required tables exist in the database."""
    tables = ["cves", "cisa_kev_metadata", "affected_products", ...]

    result = {}
    async with self.get_session() as session:
        for table in tables:
            query = text(
                f"SELECT EXISTS (SELECT FROM information_schema.tables "
                f"WHERE table_name = '{table}')"
            )
            res = await session.execute(query)
            result[table] = bool(res.scalar())

    return result
```

---

## 3. Mejoras en Tipos

**Añadidos type hints completos:**

```python
from typing import Optional, List, Dict, Any

# En todos los métodos
def to_dict(self) -> Dict[str, Any]:
    ...

@property
def latest_enrichment(self) -> Optional["CVEEnrichmentRecord"]:
    ...

def matches_product(self, vendor: str, product: str, version: Optional[str] = None) -> bool:
    ...
```

**Beneficios:**
- Mejor autocompletado en IDEs
- Type checking con mypy
- Documentación clara de interfaces

---

## 4. Resumen de Beneficios

### 4.1 Robustez
- ✅ Validación de datos a nivel de aplicación y BD
- ✅ Retry logic para errores transitorios
- ✅ Manejo detallado de excepciones
- ✅ Pool de conexiones con timeouts

### 4.2 Mantenibilidad
- ✅ Relaciones SQLAlchemy para navegación fácil
- ✅ Propiedades computadas reutilizables
- ✅ Métodos to_dict() para serialización
- ✅ Type hints completos

### 4.3 Monitoreo
- ✅ Pool event listeners
- ✅ Métricas de conexión
- ✅ Health checks detallados
- ✅ Logging estructurado

### 4.4 Performance
- ✅ Lazy loading optimizado (selectin)
- ✅ Pool recycle automático
- ✅ Pre-ping para detectar conexiones muertas
- ✅ Índices adicionales

---

## 5. Ejemplos de Uso

### 5.1 Usando Relaciones

```python
# Antes (sin relaciones)
cisa_repo = CISAKEVRepository(session)
cisa_data = await cisa_repo.get_by_cve_id(cve.cve_id)

# Ahora (con relaciones)
if cve.cisa_kev_metadata and cve.cisa_kev_metadata.is_overdue:
    logger.warning(f"CVE {cve.cve_id} action is overdue!")
```

### 5.2 Usando Propiedades Computadas

```python
# Antes
if cve.final_severity in ("HIGH", "CRITICAL"):
    # process high severity

# Ahora
if cve.has_high_severity:
    # process high severity

# Antes
for ref in cve.references:
    if ref.reference_type and "exploit" in ref.reference_type.lower():
        exploits.append(ref)

# Ahora
exploits = [ref for ref in cve.references if ref.is_exploit]
```

### 5.3 Usando Retry Logic

```python
# Operación crítica con reintentos
async def update_critical_cve(session):
    cve = await session.get(CVERecord, "CVE-2024-12345")
    cve.final_severity = "CRITICAL"
    await session.flush()
    return cve

cve = await db.execute_with_retry(update_critical_cve, max_retries=5)
```

### 5.4 Health Check en API

```python
@app.get("/health")
async def health_endpoint(detailed: bool = False):
    health = await db.health_check(detailed=detailed)
    status_code = 200 if health["healthy"] else 503
    return JSONResponse(content=health, status_code=status_code)
```

---

## 6. Próximos Pasos

### 6.1 Testing
- [ ] Tests unitarios para nuevas propiedades
- [ ] Tests de integración para retry logic
- [ ] Tests de pool exhaustion

### 6.2 Documentación
- [x] Este documento de mejoras
- [ ] Actualizar README con ejemplos
- [ ] API docs con Swagger

### 6.3 Monitoreo
- [ ] Exportar métricas de pool a Prometheus
- [ ] Dashboard de Grafana para pool stats
- [ ] Alertas para health check failures

---

## 7. Compatibilidad

**Todos los cambios son backward-compatible:**
- ✅ Las APIs existentes siguen funcionando
- ✅ Los repositorios existentes no requieren cambios
- ✅ Las migraciones Alembic son compatibles

**Opcional:** Para aprovechar las nuevas features:
- Usar `eager loading` con relationships: `selectinload(CVERecord.cisa_kev_metadata)`
- Llamar a `to_dict()` en lugar de serialización manual
- Usar `execute_with_retry()` para operaciones críticas
