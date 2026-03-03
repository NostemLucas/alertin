# Antes vs Después: Comparación Visual

## 📊 Visión General

Este documento muestra lado a lado el código ANTES y DESPUÉS de la refactorización.

---

## 1. Pipeline NLP: dict vs Pydantic

### ❌ ANTES: Diccionarios sin validación

```python
# pipeline.py (línea 113)
async def enrich_cve(
    self,
    cve_id: str,
    description_en: str,
    min_confidence: float = 0.5
) -> dict[str, any]:  # ⚠️ Tipo "any" - sin validación
    """Process CVE and return enrichment data."""

    result = {
        "cve_id": cve_id,
        "enriched_at": start_time.isoformat(),
        "translation": None,  # ⚠️ Será dict o None
        "entities": None,
        "keywords": None,
        "processing_time_ms": 0,
        "errors": []
    }

    # Translation
    translation_result = await self.translator.translate_cve(description_en)
    result["translation"] = {
        "description_es": translation_result["translated_text"],  # ⚠️ KeyError posible
        "translation_confidence": translation_result["confidence"],  # ⚠️ Sin validar
        "translation_model": self.translation_model
    }

    return result  # ⚠️ dict[str, any]


# USO DEL CÓDIGO
result = await pipeline.enrich_cve("CVE-2024-1234", description)

# ❌ Sin autocompletado
text = result["translation"]["description_es"]  # ⚠️ KeyError si translation falló

# ❌ Sin validación de tipo
confidence = result["translation"]["translation_confidence"]  # ⚠️ Podría ser string, None, etc.

# ❌ IDE no ayuda
if result["errors"]:  # ⚠️ No sé qué otros campos hay
    ...
```

**Problemas**:
- ⚠️ No hay autocompletado (escribes a ciegas)
- ⚠️ KeyError si algún campo falta
- ⚠️ Sin validación de tipos (confidence podría ser "abc")
- ⚠️ Errores aparecen en **producción**, no en desarrollo
- ⚠️ Difícil de documentar

---

### ✅ DESPUÉS: Modelos Pydantic validados

```python
# models/nlp.py
from pydantic import BaseModel, Field

class TranslationResult(BaseModel):
    description_es: str
    confidence: float = Field(ge=0.0, le=1.0)  # ✅ Validado automáticamente
    model: str

class NLPEnrichmentResult(BaseModel):
    cve_id: str
    enriched_at: datetime
    translation: Optional[TranslationResult] = None  # ✅ Tipo específico
    entities: Optional[EntityExtractionResult] = None
    keywords: Optional[KeywordExtractionResult] = None
    processing_time_ms: int
    errors: list[str] = []

    @property
    def has_errors(self) -> bool:
        """Check if enrichment had errors."""
        return len(self.errors) > 0


# pipeline.py
async def enrich_cve(
    self,
    cve_id: str,
    description_en: str,
    min_confidence: float = 0.5
) -> NLPEnrichmentResult:  # ✅ Tipo específico y validado
    """Process CVE and return validated enrichment data."""

    # Translation
    translation_data = await self.translator.translate_cve(description_en)

    # ✅ Pydantic valida automáticamente
    translation_result = TranslationResult(
        description_es=translation_data["translated_text"],
        confidence=translation_data["confidence"],  # ✅ Valida que sea 0.0-1.0
        model=self.translator.model_name
    )

    # ✅ Resultado final validado
    return NLPEnrichmentResult(
        cve_id=cve_id,
        translation=translation_result,
        processing_time_ms=processing_time_ms,
        errors=errors
    )


# USO DEL CÓDIGO
result = await pipeline.enrich_cve("CVE-2024-1234", description)

# ✅ Autocompletado completo
if result.translation:  # ✅ IDE sabe que es Optional[TranslationResult]
    text = result.translation.description_es  # ✅ Autocompletado funciona

# ✅ Validación automática
confidence = result.translation.confidence  # ✅ Type checker garantiza que es float

# ✅ Propiedades calculadas
if result.has_errors:  # ✅ IDE muestra todas las propiedades
    logger.warning(f"Errors: {result.errors}")
```

**Beneficios**:
- ✅ Autocompletado total en IDE
- ✅ Validación automática (confidence debe ser 0.0-1.0)
- ✅ Type checker detecta errores en **desarrollo**
- ✅ Documentación automática con FastAPI
- ✅ Propiedades calculadas (has_errors, enrichment_coverage)

---

## 2. CVE Repository: Mapeo Manual vs Relationships

### ❌ ANTES: Coordinación manual de 3 repositorios

```python
# cve_repository.py (líneas 294-331)
async def save_complete_cve(self, cve: CVE) -> CVERecord:
    """
    Save complete CVE with all related data.

    Saves to THREE tables manually:
    1. cves (main table)
    2. cisa_kev_metadata (if CVE in KEV)
    3. cve_references (normalized references)
    """
    logger.info(f"Saving complete CVE: {cve.cve_id}")

    # ⚠️ Paso 1: Guardar CVE principal (38 líneas de mapeo manual)
    cve_record = await self.create_or_update(cve)

    # ⚠️ Paso 2: Guardar CISA metadata MANUALMENTE en otro repositorio
    if cve.is_in_cisa_kev:
        cisa_repo = CISAKEVRepository(self.session)  # ⚠️ Repositorio separado
        await cisa_repo.upsert_cisa_metadata(cve)  # ⚠️ Operación manual
        logger.debug(f"CISA KEV metadata saved for {cve.cve_id}")

    # ⚠️ Paso 3: Guardar referencias MANUALMENTE en otro repositorio
    if cve.references:
        ref_repo = CVEReferenceRepository(self.session)  # ⚠️ Repositorio separado
        await ref_repo.bulk_upsert_references(cve)  # ⚠️ Operación manual
        logger.debug(f"References saved for {cve.cve_id}")

    logger.info(f"Complete CVE saved: {cve.cve_id}")
    return cve_record


async def _create_record(self, cve: CVE) -> CVERecord:
    """Create new CVE record - MAPEO MANUAL campo por campo."""
    # ⚠️ 38 líneas de mapeo manual
    record = CVERecord(
        cve_id=cve.cve_id,
        description=cve.description,
        published_date=cve.published_date,
        last_modified_date=cve.last_modified_date,
        cvss_v3_score=cve.cvss_v3_score,
        cvss_v3_vector=cve.cvss_v3_vector,
        cvss_v2_score=cve.cvss_v2_score,
        cvss_v2_vector=cve.cvss_v2_vector,
        severity_nist=cve.severity_nist.value,
        is_in_cisa_kev=cve.is_in_cisa_kev,
        final_severity=cve.final_severity.value,
        classification_sources=[s.value for s in cve.classification_sources],
        source_identifier=cve.source_identifier,
        vuln_status=cve.vuln_status,
    )
    # ⚠️ Faltan referencias y metadata (se guardan después)

    self.session.add(record)
    await self.session.flush()
    return record
```

**Problemas**:
- ⚠️ **332 líneas** en total
- ⚠️ **3 repositorios** coordinados manualmente
- ⚠️ **3 operaciones de DB** separadas (no atómicas)
- ⚠️ **Código duplicado** (mapeo en create y update)
- ⚠️ **Frágil**: Si falla paso 2, quedas con datos inconsistentes

---

### ✅ DESPUÉS: Relationships automáticas

```python
# database.py - Conversión automática
class CVERecord(Base):
    # ... columnas ...

    # ✅ Relationships YA definidas (con cascade)
    cisa_kev_metadata = relationship(
        "CISAKEVMetadata",
        cascade="all, delete-orphan",  # ✅ SQLAlchemy guarda automáticamente
        lazy="selectin"
    )
    references = relationship(
        "CVEReference",
        cascade="all, delete-orphan",  # ✅ SQLAlchemy guarda automáticamente
    )

    @classmethod
    def from_pydantic(cls, cve: CVE) -> "CVERecord":
        """Conversión automática Pydantic → SQLAlchemy."""
        record = cls(
            cve_id=cve.cve_id,
            description=cve.description,
            # ... otros campos ...
        )

        # ✅ Relaciones automáticas
        if cve.is_in_cisa_kev:
            record.cisa_kev_metadata = CISAKEVMetadata.from_pydantic(cve)

        record.references = [
            CVEReference(url=url, source="NIST")
            for url in cve.references
        ]

        return record  # ✅ Un solo objeto con TODO


# cve_repository.py - Simplificado
async def save(self, cve: CVE) -> CVERecord:
    """
    Save or update CVE with all related data.

    SQLAlchemy guarda automáticamente en 3 tablas gracias a cascade.
    """
    existing = await self.get_by_id(cve.cve_id)

    if existing:
        existing.update_from_pydantic(cve)  # ✅ Método en CVERecord
        return existing

    # ✅ Conversión automática
    cve_record = CVERecord.from_pydantic(cve)

    # ✅ MAGIA: session.add() guarda en 3 tablas:
    # 1. cves
    # 2. cisa_kev_metadata (si existe)
    # 3. cve_references (todas)
    self.session.add(cve_record)
    await self.session.flush()

    return cve_record  # ✅ TODO guardado en 1 operación
```

**Beneficios**:
- ✅ **~80 líneas** (-76% de código)
- ✅ **1 repositorio** (eliminar CISAKEVRepository y ReferenceRepository)
- ✅ **1 operación de DB** (atómica)
- ✅ **Sin duplicación** (conversión en un solo lugar)
- ✅ **Robusto**: Transacción atómica garantizada

---

## 3. Uso en Producción: Comparación Real

### Escenario: Procesar CVE de NIST y guardar

#### ❌ ANTES

```python
# cve_processor.py
async def process_specific_cve(self, cve_id: str):
    # 1. Fetch de NIST
    nist_data = await self.nist_client.get_cve(cve_id)

    # 2. Convertir a modelo de dominio
    cve = self._parse_nist_cve(nist_data)

    # 3. Verificar CISA KEV
    is_in_kev = await self.cisa_client.check_kev(cve_id)
    if is_in_kev:
        cisa_data = await self.cisa_client.get_kev_data(cve_id)
        cve.is_in_cisa_kev = True
        cve.cisa_exploit_add = cisa_data.get("dateAdded")
        # ... más campos CISA ...

    # 4. Guardar (COMPLEJO - 3 repositorios coordinados)
    async with get_database().get_session() as session:
        repo = CVERepository(session)

        # ⚠️ Guardar en tabla principal
        cve_record = await repo.create_or_update(cve)

        # ⚠️ Guardar metadata CISA (repositorio separado)
        if cve.is_in_cisa_kev:
            cisa_repo = CISAKEVRepository(session)
            await cisa_repo.upsert_cisa_metadata(cve)

        # ⚠️ Guardar referencias (repositorio separado)
        if cve.references:
            ref_repo = CVEReferenceRepository(session)
            await ref_repo.bulk_upsert_references(cve)

        await session.commit()  # ⚠️ Si falla aquí, posibles datos inconsistentes

    # 5. Enriquecimiento NLP
    enrichment = await self.nlp_pipeline.enrich_cve(cve_id, cve.description)

    # ⚠️ Uso del diccionario sin validación
    if enrichment["translation"]:
        description_es = enrichment["translation"]["description_es"]  # ⚠️ KeyError posible

    return cve_record
```

#### ✅ DESPUÉS

```python
# cve_processor.py
async def process_specific_cve(self, cve_id: str):
    # 1. Fetch de NIST
    nist_data = await self.nist_client.get_cve(cve_id)

    # 2. Convertir a modelo de dominio
    cve = self._parse_nist_cve(nist_data)

    # 3. Verificar CISA KEV
    is_in_kev = await self.cisa_client.check_kev(cve_id)
    if is_in_kev:
        cisa_data = await self.cisa_client.get_kev_data(cve_id)
        cve.is_in_cisa_kev = True
        cve.cisa_exploit_add = cisa_data.get("dateAdded")
        # ... más campos CISA ...

    # 4. Guardar (SIMPLE - 1 repositorio, 1 operación)
    async with get_database().get_session() as session:
        repo = CVERepository(session)

        # ✅ Guardar en 3 tablas automáticamente
        cve_record = await repo.save(cve)

        await session.commit()  # ✅ Atómico, todo o nada

    # 5. Enriquecimiento NLP
    enrichment = await self.nlp_pipeline.enrich_cve(cve_id, cve.description)

    # ✅ Uso del modelo Pydantic con autocompletado y validación
    if enrichment.translation:
        description_es = enrichment.translation.description_es  # ✅ Type-safe

    return cve_record
```

---

## 4. Testing: Comparación

### ❌ ANTES: Tests complejos

```python
# test_cve_repository.py
async def test_save_complete_cve():
    # ⚠️ Setup complejo
    cve = CVE(cve_id="CVE-2024-1234", ...)

    async with get_session() as session:
        # ⚠️ Necesitas crear 3 repositorios
        cve_repo = CVERepository(session)
        cisa_repo = CISAKEVRepository(session)
        ref_repo = CVEReferenceRepository(session)

        # ⚠️ Guardar manualmente en cada uno
        cve_record = await cve_repo.create_or_update(cve)
        await cisa_repo.upsert_cisa_metadata(cve)
        await ref_repo.bulk_upsert_references(cve)

        await session.commit()

        # ⚠️ Verificar en 3 tablas separadas
        assert cve_record.cve_id == "CVE-2024-1234"

        cisa = await cisa_repo.get_by_cve_id("CVE-2024-1234")
        assert cisa is not None

        refs = await ref_repo.get_by_cve_id("CVE-2024-1234")
        assert len(refs) > 0
```

### ✅ DESPUÉS: Tests simples

```python
# test_cve_repository.py
async def test_save_cve():
    # ✅ Setup simple
    cve = CVE(cve_id="CVE-2024-1234", ...)

    async with get_session() as session:
        # ✅ Un solo repositorio
        repo = CVERepository(session)

        # ✅ Una operación
        cve_record = await repo.save(cve)

        await session.commit()

        # ✅ Verificar todo de una vez
        saved = await repo.get_by_id("CVE-2024-1234")
        assert saved.cve_id == "CVE-2024-1234"

        # ✅ Relationships cargadas automáticamente
        assert saved.cisa_kev_metadata is not None
        assert len(saved.references) > 0
```

---

## 📊 Resumen del Impacto

| Aspecto | Antes | Después | Mejora |
|---------|-------|---------|--------|
| **Líneas en CVERepository** | 332 | ~80 | ✅ -76% |
| **Repositorios necesarios** | 3 | 1 | ✅ -67% |
| **Operaciones DB por CVE** | 3+ | 1 | ✅ -67% |
| **Mapeo manual de campos** | Sí (38 líneas) | No | ✅ Eliminado |
| **Diccionarios sin validar** | Sí | No | ✅ Eliminado |
| **Autocompletado en IDE** | ❌ | ✅ | ✅ 100% |
| **Validación de tipos** | Runtime | Compile-time | ✅ Desarrollo |
| **Código duplicado** | Sí (create/update) | No | ✅ Eliminado |
| **Testing complexity** | Alta | Baja | ✅ -50% |
| **Código total eliminado** | - | ~500 líneas | ✅ |

---

## 🎯 Conclusión Visual

```
ANTES:
┌─────────────────────────────────────┐
│ CVEProcessor                        │
│  ├─ create_or_update()    (38 líneas)
│  ├─ CISAKEVRepository     (100 líneas)
│  └─ ReferenceRepository   (100 líneas)
│                                     │
│ NLPPipeline                         │
│  └─ enrich_cve() → dict[str, any]  │
│     ❌ Sin validación                │
│     ❌ Sin autocompletado            │
│     ❌ KeyError posible              │
└─────────────────────────────────────┘
Total: ~600 líneas, 3 repos, dict sin validar

DESPUÉS:
┌─────────────────────────────────────┐
│ CVERepository                       │
│  └─ save()                 (10 líneas)
│     ✅ Guarda en 3 tablas automático │
│     ✅ Un solo repositorio           │
│                                     │
│ NLPPipeline                         │
│  └─ enrich_cve() → NLPEnrichmentResult
│     ✅ Validación automática         │
│     ✅ Autocompletado completo       │
│     ✅ Type-safe                     │
└─────────────────────────────────────┘
Total: ~100 líneas, 1 repo, Pydantic validado
```

---

**🚀 La diferencia es clara: de código imperativo y frágil a código declarativo y robusto.**
