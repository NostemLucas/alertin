# Guía de Refactorización: De Imperativo a Declarativo

## Problema Identificado

El código actual usa Python de forma **imperativa** (bajo nivel) cuando debería ser **declarativo** (alto nivel).

### 🔴 Antipatrones Actuales

1. **Mapeo manual de campos**: 100 líneas de código moviendo datos campo por campo
2. **Diccionarios en lugar de modelos**: `dict[str, any]` sin validación
3. **Relaciones ignoradas**: Tienes `relationship()` pero no las usas
4. **Repositorios inflados**: 3 repositorios separados para guardar 1 CVE

---

## ✅ Solución: Código Declarativo

### 1. Modelos Pydantic en el Centro

#### ❌ ANTES (pipeline.py):
```python
async def enrich_cve(...) -> dict[str, any]:
    result = {
        "cve_id": cve_id,
        "translation": {
            "description_es": translation_result["translated_text"],  # KeyError posible
            "translation_confidence": translation_result["confidence"],  # Sin validación
        },
        "entities": None,  # Tipo any, sin estructura
        "errors": []
    }
    return result  # Diccionario ciego
```

**Problemas**:
- No hay autocompletado
- Errores de tipo en runtime
- No puedes hacer `result.translation.description_es` (solo `result["translation"]["description_es"]`)

#### ✅ DESPUÉS (con Pydantic):
```python
from pydantic import BaseModel, Field

class TranslationResult(BaseModel):
    description_es: str
    confidence: float = Field(ge=0.0, le=1.0)
    model: str

class EntityResult(BaseModel):
    organizations: list[str] = []
    versions: list[str] = []
    technical_terms: list[str] = []

class NLPEnrichmentResult(BaseModel):
    cve_id: str
    translation: Optional[TranslationResult] = None
    entities: Optional[EntityResult] = None
    processing_time_ms: int
    errors: list[str] = []

async def enrich_cve(...) -> NLPEnrichmentResult:
    # Pydantic valida automáticamente
    return NLPEnrichmentResult(
        cve_id=cve_id,
        translation=TranslationResult(
            description_es=translation_text,
            confidence=0.95,
            model="Helsinki-NLP/opus-mt-en-es"
        ),
        entities=EntityResult(organizations=["Apache", "Microsoft"]),
        processing_time_ms=1250
    )
```

**Beneficios**:
- ✅ Autocompletado: `result.translation.description_es`
- ✅ Validación automática: `confidence` debe estar entre 0.0-1.0
- ✅ Errores en desarrollo, no en producción
- ✅ Documentación automática con FastAPI

---

### 2. Usar Relationships de SQLAlchemy

#### ❌ ANTES (cve_repository.py):
```python
async def save_complete_cve(self, cve: CVE) -> CVERecord:
    # Paso 1: Guardar CVE principal
    cve_record = await self.create_or_update(cve)

    # Paso 2: Guardar CISA metadata MANUALMENTE
    if cve.is_in_cisa_kev:
        cisa_repo = CISAKEVRepository(self.session)
        await cisa_repo.upsert_cisa_metadata(cve)

    # Paso 3: Guardar referencias MANUALMENTE
    if cve.references:
        ref_repo = CVEReferenceRepository(self.session)
        await ref_repo.bulk_upsert_references(cve)

    return cve_record  # 3 repositorios, 50+ líneas
```

**Problemas**:
- Coordinación manual de 3 tablas
- Si falla el paso 2, tienes datos inconsistentes
- Código largo y frágil

#### ✅ DESPUÉS (usando relationships):
```python
async def save_complete_cve(self, cve: CVE) -> CVERecord:
    # Convertir modelo Pydantic a SQLAlchemy
    cve_record = CVERecord.from_pydantic(cve)

    # Las relaciones se guardan AUTOMÁTICAMENTE por cascade="all, delete-orphan"
    self.session.add(cve_record)
    await self.session.flush()

    return cve_record  # 4 líneas, 3 tablas actualizadas
```

**Cómo funciona**:
```python
# En database.py - CVERecord
class CVERecord(Base):
    cisa_kev_metadata = relationship(
        "CISAKEVMetadata",
        cascade="all, delete-orphan",  # SQLAlchemy guarda automáticamente
        lazy="selectin"
    )
    references = relationship(
        "CVEReference",
        cascade="all, delete-orphan"  # SQLAlchemy guarda automáticamente
    )
```

Cuando haces `session.add(cve_record)`, SQLAlchemy automáticamente:
1. Inserta en `cves`
2. Inserta en `cisa_kev_metadata` (si existe)
3. Inserta en `cve_references` (todos los items)

---

### 3. Conversión Automática Pydantic ↔ SQLAlchemy

#### ✅ SOLUCIÓN: Métodos de Clase

```python
# En database.py - CVERecord
class CVERecord(Base):
    __tablename__ = "cves"

    # ... columnas ...

    @classmethod
    def from_pydantic(cls, cve: CVE) -> "CVERecord":
        """Conversión automática de Pydantic a SQLAlchemy."""
        record = cls(
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

        # Relaciones automáticas
        if cve.is_in_cisa_kev:
            record.cisa_kev_metadata = CISAKEVMetadata.from_pydantic(cve)

        record.references = [
            CVEReference(url=url, source="NIST")
            for url in cve.references
        ]

        return record  # ¡Un solo objeto con TODO incluido!

    def to_pydantic(self) -> CVE:
        """Conversión de SQLAlchemy a Pydantic."""
        return CVE(
            cve_id=self.cve_id,
            description=self.description,
            # ... conversión automática ...
            # Relaciones se cargan automáticamente por lazy="selectin"
        )
```

**Uso**:
```python
# Guardar
cve_domain = CVE(cve_id="CVE-2024-1234", ...)
cve_record = CVERecord.from_pydantic(cve_domain)
session.add(cve_record)  # Guarda en 3 tablas automáticamente

# Leer
cve_record = await session.get(CVERecord, "CVE-2024-1234")
cve_domain = cve_record.to_pydantic()  # Conversión automática
```

---

### 4. Pipeline NLP Declarativo

#### ❌ ANTES:
```python
class NLPEnrichmentPipeline:
    def __init__(self, ...):
        self._translator = None  # Lazy-loading manual
        self._entity_extractor = None

    @property
    def translator(self):
        if self._translator is None:
            self._translator = get_translator(...)  # Carga síncrona
        return self._translator
```

#### ✅ DESPUÉS:
```python
from dataclasses import dataclass

@dataclass
class NLPPipeline:
    """Pipeline declarativo con dependencias inyectadas."""
    translator: CVETranslator
    entity_extractor: CVEEntityExtractor
    keyword_extractor: CVEKeywordExtractor

    async def enrich(self, cve: CVE) -> NLPEnrichmentResult:
        """Proceso simple y lineal."""
        translation = await self.translator.translate(cve.description)
        entities = await self.entity_extractor.extract(cve.description)
        keywords = self.keyword_extractor.extract(cve.description)

        return NLPEnrichmentResult(
            cve_id=cve.cve_id,
            translation=translation,
            entities=entities,
            keywords=keywords
        )

# Uso con dependency injection
def get_pipeline() -> NLPPipeline:
    return NLPPipeline(
        translator=get_translator(),
        entity_extractor=get_entity_extractor(),
        keyword_extractor=get_keyword_extractor()
    )
```

---

## 📊 Impacto de la Refactorización

| Métrica | Antes | Después | Mejora |
|---------|-------|---------|--------|
| Líneas en repositorio | 332 | ~50 | -85% |
| Repositorios necesarios | 3 | 1 | -67% |
| Validación de tipos | Runtime | Compile-time | ✅ |
| Autocompletado | ❌ | ✅ | ✅ |
| Transacciones manuales | 3 | 1 | ✅ |

---

## 🎯 Próximos Pasos

1. **Fase 1**: Crear modelos Pydantic para NLP (`src/soc_alerting/models/nlp.py`)
2. **Fase 2**: Agregar métodos `from_pydantic()` y `to_pydantic()` a modelos SQLAlchemy
3. **Fase 3**: Refactorizar `CVERepository.save_complete_cve()` usando relationships
4. **Fase 4**: Refactorizar `NLPEnrichmentPipeline` a clase declarativa
5. **Fase 5**: Eliminar repositorios redundantes (CISAKEVRepository, CVEReferenceRepository)

---

## 💡 La Mentalidad Correcta

### Imperativo (Manual):
```python
# Tú le dices a Python CÓMO hacer cada cosa
record = CVERecord()
record.cve_id = cve.cve_id
record.description = cve.description
# ... 50 líneas más ...

cisa_repo = CISAKEVRepository()
await cisa_repo.save(...)
```

### Declarativo (Automático):
```python
# Tú le dices a Python QUÉ quieres, él decide CÓMO
record = CVERecord.from_pydantic(cve)
session.add(record)  # SQLAlchemy hace el resto
```

**Este es el poder de Python moderno**: Pydantic + SQLAlchemy hacen el trabajo pesado por ti.
