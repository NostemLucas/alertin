# Integración del Pipeline NLP - Guía de Uso

## 📋 Resumen

El pipeline NLP está completamente implementado y listo para usar. Esta guía muestra cómo integrarlo en tu flujo de procesamiento de CVEs.

---

## 🔧 Componentes Implementados

### 1. **Servicios NLP** (`src/soc_alerting/services/nlp/`)
- ✅ `translator.py` - Traducción EN→ES con Helsinki-NLP/opus-mt-en-es
- ✅ `entity_extractor.py` - Extracción de entidades con dslim/bert-base-NER
- ✅ `keyword_extractor.py` - Extracción de keywords técnicas y análisis de ataque
- ✅ `pipeline.py` - Pipeline coordinador de todos los componentes

### 2. **Servicio de Enriquecimiento** (`src/soc_alerting/services/enrichment_service.py`)
- ✅ `EnrichmentService` - Servicio principal para enriquecer CVEs
- ✅ Integración con base de datos
- ✅ Threshold de severidad configurable
- ✅ Batch enrichment

### 3. **Base de Datos**
- ✅ Modelo actualizado (`CVEEnrichmentRecord`) con 20+ campos NLP
- ✅ Migración Alembic (`002_add_nlp_enrichment_fields.py`)

---

## 🚀 Uso Básico

### Opción 1: Enriquecer un CVE individual

```python
from sqlalchemy.ext.asyncio import AsyncSession
from soc_alerting.services.enrichment_service import EnrichmentService
from soc_alerting.models.domain import CVE
from soc_alerting.database.connection import get_database

# Crear servicio de enriquecimiento
enrichment_service = EnrichmentService(
    enable_translation=True,
    enable_ner=True,
    enable_keywords=True,
    device="cpu",  # o "cuda" para GPU
    enrich_severity_threshold="LOW"  # Enriquecer CVEs >= LOW
)

# Obtener sesión de base de datos
db = get_database()

async with db.get_session() as session:
    # Tu CVE ya procesado
    cve = CVE(...)  # CVE del pipeline NIST/CISA

    # Enriquecer con NLP
    enrichment_record = await enrichment_service.enrich_cve(
        session=session,
        cve=cve,
        force=False  # Respetar threshold de severidad
    )

    if enrichment_record:
        print(f"✅ CVE enriquecido: {cve.cve_id}")
        print(f"   Traducción: {enrichment_record.description_es[:100]}...")
        print(f"   Tipo de ataque: {enrichment_record.attack_type}")
        print(f"   Keywords: {enrichment_record.technical_keywords[:5]}")
```

### Opción 2: Enriquecimiento en Batch

```python
async with db.get_session() as session:
    # Lista de CVEs procesados
    cves = [cve1, cve2, cve3, ...]  # CVEs del pipeline

    # Enriquecer todos
    stats = await enrichment_service.batch_enrich(
        session=session,
        cves=cves,
        force=False
    )

    print(f"Enriquecidos: {stats['enriched']}")
    print(f"Omitidos: {stats['skipped']}")
    print(f"Tiempo total: {stats['total_time_ms']}ms")
```

### Opción 3: Solo Traducción (Sin NER/Keywords)

```python
# Servicio solo con traducción (más rápido, menos recursos)
translation_only = EnrichmentService(
    enable_translation=True,
    enable_ner=False,
    enable_keywords=False,
    device="cpu"
)

async with db.get_session() as session:
    enrichment = await translation_only.enrich_cve(session, cve)
    print(enrichment.description_es)
```

---

## 🔗 Integración con CVEProcessor

### Modificar `process_cve_list()` para incluir NLP

```python
# En src/soc_alerting/services/cve_processor.py

from .enrichment_service import create_enrichment_service_from_settings

class CVEProcessor:
    def __init__(self):
        self.nist_client: Optional[NISTClient] = None
        self.cisa_client: Optional[CISAClient] = None
        # NUEVO: Servicio de enriquecimiento NLP
        self.enrichment_service = create_enrichment_service_from_settings()

    async def process_cve_list(self, nist_vulnerabilities: list, session: AsyncSession) -> dict:
        """Process CVEs with NLP enrichment."""

        stats = {
            # ... stats existentes ...
            "cves_enriched": 0,  # NUEVO
        }

        # ... procesamiento NIST/CISA existente ...

        # NUEVO: Enriquecimiento NLP
        cves_to_enrich = []

        for nist_vuln in nist_vulnerabilities:
            try:
                # ... conversión a domain model ...
                cve = self.nist_client.convert_to_domain_model(nist_vuln, ...)

                # ... enrichment con CISA ...
                if is_in_kev:
                    cve = await self.cisa_client.enrich_cve_with_kev_data(cve)

                # ... guardado en BD ...
                # (aquí deberías usar session async en lugar de context manager)

                # Agregar a lista para enriquecimiento NLP
                cves_to_enrich.append(cve)

            except Exception as e:
                logger.error(f"Error processing CVE: {e}")

        # NUEVO: Batch NLP enrichment
        if cves_to_enrich:
            nlp_stats = await self.enrichment_service.batch_enrich(
                session=session,
                cves=cves_to_enrich
            )
            stats["cves_enriched"] = nlp_stats["enriched"]

        return stats
```

---

## ⚙️ Configuración

### Agregar a `config/settings.py`

```python
class Settings(BaseSettings):
    # ... configuración existente ...

    # NLP Enrichment Configuration
    nlp_enable_translation: bool = Field(
        default=True,
        description="Enable EN→ES translation"
    )
    nlp_enable_ner: bool = Field(
        default=True,
        description="Enable Named Entity Recognition"
    )
    nlp_enable_keywords: bool = Field(
        default=True,
        description="Enable keyword extraction"
    )
    nlp_device: str = Field(
        default="cpu",
        description="Device for NLP models: 'cpu' or 'cuda'"
    )
    enrich_severity_threshold: str = Field(
        default="LOW",
        description="Minimum severity to enrich: NONE/LOW/MEDIUM/HIGH"
    )
```

### Variables de Entorno (.env)

```bash
# NLP Configuration
NLP_ENABLE_TRANSLATION=true
NLP_ENABLE_NER=true
NLP_ENABLE_KEYWORDS=true
NLP_DEVICE=cpu  # Cambiar a 'cuda' si tienes GPU
ENRICH_SEVERITY_THRESHOLD=LOW  # NONE/LOW/MEDIUM/HIGH/CRITICAL
```

---

## 🗄️ Migración de Base de Datos

### Ejecutar Migración

```bash
# Aplicar migración para nuevos campos NLP
cd src/soc_alerting/database/migrations
alembic upgrade head

# Verificar que la migración se aplicó
alembic current

# Debería mostrar: 002_add_nlp_enrichment_fields (head)
```

### Reverter Migración (si es necesario)

```bash
# Volver a versión anterior
alembic downgrade -1

# O especificar revisión
alembic downgrade 001_add_scalability_tables
```

---

## 📊 Consultar Datos Enriquecidos

### Ejemplo SQL: Ver CVEs Traducidos

```sql
SELECT
    cve_id,
    LEFT(description_es, 100) AS resumen_es,
    translation_confidence,
    attack_type,
    attack_complexity
FROM cve_enrichments
WHERE description_es IS NOT NULL
ORDER BY enriched_at DESC
LIMIT 10;
```

### Ejemplo SQL: Buscar por Tipo de Ataque

```sql
SELECT
    e.cve_id,
    e.attack_type,
    e.attack_complexity,
    e.requires_authentication,
    c.final_severity
FROM cve_enrichments e
JOIN cves c ON e.cve_id = c.cve_id
WHERE e.attack_type = 'Remote Code Execution'
  AND e.requires_authentication = false
ORDER BY c.cvss_v3_score DESC;
```

### Ejemplo SQL: Keywords Más Comunes

```sql
SELECT
    keyword->>'keyword' AS keyword,
    COUNT(*) AS frequency
FROM cve_enrichments,
     LATERAL jsonb_array_elements(technical_keywords) AS keyword
WHERE technical_keywords IS NOT NULL
GROUP BY keyword->>'keyword'
ORDER BY frequency DESC
LIMIT 20;
```

---

## 🔍 Ejemplo Completo: Pipeline End-to-End

```python
import asyncio
from datetime import datetime, timedelta
from soc_alerting.clients.nist_client import NISTClient
from soc_alerting.clients.cisa_client import CISAClient
from soc_alerting.services.enrichment_service import EnrichmentService
from soc_alerting.database.connection import get_database
from soc_alerting.database.repositories.cve_repository import CVERepository

async def process_and_enrich_recent_cves():
    """
    Pipeline completo: NIST → CISA → Database → NLP Enrichment
    """
    # 1. Inicializar clientes y servicios
    nist_client = NISTClient()
    cisa_client = CISAClient()
    enrichment_service = EnrichmentService(
        enable_translation=True,
        enable_ner=True,
        enable_keywords=True,
        device="cpu",
        enrich_severity_threshold="MEDIUM"  # Solo >= MEDIUM
    )

    db = get_database()

    async with nist_client, cisa_client:
        # 2. Fetch CVEs de NIST (últimas 24 horas)
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(hours=24)

        nist_vulns = await nist_client.fetch_cves_by_modified_date(
            start_date=start_date,
            end_date=end_date,
            max_results=100
        )

        print(f"📥 Fetched {len(nist_vulns)} CVEs from NIST")

        # 3. Fetch CISA KEV catalog
        kev_catalog = await cisa_client.fetch_kev_catalog()
        kev_ids = kev_catalog.get_cve_ids()
        print(f"🔐 CISA KEV catalog: {len(kev_ids)} CVEs")

        # 4. Procesar CVEs
        cves_processed = []

        async with db.get_session() as session:
            for nist_vuln in nist_vulns:
                try:
                    # Convertir a domain model
                    is_in_kev = nist_vuln.id in kev_ids
                    cve = nist_client.convert_to_domain_model(
                        nist_vuln,
                        is_in_cisa_kev=is_in_kev
                    )

                    # Enriquecer con CISA si está en KEV
                    if is_in_kev:
                        cve = await cisa_client.enrich_cve_with_kev_data(cve)

                    # Guardar en BD (aquí deberías usar async repository)
                    # Por ahora, simplemente agregamos a la lista
                    cves_processed.append(cve)

                    print(f"✅ {cve.cve_id}: {cve.final_severity}")

                except Exception as e:
                    print(f"❌ Error processing {nist_vuln.id}: {e}")

            # 5. Enriquecimiento NLP en batch
            if cves_processed:
                print(f"\n🧠 Starting NLP enrichment for {len(cves_processed)} CVEs...")

                nlp_stats = await enrichment_service.batch_enrich(
                    session=session,
                    cves=cves_processed,
                    force=False
                )

                print(f"\n📊 NLP Enrichment Results:")
                print(f"   Enriched: {nlp_stats['enriched']}")
                print(f"   Skipped: {nlp_stats['skipped']}")
                print(f"   Failed: {nlp_stats['failed']}")
                print(f"   Total time: {nlp_stats['total_time_ms']}ms")
                print(f"   Avg per CVE: {nlp_stats['total_time_ms'] / max(nlp_stats['enriched'], 1):.0f}ms")

# Ejecutar
if __name__ == "__main__":
    asyncio.run(process_and_enrich_recent_cves())
```

---

## 📈 Performance y Recursos

### Tiempo de Procesamiento Esperado (CPU)

| Componente | Tiempo por CVE |
|------------|----------------|
| Traducción (Helsinki-NLP) | ~500-800ms |
| NER (BERT) | ~300-500ms |
| Keywords (regex) | ~5-10ms |
| **Total** | **~1-1.5s** |

### Uso de Memoria

| Componente | RAM |
|------------|-----|
| Translation model | ~300MB |
| NER model | ~400MB |
| **Total** | **~700MB** |

### Optimizaciones

1. **Lazy Loading**: Modelos se cargan solo cuando se usan
2. **Singleton Pattern**: Una sola instancia de cada modelo en memoria
3. **Batch Processing**: Procesar múltiples CVEs reduce overhead
4. **Threshold Filtering**: Solo enriquecer CVEs importantes (>= threshold)

---

## 🧪 Testing

### Test Manual con un CVE

```python
import asyncio
from soc_alerting.services.nlp import get_nlp_pipeline

async def test_nlp():
    pipeline = get_nlp_pipeline()

    result = pipeline.enrich_cve(
        cve_id="CVE-2021-44228",
        description_en=(
            "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security "
            "releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in "
            "configuration, log messages, and parameters do not protect "
            "against attacker controlled LDAP and other JNDI related endpoints."
        )
    )

    print("✅ Traducción:")
    print(result["translation"]["description_es"])
    print(f"\n✅ Entidades: {result['entities']['organizations']}")
    print(f"\n✅ Versiones: {result['entities']['versions']}")
    print(f"\n✅ Tipo de ataque: {result['attack_analysis']['attack_type']}")
    print(f"\n✅ Vectores: {result['keywords']['attack_vectors']}")
    print(f"\n✅ CIA Impact: {result['cia_impact']}")
    print(f"\n⏱️ Tiempo: {result['processing_time_ms']}ms")

asyncio.run(test_nlp())
```

---

## 🐛 Troubleshooting

### Problema: "Model not found"

```bash
# Descargar modelos manualmente
python -c "from transformers import MarianMTModel, MarianTokenizer; \
           MarianTokenizer.from_pretrained('Helsinki-NLP/opus-mt-en-es'); \
           MarianMTModel.from_pretrained('Helsinki-NLP/opus-mt-en-es')"

python -c "from transformers import AutoTokenizer, AutoModelForTokenClassification; \
           AutoTokenizer.from_pretrained('dslim/bert-base-NER'); \
           AutoModelForTokenClassification.from_pretrained('dslim/bert-base-NER')"
```

### Problema: "Out of Memory"

```python
# Usar solo componentes necesarios
enrichment_service = EnrichmentService(
    enable_translation=True,   # Mantener
    enable_ner=False,           # Desactivar (ahorra ~400MB)
    enable_keywords=True,       # Mantener (no usa ML)
    device="cpu"
)
```

### Problema: "Muy lento"

```python
# Aumentar threshold para procesar menos CVEs
enrichment_service = EnrichmentService(
    enrich_severity_threshold="HIGH"  # Solo HIGH y CRITICAL
)

# O usar GPU si está disponible
enrichment_service = EnrichmentService(
    device="cuda"  # 5-10x más rápido
)
```

---

## ✅ Verificación Post-Implementación

```bash
# 1. Verificar migración
docker exec soc-alerting-app alembic current

# 2. Verificar columnas en BD
docker exec soc-alerting-db psql -U postgres -d soc_alerting -c "\d cve_enrichments"

# 3. Test rápido de NLP
docker exec soc-alerting-app python -c "
from soc_alerting.services.nlp import get_nlp_pipeline
pipeline = get_nlp_pipeline()
result = pipeline.enrich_cve('TEST', 'Remote code execution vulnerability')
print('✅ NLP pipeline OK')
print(f'Attack type: {result[\"attack_analysis\"][\"attack_type\"]}')
"
```

---

## 📚 Próximos Pasos

1. ✅ **Migración aplicada**: `alembic upgrade head`
2. ⏭️ **Actualizar CVEProcessor**: Integrar `EnrichmentService`
3. ⏭️ **Testing**: Procesar CVEs reales y verificar resultados
4. ⏭️ **Dashboard**: Agregar endpoints API para consultar enrichments
5. ⏭️ **Monitoring**: Agregar métricas de NLP a processing_logs

---

¿Listo para probarlo? 🚀
