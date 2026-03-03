# Plan de Enriquecimiento Avanzado con HuggingFace

## 🎯 Objetivo

Mejorar el enriquecimiento de CVEs con capacidades NLP avanzadas:
- ✅ **Traducción** automática (inglés → español)
- ✅ **Extracción de entidades** (productos, versiones, vectores de ataque)
- ✅ **Clasificación mejorada** de severidad
- ✅ **Resúmenes ejecutivos** en español
- ✅ **Análisis de impacto** detallado

---

## 📊 Arquitectura Propuesta

```
CVE (inglés)
    ↓
┌─────────────────────────────────────┐
│   Pipeline de Enriquecimiento       │
├─────────────────────────────────────┤
│ 1. Traducción (EN → ES)             │
│ 2. Extracción de Entidades (NER)    │
│ 3. Clasificación de Severidad       │
│ 4. Análisis de Vectores de Ataque   │
│ 5. Generación de Resumen            │
│ 6. Extracción de Keywords            │
└─────────────────────────────────────┘
    ↓
CVE Enriquecido (bilingüe + metadata)
```

---

## 🤖 Modelos HuggingFace Recomendados

### 1. **Traducción (EN → ES)**
```python
# Opción 1: Helsinki-NLP (Recomendado - más rápido)
model = "Helsinki-NLP/opus-mt-en-es"
# - Especializado en traducción
# - Modelo pequeño (~300MB)
# - Muy rápido en CPU

# Opción 2: Facebook NLLB (Más preciso pero más pesado)
model = "facebook/nllb-200-distilled-600M"
# - Traducción multilingual
# - Mejor calidad
# - Requiere más recursos
```

### 2. **NER (Named Entity Recognition) - Extracción de Entidades**
```python
# Para extraer: productos, versiones, CVEs relacionados
model = "dslim/bert-base-NER"
# Extrae: PERSON, ORG, LOC, MISC

# Específico para seguridad cibernética
model = "jackaduma/SecBERT"
# Entrenado en textos de seguridad
```

### 3. **Clasificación de Severidad Mejorada**
```python
# Actual
model = "PEASEC/CVE-BERT"
# Especializado en CVEs

# Adicional: Clasificación de tipo de ataque
model = "neuml/t5-small-txti"
# Para clasificar tipo de vulnerabilidad
```

### 4. **Generación de Resumen**
```python
# Resúmenes ejecutivos en español
model = "facebook/bart-large-cnn"  # Inglés
model = "ELiRF/BART-base-spanish"  # Español (recomendado)
# Genera resúmenes de 2-3 líneas
```

### 5. **Extracción de Keywords**
```python
# Keywords técnicas
model = "ml6team/keyphrase-extraction-distilbert-inspec"
# Extrae frases clave técnicas
```

---

## 💾 Nuevo Schema de Base de Datos

### Extensión de `cve_enrichments` table:

```sql
ALTER TABLE cve_enrichments ADD COLUMN IF NOT EXISTS
    -- Traducción
    description_es TEXT,
    summary_es TEXT,

    -- Entidades extraídas
    affected_products_ner JSONB,  -- [{name, version, vendor}]
    attack_vectors JSONB,          -- ["RCE", "SQL Injection", ...]
    cve_references_extracted JSONB, -- ["CVE-2024-1234", ...]

    -- Clasificaciones adicionales
    attack_type VARCHAR(100),      -- "Remote Code Execution"
    attack_complexity VARCHAR(50),  -- "LOW", "MEDIUM", "HIGH"
    requires_auth BOOLEAN,
    requires_user_interaction BOOLEAN,

    -- Keywords y contexto
    technical_keywords JSONB,      -- ["buffer overflow", "SQL injection"]
    affected_os JSONB,             -- ["Windows", "Linux"]
    affected_software JSONB,       -- ["Apache", "MySQL"]

    -- Confianza de traducción
    translation_confidence FLOAT,

    -- Metadata de procesamiento
    nlp_model_version VARCHAR(50),
    processing_time_ms INTEGER;
```

---

## 🔧 Implementación

### Estructura de Archivos

```
src/soc_alerting/services/
├── enrichment_service.py           # Actual (básico)
└── nlp/
    ├── __init__.py
    ├── base.py                     # Base NLP Service
    ├── translator.py               # Traducción EN→ES
    ├── entity_extractor.py         # NER para productos/versiones
    ├── classifier.py               # Clasificación de tipo/severidad
    ├── summarizer.py               # Generación de resúmenes
    ├── keyword_extractor.py        # Extracción de keywords
    └── pipeline.py                 # Orquestador del pipeline
```

---

## 📝 Código Propuesto

### 1. `nlp/translator.py` - Traducción

```python
from transformers import MarianMTModel, MarianTokenizer
import logging

logger = logging.getLogger(__name__)

class CVETranslator:
    """Traductor de descripciones de CVE (EN → ES)."""

    def __init__(self, model_name: str = "Helsinki-NLP/opus-mt-en-es"):
        self.model_name = model_name
        self.tokenizer = MarianTokenizer.from_pretrained(model_name)
        self.model = MarianMTModel.from_pretrained(model_name)
        logger.info(f"Translator loaded: {model_name}")

    def translate(self, text: str, max_length: int = 512) -> dict:
        """
        Traduce texto de inglés a español.

        Returns:
            {
                "translated_text": str,
                "confidence": float,
                "processing_time_ms": int
            }
        """
        import time
        start = time.time()

        # Truncar si es muy largo
        if len(text) > 3000:
            text = text[:3000] + "..."

        # Tokenizar
        inputs = self.tokenizer(text, return_tensors="pt", padding=True, truncation=True)

        # Traducir
        translated = self.model.generate(**inputs, max_length=max_length)
        translated_text = self.tokenizer.decode(translated[0], skip_special_tokens=True)

        elapsed_ms = int((time.time() - start) * 1000)

        # Calcular confidence (simplificado)
        confidence = min(1.0, len(translated_text) / max(len(text), 1))

        return {
            "translated_text": translated_text,
            "confidence": confidence,
            "processing_time_ms": elapsed_ms
        }

    def translate_cve(self, description: str) -> tuple[str, float]:
        """Traduce descripción de CVE, retorna (texto_es, confidence)."""
        result = self.translate(description)
        return result["translated_text"], result["confidence"]
```

### 2. `nlp/entity_extractor.py` - NER

```python
from transformers import pipeline
import re
import logging

logger = logging.getLogger(__name__)

class CVEEntityExtractor:
    """Extractor de entidades de CVEs (productos, versiones, vectores)."""

    def __init__(self):
        # NER general
        self.ner_pipeline = pipeline("ner", model="dslim/bert-base-NER", aggregation_strategy="simple")

        # Patrones regex para entidades específicas
        self.patterns = {
            "cve_ids": r"CVE-\d{4}-\d{4,}",
            "versions": r"\d+\.\d+\.?\d*\.?\d*",  # 2.14.1, 10.0, etc.
            "ip_addresses": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        }

        logger.info("Entity extractor initialized")

    def extract_entities(self, text: str) -> dict:
        """
        Extrae entidades del texto.

        Returns:
            {
                "products": ["Apache Log4j", "Windows"],
                "versions": ["2.14.1", "10.0"],
                "cve_references": ["CVE-2021-44228"],
                "organizations": ["Microsoft", "Apache"],
                "attack_vectors": ["Remote Code Execution", "SQL Injection"]
            }
        """
        entities = {
            "products": [],
            "versions": [],
            "cve_references": [],
            "organizations": [],
            "attack_vectors": []
        }

        # 1. Extraer con NER pipeline
        ner_results = self.ner_pipeline(text)
        for entity in ner_results:
            entity_type = entity["entity_group"]
            entity_text = entity["word"]

            if entity_type == "ORG":
                entities["organizations"].append(entity_text)
            elif entity_type == "MISC":
                # Productos suelen estar en MISC
                entities["products"].append(entity_text)

        # 2. Extraer con regex
        entities["cve_references"] = re.findall(self.patterns["cve_ids"], text)
        entities["versions"] = re.findall(self.patterns["versions"], text)

        # 3. Detectar vectores de ataque (keywords)
        attack_keywords = {
            "Remote Code Execution": ["remote code execution", "rce", "arbitrary code"],
            "SQL Injection": ["sql injection", "sqli"],
            "Cross-Site Scripting": ["xss", "cross-site scripting"],
            "Buffer Overflow": ["buffer overflow", "stack overflow"],
            "Privilege Escalation": ["privilege escalation", "escalate privileges"],
            "Denial of Service": ["denial of service", "dos", "crash"],
        }

        text_lower = text.lower()
        for attack_type, keywords in attack_keywords.items():
            if any(kw in text_lower for kw in keywords):
                entities["attack_vectors"].append(attack_type)

        # Deduplicar
        for key in entities:
            entities[key] = list(set(entities[key]))

        return entities

    def extract_product_info(self, text: str) -> list[dict]:
        """
        Extrae información estructurada de productos.

        Returns:
            [
                {
                    "name": "Apache Log4j",
                    "vendor": "Apache",
                    "versions": ["2.14.1", "2.15.0"]
                }
            ]
        """
        entities = self.extract_entities(text)

        # Combinar productos y vendors
        products = []
        for org in entities["organizations"]:
            for product in entities["products"]:
                if org.lower() in product.lower():
                    products.append({
                        "name": product,
                        "vendor": org,
                        "versions": entities["versions"][:3]  # Primeras 3
                    })

        return products
```

### 3. `nlp/classifier.py` - Clasificación Avanzada

```python
from transformers import pipeline
import logging

logger = logging.getLogger(__name__)

class CVEClassifier:
    """Clasificador de CVEs (tipo de ataque, complejidad, etc.)."""

    def __init__(self):
        # Clasificador de severidad (actual)
        self.severity_pipeline = pipeline(
            "text-classification",
            model="PEASEC/CVE-BERT"
        )

        logger.info("Classifier initialized")

    def classify_severity(self, description: str) -> dict:
        """
        Clasifica severidad con ML.

        Returns:
            {
                "severity": "CRITICAL",
                "confidence": 0.95
            }
        """
        result = self.severity_pipeline(description[:512])[0]
        return {
            "severity": result["label"].upper(),
            "confidence": result["score"]
        }

    def analyze_attack_characteristics(self, description: str) -> dict:
        """
        Analiza características del ataque.

        Returns:
            {
                "attack_complexity": "LOW" | "MEDIUM" | "HIGH",
                "requires_auth": bool,
                "requires_user_interaction": bool,
                "network_access": "LOCAL" | "ADJACENT" | "NETWORK"
            }
        """
        desc_lower = description.lower()

        # Detectar complejidad
        complexity = "MEDIUM"  # Default
        if any(kw in desc_lower for kw in ["no authentication", "unauthenticated", "remote"]):
            complexity = "LOW"
        elif any(kw in desc_lower for kw in ["requires privileges", "authenticated", "local access"]):
            complexity = "HIGH"

        # Requiere autenticación?
        requires_auth = any(kw in desc_lower for kw in [
            "authenticated", "requires login", "requires credentials"
        ])

        # Requiere interacción del usuario?
        requires_ui = any(kw in desc_lower for kw in [
            "user interaction", "user must", "victim must", "phishing"
        ])

        # Acceso de red
        if "remote" in desc_lower or "network" in desc_lower:
            network_access = "NETWORK"
        elif "local" in desc_lower:
            network_access = "LOCAL"
        else:
            network_access = "ADJACENT"

        return {
            "attack_complexity": complexity,
            "requires_auth": requires_auth,
            "requires_user_interaction": requires_ui,
            "network_access": network_access
        }
```

### 4. `nlp/summarizer.py` - Generación de Resúmenes

```python
from transformers import pipeline
import logging

logger = logging.getLogger(__name__)

class CVESummarizer:
    """Generador de resúmenes ejecutivos de CVEs."""

    def __init__(self):
        # Summarizer en inglés (primero)
        self.summarizer_en = pipeline("summarization", model="facebook/bart-large-cnn")

        logger.info("Summarizer initialized")

    def generate_summary(self, description: str, max_length: int = 100) -> str:
        """
        Genera resumen ejecutivo (2-3 líneas).

        Args:
            description: Descripción completa del CVE
            max_length: Longitud máxima del resumen

        Returns:
            Resumen ejecutivo
        """
        # Truncar si es muy largo
        if len(description) > 1024:
            description = description[:1024]

        # Generar resumen
        summary = self.summarizer_en(
            description,
            max_length=max_length,
            min_length=30,
            do_sample=False
        )[0]["summary_text"]

        return summary

    def generate_executive_summary_es(self, description_es: str, entities: dict) -> str:
        """
        Genera resumen ejecutivo en español con contexto.

        Returns:
            Resumen ejecutivo estructurado
        """
        # Template basado en entidades
        attack_vectors = ", ".join(entities.get("attack_vectors", ["N/A"]))
        products = ", ".join(entities.get("products", ["N/A"])[:3])

        summary = f"Vulnerabilidad que permite {attack_vectors.lower()}. "
        summary += f"Afecta a: {products}. "

        # Agregar primeras 150 caracteres de descripción
        summary += description_es[:150] + "..."

        return summary
```

### 5. `nlp/pipeline.py` - Orquestador

```python
import logging
from typing import Optional
from datetime import datetime

from .translator import CVETranslator
from .entity_extractor import CVEEntityExtractor
from .classifier import CVEClassifier
from .summarizer import CVESummarizer
from .keyword_extractor import CVEKeywordExtractor

logger = logging.getLogger(__name__)

class NLPEnrichmentPipeline:
    """
    Pipeline completo de enriquecimiento NLP.

    Procesa CVE en 6 pasos:
    1. Traducción EN→ES
    2. Extracción de entidades (NER)
    3. Clasificación de severidad
    4. Análisis de características
    5. Generación de resumen
    6. Extracción de keywords
    """

    def __init__(self, enable_translation: bool = True):
        self.enable_translation = enable_translation

        # Inicializar componentes
        self.translator = CVETranslator() if enable_translation else None
        self.entity_extractor = CVEEntityExtractor()
        self.classifier = CVEClassifier()
        self.summarizer = CVESummarizer()
        self.keyword_extractor = CVEKeywordExtractor()

        logger.info("NLP Pipeline initialized")

    def enrich_cve(self, cve_id: str, description_en: str) -> dict:
        """
        Enriquece un CVE con análisis NLP completo.

        Returns:
            {
                # Traducción
                "description_es": str,
                "summary_es": str,
                "translation_confidence": float,

                # Entidades
                "affected_products_ner": [...],
                "attack_vectors": [...],
                "cve_references_extracted": [...],

                # Clasificación
                "predicted_severity": str,
                "severity_confidence": float,
                "attack_type": str,
                "attack_complexity": str,
                "requires_auth": bool,
                "requires_user_interaction": bool,

                # Keywords
                "technical_keywords": [...],
                "affected_os": [...],
                "affected_software": [...],

                # Metadata
                "nlp_model_version": str,
                "processing_time_ms": int,
                "enriched_at": datetime
            }
        """
        import time
        start_time = time.time()

        enrichment = {
            "cve_id": cve_id,
            "enriched_at": datetime.utcnow()
        }

        logger.info(f"Starting NLP enrichment for {cve_id}")

        # 1. Traducción
        if self.enable_translation and self.translator:
            logger.debug(f"{cve_id}: Translating...")
            description_es, trans_conf = self.translator.translate_cve(description_en)
            enrichment["description_es"] = description_es
            enrichment["translation_confidence"] = trans_conf
        else:
            enrichment["description_es"] = None
            enrichment["translation_confidence"] = None

        # 2. Extracción de entidades
        logger.debug(f"{cve_id}: Extracting entities...")
        entities = self.entity_extractor.extract_entities(description_en)
        product_info = self.entity_extractor.extract_product_info(description_en)

        enrichment["attack_vectors"] = entities["attack_vectors"]
        enrichment["cve_references_extracted"] = entities["cve_references"]
        enrichment["affected_products_ner"] = product_info

        # 3. Clasificación de severidad
        logger.debug(f"{cve_id}: Classifying severity...")
        severity_result = self.classifier.classify_severity(description_en)
        enrichment["predicted_severity"] = severity_result["severity"]
        enrichment["severity_confidence"] = severity_result["confidence"]

        # 4. Análisis de características
        logger.debug(f"{cve_id}: Analyzing attack characteristics...")
        characteristics = self.classifier.analyze_attack_characteristics(description_en)
        enrichment.update(characteristics)
        enrichment["attack_type"] = entities["attack_vectors"][0] if entities["attack_vectors"] else "Unknown"

        # 5. Generación de resumen
        logger.debug(f"{cve_id}: Generating summary...")
        summary_en = self.summarizer.generate_summary(description_en)
        if enrichment["description_es"]:
            enrichment["summary_es"] = self.summarizer.generate_executive_summary_es(
                enrichment["description_es"], entities
            )
        else:
            enrichment["summary_es"] = summary_en

        # 6. Extracción de keywords
        logger.debug(f"{cve_id}: Extracting keywords...")
        keywords = self.keyword_extractor.extract_keywords(description_en)
        enrichment["technical_keywords"] = keywords["keywords"]
        enrichment["affected_os"] = keywords.get("os", [])
        enrichment["affected_software"] = keywords.get("software", [])

        # Metadata
        enrichment["nlp_model_version"] = "v2.0.0"
        enrichment["processing_time_ms"] = int((time.time() - start_time) * 1000)

        logger.info(f"{cve_id}: Enrichment completed in {enrichment['processing_time_ms']}ms")

        return enrichment
```

---

## 🚀 Integración con el Sistema Actual

### Actualizar `enrichment_service.py`

```python
from .nlp.pipeline import NLPEnrichmentPipeline

class EnrichmentService:
    """Servicio de enriquecimiento mejorado."""

    def __init__(self, enable_translation: bool = True):
        self.nlp_pipeline = NLPEnrichmentPipeline(enable_translation=enable_translation)

    async def enrich_cve(self, cve: CVE) -> CVEEnrichment:
        """Enriquece CVE con pipeline completo."""

        # Ejecutar pipeline NLP
        enrichment_data = self.nlp_pipeline.enrich_cve(
            cve_id=cve.cve_id,
            description_en=cve.description
        )

        # Crear modelo de dominio
        enrichment = CVEEnrichment(
            cve_id=cve.cve_id,
            enriched_at=enrichment_data["enriched_at"],

            # Datos actuales
            predicted_severity=enrichment_data["predicted_severity"],
            severity_confidence=enrichment_data["severity_confidence"],

            # Nuevos campos
            description_es=enrichment_data["description_es"],
            summary_es=enrichment_data["summary_es"],
            attack_vectors=enrichment_data["attack_vectors"],
            attack_type=enrichment_data["attack_type"],
            # ...
        )

        return enrichment
```

---

## 📦 Nuevas Dependencias

```txt
# Añadir a requirements.txt

# Traducción
transformers==4.37.2  # Ya existe
sentencepiece==0.1.99  # Ya existe

# Modelos específicos (se descargan automáticamente)
# Helsinki-NLP/opus-mt-en-es (~300MB)
# dslim/bert-base-NER (~400MB)
# facebook/bart-large-cnn (~1.6GB) - OPCIONAL
```

---

## 🎨 Ejemplo de Uso

### Input:
```json
{
  "cve_id": "CVE-2021-44228",
  "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled."
}
```

### Output:
```json
{
  "cve_id": "CVE-2021-44228",
  "description_es": "Apache Log4j2 2.0-beta9 hasta 2.15.0 (excluyendo lanzamientos de seguridad 2.12.2, 2.12.3 y 2.3.1) las funciones JNDI utilizadas en configuración, mensajes de registro y parámetros no protegen contra endpoints LDAP y otros relacionados con JNDI controlados por atacantes. Un atacante que puede controlar mensajes de registro o parámetros de mensajes puede ejecutar código arbitrario cargado desde servidores LDAP cuando la sustitución de búsqueda de mensajes está habilitada.",

  "summary_es": "Vulnerabilidad que permite remote code execution. Afecta a: Apache Log4j2. Permite ejecutar código arbitrario a través de endpoints JNDI maliciosos...",

  "translation_confidence": 0.92,

  "affected_products_ner": [
    {
      "name": "Apache Log4j2",
      "vendor": "Apache",
      "versions": ["2.0-beta9", "2.15.0", "2.12.2"]
    }
  ],

  "attack_vectors": ["Remote Code Execution"],
  "cve_references_extracted": ["CVE-2021-44228"],

  "predicted_severity": "CRITICAL",
  "severity_confidence": 0.98,

  "attack_type": "Remote Code Execution",
  "attack_complexity": "LOW",
  "requires_auth": false,
  "requires_user_interaction": false,
  "network_access": "NETWORK",

  "technical_keywords": [
    "JNDI injection",
    "LDAP",
    "Log4Shell",
    "arbitrary code execution",
    "message lookup substitution"
  ],

  "affected_os": [],
  "affected_software": ["Apache Log4j2"],

  "nlp_model_version": "v2.0.0",
  "processing_time_ms": 2345
}
```

---

## ⚡ Optimizaciones

### 1. **Cache de Modelos**
```python
# Cargar modelos una sola vez al inicio
# No recargarlos por cada CVE
```

### 2. **Procesamiento en Batch**
```python
# Procesar múltiples CVEs en un solo batch
enrichments = nlp_pipeline.enrich_batch(cves_list)
```

### 3. **Async Processing**
```python
# Procesar en background con asyncio
asyncio.create_task(enrich_cve_async(cve))
```

### 4. **Selectivo por Severidad**
```python
# Solo traducir CVEs CRITICAL/HIGH
if cve.final_severity in ["CRITICAL", "HIGH"]:
    enrich_with_translation(cve)
```

---

## 📊 Costos de Procesamiento

| Componente | Tiempo (avg) | Modelo Size |
|------------|--------------|-------------|
| Traducción | ~500ms | 300MB |
| NER | ~200ms | 400MB |
| Clasificación | ~300ms | 450MB |
| Resumen | ~800ms | 1.6GB (opcional) |
| Keywords | ~100ms | Incluido |
| **TOTAL** | **~2s por CVE** | **~1GB min** |

---

## ✅ Ventajas

1. **Para Analistas SOC**:
   - Descripciones en español nativo
   - Resúmenes ejecutivos
   - Información estructurada de productos afectados

2. **Para el Sistema**:
   - Mejor clasificación automática
   - Detección de productos vulnerables
   - Correlación entre CVEs

3. **Para Búsqueda**:
   - Keywords técnicas extraídas
   - Búsqueda multilingüe (ES + EN)
   - Filtrado por tipo de ataque

---

## 🎯 Próximos Pasos

¿Te gustaría que implemente:

1. **Opción 1: MVP Básico** (rápido)
   - Solo traducción EN→ES
   - Extracción básica de entidades
   - ~2 horas de trabajo

2. **Opción 2: Pipeline Completo** (completo)
   - Todos los componentes
   - Tests incluidos
   - ~1 día de trabajo

3. **Opción 3: Híbrido** (equilibrado)
   - Traducción + NER + Clasificación mejorada
   - Sin generación de resúmenes (más pesado)
   - ~4 horas de trabajo

¿Cuál prefieres?
