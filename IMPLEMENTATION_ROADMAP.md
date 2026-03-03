# Hoja de Ruta de Implementación: De Imperativo a Declarativo

## 📊 Resumen Ejecutivo

### Estado Actual
- **332 líneas** en CVE repository con mapeo manual
- **3 repositorios** coordinados manualmente para guardar 1 CVE
- **dict[str, any]** en pipeline NLP sin validación
- Relationships de SQLAlchemy definidas pero **no utilizadas**

### Estado Objetivo
- **~80 líneas** en CVE repository usando relationships
- **1 repositorio** que confía en cascade
- **Modelos Pydantic** validados en todo el pipeline
- **85% menos código**, 100% más mantenible

---

## 🎯 Fases de Implementación

### Fase 1: Modelos Pydantic para NLP (1-2 horas)

**Objetivo**: Reemplazar `dict[str, any]` con modelos validados

#### Tareas:
1. ✅ **COMPLETADO**: Crear `src/soc_alerting/models/nlp.py`
   - Ya existe con todos los modelos necesarios
   - `NLPEnrichmentResult`, `TranslationResult`, etc.

2. ⏭️ **SIGUIENTE**: Actualizar `pipeline.py` para usar los nuevos modelos
   ```bash
   # Archivo a modificar
   src/soc_alerting/services/nlp/pipeline.py
   ```

3. ⏭️ Actualizar tests para validar modelos Pydantic

#### Impacto:
- ✅ Autocompletado en IDE
- ✅ Validación automática de datos
- ✅ Errores detectados en desarrollo, no en producción
- ✅ Documentación automática en FastAPI

#### Archivos afectados:
- `src/soc_alerting/services/nlp/pipeline.py` (modificar)
- `tests/test_nlp_pipeline.py` (modificar)

---

### Fase 2: Conversión Automática Pydantic ↔ SQLAlchemy (2-3 horas)

**Objetivo**: Agregar métodos `from_pydantic()` y `to_pydantic()` a modelos de base de datos

#### Tareas:
1. ⏭️ Agregar métodos a `CVERecord` en `database.py`
   ```python
   @classmethod
   def from_pydantic(cls, cve: CVE) -> "CVERecord":
       """Conversión automática Pydantic → SQLAlchemy."""
       # Ver EXAMPLE_REFACTORED_REPOSITORY.py para implementación

   def update_from_pydantic(self, cve: CVE):
       """Actualizar desde modelo Pydantic."""

   def to_pydantic(self) -> CVE:
       """Conversión SQLAlchemy → Pydantic."""
   ```

2. ⏭️ Agregar métodos a `CISAKEVMetadata`
   ```python
   @classmethod
   def from_pydantic(cls, cve: CVE) -> "CISAKEVMetadata":
       """Crear metadata desde CVE Pydantic."""
   ```

3. ⏭️ Agregar tests de conversión

#### Impacto:
- ✅ Elimina mapeo manual campo por campo
- ✅ Conversión bidireccional automática
- ✅ Código más corto y claro

#### Archivos afectados:
- `src/soc_alerting/models/database.py` (modificar)
- `tests/test_model_conversion.py` (crear)

---

### Fase 3: Refactorizar CVERepository (3-4 horas)

**Objetivo**: Usar relationships para guardar automáticamente en múltiples tablas

#### Tareas:
1. ⏭️ Simplificar `save_complete_cve()` → `save()`
   ```python
   async def save(self, cve: CVE) -> CVERecord:
       existing = await self.get_by_id(cve.cve_id)

       if existing:
           existing.update_from_pydantic(cve)
           return existing

       cve_record = CVERecord.from_pydantic(cve)
       self.session.add(cve_record)  # Guarda en 3 tablas automáticamente
       await self.session.flush()
       return cve_record
   ```

2. ⏭️ Eliminar métodos redundantes:
   - `_create_record()` → reemplazado por `from_pydantic()`
   - `_update_record()` → reemplazado por `update_from_pydantic()`

3. ⏭️ Actualizar todos los llamados a `save_complete_cve()` → `save()`

4. ⏭️ Actualizar tests

#### Impacto:
- ✅ De 332 líneas a ~80 líneas (-75%)
- ✅ 1 repositorio en lugar de 3
- ✅ Transacciones atómicas automáticas
- ✅ Código más fácil de entender

#### Archivos afectados:
- `src/soc_alerting/database/repositories/cve_repository.py` (modificar)
- `src/soc_alerting/services/cve_processor.py` (modificar llamadas)
- `tests/test_cve_repository.py` (modificar)

---

### Fase 4: Eliminar Repositorios Redundantes (1 hora)

**Objetivo**: Eliminar código innecesario

#### Tareas:
1. ⏭️ **ELIMINAR** `cisa_repository.py`
   - Funcionalidad movida a `CVERecord.from_pydantic()`
   - ~100 líneas eliminadas

2. ⏭️ **ELIMINAR** `reference_repository.py`
   - Funcionalidad movida a `CVERecord.from_pydantic()`
   - ~100 líneas eliminadas

3. ⏭️ Actualizar imports en archivos que los usaban

#### Impacto:
- ✅ ~200 líneas menos de código
- ✅ Menos archivos que mantener
- ✅ Una sola fuente de verdad

#### Archivos a eliminar:
- `src/soc_alerting/database/repositories/cisa_repository.py` (eliminar)
- `src/soc_alerting/database/repositories/reference_repository.py` (eliminar)

---

### Fase 5: Refactorizar NLP Pipeline (2-3 horas)

**Objetivo**: Pipeline declarativo usando inyección de dependencias

#### Tareas:
1. ⏭️ Convertir `NLPEnrichmentPipeline` a dataclass
   ```python
   from dataclasses import dataclass

   @dataclass
   class NLPPipeline:
       translator: CVETranslator
       entity_extractor: CVEEntityExtractor
       keyword_extractor: CVEKeywordExtractor
   ```

2. ⏭️ Actualizar `enrich_cve()` para devolver `NLPEnrichmentResult`
   - Usar modelos Pydantic de Fase 1
   - Ver `EXAMPLE_REFACTORED_PIPELINE.py`

3. ⏭️ Actualizar `batch_enrich()` para devolver `NLPEnrichmentBatchResult`

4. ⏭️ Actualizar tests

#### Impacto:
- ✅ Código más simple y testeable
- ✅ Dependencias explícitas
- ✅ Resultados validados automáticamente

#### Archivos afectados:
- `src/soc_alerting/services/nlp/pipeline.py` (modificar)
- `tests/test_nlp_pipeline.py` (modificar)

---

## 📈 Métricas de Éxito

| Métrica | Antes | Después | Mejora |
|---------|-------|---------|--------|
| **Líneas en CVERepository** | 332 | ~80 | -76% |
| **Repositorios para guardar CVE** | 3 | 1 | -67% |
| **Total de repositorios** | 5 | 3 | -40% |
| **Diccionarios sin validar** | Sí | No | ✅ |
| **Autocompletado en IDE** | ❌ | ✅ | ✅ |
| **Validación de tipos** | Runtime | Compile-time | ✅ |
| **Código total eliminado** | - | ~500 líneas | ✅ |

---

## ⚠️ Riesgos y Mitigación

### Riesgo 1: Cambios incompatibles con código existente
**Mitigación**:
- Implementar en feature branch
- Ejecutar todos los tests después de cada fase
- Mantener backward compatibility temporalmente

### Riesgo 2: Bugs introducidos por refactorización
**Mitigación**:
- Tests exhaustivos en cada fase
- Code review minucioso
- Despliegue gradual (canary deployment)

### Riesgo 3: Performance degradation
**Mitigación**:
- Benchmarks antes/después de cada fase
- `lazy="selectin"` ya está configurado correctamente
- Monitoreo de queries SQL (sqlalchemy.engine logging)

---

## 🚀 Plan de Ejecución

### Opción A: Incremental (Recomendado)
```
Semana 1: Fase 1 + Fase 2
Semana 2: Fase 3 + Tests
Semana 3: Fase 4 + Fase 5
Semana 4: Testing integral + Deployment
```

### Opción B: Agresivo (Solo si hay urgencia)
```
Día 1-2: Fase 1 + Fase 2
Día 3-4: Fase 3
Día 5: Fase 4 + Fase 5
Día 6-7: Testing + Fixes
```

---

## 📋 Checklist de Pre-Refactorización

Antes de empezar, asegúrate de:

- [ ] **Backup de base de datos** (desarrollo/staging)
- [ ] **Branch nueva**: `git checkout -b refactor/declarative-python`
- [ ] **Tests pasando al 100%**: `pytest`
- [ ] **Cobertura de tests documentada**: Saber qué áreas tienen menos coverage
- [ ] **Benchmarks baseline**: Medir performance actual para comparar
- [ ] **Revisar REFACTOR_GUIDE.md**: Entender la mentalidad del cambio

---

## 📚 Recursos de Referencia

### Documentos creados:
1. **REFACTOR_GUIDE.md** - Guía conceptual del cambio de mentalidad
2. **EXAMPLE_REFACTORED_REPOSITORY.py** - Ejemplo de repositorio refactorizado
3. **EXAMPLE_REFACTORED_PIPELINE.py** - Ejemplo de pipeline refactorizado
4. **src/soc_alerting/models/nlp.py** - Modelos Pydantic para NLP

### Documentación externa:
- [SQLAlchemy Relationships](https://docs.sqlalchemy.org/en/20/orm/relationships.html)
- [Pydantic Validation](https://docs.pydantic.dev/latest/concepts/validators/)
- [FastAPI Dependency Injection](https://fastapi.tiangolo.com/tutorial/dependencies/)

---

## 🎯 Próximos Pasos Inmediatos

### Paso 1: Validar Approach
```bash
# Revisar los archivos de ejemplo
cat REFACTOR_GUIDE.md
cat EXAMPLE_REFACTORED_REPOSITORY.py
cat EXAMPLE_REFACTORED_PIPELINE.py
cat src/soc_alerting/models/nlp.py
```

### Paso 2: Crear Branch
```bash
git checkout -b refactor/declarative-python
```

### Paso 3: Empezar con Fase 1
```bash
# Modificar pipeline.py para usar modelos Pydantic
# Ver EXAMPLE_REFACTORED_PIPELINE.py como referencia
```

### Paso 4: Testing
```bash
pytest tests/test_nlp_pipeline.py -v
```

---

## 💬 Preguntas Frecuentes

### ¿Por qué no usar relationships desde el principio?
- Falta de conocimiento del poder de SQLAlchemy
- Tendencia a escribir código imperativo en vez de declarativo
- No confiar en el framework

### ¿Esto romperá mi código existente?
- Sí, requiere actualizar llamadas a los repositorios
- Pero el API público puede mantener backward compatibility
- Los tests te dirán exactamente qué rompe

### ¿Vale la pena el esfuerzo?
**Absolutamente sí**:
- -500 líneas de código a mantener
- Código más fácil de entender para nuevos desarrolladores
- Menos bugs (validación automática)
- Mejor experiencia de desarrollo (autocompletado)

### ¿Cuándo veré los beneficios?
- **Inmediato**: Autocompletado y validación (Fase 1)
- **Corto plazo**: Menos código que mantener (Fase 3-4)
- **Largo plazo**: Velocidad de desarrollo aumentada

---

## ✅ Conclusión

Este refactor transforma el código de **imperativo** (tú le dices a Python CÓMO hacer las cosas) a **declarativo** (tú le dices QUÉ quieres, Python decide CÓMO).

**El resultado**: Código que se escribe como Python moderno debería escribirse, aprovechando el poder de Pydantic + SQLAlchemy en lugar de luchar contra ellos.

**¿Listo para empezar?** 🚀

```bash
# Crear branch y comenzar
git checkout -b refactor/declarative-python

# Ver la guía completa
cat REFACTOR_GUIDE.md

# Empezar con Fase 1
# Modificar src/soc_alerting/services/nlp/pipeline.py
```
