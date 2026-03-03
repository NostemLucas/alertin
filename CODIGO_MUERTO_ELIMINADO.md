# Código Muerto Eliminado

## Fecha: 2026-03-02

### ✅ Eliminaciones Realizadas

#### 1. database/connection.py - Métodos de Schema Management

**Eliminado:**
- `async def initialize()` - Método vacío que solo loggeaba
- `async def create_tables()` - Deprecado, lanzaba NotImplementedError
- `async def drop_tables()` - Peligroso, duplicaba funcionalidad de Alembic

**Reemplazado con:**
```python
# ============================================================================
# Schema management removed - Use Alembic migrations exclusively
# ============================================================================
# Previously: initialize(), create_tables(), drop_tables()
# Now: Run `alembic upgrade head` to manage schema
# ============================================================================
```

**Impacto:**
- 🗑️ -40 líneas de código muerto
- ✅ Claridad: Solo hay UN camino para schema management (Alembic)
- ✅ Menos superficie de error

---

## 📊 Antes vs. Después

### Antes
```python
class DatabaseConnection:
    async def initialize(self):
        logger.info("Database connection initialized")
        # Removed automatic table creation...
    
    async def create_tables(self):
        raise NotImplementedError("Use Alembic...")
    
    async def drop_tables(self):
        logger.warning("Dropping all tables...")
        # ... código peligroso
```

### Después
```python
class DatabaseConnection:
    # ============================================================================
    # Schema management removed - Use Alembic migrations exclusively
    # ============================================================================
    
    @asynccontextmanager
    async def get_session(self, auto_commit: bool = True):
        # ... código útil
```

---

## 🎯 Beneficios

1. **Menos Confusión Mental**
   - No hay métodos que "parecen" útiles pero están deprecados
   - Comentario claro explica qué cambió y por qué

2. **Menos Superficie de Ataque**
   - No hay forma accidental de llamar `drop_tables()` y perder datos

3. **Un Solo Camino Correcto**
   - Schema management = Alembic migrations
   - No hay "plan B" tentador que cause problemas

---

## ✅ Validado

```bash
python -m py_compile src/soc_alerting/database/connection.py
✓ OK - Sintaxis correcta
```

---

**Próximo Paso**: Refactoring arquitectónico para eliminar acoplamiento
