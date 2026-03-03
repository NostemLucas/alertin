# SOC Alerting System

Sistema de alertas de CVEs para operaciones SOC.

---

## Inicio Rápido (3 pasos)

### 1. Configurar variables de entorno

```bash
# Copiar el template
cp .env.example .env

# Editar con tus valores
nano .env
```

**Mínimo requerido en `.env`:**
```bash
# Base de datos
POSTGRES_PASSWORD=tu-password-seguro-aqui

# API de NIST (opcional pero muy recomendado)
NIST_API_KEY=tu-api-key-aqui
```

### 2. Levantar infraestructura (PostgreSQL + Redis)

```bash
# Levantar contenedores
docker-compose up -d postgres redis

# Verificar que estén corriendo
docker-compose ps
```

### 3. Ejecutar aplicación localmente

```bash
# Instalar dependencias
poetry install

# Aplicar migraciones de base de datos
poetry run alembic upgrade head

# Opción A: Ejecutar API
poetry run uvicorn soc_alerting.api.app:app --reload

# Opción B: Sincronizar CVEs
poetry run python -m soc_alerting.main sync --hours-back 24
```

---

## Estructura del Proyecto

```
soc-alertin/
├── .env                    ← Tu configuración (NO subir a git)
├── .env.example            ← Template de configuración
├── docker-compose.yml      ← Docker (solo PostgreSQL + Redis)
├── Dockerfile              ← Build de la app (opcional)
├── pyproject.toml          ← Dependencias de Python
├── alembic.ini             ← Configuración de migraciones
├── quick-start.sh          ← Script de instalación automatizada
└── src/
    └── soc_alerting/       ← Código de la aplicación
        ├── api/            ← FastAPI endpoints
        ├── models/         ← Modelos de base de datos
        ├── services/       ← Lógica de negocio
        ├── clients/        ← Clientes NIST/CISA
        └── database/       ← Repositorios y migraciones
```

---

## Comandos Útiles

### Docker (Infraestructura)

```bash
# Levantar solo base de datos y Redis
docker-compose up -d postgres redis

# Ver logs en tiempo real
docker-compose logs -f postgres redis

# Detener todo
docker-compose down

# Resetear base de datos (¡CUIDADO! Pierdes datos)
docker-compose down -v
docker-compose up -d postgres redis
poetry run alembic upgrade head
```

### Aplicación

```bash
# Ejecutar API (desarrollo con hot-reload)
poetry run uvicorn soc_alerting.api.app:app --reload

# Sincronizar CVEs de las últimas 24 horas
poetry run python -m soc_alerting.main sync --hours-back 24

# Sincronizar desde fecha específica
poetry run python -m soc_alerting.main sync --start-date 2024-01-01
```

### Base de Datos

```bash
# Aplicar migraciones
poetry run alembic upgrade head

# Ver estado de migraciones
poetry run alembic current

# Crear nueva migración (si cambias modelos)
poetry run alembic revision --autogenerate -m "descripcion"

# Backup manual
docker-compose exec postgres pg_dump -U soc_user soc_alerting > backups/backup_$(date +%Y%m%d).sql
```

---

## Troubleshooting

### "Port 5432 already in use"

Tienes PostgreSQL corriendo localmente:

```bash
# Opción 1: Detener PostgreSQL local
sudo systemctl stop postgresql

# Opción 2: Cambiar puerto en .env
echo "POSTGRES_PORT=5433" >> .env
# Y actualizar DATABASE_URL en .env:
# DATABASE_URL=postgresql://soc_user:password@localhost:5433/soc_alerting
```

### "Connection refused to database"

```bash
# Verificar que PostgreSQL esté corriendo
docker-compose ps postgres

# Ver logs de PostgreSQL
docker-compose logs postgres

# Esperar a que esté listo (puede tardar 5-10 segundos)
docker-compose up -d postgres
sleep 10
```

### "Redis connection error"

```bash
# Verificar Redis
docker-compose ps redis

# Probar conexión
docker-compose exec redis redis-cli ping
# Debe responder: PONG
```

### "Alembic can't find database"

Verifica que DATABASE_URL en `.env` coincida con los valores de Docker:

```bash
# En .env debe ser:
DATABASE_URL=postgresql://soc_user:TU_PASSWORD@localhost:5432/soc_alerting

# Los mismos valores que:
POSTGRES_USER=soc_user
POSTGRES_PASSWORD=TU_PASSWORD
POSTGRES_DB=soc_alerting
```

---

## Flujo de Trabajo Recomendado

```bash
# 1. Levantar infraestructura en Docker (una vez)
docker-compose up -d postgres redis

# 2. Ejecutar app localmente (más fácil de debuggear)
poetry run uvicorn soc_alerting.api.app:app --reload

# 3. En otra terminal, sincronizar CVEs
poetry run python -m soc_alerting.main sync --hours-back 24

# 4. Cuando termines, detener Docker
docker-compose down
```

**Ventajas:**
- Base de datos aislada en Docker
- App local con hot-reload
- Fácil de debuggear con breakpoints
- No contaminas tu sistema

---

## Configuración Importante

### API Key de NIST

**Sin API key**: 5 peticiones cada 30 segundos (muy lento)
**Con API key**: 50 peticiones cada 30 segundos (10x más rápido)

Consigue tu API key gratis en: https://nvd.nist.gov/developers/request-an-api-key

Configura en `.env`:
```bash
NIST_API_KEY=tu-api-key-aqui
NIST_RATE_LIMIT_DELAY=0.6  # 0.6s con API key, 6.0s sin API key
```

### Redis (Obligatorio para Producción)

Redis es **OBLIGATORIO** en producción porque:
- El enriquecimiento NLP toma 2-5 segundos por CVE
- 100 CVEs = 8 minutos de procesamiento
- Sin Redis, la API se bloquea
- Redis permite procesar en background

---

## Arquitectura

```
Usuario
   ↓
FastAPI (puerto 8000)
   ↓
PostgreSQL (Docker)
   ↓
Redis (Docker) → Celery Worker → NLP Enrichment
```

---

## Documentación Adicional

- `DOCKER_QUICKSTART.md` - Guía detallada de Docker
- `PRODUCTION_DEPLOYMENT.md` - Deployment en producción
- `.env.example` - Template de configuración

---

## Seguridad

- **NUNCA** subir `.env` a git (ya está en .gitignore)
- Usar contraseñas seguras (mínimo 16 caracteres)
- Rotar credenciales cada 90 días
- En producción, usar secrets management (no .env)

---

## Soporte

Para más ayuda, consulta la documentación en los archivos `.md` del proyecto.
