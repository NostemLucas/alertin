# Docker Quick Start - SOC Alerting System

Guía rápida para ejecutar el sistema con Docker.

---

## 🚀 Inicio Rápido (3 pasos)

### 1. Configurar Variables de Entorno

```bash
# Copiar template
cp .env.example .env

# Editar con tus valores
nano .env
```

**Mínimo requerido en `.env`**:
```bash
POSTGRES_PASSWORD=tu-password-seguro-aqui
NIST_API_KEY=tu-api-key-de-nist  # Opcional pero MUY recomendado
```

### 2. Levantar Infraestructura

```bash
# Solo PostgreSQL + Redis (recomendado para desarrollo local)
docker-compose up -d postgres redis

# Verificar que estén corriendo
docker-compose ps
```

### 3. Ejecutar Migraciones y App (Local)

```bash
# Instalar dependencias localmente
poetry install

# Aplicar migraciones
poetry run alembic upgrade head

# Ejecutar API
poetry run uvicorn soc_alerting.api.app:app --reload

# O ejecutar sync de CVEs
poetry run python -m soc_alerting.main sync --hours-back 24
```

---

## 🐳 Ejecutar TODO en Docker (Opcional)

Si prefieres ejecutar la app también en Docker (no solo PostgreSQL/Redis):

### 1. Descomentar servicio `api` en docker-compose.yml

```yaml
# Buscar esta sección y descomentar:
api:
  build:
    context: .
    dockerfile: Dockerfile
  # ... resto del config
```

### 2. Build y Levantar

```bash
# Build de imagen
docker-compose build api

# Levantar todo el stack
docker-compose up -d

# Ver logs
docker-compose logs -f api
```

### 3. Ejecutar Comandos Dentro del Container

```bash
# Aplicar migraciones
docker-compose exec api alembic upgrade head

# Sync de CVEs
docker-compose exec api python -m soc_alerting.main sync --hours-back 24

# Shell interactivo
docker-compose exec api bash
```

---

## 📋 Comandos Útiles

### Estado de Servicios

```bash
# Ver qué está corriendo
docker-compose ps

# Logs en tiempo real
docker-compose logs -f

# Logs de un servicio específico
docker-compose logs -f postgres
docker-compose logs -f redis
```

### Detener/Reiniciar

```bash
# Detener todo
docker-compose down

# Detener y borrar volúmenes (¡CUIDADO! Pierdes datos)
docker-compose down -v

# Reiniciar un servicio
docker-compose restart postgres
```

### Backups

```bash
# Backup manual de PostgreSQL
docker-compose exec postgres pg_dump -U soc_user soc_alerting > backups/backup_$(date +%Y%m%d_%H%M%S).sql

# Restaurar backup
docker-compose exec -T postgres psql -U soc_user soc_alerting < backups/backup_20260303_120000.sql
```

### Limpieza

```bash
# Eliminar containers
docker-compose down

# Eliminar containers + volúmenes + imágenes
docker-compose down -v --rmi all

# Ver espacio usado
docker system df
```

---

## 🔧 Troubleshooting

### "Port 5432 already in use"

Tienes PostgreSQL corriendo localmente:

```bash
# Opción 1: Detener PostgreSQL local
sudo systemctl stop postgresql

# Opción 2: Cambiar puerto en .env
echo "POSTGRES_PORT=5433" >> .env
docker-compose up -d postgres
```

### "Connection refused to database"

```bash
# Verificar que PostgreSQL esté corriendo
docker-compose ps postgres

# Ver logs de PostgreSQL
docker-compose logs postgres

# Verificar healthcheck
docker inspect soc-postgres | grep -A 5 Health
```

### "Redis connection error"

```bash
# Verificar Redis
docker-compose ps redis

# Probar conexión
docker-compose exec redis redis-cli ping
# Debe responder: PONG
```

### Resetear Base de Datos

```bash
# Detener todo
docker-compose down

# Borrar volumen de PostgreSQL
docker volume rm soc-alertin_postgres_data

# Levantar de nuevo (BD vacía)
docker-compose up -d postgres

# Aplicar migraciones
poetry run alembic upgrade head
```

---

## 🎯 Workflow Recomendado (Desarrollo)

```bash
# 1. Levantar solo infraestructura en Docker
docker-compose up -d postgres redis

# 2. Ejecutar app localmente (más fácil de debuggear)
poetry run uvicorn soc_alerting.api.app:app --reload

# 3. En otra terminal, ejecutar worker de Celery (si lo usas)
poetry run celery -A soc_alerting.celery_app worker --loglevel=info

# 4. Cuando termines, detener Docker
docker-compose down
```

**Ventajas**:
- ✅ Base de datos aislada (no contaminas tu sistema)
- ✅ Redis fácil de resetear
- ✅ App local con hot-reload
- ✅ Fácil de debuggear con breakpoints

---

## 📊 Verificar Instalación

```bash
# PostgreSQL
docker-compose exec postgres psql -U soc_user -d soc_alerting -c "SELECT COUNT(*) FROM cves;"

# Redis
docker-compose exec redis redis-cli INFO stats

# API (si está en Docker)
curl http://localhost:8000/health

# O si API está local
curl http://localhost:8000/health
```

---

## 🚀 Producción

Para producción, lee `PRODUCTION_DEPLOYMENT.md` que incluye:
- Secrets management (no usar .env)
- Network security
- Monitoring
- Backups automáticos
- SSL/TLS

**NO uses docker-compose en producción real**, usa:
- Kubernetes
- Docker Swarm
- ECS/Fargate
- O deployment nativo con systemd

---

## 📞 FAQ

### ¿Debo ejecutar la app en Docker?

**Desarrollo**: No, es más fácil ejecutar solo PostgreSQL/Redis en Docker y la app localmente.

**Producción**: Sí, pero con orquestación (Kubernetes, etc.), no docker-compose.

### ¿Cómo actualizo la imagen de Docker?

```bash
# Rebuild después de cambiar código
docker-compose build api

# Recrear container
docker-compose up -d --force-recreate api
```

### ¿Los datos persisten si hago `docker-compose down`?

Sí, gracias a los volumes. Solo se borran con `docker-compose down -v`.

---

**Listo!** Con esto tienes PostgreSQL + Redis corriendo en Docker y puedes desarrollar localmente. 🎉
