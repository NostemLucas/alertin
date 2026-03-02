# Docker Guide - SOC Alert System

Guía completa para usar Docker en el desarrollo y despliegue del sistema SOC de alertas CVE.

## Tabla de Contenidos

- [Ventajas de Usar Docker](#ventajas-de-usar-docker)
- [Arquitectura Docker](#arquitectura-docker)
- [Quick Start](#quick-start)
- [Desarrollo con Hot Reload](#desarrollo-con-hot-reload)
- [Producción](#producción)
- [Comandos Útiles](#comandos-útiles)
- [Troubleshooting](#troubleshooting)

---

## Ventajas de Usar Docker

### ✅ Hot Reload en Desarrollo
- Cambios en el código se reflejan **instantáneamente** sin reconstruir la imagen
- Volúmenes mapean tu código local dentro del contenedor
- Experiencia de desarrollo idéntica a trabajar sin Docker

### ✅ Consistencia Entre Entornos
- Mismo entorno en desarrollo, testing y producción
- No más "funciona en mi máquina"
- Dependencias y versiones controladas

### ✅ Fácil Setup
- Un comando para levantar toda la infraestructura
- PostgreSQL, Redis, aplicación todo pre-configurado
- No contaminas tu sistema local

### ✅ Builds Multietapa
- Imagen optimizada para desarrollo (con debug tools)
- Imagen minimal para producción (sin herramientas innecesarias)
- Builds rápidos con cache de capas

---

## Arquitectura Docker

### Archivos Clave

```
soc-alertin/
├── Dockerfile                   # Multietapa: development, production, testing
├── docker-compose.yml           # Solo PostgreSQL (uso básico)
├── docker-compose.dev.yml       # Desarrollo con hot reload
├── docker-compose.prod.yml      # Producción con optimizaciones
├── .dockerignore                # Excluir archivos del build
├── Makefile                     # Comandos simplificados
└── .env / .env.example          # Variables de entorno
```

### Stages del Dockerfile

#### 1. **base** - Dependencias comunes
- Python 3.11 slim
- Dependencias del sistema (libpq-dev, etc.)
- Instalación de requirements.txt
- Usado como base para dev y prod

#### 2. **development** - Para desarrollo
- Incluye herramientas de debug (ipython, ipdb, watchdog)
- NO copia código (usa volúmenes para hot reload)
- Usuario no-root para seguridad
- Expone puerto 8000

#### 3. **production** - Para despliegue
- Copia código dentro de la imagen
- Imagen optimizada y minimal
- Health checks configurados
- Limits de recursos

#### 4. **testing** - Para CI/CD
- Incluye pytest y coverage
- Ejecuta tests automáticamente
- Usado en pipelines de integración continua

---

## Quick Start

### Opción 1: Makefile (Recomendado)

```bash
# Ver todos los comandos disponibles
make help

# Iniciar desarrollo (con hot reload)
make dev

# En otra terminal, ver logs
make dev-logs

# Abrir shell en el contenedor
make dev-shell

# Detener todo
make dev-down
```

### Opción 2: Docker Compose Directo

```bash
# Desarrollo
docker-compose -f docker-compose.dev.yml up --build

# Producción
docker-compose -f docker-compose.prod.yml up --build

# Solo PostgreSQL
docker-compose up -d postgres
```

---

## Desarrollo con Hot Reload

### 1. Setup Inicial

```bash
# 1. Copiar variables de entorno
cp .env.example .env

# 2. Editar .env para Docker (usar hostname 'postgres' en vez de 'localhost')
# DATABASE_URL=postgresql://soc_user:secure_password@postgres:5432/soc_alerting

# 3. Levantar entorno
make dev
```

### 2. Cómo Funciona el Hot Reload

El archivo `docker-compose.dev.yml` mapea tu código local como volumen:

```yaml
volumes:
  - ./src:/app/src          # Tu código local → Contenedor
  - ./tests:/app/tests
  - ./scripts:/app/scripts
```

**Esto significa:**
- Editas `src/soc_alerting/models/domain.py` en VS Code
- El cambio se refleja **inmediatamente** en el contenedor
- La aplicación se reinicia automáticamente (si usas watchdog/reload)
- **NO necesitas reconstruir la imagen**

### 3. Desarrollo Típico

```bash
# Terminal 1: Levantar contenedores
make dev-up-d

# Terminal 2: Ver logs en tiempo real
make dev-logs

# Terminal 3: Trabajar normalmente
code .  # O tu editor favorito

# Hacer cambios en src/soc_alerting/...
# Los cambios se ven inmediatamente en los logs (Terminal 2)
```

### 4. Ejecutar Migraciones

```bash
# Dentro del contenedor
make dev-shell
alembic upgrade head

# O desde fuera
make db-migrate
```

### 5. Ejecutar Tests

```bash
# Tests en Docker
make test

# Tests con coverage
make test-cov

# Tests locales (sin Docker)
make test-local
```

---

## Producción

### 1. Preparación

```bash
# 1. Crear .env.production con credenciales seguras
cp .env.example .env.production

# 2. Editar .env.production
#    - Cambiar DB_PASSWORD
#    - Configurar NIST_API_KEY
#    - Configurar REDIS_PASSWORD
#    - Habilitar LOG_JSON=true

# 3. Build de producción
make prod-build
```

### 2. Despliegue

```bash
# Levantar en producción (background)
make prod-up-d

# Ver logs
make prod-logs

# Verificar estado
docker-compose -f docker-compose.prod.yml ps
```

### 3. Características de Producción

- **Health Checks**: Verifica que la app y DB estén saludables
- **Resource Limits**: CPU y memoria limitadas
- **Auto-restart**: Contenedores se reinician si fallan
- **Logging**: JSON structured logs con rotación
- **Nginx**: Reverse proxy (opcional, usar `--profile nginx`)
- **Backups**: Servicio de backup automático de DB (usar `--profile backup`)

### 4. Nginx Reverse Proxy (Opcional)

```bash
# 1. Crear configuración nginx
mkdir -p nginx
touch nginx/nginx.conf

# 2. Levantar con nginx
docker-compose -f docker-compose.prod.yml --profile nginx up -d
```

### 5. Backups Automáticos

```bash
# Levantar servicio de backup (corre cada 24h)
docker-compose -f docker-compose.prod.yml --profile backup up -d

# Backup manual
make db-backup

# Restaurar backup
make db-restore
```

---

## Comandos Útiles

### Gestión de Contenedores

```bash
# Ver contenedores corriendo
make ps
docker-compose -f docker-compose.dev.yml ps

# Ver recursos (CPU, RAM)
make stats

# Reiniciar app sin bajar DB
make dev-restart

# Logs de un servicio específico
docker-compose -f docker-compose.dev.yml logs -f app
docker-compose -f docker-compose.dev.yml logs -f postgres
```

### Base de Datos

```bash
# Abrir psql shell
make db-shell

# Dentro de psql:
\dt                # Listar tablas
\d cves           # Describir tabla cves
SELECT COUNT(*) FROM cves WHERE final_severity = 'CRITICAL';

# Backup/restore
make db-backup
make db-restore

# Conectar desde herramienta externa (DBeaver, pgAdmin)
Host: localhost
Port: 5432
Database: soc_alerting
User: soc_user
Password: secure_password
```

### Debugging

```bash
# Abrir shell dentro del contenedor
make dev-shell

# Ejecutar comandos manualmente
python -c "from soc_alerting.config import get_settings; print(get_settings())"
python -m soc_alerting.main  # Run app
ipython  # Interactive Python

# Ver variables de entorno
docker-compose -f docker-compose.dev.yml exec app env

# Inspeccionar red
docker network inspect soc-alertin_soc_network
```

### Limpieza

```bash
# Detener y remover contenedores + volúmenes
make clean

# Remover también las imágenes
make clean-all

# Limpieza manual
docker-compose -f docker-compose.dev.yml down -v
docker system prune -a  # Limpia todo Docker (¡CUIDADO!)
```

---

## Servicios Opcionales

### pgAdmin (GUI para PostgreSQL)

```bash
# Levantar con pgAdmin
docker-compose -f docker-compose.dev.yml --profile tools up -d

# Acceder en navegador
http://localhost:5050
Email: admin@soc-alerting.local
Password: admin

# Configurar conexión a PostgreSQL:
Host: postgres
Port: 5432
Database: soc_alerting
Username: soc_user
Password: secure_password
```

### Redis (Para caching futuro)

```bash
# Levantar con Redis
docker-compose -f docker-compose.dev.yml --profile cache up -d

# Conectar a Redis
docker-compose exec redis redis-cli

# En redis-cli:
PING
SET test "hello"
GET test
```

---

## Troubleshooting

### Error: "Port 5432 already in use"

**Problema**: PostgreSQL ya está corriendo localmente

**Solución**:
```bash
# Opción 1: Detener PostgreSQL local
sudo systemctl stop postgresql

# Opción 2: Cambiar puerto en docker-compose
ports:
  - "5433:5432"  # Mapear a 5433 en host
```

### Error: "Cannot connect to database"

**Problema**: DATABASE_URL usa `localhost` en vez de `postgres`

**Solución**:
```bash
# En .env, cambiar:
# De: DATABASE_URL=postgresql://soc_user:secure_password@localhost:5432/soc_alerting
# A:  DATABASE_URL=postgresql://soc_user:secure_password@postgres:5432/soc_alerting
```

### Error: "Module not found: soc_alerting"

**Problema**: PYTHONPATH no está configurado

**Solución**: Ya está configurado en docker-compose, pero si falla:
```bash
docker-compose -f docker-compose.dev.yml exec app env | grep PYTHONPATH
# Debe mostrar: PYTHONPATH=/app
```

### Hot Reload No Funciona

**Problema**: Cambios en código no se reflejan

**Verificación**:
```bash
# 1. Verificar que los volúmenes estén montados
docker-compose -f docker-compose.dev.yml exec app ls -la /app/src

# 2. Verificar que el archivo existe en el contenedor
docker-compose -f docker-compose.dev.yml exec app cat /app/src/soc_alerting/models/domain.py

# 3. Forzar rebuild si es necesario
make dev-down
make dev-build
make dev-up
```

### Contenedor se Reinicia Constantemente

**Problema**: La app falla al iniciar

**Diagnóstico**:
```bash
# Ver logs completos
make dev-logs

# Ver logs de inicio
docker-compose -f docker-compose.dev.yml logs app | head -50

# Ejecutar shell y probar manualmente
make dev-shell
python -m soc_alerting.main
```

### Permisos de Archivos en Linux

**Problema**: Archivos creados por Docker pertenecen a root

**Solución**: El Dockerfile usa UID 1000 (tu usuario)
```bash
# Verificar UID
id -u  # Debe ser 1000

# Si es diferente, editar Dockerfile:
RUN useradd -m -u $(id -u) appuser
```

---

## Workflows Comunes

### Agregar Nueva Dependencia

```bash
# 1. Agregar a requirements.txt
echo "nueva-libreria==1.0.0" >> requirements.txt

# 2. Rebuild imagen
make dev-build

# 3. Reiniciar
make dev-down
make dev-up
```

### Crear Nueva Migración

```bash
# 1. Hacer cambios en models/database.py

# 2. Generar migración
make dev-shell
alembic revision --autogenerate -m "descripción del cambio"

# 3. Revisar migración generada
cat src/soc_alerting/database/migrations/versions/XXXXX_descripcion.py

# 4. Aplicar migración
alembic upgrade head

# O desde fuera:
make db-migrate
```

### Debugear con pdb

```python
# En tu código
import pdb; pdb.set_trace()

# O con ipdb (ya instalado en dev)
import ipdb; ipdb.set_trace()

# Ejecutar app
make dev-up

# El debugger se activará en los logs
make dev-logs
```

---

## Comparación: Local vs Docker

| Aspecto | Local | Docker |
|---------|-------|--------|
| **Setup** | Instalar Python, PostgreSQL, Redis | `make dev` |
| **Hot Reload** | ✅ Directo | ✅ Via volúmenes |
| **Consistencia** | ❌ Depende del sistema | ✅ Siempre igual |
| **Cleanup** | ❌ Difícil | ✅ `make clean` |
| **Producción** | ❌ Diferente | ✅ Mismo entorno |
| **Performance** | ✅ Nativo | ⚠️ Ligero overhead |

---

## Mejores Prácticas

1. **Usar .env para secretos**: Nunca commitear `.env` a git
2. **Volumes solo en desarrollo**: En producción, copiar código en imagen
3. **Multi-stage builds**: Separar dev/prod para optimizar
4. **Health checks**: Siempre configurar en producción
5. **Resource limits**: Evitar que un contenedor consuma todos los recursos
6. **Logs estructurados**: JSON en producción para parsing
7. **No correr como root**: Siempre crear usuario no-root

---

## Recursos

- [Docker Docs](https://docs.docker.com/)
- [Docker Compose Docs](https://docs.docker.com/compose/)
- [Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Multi-stage Builds](https://docs.docker.com/build/building/multi-stage/)

---

**Happy Dockering! 🐳**
