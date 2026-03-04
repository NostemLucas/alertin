# 🚀 Quick Start - CVE Scraper en Docker

## Configuración en 3 Pasos

### 1️⃣ Configurar Variables de Entorno

```bash
# Copiar archivo de configuración
cp .env.scraper .env

# (Opcional) Editar y agregar tu NIST API Key
nano .env
```

### 2️⃣ Levantar Servicios

```bash
# Levantar Kafka + PostgreSQL + Scraper
docker-compose -f docker-compose.scraper.yml up -d

# Ver logs
docker-compose -f docker-compose.scraper.yml logs -f cve-scraper
```

### 3️⃣ (Opcional) Poblar Base de Datos

```bash
# Instalar dependencias
cd scripts && pip install -r requirements.txt && cd ..

# Ejecutar seed
python scripts/seed_database.py
```

## ✅ Verificar que Funciona

```bash
# Ver estado de servicios
docker-compose -f docker-compose.scraper.yml ps

# Ver logs del scraper
docker-compose -f docker-compose.scraper.yml logs -f cve-scraper

# Acceder a Kafka UI
# http://localhost:8080

# Conectar a PostgreSQL
docker exec -it soc-postgres psql -U soc_user -d soc_alerting
```

## 🛠️ Usando Makefile (Opcional)

Si prefieres usar comandos más cortos:

```bash
# Usar el Makefile
make -f Makefile.scraper help     # Ver todos los comandos
make -f Makefile.scraper setup    # Configurar .env
make -f Makefile.scraper check    # Verificar instalación
make -f Makefile.scraper up       # Levantar servicios
make -f Makefile.scraper logs     # Ver logs
make -f Makefile.scraper seed     # Poblar DB
make -f Makefile.scraper down     # Detener servicios
```

## 📊 Monitoreo

- **Kafka UI**: http://localhost:8080
- **PostgreSQL**: `localhost:5432`
  - User: `soc_user`
  - Password: `soc_password`
  - Database: `soc_alerting`

## 🔧 Comandos Útiles

```bash
# Reiniciar solo el scraper
docker-compose -f docker-compose.scraper.yml restart cve-scraper

# Ver últimas 100 líneas de logs
docker-compose -f docker-compose.scraper.yml logs --tail=100 cve-scraper

# Ejecutar scrape manual (una vez)
docker-compose -f docker-compose.scraper.yml run --rm cve-scraper \
  python scraper.py --hours-back 48

# Conectar a PostgreSQL
docker exec -it soc-postgres psql -U soc_user -d soc_alerting

# Ver CVEs en la base de datos
docker exec -it soc-postgres psql -U soc_user -d soc_alerting \
  -c "SELECT cve_id, severity, cvss_score FROM cve_records LIMIT 10;"
```

## 🛑 Detener Todo

```bash
# Detener servicios (mantiene datos)
docker-compose -f docker-compose.scraper.yml down

# Detener Y eliminar datos
docker-compose -f docker-compose.scraper.yml down -v
```

## 📚 Documentación Completa

Ver `README.scraper.md` para información detallada sobre:
- Configuración avanzada
- Troubleshooting
- Correr otros servicios localmente
- Tips de producción

## 💡 Tips

1. **Primera vez**: El scraper puede tardar varios minutos en fetch CVEs
2. **Sin API Key**: Límite de 5 requests/30s (más lento)
3. **Con API Key**: Límite de 50 requests/30s (10x más rápido)
4. **Kafka UI**: Úsalo para ver mensajes en topics en tiempo real
5. **Desarrollo**: Reduce `SCRAPER_INTERVAL_MINUTES` a 5 en `.env` para testing rápido

## ❓ Problemas Comunes

**El scraper no arranca:**
```bash
# Ver logs para diagnóstico
docker-compose -f docker-compose.scraper.yml logs cve-scraper
```

**Kafka no se conecta:**
```bash
# Verificar que Kafka esté healthy
docker-compose -f docker-compose.scraper.yml ps kafka

# Ver logs de Kafka
docker-compose -f docker-compose.scraper.yml logs kafka
```

**PostgreSQL no acepta conexiones:**
```bash
# Cambiar puerto en .env
POSTGRES_PORT=5433
```

## 📞 Soporte

Si tienes problemas:
1. Revisa `README.scraper.md` (sección Troubleshooting)
2. Ejecuta `bash scripts/check_setup.sh`
3. Verifica logs con `make logs` o `docker-compose logs`
