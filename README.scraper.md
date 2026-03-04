# CVE Scraper - Configuración con Docker

Este README explica cómo ejecutar **solo el servicio de scraper** en Docker, mientras que el resto de servicios (processor, alert-manager) pueden correr localmente en tu PC.

## 📋 Requisitos Previos

- Docker y Docker Compose instalados
- Python 3.11+ (para scripts locales)
- Conexión a Internet (para descargar CVEs)

## 🚀 Inicio Rápido

### 1. Configurar Variables de Entorno

Copia el archivo de configuración de ejemplo:

```bash
cp .env.scraper .env
```

Edita `.env` y configura tu **NIST API Key** (opcional pero recomendado):

```env
NIST_API_KEY=tu-api-key-aqui
```

> **Obtener API Key**: https://nvd.nist.gov/developers/request-an-api-key
> - **Sin API key**: 5 requests cada 30 segundos
> - **Con API key**: 50 requests cada 30 segundos

### 2. Levantar Servicios en Docker

Ejecuta solo el scraper + infraestructura (Kafka + PostgreSQL):

```bash
docker-compose -f docker-compose.scraper.yml up -d
```

Esto iniciará:
- ✅ **Kafka** (puerto 9092)
- ✅ **PostgreSQL** (puerto 5432)
- ✅ **Kafka UI** (puerto 8080) - Para monitoreo
- ✅ **CVE Scraper** (servicio)

### 3. Verificar que Todo Funciona

Verifica el estado de los contenedores:

```bash
docker-compose -f docker-compose.scraper.yml ps
```

Deberías ver todos los servicios como `Up` o `healthy`.

Ver logs del scraper:

```bash
docker-compose -f docker-compose.scraper.yml logs -f cve-scraper
```

### 4. (Opcional) Poblar Base de Datos con Datos de Prueba

Instala dependencias locales para el script de seed:

```bash
cd scripts
pip install -r requirements.txt
cd ..
```

Ejecuta el script de seed:

```bash
python scripts/seed_database.py
```

Esto creará las tablas y poblará con 3 CVEs de ejemplo.

## 📊 Monitoreo

### Kafka UI (Interfaz Web)

Accede a http://localhost:8080 para:
- Ver topics de Kafka
- Monitorear mensajes
- Ver consumers activos

### PostgreSQL

Conéctate a la base de datos:

```bash
# Usando psql
psql postgresql://soc_user:soc_password@localhost:5432/soc_alerting

# O desde Docker
docker exec -it soc-postgres psql -U soc_user -d soc_alerting
```

Consultas útiles:

```sql
-- Total de CVEs
SELECT COUNT(*) FROM cve_records;

-- CVEs por severidad
SELECT severity, COUNT(*)
FROM cve_records
GROUP BY severity;

-- CVEs en CISA KEV
SELECT COUNT(*)
FROM cve_records
WHERE is_in_cisa_kev = true;
```

### Logs del Scraper

```bash
# Ver logs en tiempo real
docker-compose -f docker-compose.scraper.yml logs -f cve-scraper

# Ver últimas 100 líneas
docker-compose -f docker-compose.scraper.yml logs --tail=100 cve-scraper
```

## ⚙️ Configuración del Scraper

Edita `.env` para ajustar el comportamiento:

```env
# Intervalo entre ejecuciones (minutos)
SCRAPER_INTERVAL_MINUTES=60

# Cuántas horas hacia atrás buscar CVEs
SCRAPER_HOURS_BACK=24

# Nivel de logging
LOG_LEVEL=INFO
```

Reinicia el scraper para aplicar cambios:

```bash
docker-compose -f docker-compose.scraper.yml restart cve-scraper
```

## 🔄 Ejecutar Scrape Manual (Una Vez)

Si quieres ejecutar el scraper una sola vez sin el scheduler:

```bash
docker-compose -f docker-compose.scraper.yml run --rm cve-scraper python scraper.py --hours-back 48
```

Opciones disponibles:

```bash
# Scrape de las últimas 48 horas
python scraper.py --hours-back 48

# Scrape de un rango específico
python scraper.py --start-date 2024-01-01 --end-date 2024-01-31
```

## 🛑 Detener Servicios

```bash
# Detener todos los servicios
docker-compose -f docker-compose.scraper.yml down

# Detener Y eliminar volúmenes (BORRA LA BASE DE DATOS)
docker-compose -f docker-compose.scraper.yml down -v
```

## 🔧 Troubleshooting

### El scraper no se conecta a Kafka

1. Verifica que Kafka esté healthy:
   ```bash
   docker-compose -f docker-compose.scraper.yml ps kafka
   ```

2. Revisa logs de Kafka:
   ```bash
   docker-compose -f docker-compose.scraper.yml logs kafka
   ```

### "Rate limit exceeded" de NIST

Soluciones:
1. Obtén una API key de NIST
2. Aumenta el `NIST_RATE_LIMIT_DELAY` en `.env`
3. Reduce `SCRAPER_HOURS_BACK` para buscar menos CVEs

### No se crean los topics de Kafka

Verifica que kafka-init se ejecutó correctamente:

```bash
docker-compose -f docker-compose.scraper.yml logs kafka-init
```

Si falló, elimina y recrea:

```bash
docker-compose -f docker-compose.scraper.yml down
docker-compose -f docker-compose.scraper.yml up -d
```

### PostgreSQL no acepta conexiones

1. Verifica que el puerto no esté en uso:
   ```bash
   lsof -i :5432
   ```

2. Cambia el puerto en `.env`:
   ```env
   POSTGRES_PORT=5433
   ```

## 📁 Estructura de Archivos

```
.
├── docker-compose.scraper.yml    # Docker Compose solo para scraper
├── .env                          # Configuración (copia de .env.scraper)
├── services/
│   └── cve-scraper/
│       ├── Dockerfile            # Imagen del scraper
│       └── src/                  # Código fuente
├── shared/                       # Código compartido
│   ├── models/                   # Modelos de datos
│   ├── kafka/                    # Cliente Kafka
│   └── database/                 # Cliente PostgreSQL
├── scripts/
│   ├── seed_database.py          # Script de seed
│   └── requirements.txt          # Dependencias para scripts
└── infrastructure/
    └── kafka/
        └── create-topics.sh      # Script para crear topics
```

## 🏃 Correr Otros Servicios Localmente

Si quieres correr el processor o alert-manager localmente (fuera de Docker):

1. Instala dependencias:
   ```bash
   cd services/cve-processor
   pip install -r requirements.txt
   ```

2. Configura variables de entorno para conectar a Docker:
   ```bash
   export KAFKA_BOOTSTRAP_SERVERS=localhost:9092
   export DATABASE_URL=postgresql://soc_user:soc_password@localhost:5432/soc_alerting
   ```

3. Ejecuta el servicio:
   ```bash
   python src/processor.py
   ```

## 📚 Más Información

- [NIST NVD API Documentation](https://nvd.nist.gov/developers)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Kafka Documentation](https://kafka.apache.org/documentation/)

## 💡 Tips

1. **Primera ejecución**: El scraper puede tardar varios minutos en la primera ejecución dependiendo de `SCRAPER_HOURS_BACK`

2. **Producción**: Para producción, configura:
   - API key de NIST
   - Contraseña segura de PostgreSQL
   - Backups regulares de la base de datos

3. **Desarrollo**: Para desarrollo rápido, reduce `SCRAPER_INTERVAL_MINUTES` a 5-10 minutos

4. **Monitoreo**: Usa Kafka UI para verificar que los mensajes llegan a los topics correctamente
