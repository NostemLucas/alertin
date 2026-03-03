#!/bin/bash
# ============================================================================
# SOC Alerting System - Quick Start Script
# ============================================================================
set -e

echo "=================================================="
echo "🚀 SOC Alerting System - Quick Start"
echo "=================================================="
echo ""

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Función para imprimir con color
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# 1. Verificar .env
echo "1️⃣  Verificando configuración..."
if [ ! -f .env ]; then
    print_warning ".env no encontrado, copiando desde .env.example"
    cp .env.example .env
    print_warning "⚠️  IMPORTANTE: Edita .env y cambia POSTGRES_PASSWORD antes de continuar"
    echo ""
    read -p "Presiona Enter cuando hayas editado .env..."
fi
print_success ".env encontrado"

# 2. Verificar Docker
echo ""
echo "2️⃣  Verificando Docker..."
if ! command -v docker &> /dev/null; then
    print_error "Docker no está instalado. Instálalo desde: https://docs.docker.com/get-docker/"
    exit 1
fi
print_success "Docker instalado"

if ! command -v docker-compose &> /dev/null; then
    print_error "docker-compose no está instalado"
    exit 1
fi
print_success "docker-compose instalado"

# 3. Levantar PostgreSQL y Redis
echo ""
echo "3️⃣  Levantando PostgreSQL y Redis..."
docker-compose up -d postgres redis
sleep 5
print_success "PostgreSQL y Redis corriendo"

# 4. Verificar que Poetry esté instalado
echo ""
echo "4️⃣  Verificando Poetry..."
if ! command -v poetry &> /dev/null; then
    print_warning "Poetry no está instalado. Instalando..."
    curl -sSL https://install.python-poetry.org | python3 -
fi
print_success "Poetry instalado"

# 5. Instalar dependencias
echo ""
echo "5️⃣  Instalando dependencias de Python..."
poetry install
print_success "Dependencias instaladas"

# 6. Aplicar migraciones
echo ""
echo "6️⃣  Aplicando migraciones de base de datos..."
poetry run alembic upgrade head
print_success "Migraciones aplicadas"

# 7. Verificar conexión a BD
echo ""
echo "7️⃣  Verificando conexión a base de datos..."
docker-compose exec -T postgres psql -U soc_user -d soc_alerting -c "SELECT 1;" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    print_success "Conexión a PostgreSQL exitosa"
else
    print_error "No se pudo conectar a PostgreSQL"
    exit 1
fi

# 8. Verificar Redis
echo ""
echo "8️⃣  Verificando Redis..."
docker-compose exec -T redis redis-cli ping > /dev/null 2>&1
if [ $? -eq 0 ]; then
    print_success "Conexión a Redis exitosa"
else
    print_error "No se pudo conectar a Redis"
    exit 1
fi

# Completado
echo ""
echo "=================================================="
echo -e "${GREEN}✅ ¡Instalación completada!${NC}"
echo "=================================================="
echo ""
echo "Próximos pasos:"
echo ""
echo "  1. Ejecutar API:"
echo "     poetry run uvicorn soc_alerting.api.app:app --reload"
echo ""
echo "  2. Sincronizar CVEs (en otra terminal):"
echo "     poetry run python -m soc_alerting.main sync --hours-back 24"
echo ""
echo "  3. Ver logs de Docker:"
echo "     docker-compose logs -f"
echo ""
echo "  4. Detener Docker cuando termines:"
echo "     docker-compose down"
echo ""
echo "📖 Más info en: DOCKER_QUICKSTART.md"
echo ""
