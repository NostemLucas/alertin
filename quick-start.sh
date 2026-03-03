#!/bin/bash
# ============================================================================
# SOC Alerting System - Quick Start Script (Microservices)
# ============================================================================
set -e

echo "=================================================="
echo "SOC Alerting System - Microservices Architecture"
echo "=================================================="
echo ""

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# 1. Verificar .env
echo "1️⃣  Verificando configuración..."
if [ ! -f .env ]; then
    print_warning ".env no encontrado, copiando desde .env.example"
    cp .env.example .env
    print_warning "⚠️  IMPORTANTE: Edita .env y cambia POSTGRES_PASSWORD y NIST_API_KEY"
    echo ""
    read -p "Presiona Enter cuando hayas editado .env..."
fi
print_success ".env encontrado"

# 2. Verificar Docker
echo ""
echo "2️⃣  Verificando Docker..."
if ! command -v docker &> /dev/null; then
    print_error "Docker no está instalado"
    exit 1
fi
print_success "Docker instalado"

if ! command -v docker-compose &> /dev/null; then
    print_error "docker-compose no está instalado"
    exit 1
fi
print_success "docker-compose instalado"

# 3. Verificar recursos
echo ""
echo "3️⃣  Verificando recursos del sistema..."
total_ram=$(free -g | awk '/^Mem:/{print $2}')
if [ "$total_ram" -lt 8 ]; then
    print_warning "RAM disponible: ${total_ram}GB (recomendado: 8GB+)"
else
    print_success "RAM disponible: ${total_ram}GB"
fi

# 4. Build de servicios
echo ""
echo "4️⃣  Construyendo servicios..."
print_info "Esto puede tardar varios minutos en la primera vez..."
docker-compose -f docker-compose.yml build
print_success "Servicios construidos"

# 5. Levantar infraestructura primero
echo ""
echo "5️⃣  Levantando infraestructura (Kafka, PostgreSQL, Redis)..."
docker-compose -f docker-compose.yml up -d zookeeper kafka postgres redis
print_info "Esperando a que Kafka esté listo (30 segundos)..."
sleep 30
print_success "Infraestructura levantada"

# 6. Crear topics de Kafka
echo ""
echo "6️⃣  Creando topics de Kafka..."
docker-compose -f docker-compose.yml up -d kafka-init
sleep 5
print_success "Topics de Kafka creados"

# 7. Levantar servicios
echo ""
echo "7️⃣  Levantando microservicios..."
docker-compose -f docker-compose.yml up -d cve-scraper cve-processor alert-manager api-gateway
print_success "Microservicios levantados"

# 8. Verificar estado
echo ""
echo "8️⃣  Verificando estado de servicios..."
sleep 10

# Check API Gateway
if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
    print_success "API Gateway respondiendo"
else
    print_warning "API Gateway aún no está listo"
fi

# Check Kafka
if docker exec soc-kafka kafka-topics --bootstrap-server localhost:9092 --list > /dev/null 2>&1; then
    print_success "Kafka funcionando"
else
    print_warning "Kafka aún no está listo"
fi

# Check PostgreSQL
if docker-compose -f docker-compose.yml exec -T postgres psql -U soc_user -d soc_alerting -c "SELECT 1;" > /dev/null 2>&1; then
    print_success "PostgreSQL funcionando"
else
    print_warning "PostgreSQL aún no está listo"
fi

# Completado
echo ""
echo "=================================================="
echo -e "${GREEN}✅ ¡Sistema levantado!${NC}"
echo "=================================================="
echo ""
echo "🔍 Ver estado de servicios:"
echo "   docker-compose -f docker-compose.yml ps"
echo ""
echo "📋 Ver logs:"
echo "   docker-compose -f docker-compose.yml logs -f"
echo ""
echo "🌐 API Gateway:"
echo "   http://localhost:8000/docs (Swagger UI)"
echo "   curl http://localhost:8000/health"
echo ""
echo "📊 Ver mensajes en Kafka:"
echo "   docker exec soc-kafka kafka-console-consumer \\"
echo "     --bootstrap-server localhost:9092 \\"
echo "     --topic cve.raw --from-beginning"
echo ""
echo "🛑 Detener todo:"
echo "   docker-compose -f docker-compose.yml down"
echo ""
echo "📖 Más info en: README-MICROSERVICES.md"
echo ""
