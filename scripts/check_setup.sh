#!/bin/bash
# ============================================================================
# Setup Checker - Verifica que todo esté configurado correctamente
# ============================================================================

echo "======================================"
echo "SOC Alerting - Setup Checker"
echo "======================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Docker
echo -n "Checking Docker... "
if command -v docker &> /dev/null; then
    echo -e "${GREEN}✓ Installed${NC}"
    docker --version
else
    echo -e "${RED}✗ Not installed${NC}"
    echo "  Install Docker from: https://docs.docker.com/get-docker/"
fi
echo ""

# Check Docker Compose
echo -n "Checking Docker Compose... "
if command -v docker-compose &> /dev/null; then
    echo -e "${GREEN}✓ Installed${NC}"
    docker-compose --version
else
    echo -e "${RED}✗ Not installed${NC}"
    echo "  Install Docker Compose from: https://docs.docker.com/compose/install/"
fi
echo ""

# Check Python
echo -n "Checking Python 3.11+... "
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    echo -e "${GREEN}✓ Installed${NC}"
    echo "  Version: $PYTHON_VERSION"
else
    echo -e "${RED}✗ Not installed${NC}"
    echo "  Install Python 3.11+ from: https://www.python.org/downloads/"
fi
echo ""

# Check .env file
echo -n "Checking .env file... "
if [ -f ".env" ]; then
    echo -e "${GREEN}✓ Exists${NC}"

    # Check for API key
    if grep -q "NIST_API_KEY=.\+" .env; then
        echo -e "  ${GREEN}✓ NIST API Key configured${NC}"
    else
        echo -e "  ${YELLOW}⚠ NIST API Key not configured (optional but recommended)${NC}"
        echo "    Get one from: https://nvd.nist.gov/developers/request-an-api-key"
    fi
else
    echo -e "${RED}✗ Not found${NC}"
    echo "  Run: cp .env.scraper .env"
fi
echo ""

# Check Docker services status
echo "Checking Docker services..."
if command -v docker-compose &> /dev/null; then
    cd "$(dirname "$0")/.." || exit

    if docker-compose -f docker-compose.scraper.yml ps | grep -q "Up"; then
        echo -e "${GREEN}✓ Services are running${NC}"
        docker-compose -f docker-compose.scraper.yml ps
    else
        echo -e "${YELLOW}⚠ Services are not running${NC}"
        echo "  Run: docker-compose -f docker-compose.scraper.yml up -d"
    fi
else
    echo -e "${YELLOW}⚠ Cannot check (docker-compose not installed)${NC}"
fi
echo ""

# Check ports
echo "Checking ports..."
check_port() {
    PORT=$1
    NAME=$2
    if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Port $PORT ($NAME) is in use${NC}"
    else
        echo -e "${YELLOW}⚠ Port $PORT ($NAME) is free${NC}"
    fi
}

check_port 9092 "Kafka"
check_port 5432 "PostgreSQL"
check_port 8080 "Kafka UI"
echo ""

echo "======================================"
echo "Setup check complete!"
echo "======================================"
echo ""
echo "Next steps:"
echo "  1. Configure .env if not done"
echo "  2. Run: docker-compose -f docker-compose.scraper.yml up -d"
echo "  3. Run: python scripts/seed_database.py (optional)"
echo "  4. Check logs: docker-compose -f docker-compose.scraper.yml logs -f cve-scraper"
echo ""
