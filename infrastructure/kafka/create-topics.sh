#!/bin/bash
# ============================================================================
# Kafka Topics Creation - SOC Alerting System
# ============================================================================
set -e

KAFKA_BROKER="kafka:29092"

echo "🔧 Esperando a que Kafka esté listo..."
sleep 10

echo "📋 Creando topics de Kafka..."

# Topic 1: CVEs crudos desde NIST/CISA
kafka-topics --bootstrap-server $KAFKA_BROKER \
  --create \
  --if-not-exists \
  --topic cve.raw \
  --partitions 3 \
  --replication-factor 1 \
  --config retention.ms=604800000

echo "✓ Topic creado: cve.raw (CVEs crudos)"

# Topic 2: CVEs enriquecidos con NLP
kafka-topics --bootstrap-server $KAFKA_BROKER \
  --create \
  --if-not-exists \
  --topic cve.enriched \
  --partitions 3 \
  --replication-factor 1 \
  --config retention.ms=604800000

echo "✓ Topic creado: cve.enriched (CVEs enriquecidos)"

# Topic 3: Alertas generadas
kafka-topics --bootstrap-server $KAFKA_BROKER \
  --create \
  --if-not-exists \
  --topic cve.alerts \
  --partitions 3 \
  --replication-factor 1 \
  --config retention.ms=2592000000

echo "✓ Topic creado: cve.alerts (Alertas)"

# Topic 4: Notificaciones (emails, Slack, etc)
kafka-topics --bootstrap-server $KAFKA_BROKER \
  --create \
  --if-not-exists \
  --topic cve.notifications \
  --partitions 3 \
  --replication-factor 1 \
  --config retention.ms=86400000

echo "✓ Topic creado: cve.notifications (Notificaciones)"

# Topic 5: Dead Letter Queue (errores)
kafka-topics --bootstrap-server $KAFKA_BROKER \
  --create \
  --if-not-exists \
  --topic cve.dlq \
  --partitions 1 \
  --replication-factor 1 \
  --config retention.ms=2592000000

echo "✓ Topic creado: cve.dlq (Dead Letter Queue)"

echo ""
echo "✅ Todos los topics creados exitosamente"
echo ""
echo "📊 Listado de topics:"
kafka-topics --bootstrap-server $KAFKA_BROKER --list
