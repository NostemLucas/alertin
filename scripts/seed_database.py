#!/usr/bin/env python3
"""
Seed Database Script - Populate database with sample data
"""
import asyncio
import sys
import os
from datetime import datetime, timedelta
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "shared"))

from shared.database.connection import get_database
from shared.models.database_minimal import CVERecord
from shared.models.domain_minimal import SeverityLevel, AttackVector, AttackComplexity
from sqlalchemy import text
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


async def check_connection():
    """Verify database connection."""
    logger.info("Checking database connection...")
    db = get_database()

    try:
        result = await db.health_check(detailed=True)
        if result.healthy:
            logger.info(f"✓ Database connection successful (latency: {result.latency_ms}ms)")
            logger.info(f"  URL: {result.database_url}")
            if result.pool_stats:
                logger.info(f"  Pool size: {result.pool_stats['pool_size']}")
            return True
        else:
            logger.error(f"✗ Database connection failed: {result.error}")
            return False
    except Exception as e:
        logger.error(f"✗ Database connection error: {e}")
        return False


async def create_tables():
    """Create database tables if they don't exist."""
    logger.info("Creating database tables...")
    db = get_database()

    try:
        async with db.get_session() as session:
            # Import Base to create tables
            from shared.models.database_minimal import Base

            # Create all tables
            async with db.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            logger.info("✓ Database tables created successfully")
            return True
    except Exception as e:
        logger.error(f"✗ Error creating tables: {e}")
        return False


async def seed_sample_cves():
    """Insert sample CVE records."""
    logger.info("Seeding sample CVE records...")
    db = get_database()

    # Sample CVE data
    sample_cves = [
        {
            "cve_id": "CVE-2024-12345",
            "description": "Critical remote code execution vulnerability in Apache Log4j",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": SeverityLevel.CRITICAL,
            "cwe_id": "CWE-502",
            "attack_vector": AttackVector.NETWORK,
            "attack_complexity": AttackComplexity.LOW,
            "requires_auth": False,
            "user_interaction_required": False,
            "affected_products": [
                {"vendor": "apache", "product": "log4j", "versions": ["2.0-2.14.1"]}
            ],
            "is_in_cisa_kev": True,
            "cisa_date_added": datetime.utcnow() - timedelta(days=30),
            "cisa_required_action": "Apply patches immediately",
            "cisa_due_date": datetime.utcnow() + timedelta(days=7),
            "published_date": datetime.utcnow() - timedelta(days=60),
            "last_modified_date": datetime.utcnow() - timedelta(days=30),
        },
        {
            "cve_id": "CVE-2024-54321",
            "description": "SQL injection vulnerability in WordPress plugin",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "severity": SeverityLevel.HIGH,
            "cwe_id": "CWE-89",
            "attack_vector": AttackVector.NETWORK,
            "attack_complexity": AttackComplexity.LOW,
            "requires_auth": False,
            "user_interaction_required": False,
            "affected_products": [
                {"vendor": "wordpress", "product": "contact-form-7", "versions": ["5.0-5.6"]}
            ],
            "is_in_cisa_kev": False,
            "published_date": datetime.utcnow() - timedelta(days=10),
            "last_modified_date": datetime.utcnow() - timedelta(days=5),
        },
        {
            "cve_id": "CVE-2024-99999",
            "description": "Cross-site scripting (XSS) in popular JavaScript framework",
            "cvss_score": 6.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "severity": SeverityLevel.MEDIUM,
            "cwe_id": "CWE-79",
            "attack_vector": AttackVector.NETWORK,
            "attack_complexity": AttackComplexity.LOW,
            "requires_auth": False,
            "user_interaction_required": True,
            "affected_products": [
                {"vendor": "react", "product": "react-dom", "versions": ["17.0.0-17.0.2"]}
            ],
            "is_in_cisa_kev": False,
            "published_date": datetime.utcnow() - timedelta(days=3),
            "last_modified_date": datetime.utcnow() - timedelta(days=1),
        },
    ]

    try:
        async with db.get_session() as session:
            inserted_count = 0

            for cve_data in sample_cves:
                # Check if CVE already exists
                result = await session.execute(
                    text("SELECT cve_id FROM cve_records WHERE cve_id = :cve_id"),
                    {"cve_id": cve_data["cve_id"]}
                )
                exists = result.scalar()

                if exists:
                    logger.info(f"  Skipping {cve_data['cve_id']} (already exists)")
                    continue

                # Create CVE record
                cve = CVERecord(**cve_data)
                session.add(cve)
                inserted_count += 1
                logger.info(f"  ✓ Inserted {cve_data['cve_id']}")

            await session.commit()
            logger.info(f"✓ Seeded {inserted_count} CVE records")
            return True

    except Exception as e:
        logger.error(f"✗ Error seeding CVEs: {e}", exc_info=True)
        return False


async def show_statistics():
    """Show database statistics."""
    logger.info("\nDatabase Statistics:")
    db = get_database()

    try:
        async with db.get_session() as session:
            # Total CVEs
            result = await session.execute(text("SELECT COUNT(*) FROM cve_records"))
            total = result.scalar()
            logger.info(f"  Total CVEs: {total}")

            # By severity
            result = await session.execute(
                text("SELECT severity, COUNT(*) FROM cve_records GROUP BY severity")
            )
            logger.info("  By Severity:")
            for row in result:
                logger.info(f"    {row[0]}: {row[1]}")

            # CISA KEV
            result = await session.execute(
                text("SELECT COUNT(*) FROM cve_records WHERE is_in_cisa_kev = true")
            )
            kev_count = result.scalar()
            logger.info(f"  CISA KEV: {kev_count}")

    except Exception as e:
        logger.error(f"✗ Error getting statistics: {e}")


async def main():
    """Main seed function."""
    logger.info("=" * 60)
    logger.info("SOC Alerting - Database Seed Script")
    logger.info("=" * 60)

    # Check connection
    if not await check_connection():
        logger.error("Failed to connect to database. Check your configuration.")
        sys.exit(1)

    # Create tables
    if not await create_tables():
        logger.error("Failed to create tables.")
        sys.exit(1)

    # Seed data
    if not await seed_sample_cves():
        logger.error("Failed to seed data.")
        sys.exit(1)

    # Show stats
    await show_statistics()

    logger.info("\n" + "=" * 60)
    logger.info("✓ Database seeding completed successfully!")
    logger.info("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
