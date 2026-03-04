#!/usr/bin/env python3
"""
Seed Database Script - Populate database with sample data (Versioned Model)
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
from shared.models.db_models import CVE, CVEVersion, Base
from shared.models.domain import SeverityLevel, AttackVector, AttackComplexity
from sqlalchemy import text
import logging
import uuid

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
            # Create all tables
            async with db.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            logger.info("✓ Database tables created successfully")
            return True
    except Exception as e:
        logger.error(f"✗ Error creating tables: {e}")
        return False


async def seed_sample_cves():
    """Insert sample CVE records with versioned model."""
    logger.info("Seeding sample CVE records...")
    db = get_database()

    # Sample CVE data
    sample_cves = [
        {
            "cve_id": "CVE-2024-12345",
            "description": "Critical remote code execution vulnerability in Apache Log4j",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": SeverityLevel.CRITICAL.value,
            "cwe_id": "CWE-502",
            "attack_vector": AttackVector.NETWORK.value,
            "attack_complexity": AttackComplexity.LOW.value,
            "requires_auth": False,
            "user_interaction_required": False,
            "affected_products": [
                {"vendor": "apache", "product": "log4j", "versions": ["2.0-2.14.1"]}
            ],
            "is_in_cisa_kev": True,
            "cisa_date_added": datetime.utcnow() - timedelta(days=30),
            "cisa_required_action": "Apply patches immediately",
            "cisa_due_date": datetime.utcnow() + timedelta(days=7),
            "cisa_known_ransomware": False,
            "status_nist": "Analyzed",
            "source": "cna@apache.org",
            "published_date": datetime.utcnow() - timedelta(days=60),
            "last_modified_date": datetime.utcnow() - timedelta(days=30),
            "primary_reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
            "references": ["https://logging.apache.org/log4j/2.x/security.html"],
        },
        {
            "cve_id": "CVE-2024-54321",
            "description": "SQL injection vulnerability in WordPress plugin",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "severity": SeverityLevel.HIGH.value,
            "cwe_id": "CWE-89",
            "attack_vector": AttackVector.NETWORK.value,
            "attack_complexity": AttackComplexity.LOW.value,
            "requires_auth": False,
            "user_interaction_required": False,
            "affected_products": [
                {"vendor": "wordpress", "product": "contact-form-7", "versions": ["5.0-5.6"]}
            ],
            "is_in_cisa_kev": False,
            "cisa_known_ransomware": False,
            "status_nist": "Analyzed",
            "source": "cna@wordpress.org",
            "published_date": datetime.utcnow() - timedelta(days=10),
            "last_modified_date": datetime.utcnow() - timedelta(days=5),
            "primary_reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-54321",
            "references": ["https://wordpress.org/plugins/contact-form-7/"],
        },
        {
            "cve_id": "CVE-2024-99999",
            "description": "Cross-site scripting (XSS) in popular JavaScript framework",
            "cvss_score": 6.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "severity": SeverityLevel.MEDIUM.value,
            "cwe_id": "CWE-79",
            "attack_vector": AttackVector.NETWORK.value,
            "attack_complexity": AttackComplexity.LOW.value,
            "requires_auth": False,
            "user_interaction_required": True,
            "affected_products": [
                {"vendor": "react", "product": "react-dom", "versions": ["17.0.0-17.0.2"]}
            ],
            "is_in_cisa_kev": False,
            "cisa_known_ransomware": False,
            "status_nist": "Undergoing Analysis",
            "source": "cna@facebook.com",
            "published_date": datetime.utcnow() - timedelta(days=3),
            "last_modified_date": datetime.utcnow() - timedelta(days=1),
            "primary_reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-99999",
            "references": ["https://reactjs.org/security"],
        },
    ]

    try:
        async with db.get_session() as session:
            inserted_count = 0

            for cve_data in sample_cves:
                # Check if CVE already exists
                result = await session.execute(
                    text("SELECT cve_id FROM cves WHERE cve_id = :cve_id"),
                    {"cve_id": cve_data["cve_id"]}
                )
                exists = result.scalar()

                if exists:
                    logger.info(f"  Skipping {cve_data['cve_id']} (already exists)")
                    continue

                # Create CVE header
                cve_header = CVE(
                    cve_id=cve_data["cve_id"],
                    first_seen=datetime.utcnow(),
                    created_at=datetime.utcnow(),
                    current_version_id=None
                )
                session.add(cve_header)
                await session.flush()

                # Create version 1
                version_id = uuid.uuid4()
                version = CVEVersion(
                    id=version_id,
                    cve_id=cve_data["cve_id"],
                    version=1,
                    description=cve_data["description"],
                    cwe_id=cve_data.get("cwe_id"),
                    cvss_score=cve_data.get("cvss_score"),
                    cvss_vector=cve_data.get("cvss_vector"),
                    severity=cve_data["severity"],
                    attack_vector=cve_data.get("attack_vector"),
                    attack_complexity=cve_data.get("attack_complexity"),
                    requires_auth=cve_data.get("requires_auth"),
                    user_interaction_required=cve_data.get("user_interaction_required"),
                    affected_products=cve_data.get("affected_products", []),
                    status_nist=cve_data["status_nist"],
                    source=cve_data["source"],
                    published_date=cve_data["published_date"],
                    last_modified_date=cve_data["last_modified_date"],
                    is_in_cisa_kev=cve_data.get("is_in_cisa_kev", False),
                    cisa_date_added=cve_data.get("cisa_date_added"),
                    cisa_due_date=cve_data.get("cisa_due_date"),
                    cisa_required_action=cve_data.get("cisa_required_action"),
                    cisa_known_ransomware=cve_data.get("cisa_known_ransomware", False),
                    primary_reference=cve_data.get("primary_reference"),
                    references=cve_data.get("references", []),
                    created_at=datetime.utcnow(),
                )
                session.add(version)
                await session.flush()

                # Update current_version_id
                cve_header.current_version_id = version_id
                await session.flush()

                inserted_count += 1
                logger.info(f"  ✓ Inserted {cve_data['cve_id']} v1")

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
            # Total CVEs (unique)
            result = await session.execute(text("SELECT COUNT(*) FROM cves"))
            total = result.scalar()
            logger.info(f"  Total CVEs: {total}")

            # Total versions
            result = await session.execute(text("SELECT COUNT(*) FROM cve_versions"))
            total_versions = result.scalar()
            logger.info(f"  Total Versions: {total_versions}")

            # By severity (latest version)
            result = await session.execute(
                text("""
                    SELECT v.severity, COUNT(*)
                    FROM cve_versions v
                    JOIN cves c ON c.current_version_id = v.id
                    GROUP BY v.severity
                """)
            )
            logger.info("  By Severity (latest version):")
            for row in result:
                logger.info(f"    {row[0]}: {row[1]}")

            # CISA KEV (latest version)
            result = await session.execute(
                text("""
                    SELECT COUNT(*)
                    FROM cve_versions v
                    JOIN cves c ON c.current_version_id = v.id
                    WHERE v.is_in_cisa_kev = true
                """)
            )
            kev_count = result.scalar()
            logger.info(f"  CISA KEV (latest version): {kev_count}")

    except Exception as e:
        logger.error(f"✗ Error getting statistics: {e}")


async def main():
    """Main seed function."""
    logger.info("=" * 60)
    logger.info("SOC Alerting - Database Seed Script (Versioned Model)")
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
