#!/usr/bin/env python3
"""
Execute scalability migration: Create CPE, CISA metadata, and references tables.

This migration:
1. Creates cisa_kev_metadata table (separates CISA fields)
2. Creates affected_products table (CPE for version matching)
3. Creates cve_references table (normalized references)
4. Migrates existing data from cves table
5. Drops redundant columns from cves table

Usage:
    python scripts/migrate_scalability_tables.py
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parents[1]))

from soc_alerting.database.connection import get_database
from soc_alerting.models.database import Base, CISAKEVMetadata, AffectedProduct, CVEReference
from sqlalchemy import text
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    """Execute scalability migration."""
    logger.info("=" * 80)
    logger.info("Migration: Scalability Tables (CPE + CISA + References)")
    logger.info("=" * 80)

    db = get_database()

    if not db.health_check():
        logger.error("Database connection failed!")
        sys.exit(1)

    logger.info("✓ Database connection healthy")

    session = db.get_raw_session()

    try:
        # Check if tables already exist
        result = session.execute(text("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_name IN ('cisa_kev_metadata', 'affected_products', 'cve_references')
        """))

        existing_tables = [row[0] for row in result]

        if len(existing_tables) == 3:
            logger.info("✓ Tables already exist, skipping creation")
        else:
            logger.info("")
            logger.info("Creating new tables...")

            # Enable pg_trgm extension (must commit before using)
            logger.info("  • Enabling pg_trgm extension...")
            session.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
            session.commit()  # Commit extension before creating indexes that use it

            # Create tables using SQLAlchemy models
            logger.info("  • Creating cisa_kev_metadata...")
            logger.info("  • Creating affected_products...")
            logger.info("  • Creating cve_references...")

            Base.metadata.create_all(
                bind=db.engine,
                tables=[
                    CISAKEVMetadata.__table__,
                    AffectedProduct.__table__,
                    CVEReference.__table__
                ]
            )

            session.commit()
            logger.info("✓ Tables created")

        # Migrate data from cves table
        logger.info("")
        logger.info("Migrating existing data...")

        # Check if cves table has CISA columns
        result = session.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'cves'
            AND column_name IN ('cisa_exploit_add', 'cisa_action_due', 'references')
        """))

        existing_columns = [row[0] for row in result]

        if not existing_columns:
            logger.info("  ✓ Data already migrated, columns removed")
        else:
            logger.info(f"  • Found columns to migrate: {existing_columns}")

            # Migrate CISA data
            if 'cisa_exploit_add' in existing_columns:
                logger.info("  • Migrating CISA KEV metadata...")
                session.execute(text("""
                    INSERT INTO cisa_kev_metadata (
                        cve_id,
                        exploit_add,
                        action_due,
                        required_action,
                        vulnerability_name,
                        known_ransomware,
                        created_at,
                        updated_at
                    )
                    SELECT
                        cve_id,
                        cisa_exploit_add,
                        cisa_action_due,
                        COALESCE(cisa_required_action, 'Apply updates per vendor instructions'),
                        cisa_vulnerability_name,
                        COALESCE(cisa_known_ransomware, false),
                        CURRENT_TIMESTAMP,
                        CURRENT_TIMESTAMP
                    FROM cves
                    WHERE is_in_cisa_kev = true
                      AND cisa_exploit_add IS NOT NULL
                    ON CONFLICT (cve_id) DO NOTHING
                """))

            # Migrate references
            if 'references' in existing_columns:
                logger.info("  • Migrating references...")
                session.execute(text("""
                    INSERT INTO cve_references (id, cve_id, url, source, created_at)
                    SELECT
                        gen_random_uuid(),
                        c.cve_id,
                        jsonb_array_elements_text(c.references) as url,
                        'NIST' as source,
                        CURRENT_TIMESTAMP
                    FROM cves c
                    WHERE c.references IS NOT NULL
                      AND jsonb_array_length(c.references) > 0
                    ON CONFLICT (cve_id, url) DO NOTHING
                """))

            session.commit()
            logger.info("  ✓ Data migrated")

            # Drop old columns
            logger.info("")
            logger.info("Cleaning up old columns...")

            if 'cisa_exploit_add' in existing_columns:
                logger.info("  • Dropping CISA columns from cves table...")
                session.execute(text("ALTER TABLE cves DROP COLUMN IF EXISTS cisa_exploit_add"))
                session.execute(text("ALTER TABLE cves DROP COLUMN IF EXISTS cisa_action_due"))
                session.execute(text("ALTER TABLE cves DROP COLUMN IF EXISTS cisa_required_action"))
                session.execute(text("ALTER TABLE cves DROP COLUMN IF EXISTS cisa_vulnerability_name"))
                session.execute(text("ALTER TABLE cves DROP COLUMN IF EXISTS cisa_known_ransomware"))

            if 'references' in existing_columns:
                logger.info("  • Dropping references column from cves table...")
                session.execute(text('ALTER TABLE cves DROP COLUMN IF EXISTS "references"'))

            session.commit()
            logger.info("  ✓ Columns dropped")

        # Statistics
        result = session.execute(text("""
            SELECT
                (SELECT count(*) FROM cisa_kev_metadata) as cisa_records,
                (SELECT count(*) FROM affected_products) as cpe_records,
                (SELECT count(*) FROM cve_references) as ref_records
        """))

        cisa_count, cpe_count, ref_count = result.fetchone()

        logger.info("")
        logger.info("=" * 80)
        logger.info("Migration completed successfully!")
        logger.info("=" * 80)
        logger.info("")
        logger.info(f"  • CISA KEV metadata: {cisa_count} records")
        logger.info(f"  • CPE records: {cpe_count} records (populate from NIST)")
        logger.info(f"  • References: {ref_count} records")
        logger.info("")
        logger.info("Next steps:")
        logger.info("  1. Update CVE processor to populate CPE data")
        logger.info("  2. Add API endpoints for vulnerability management")
        logger.info("  3. Test queries: affected_products joins")

    except Exception as e:
        logger.error(f"Migration failed: {e}", exc_info=True)
        session.rollback()
        sys.exit(1)
    finally:
        session.close()


if __name__ == "__main__":
    main()
