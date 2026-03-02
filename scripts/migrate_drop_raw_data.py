#!/usr/bin/env python3
"""
Migration script to drop raw_data columns from cves table.

This removes nist_raw_data and cisa_raw_data JSONB columns
that were taking up storage space unnecessarily.

Usage:
    python scripts/migrate_drop_raw_data.py
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parents[1]))

from soc_alerting.database.connection import get_database
from sqlalchemy import text
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    """Execute migration to drop raw_data columns."""
    logger.info("=" * 80)
    logger.info("Migration: Drop raw_data columns")
    logger.info("=" * 80)

    db = get_database()

    # Check database connection
    if not db.health_check():
        logger.error("Database connection failed!")
        sys.exit(1)

    logger.info("✓ Database connection healthy")

    # Get raw session
    session = db.get_raw_session()

    try:
        # Check if columns exist
        result = session.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'cves'
            AND column_name IN ('nist_raw_data', 'cisa_raw_data')
        """))

        existing_columns = [row[0] for row in result]

        if not existing_columns:
            logger.info("✓ Columns already dropped, nothing to do")
            return

        logger.info(f"Found columns to drop: {existing_columns}")

        # Drop nist_raw_data
        if 'nist_raw_data' in existing_columns:
            logger.info("Dropping nist_raw_data column...")
            session.execute(text("ALTER TABLE cves DROP COLUMN IF EXISTS nist_raw_data"))
            logger.info("✓ Dropped nist_raw_data")

        # Drop cisa_raw_data
        if 'cisa_raw_data' in existing_columns:
            logger.info("Dropping cisa_raw_data column...")
            session.execute(text("ALTER TABLE cves DROP COLUMN IF EXISTS cisa_raw_data"))
            logger.info("✓ Dropped cisa_raw_data")

        # Commit transaction
        session.commit()
        logger.info("✓ Transaction committed")

        # Verify columns are gone
        result = session.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'cves'
            AND column_name IN ('nist_raw_data', 'cisa_raw_data')
        """))

        remaining = [row[0] for row in result]

        if remaining:
            logger.error(f"✗ Columns still exist: {remaining}")
            sys.exit(1)

        logger.info("")
        logger.info("=" * 80)
        logger.info("Migration completed successfully!")
        logger.info("=" * 80)
        logger.info("")
        logger.info("Benefits:")
        logger.info("  - Reduced storage per CVE: ~15-50 KB → ~2 KB")
        logger.info("  - Faster queries (smaller row size)")
        logger.info("  - Improved cache efficiency")

    except Exception as e:
        logger.error(f"Migration failed: {e}")
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    main()
