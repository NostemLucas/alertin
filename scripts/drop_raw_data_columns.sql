-- Migration: Remove raw_data columns
-- Purpose: Eliminate unused JSONB columns that bloat storage
-- Author: SOC Alerting System
-- Date: 2026-03-02

BEGIN;

-- Drop nist_raw_data column
ALTER TABLE cves DROP COLUMN IF EXISTS nist_raw_data;

-- Drop cisa_raw_data column
ALTER TABLE cves DROP COLUMN IF EXISTS cisa_raw_data;

-- Verify columns are gone
DO $$
DECLARE
    nist_exists BOOLEAN;
    cisa_exists BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'cves'
        AND column_name = 'nist_raw_data'
    ) INTO nist_exists;

    SELECT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'cves'
        AND column_name = 'cisa_raw_data'
    ) INTO cisa_exists;

    IF nist_exists OR cisa_exists THEN
        RAISE EXCEPTION 'Columns still exist after drop!';
    END IF;

    RAISE NOTICE 'Successfully dropped raw_data columns';
END $$;

COMMIT;
