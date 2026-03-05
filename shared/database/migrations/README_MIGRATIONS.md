# Database Migrations

## 🚨 IMPORTANT: Which Migration to Use?

### Fresh Start (Recommended) ✅

If you're starting fresh or can drop your existing database:

```bash
# Drop all tables if they exist
alembic downgrade base

# Run fresh versioned schema
alembic upgrade 002_fresh_versioned
```

**Use migration: `002_fresh_versioned_schema.py`**

---

### Migrating from Old Schema ⚠️

If you already have the old monolithic schema (from `000_initial`) with data:

```bash
# Apply progressive migration
alembic upgrade 001_versioned
```

**Use migration: `001_versioned_schema.py`**

This will:
1. Migrate your existing CVEs from monolithic to versioned schema
2. Keep your data as version 1
3. Backup old tables as `cves_old`

---

## Schema Comparison

### ❌ Old Schema (000_initial_minimal_schema.py)

**DEPRECATED - Do not use**

```sql
CREATE TABLE cves (
    cve_id VARCHAR(20) PRIMARY KEY,
    description TEXT,
    cvss_score FLOAT,
    severity VARCHAR(20),
    version INTEGER,              -- ❌ Just a counter
    ... -- 17 more fields
    updated_at TIMESTAMP
);

CREATE TABLE cve_update_history (  -- ❌ Redundant
    id UUID PRIMARY KEY,
    cve_id VARCHAR(20),
    change_type VARCHAR(50),
    old_value VARCHAR(255),
    new_value VARCHAR(255)
);
```

**Problems:**
- ❌ Monolithic (all data in one table)
- ❌ No real versioning (just a counter)
- ❌ No snapshot capability
- ❌ Separate update history table (redundant)
- ❌ No race condition protection

---

### ✅ New Schema (002_fresh_versioned_schema.py)

**Current - Production Ready**

```sql
-- Table 1: Header (Identity only)
CREATE TABLE cves (
    cve_id VARCHAR(20) PRIMARY KEY,
    first_seen TIMESTAMP,
    created_at TIMESTAMP,
    current_version_id UUID          -- ✅ Pointer to latest
);

-- Table 2: Versions (Complete snapshots)
CREATE TABLE cve_versions (
    id UUID PRIMARY KEY,
    cve_id VARCHAR(20) REFERENCES cves(cve_id),
    version INTEGER,                 -- ✅ 1, 2, 3...
    description TEXT,                -- ✅ Full snapshot
    cvss_score FLOAT,
    severity VARCHAR(20),
    ... -- 17 critical fields
    created_at TIMESTAMP,            -- ✅ When this version was created
    UNIQUE(cve_id, version)          -- ✅ Race condition protection
);
```

**Advantages:**
- ✅ Clean separation (header vs data)
- ✅ True versioning with snapshots
- ✅ Race condition protection (`UNIQUE(cve_id, version)`)
- ✅ Fast current version lookup (`current_version_id`)
- ✅ Complete history without separate table
- ✅ Kafka-ready with manual commits

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     CVE Versioning Flow                      │
└─────────────────────────────────────────────────────────────┘

First Time:
  Scraper → Kafka → Consumer → DB
                                ↓
                    ┌───────────────────────┐
                    │ CVE (header)          │
                    │ cve_id: CVE-2024-1234 │
                    │ current_version_id: 1 │──┐
                    └───────────────────────┘  │
                                               │
                    ┌──────────────────────────▼
                    │ CVEVersion v1            │
                    │ severity: HIGH           │
                    │ cvss_score: 7.5          │
                    │ description: ...         │
                    └──────────────────────────┘

Update Detected:
  Scraper → Kafka → Consumer → DB
                                ↓
                    ┌───────────────────────┐
                    │ CVE (header)          │
                    │ current_version_id: 2 │──┐ (updated)
                    └───────────────────────┘  │
                                               │
                    ┌──────────────────────────┼──┐
                    │ CVEVersion v1            │  │
                    │ (unchanged)              │  │
                    └──────────────────────────┘  │
                                                  │
                    ┌──────────────────────────────▼
                    │ CVEVersion v2 (NEW)          │
                    │ severity: CRITICAL           │
                    │ cvss_score: 9.8              │
                    │ is_in_cisa_kev: true         │
                    └──────────────────────────────┘
```

---

## Race Condition Protection

### The Problem

With Kafka consumers in parallel:

```
Consumer 1                    Consumer 2
    │                             │
    ├─ Read: current v=1          │
    │                             ├─ Read: current v=1
    ├─ Create v=2                 │
    │                             ├─ Create v=2 ❌ CONFLICT
    └─ Commit                     └─ Commit
```

### The Solution

```sql
-- UniqueConstraint prevents duplicate versions
ALTER TABLE cve_versions
ADD CONSTRAINT uq_cve_version UNIQUE (cve_id, version);

-- SELECT FOR UPDATE locks row during transaction
SELECT * FROM cves
WHERE cve_id = 'CVE-2024-1234'
FOR UPDATE;  -- ✅ Locks until commit

-- Retry logic in application
for attempt in range(max_retries=3):
    try:
        save_version()
        break
    except IntegrityError:
        retry()
```

**Result:** Only ONE consumer can create v2. The other gets `IntegrityError` and retries.

---

## Migration Commands

### Check current version
```bash
alembic current
```

### View history
```bash
alembic history --verbose
```

### Upgrade to specific version
```bash
alembic upgrade 002_fresh_versioned
```

### Rollback
```bash
alembic downgrade base
```

### Generate new migration (auto-detect changes)
```bash
alembic revision --autogenerate -m "description"
```

---

## Troubleshooting

### Error: "relation 'cves' already exists"

You already have the old schema. Options:

1. **Drop and recreate (loses data)**:
   ```bash
   alembic downgrade base
   alembic upgrade 002_fresh_versioned
   ```

2. **Migrate with data preservation**:
   ```bash
   alembic upgrade 001_versioned
   ```

### Error: "UniqueViolation: duplicate key value violates unique constraint"

This is the race condition protection working! The consumer will automatically retry.

### Check which tables exist
```bash
psql -d soc_alerting -c "\dt"
```

### View table structure
```bash
psql -d soc_alerting -c "\d cves"
psql -d soc_alerting -c "\d cve_versions"
```

---

## Best Practices

1. **Always backup before migrating**:
   ```bash
   pg_dump soc_alerting > backup_$(date +%Y%m%d).sql
   ```

2. **Test migrations on dev first**:
   ```bash
   # Dev environment
   alembic upgrade head

   # Verify
   psql -d soc_alerting_dev -c "SELECT COUNT(*) FROM cves;"
   ```

3. **Monitor Kafka consumers during migration**:
   - Stop consumers before migration
   - Run migration
   - Restart consumers
   - Watch logs for race condition retries

---

## Summary

| Migration | Status | Use Case |
|-----------|--------|----------|
| `000_initial_minimal_schema.py` | ❌ Deprecated | Don't use |
| `001_versioned_schema.py` | ⚠️ Migration | Has old data to migrate |
| `002_fresh_versioned_schema.py` | ✅ Recommended | Fresh start |

**Default choice:** Use `002_fresh_versioned_schema.py` 🚀
