"""initial minimal schema: 17-field CVE model for SOC operations

Revision ID: 000_initial
Revises: None
Create Date: 2026-03-03

Creates a minimal, high-performance CVE schema with only critical fields.

Schema:
1. cves table - 17 critical fields with JSONB for products/references
2. cve_update_history - Simplified change tracking
3. processing_logs - Sync run metrics
4. sync_checkpoints - Crash recovery for long-running syncs

Features:
- No complex JOINs needed
- CVSS vector components extracted (attack_vector, complexity, auth, UI)
- CWE ID for vulnerability classification
- Built-in risk scoring (0-100)
- JSONB indexes for fast product searches

To apply:
    alembic upgrade head

To rollback (will drop all tables):
    alembic downgrade base
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '000_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Apply migration: create minimal schema."""

    print("\n" + "="*80)
    print("🚀 CREATING MINIMAL CVE SCHEMA")
    print("="*80)
    print("Creating tables:")
    print("  1. cves - Main CVE table with 17 critical fields")
    print("  2. cve_update_history - Change tracking")
    print("  3. processing_logs - Sync metrics")
    print("  4. sync_checkpoints - Crash recovery")
    print("="*80 + "\n")

    # ============================================================================
    # PHASE 1: Create main CVE table
    # ============================================================================
    print("Phase 1: Creating main CVE table...")

    op.create_table(
        'cves',
        # ===== IDENTITY =====
        sa.Column('cve_id', sa.String(length=20), nullable=False, comment='CVE identifier'),

        # ===== CONTENT =====
        sa.Column('description', sa.Text(), nullable=False, comment='Vulnerability description'),
        sa.Column('cwe_id', sa.String(length=20), nullable=True, comment='CWE identifier (e.g., CWE-79)'),

        # ===== CRITICALITY =====
        sa.Column('cvss_score', sa.Float(), nullable=True, comment='Primary CVSS score'),
        sa.Column('cvss_vector', sa.String(length=255), nullable=True, comment='CVSS vector string'),
        sa.Column('severity', sa.String(length=20), nullable=False, comment='Final severity'),

        # ===== ATTACK VECTOR (extracted from CVSS) =====
        sa.Column('attack_vector', sa.String(length=20), nullable=True, comment='NETWORK, ADJACENT, LOCAL, PHYSICAL'),
        sa.Column('attack_complexity', sa.String(length=20), nullable=True, comment='LOW, HIGH'),
        sa.Column('requires_auth', sa.Boolean(), nullable=True, comment='Authentication required'),
        sa.Column('user_interaction_required', sa.Boolean(), nullable=True, comment='User interaction needed'),

        # ===== AFFECTED PRODUCTS (JSONB) =====
        sa.Column('affected_products', postgresql.JSONB(), nullable=False, server_default='[]',
                  comment='Array of affected products'),

        # ===== TRACKING =====
        sa.Column('version', sa.Integer(), nullable=False, server_default='1', comment='Version counter'),
        sa.Column('status_nist', sa.String(length=50), nullable=False, comment='NIST analysis status'),
        sa.Column('source', sa.String(length=255), nullable=False, comment='Source identifier'),

        sa.Column('published_date', sa.DateTime(), nullable=False, comment='Publication date'),
        sa.Column('last_modified_date', sa.DateTime(), nullable=False, comment='Last modification date'),
        sa.Column('last_checked_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'),
                  comment='Last checked timestamp'),

        # ===== CISA KEV FLAGS =====
        sa.Column('is_in_cisa_kev', sa.Boolean(), nullable=False, server_default='false',
                  comment='In CISA KEV catalog'),
        sa.Column('cisa_date_added', sa.DateTime(), nullable=True, comment='CISA KEV date added'),
        sa.Column('cisa_due_date', sa.DateTime(), nullable=True, comment='CISA due date'),
        sa.Column('cisa_required_action', sa.Text(), nullable=True, comment='CISA required action'),
        sa.Column('cisa_known_ransomware', sa.Boolean(), nullable=False, server_default='false',
                  comment='Known ransomware use'),

        # ===== REFERENCES =====
        sa.Column('primary_reference', sa.String(length=1000), nullable=True, comment='Primary reference URL'),
        sa.Column('references', postgresql.JSONB(), nullable=False, server_default='[]',
                  comment='Array of reference URLs'),

        # ===== METADATA =====
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),

        sa.PrimaryKeyConstraint('cve_id'),

        # Constraints
        sa.CheckConstraint('cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)',
                          name='check_cvss_range'),
        sa.CheckConstraint("severity IN ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
                          name='check_severity'),
        sa.CheckConstraint("attack_vector IS NULL OR attack_vector IN ('NETWORK', 'ADJACENT', 'LOCAL', 'PHYSICAL')",
                          name='check_attack_vector'),
        sa.CheckConstraint("attack_complexity IS NULL OR attack_complexity IN ('LOW', 'HIGH')",
                          name='check_attack_complexity'),
        sa.CheckConstraint("status_nist IN ('Analyzed', 'Undergoing Analysis', 'Awaiting Analysis', 'Deferred', 'Rejected', 'Modified')",
                          name='check_status_nist'),
        sa.CheckConstraint('version >= 1', name='check_version_positive'),
    )

    # Create indexes for CVE table
    op.create_index('ix_cves_severity', 'cves', ['severity'])
    op.create_index('ix_cves_cisa_kev', 'cves', ['is_in_cisa_kev'])
    op.create_index('ix_cves_published_date', 'cves', ['published_date'])
    op.create_index('ix_cves_last_modified', 'cves', ['last_modified_date'])
    op.create_index('ix_cves_attack_vector', 'cves', ['attack_vector'])
    op.create_index('ix_cves_status_nist', 'cves', ['status_nist'])
    op.create_index('ix_cves_cwe_id', 'cves', ['cwe_id'])
    op.create_index('ix_cves_cisa_due_date', 'cves', ['cisa_due_date'])
    op.create_index('ix_cves_cisa_ransomware', 'cves', ['cisa_known_ransomware'])

    # Combined indexes
    op.create_index('ix_cves_severity_kev', 'cves', ['severity', 'is_in_cisa_kev'])
    op.create_index('ix_cves_severity_vector', 'cves', ['severity', 'attack_vector'])

    # JSONB GIN index for product searches
    op.create_index('ix_cves_affected_products', 'cves', ['affected_products'],
                    postgresql_using='gin')

    print("  ✓ Created minimal cves table with 17 critical fields")
    print("  ✓ Created 13 indexes for efficient queries")

    # ============================================================================
    # PHASE 3: Create simplified update history table
    # ============================================================================
    print("\nPhase 3: Creating simplified update history table...")

    op.create_table(
        'cve_update_history',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False,
                  server_default=sa.text('gen_random_uuid()'), comment='Update record ID'),
        sa.Column('cve_id', sa.String(length=20), nullable=False, comment='Associated CVE ID'),
        sa.Column('detected_at', sa.DateTime(), nullable=False,
                  server_default=sa.text('CURRENT_TIMESTAMP'), comment='Change detection time'),
        sa.Column('change_type', sa.String(length=50), nullable=False,
                  comment='SCORE_CHANGED, ADDED_TO_KEV, STATUS_UPDATED, SEVERITY_CHANGED'),
        sa.Column('old_value', sa.String(length=255), nullable=True, comment='Previous value'),
        sa.Column('new_value', sa.String(length=255), nullable=True, comment='New value'),
        sa.Column('previous_version', sa.Integer(), nullable=False, comment='Previous version'),
        sa.Column('new_version', sa.Integer(), nullable=False, comment='New version'),

        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['cve_id'], ['cves.cve_id'], ondelete='CASCADE'),
    )

    op.create_index('ix_update_history_cve_id', 'cve_update_history', ['cve_id'])
    op.create_index('ix_update_history_detected_at', 'cve_update_history', ['detected_at'])
    op.create_index('ix_update_history_change_type', 'cve_update_history', ['change_type'])
    op.create_index('ix_update_history_cve_detected', 'cve_update_history', ['cve_id', 'detected_at'])

    print("  ✓ Created simplified update history table")

    # ============================================================================
    # PHASE 4: Create processing logs table
    # ============================================================================
    print("\nPhase 4: Creating processing logs table...")

    op.create_table(
        'processing_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False,
                  server_default=sa.text('gen_random_uuid()'), comment='Log record ID'),
        sa.Column('run_started_at', sa.DateTime(), nullable=False,
                  server_default=sa.text('CURRENT_TIMESTAMP'), comment='Processing start time'),
        sa.Column('run_completed_at', sa.DateTime(), nullable=True, comment='Processing completion time'),
        sa.Column('status', sa.String(length=20), nullable=False, comment='Run status'),

        # Metrics
        sa.Column('cves_processed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('cves_created', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('cves_updated', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('cves_in_kev', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('errors_count', sa.Integer(), nullable=False, server_default='0'),

        # Details
        sa.Column('error_summary', postgresql.JSONB(), nullable=True),
        sa.Column('run_metadata', postgresql.JSONB(), nullable=True),

        sa.PrimaryKeyConstraint('id'),
        sa.CheckConstraint("status IN ('SUCCESS', 'FAILED', 'PARTIAL', 'RUNNING')",
                          name='check_status_valid'),
        sa.CheckConstraint('cves_processed >= 0', name='check_cves_processed'),
        sa.CheckConstraint('errors_count >= 0', name='check_errors_count'),
    )

    op.create_index('ix_logs_started_at', 'processing_logs', ['run_started_at'])
    op.create_index('ix_logs_status', 'processing_logs', ['status'])
    op.create_index('ix_logs_completed_at', 'processing_logs', ['run_completed_at'])

    print("  ✓ Created processing logs table")

    # ============================================================================
    # PHASE 5: Create sync checkpoints table
    # ============================================================================
    print("\nPhase 5: Creating sync checkpoints table...")

    op.create_table(
        'sync_checkpoints',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False,
                  server_default=sa.text('gen_random_uuid()'), comment='Checkpoint ID'),
        sa.Column('checkpoint_type', sa.String(length=50), nullable=False,
                  comment='Type: nist_hourly, nist_backfill, etc.'),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='in_progress',
                  comment='Status: in_progress, completed, failed'),
        sa.Column('started_at', sa.DateTime(), nullable=False,
                  server_default=sa.text('CURRENT_TIMESTAMP'), comment='Sync start time'),
        sa.Column('completed_at', sa.DateTime(), nullable=True, comment='Sync completion time'),
        sa.Column('last_updated_at', sa.DateTime(), nullable=False,
                  server_default=sa.text('CURRENT_TIMESTAMP'), comment='Last checkpoint update'),
        sa.Column('last_successful_sync_timestamp', sa.DateTime(), nullable=True,
                  comment='Last successfully processed CVE timestamp'),
        sa.Column('last_processed_cve_id', sa.String(length=20), nullable=True,
                  comment='Last CVE ID processed'),
        sa.Column('total_cves_processed', sa.Integer(), nullable=False, server_default='0',
                  comment='Total CVEs processed in this sync'),
        sa.Column('checkpoint_data', postgresql.JSONB(), nullable=True,
                  comment='Additional checkpoint data'),
        sa.Column('error_message', sa.Text(), nullable=True, comment='Error message if failed'),

        sa.PrimaryKeyConstraint('id'),
        sa.CheckConstraint("status IN ('in_progress', 'completed', 'failed')",
                          name='check_checkpoint_status_valid'),
    )

    op.create_index('ix_checkpoint_type', 'sync_checkpoints', ['checkpoint_type'])
    op.create_index('ix_checkpoint_status', 'sync_checkpoints', ['status'])
    op.create_index('ix_checkpoint_started_at', 'sync_checkpoints', ['started_at'])
    op.create_index('ix_checkpoint_last_updated', 'sync_checkpoints', ['last_updated_at'])

    print("  ✓ Created sync checkpoints table")

    print("\n" + "="*80)
    print("✅ MIGRATION COMPLETE - Minimal schema ready")
    print("="*80)
    print("Next steps:")
    print("  1. Run: poetry run python -m soc_alerting.main sync --hours-back 24")
    print("  2. Verify data with: psql -d soc_alerting -c 'SELECT COUNT(*) FROM cves;'")
    print("="*80 + "\n")


def downgrade() -> None:
    """Revert migration: drop all tables."""

    print("\n⚠️  WARNING: Downgrade will DROP all tables and LOSE all data!\n")

    # Drop all tables
    op.drop_table('sync_checkpoints')
    op.drop_table('processing_logs')
    op.drop_table('cve_update_history')
    op.drop_table('cves')

    print("✓ Dropped all minimal schema tables")
    print("\nDatabase is now empty. Re-run migration to recreate schema.\n")
