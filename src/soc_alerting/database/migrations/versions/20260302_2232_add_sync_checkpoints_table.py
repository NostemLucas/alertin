"""add_sync_checkpoints_table

Revision ID: fb7875ff2fbe
Revises: 002_add_nlp_enrichment_fields
Create Date: 2026-03-02 22:32:06.452873

Adds sync_checkpoints table for tracking NIST sync progress and crash recovery.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = 'fb7875ff2fbe'
down_revision = '002_add_nlp_enrichment_fields'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create sync_checkpoints table."""
    op.create_table(
        'sync_checkpoints',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('checkpoint_type', sa.String(50), nullable=False, comment='Type of sync: nist_hourly, nist_backfill, etc.'),
        sa.Column('status', sa.String(20), nullable=False, server_default='in_progress', comment='Checkpoint status: in_progress, completed, failed'),
        sa.Column('started_at', sa.DateTime(), nullable=False, comment='Sync start time'),
        sa.Column('completed_at', sa.DateTime(), nullable=True, comment='Sync completion time'),
        sa.Column('last_updated_at', sa.DateTime(), nullable=False, comment='Last checkpoint update time'),
        sa.Column('last_successful_sync_timestamp', sa.DateTime(), nullable=True, comment='Timestamp of last successfully processed CVE from NIST'),
        sa.Column('last_processed_cve_id', sa.String(20), nullable=True, comment='Last CVE ID processed before checkpoint'),
        sa.Column('total_cves_processed', sa.Integer(), nullable=False, server_default='0', comment='Total CVEs processed in this sync'),
        sa.Column('checkpoint_data', postgresql.JSONB(), nullable=True, comment='Additional checkpoint data (query params, cursor, etc.)'),
        sa.Column('error_message', sa.Text(), nullable=True, comment='Error message if sync failed'),

        # Constraints
        sa.CheckConstraint(
            "status IN ('in_progress', 'completed', 'failed')",
            name='check_checkpoint_status_valid'
        ),
    )

    # Create indexes
    op.create_index('ix_checkpoint_type', 'sync_checkpoints', ['checkpoint_type'])
    op.create_index('ix_checkpoint_status', 'sync_checkpoints', ['status'])
    op.create_index('ix_checkpoint_started_at', 'sync_checkpoints', ['started_at'])
    op.create_index('ix_checkpoint_last_updated', 'sync_checkpoints', ['last_updated_at'])


def downgrade() -> None:
    """Drop sync_checkpoints table."""
    op.drop_index('ix_checkpoint_last_updated', table_name='sync_checkpoints')
    op.drop_index('ix_checkpoint_started_at', table_name='sync_checkpoints')
    op.drop_index('ix_checkpoint_status', table_name='sync_checkpoints')
    op.drop_index('ix_checkpoint_type', table_name='sync_checkpoints')
    op.drop_table('sync_checkpoints')
