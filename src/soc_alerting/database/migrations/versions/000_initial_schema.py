"""initial schema: create base CVE tables

Revision ID: 000_initial
Revises:
Create Date: 2026-03-02

This migration creates the base tables for CVE storage:
1. cves - Main CVE table with NIST data
2. cve_enrichments - NLP enrichment data
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
    """Apply migration: create base tables."""

    # ============================================================================
    # 1. Create cves table (main table)
    # ============================================================================
    op.create_table(
        'cves',
        sa.Column('cve_id', sa.String(length=20), nullable=False, comment='CVE identifier'),
        sa.Column('published_date', sa.DateTime(), nullable=False, comment='Original publication date'),
        sa.Column('last_modified_date', sa.DateTime(), nullable=False, comment='Last modification date from NIST'),
        sa.Column('last_fetched_at', sa.DateTime(), nullable=True, comment='Last time we fetched this CVE'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),

        # Description
        sa.Column('description', sa.Text(), nullable=False, comment='CVE description'),
        sa.Column('source_identifier', sa.String(length=255), nullable=True, comment='NIST source identifier'),
        sa.Column('vuln_status', sa.String(length=50), nullable=True, comment='Vulnerability status'),

        # CVSS scores
        sa.Column('cvss_v3_score', sa.Float(), nullable=True, comment='CVSS v3.x score (0-10)'),
        sa.Column('cvss_v3_vector', sa.String(length=255), nullable=True, comment='CVSS v3.x vector string'),
        sa.Column('cvss_v2_score', sa.Float(), nullable=True, comment='CVSS v2 score (0-10)'),
        sa.Column('cvss_v2_vector', sa.String(length=255), nullable=True, comment='CVSS v2 vector string'),

        # Severity classification
        sa.Column('severity_nist', sa.String(length=20), nullable=False, comment='NIST severity: NONE/LOW/MEDIUM/HIGH/CRITICAL'),
        sa.Column('is_in_cisa_kev', sa.Boolean(), nullable=False, server_default='false', comment='Is this CVE in CISA KEV catalog?'),
        sa.Column('final_severity', sa.String(length=20), nullable=False, comment='Final severity (CISA KEV override)'),
        sa.Column('classification_sources', postgresql.ARRAY(sa.String()), nullable=True, comment='Sources used for classification'),

        sa.PrimaryKeyConstraint('cve_id')
    )

    # Indexes for cves table
    op.create_index('ix_cves_published_date', 'cves', ['published_date'])
    op.create_index('ix_cves_last_modified_date', 'cves', ['last_modified_date'])
    op.create_index('ix_cves_cvss_v3_score', 'cves', ['cvss_v3_score'])
    op.create_index('ix_cves_final_severity', 'cves', ['final_severity'])
    op.create_index('ix_cves_is_in_cisa_kev', 'cves', ['is_in_cisa_kev'])

    # ============================================================================
    # 2. Create cve_enrichments table
    # ============================================================================
    op.create_table(
        'cve_enrichments',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, server_default=sa.text('gen_random_uuid()')),
        sa.Column('cve_id', sa.String(length=20), nullable=False),
        sa.Column('enriched_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('predicted_severity', sa.String(length=20), nullable=True),
        sa.Column('severity_confidence', sa.Float(), nullable=True),
        sa.Column('impact_analysis', postgresql.JSONB(), nullable=True),
        sa.Column('model_name', sa.String(length=255), nullable=True),
        sa.Column('model_version', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.ForeignKeyConstraint(['cve_id'], ['cves.cve_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_index('ix_cve_enrichments_cve_id', 'cve_enrichments', ['cve_id'])


def downgrade() -> None:
    """Revert migration: drop base tables."""
    op.drop_index('ix_cve_enrichments_cve_id', table_name='cve_enrichments')
    op.drop_table('cve_enrichments')

    op.drop_index('ix_cves_is_in_cisa_kev', table_name='cves')
    op.drop_index('ix_cves_final_severity', table_name='cves')
    op.drop_index('ix_cves_cvss_v3_score', table_name='cves')
    op.drop_index('ix_cves_last_modified_date', table_name='cves')
    op.drop_index('ix_cves_published_date', table_name='cves')
    op.drop_table('cves')
