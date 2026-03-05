"""Add translation and enrichment fields to cve_versions

Revision ID: 002_translation_enrichment
Revises: 001_fresh_versioned_schema
Create Date: 2026-03-05 15:30:00.000000

This migration adds:
- Translation fields (description_es, confidence, model, translated_at)
- Enrichment status tracking (enrichment_status, approved_by, approved_at)
- NLP enrichment results (keywords, attack_types, risk_indicators, enriched_at)
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '002_translation_enrichment'
down_revision = '001_fresh_versioned_schema'
branch_labels = None
depends_on = None


def upgrade():
    """Add translation and enrichment fields to cve_versions table."""

    # =========================================================================
    # TRANSLATION FIELDS
    # =========================================================================

    op.add_column('cve_versions', sa.Column(
        'description_es',
        sa.Text(),
        nullable=True,
        comment='Spanish translation of description'
    ))

    op.add_column('cve_versions', sa.Column(
        'translation_confidence',
        sa.Float(),
        nullable=True,
        comment='Translation confidence score (0.0-1.0)'
    ))

    op.add_column('cve_versions', sa.Column(
        'translation_model',
        sa.String(50),
        nullable=True,
        comment='Translation model used (e.g., argos-en-es-1.9)'
    ))

    op.add_column('cve_versions', sa.Column(
        'translated_at',
        sa.DateTime(),
        nullable=True,
        comment='When translation was performed'
    ))

    # =========================================================================
    # ENRICHMENT STATUS FIELDS
    # =========================================================================

    op.add_column('cve_versions', sa.Column(
        'enrichment_status',
        sa.String(30),
        nullable=False,
        server_default='not_translated',
        comment='Status: not_translated, pending_approval, approved, enriched, enrichment_failed'
    ))

    op.add_column('cve_versions', sa.Column(
        'enrichment_approved_by',
        sa.String(100),
        nullable=True,
        comment='Analyst username who approved enrichment'
    ))

    op.add_column('cve_versions', sa.Column(
        'enrichment_approved_at',
        sa.DateTime(),
        nullable=True,
        comment='When enrichment was approved'
    ))

    # =========================================================================
    # NLP ENRICHMENT RESULTS FIELDS
    # =========================================================================

    op.add_column('cve_versions', sa.Column(
        'nlp_keywords',
        postgresql.JSONB(astext_type=sa.Text()),
        nullable=True,
        comment='Extracted keywords from NLP'
    ))

    op.add_column('cve_versions', sa.Column(
        'nlp_attack_types',
        postgresql.JSONB(astext_type=sa.Text()),
        nullable=True,
        comment='Detected attack types'
    ))

    op.add_column('cve_versions', sa.Column(
        'nlp_risk_indicators',
        postgresql.JSONB(astext_type=sa.Text()),
        nullable=True,
        comment='Risk indicators from NLP'
    ))

    op.add_column('cve_versions', sa.Column(
        'nlp_enriched_at',
        sa.DateTime(),
        nullable=True,
        comment='When NLP enrichment was performed'
    ))

    op.add_column('cve_versions', sa.Column(
        'nlp_processing_time_ms',
        sa.Integer(),
        nullable=True,
        comment='NLP processing time in milliseconds'
    ))

    # =========================================================================
    # INDEXES
    # =========================================================================

    op.create_index(
        'ix_cve_versions_enrichment_status',
        'cve_versions',
        ['enrichment_status']
    )

    op.create_index(
        'ix_cve_versions_translated',
        'cve_versions',
        ['translated_at']
    )

    # =========================================================================
    # CONSTRAINTS
    # =========================================================================

    # Check constraint for enrichment_status values
    op.create_check_constraint(
        'check_enrichment_status',
        'cve_versions',
        sa.column('enrichment_status').in_([
            'not_translated',
            'pending_approval',
            'approved',
            'enriched',
            'enrichment_failed'
        ])
    )

    # Check constraint for translation_confidence range
    op.create_check_constraint(
        'check_translation_confidence',
        'cve_versions',
        sa.and_(
            sa.or_(
                sa.column('translation_confidence').is_(None),
                sa.and_(
                    sa.column('translation_confidence') >= 0,
                    sa.column('translation_confidence') <= 1
                )
            )
        )
    )


def downgrade():
    """Remove translation and enrichment fields from cve_versions table."""

    # Drop constraints
    op.drop_constraint('check_translation_confidence', 'cve_versions', type_='check')
    op.drop_constraint('check_enrichment_status', 'cve_versions', type_='check')

    # Drop indexes
    op.drop_index('ix_cve_versions_translated', table_name='cve_versions')
    op.drop_index('ix_cve_versions_enrichment_status', table_name='cve_versions')

    # Drop NLP enrichment columns
    op.drop_column('cve_versions', 'nlp_processing_time_ms')
    op.drop_column('cve_versions', 'nlp_enriched_at')
    op.drop_column('cve_versions', 'nlp_risk_indicators')
    op.drop_column('cve_versions', 'nlp_attack_types')
    op.drop_column('cve_versions', 'nlp_keywords')

    # Drop enrichment status columns
    op.drop_column('cve_versions', 'enrichment_approved_at')
    op.drop_column('cve_versions', 'enrichment_approved_by')
    op.drop_column('cve_versions', 'enrichment_status')

    # Drop translation columns
    op.drop_column('cve_versions', 'translated_at')
    op.drop_column('cve_versions', 'translation_model')
    op.drop_column('cve_versions', 'translation_confidence')
    op.drop_column('cve_versions', 'description_es')
