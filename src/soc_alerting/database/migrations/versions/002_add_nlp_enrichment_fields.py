"""add nlp enrichment fields

Revision ID: 002_add_nlp_enrichment_fields
Revises: 001_add_scalability_tables
Create Date: 2026-03-02

Adds NLP enrichment fields to cve_enrichments table:
- Translation (EN → ES)
- Entity extraction (NER)
- Keyword extraction
- Attack analysis
- CIA impact assessment
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '002_add_nlp_enrichment_fields'
down_revision = '001_scalability'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """
    Add NLP enrichment fields to cve_enrichments table.
    """
    # Add translation fields
    op.add_column('cve_enrichments', sa.Column(
        'description_es',
        sa.Text(),
        nullable=True,
        comment='Spanish translation of CVE description'
    ))
    op.add_column('cve_enrichments', sa.Column(
        'translation_confidence',
        sa.Float(),
        nullable=True,
        comment='Translation confidence score (0.0-1.0)'
    ))
    op.add_column('cve_enrichments', sa.Column(
        'translation_model',
        sa.String(length=255),
        nullable=True,
        comment='Translation model name (e.g., Helsinki-NLP/opus-mt-en-es)'
    ))

    # Make existing severity fields nullable (since we're adding translation-only enrichments)
    op.alter_column('cve_enrichments', 'predicted_severity',
                    existing_type=sa.String(length=20),
                    nullable=True)
    op.alter_column('cve_enrichments', 'severity_confidence',
                    existing_type=sa.Float(),
                    nullable=True)
    op.alter_column('cve_enrichments', 'model_name',
                    existing_type=sa.String(length=255),
                    nullable=True)
    op.alter_column('cve_enrichments', 'model_version',
                    existing_type=sa.String(length=50),
                    nullable=True)

    # Add attack analysis fields
    op.add_column('cve_enrichments', sa.Column(
        'attack_type',
        sa.String(length=100),
        nullable=True,
        comment='Primary attack type (RCE, SQLi, XSS, etc.)'
    ))
    op.add_column('cve_enrichments', sa.Column(
        'attack_vectors',
        postgresql.JSONB(astext_type=sa.Text()),
        nullable=True,
        comment='List of attack vectors identified'
    ))
    op.add_column('cve_enrichments', sa.Column(
        'requires_authentication',
        sa.Boolean(),
        nullable=True,
        comment='Whether attack requires authentication (null = unknown)'
    ))
    op.add_column('cve_enrichments', sa.Column(
        'network_accessible',
        sa.Boolean(),
        nullable=True,
        comment='Whether attack is network-accessible (null = unknown)'
    ))

    # Add CIA impact field
    op.add_column('cve_enrichments', sa.Column(
        'cia_impact',
        postgresql.JSONB(astext_type=sa.Text()),
        nullable=True,
        comment='CIA triad impact assessment: {confidentiality, integrity, availability}'
    ))

    # Add entity extraction fields (NER)
    op.add_column('cve_enrichments', sa.Column(
        'affected_products_ner',
        postgresql.JSONB(astext_type=sa.Text()),
        nullable=True,
        comment='NER-extracted affected products with versions'
    ))
    op.add_column('cve_enrichments', sa.Column(
        'organizations',
        postgresql.JSONB(astext_type=sa.Text()),
        nullable=True,
        comment='Extracted organization/vendor names'
    ))
    op.add_column('cve_enrichments', sa.Column(
        'versions',
        postgresql.JSONB(astext_type=sa.Text()),
        nullable=True,
        comment='Extracted version numbers'
    ))
    op.add_column('cve_enrichments', sa.Column(
        'cve_references',
        postgresql.JSONB(astext_type=sa.Text()),
        nullable=True,
        comment='CVE IDs mentioned in description'
    ))

    # Add keyword extraction fields
    op.add_column('cve_enrichments', sa.Column(
        'technical_keywords',
        postgresql.JSONB(astext_type=sa.Text()),
        nullable=True,
        comment='Extracted technical keywords and security terms'
    ))
    op.add_column('cve_enrichments', sa.Column(
        'technical_protocols',
        postgresql.JSONB(astext_type=sa.Text()),
        nullable=True,
        comment='Identified protocols (HTTP, LDAP, JNDI, etc.)'
    ))
    op.add_column('cve_enrichments', sa.Column(
        'vulnerability_types',
        postgresql.JSONB(astext_type=sa.Text()),
        nullable=True,
        comment='Vulnerability type keywords'
    ))

    # Add model metadata fields
    op.add_column('cve_enrichments', sa.Column(
        'ner_model',
        sa.String(length=255),
        nullable=True,
        comment='NER model name (e.g., dslim/bert-base-NER)'
    ))

    # Add processing metadata
    op.add_column('cve_enrichments', sa.Column(
        'processing_time_ms',
        sa.Integer(),
        nullable=True,
        comment='Total NLP processing time in milliseconds'
    ))

    # Create indexes for frequently queried fields
    op.create_index(
        'ix_enrichments_attack_type',
        'cve_enrichments',
        ['attack_type'],
        unique=False
    )
    op.create_index(
        'ix_enrichments_requires_auth',
        'cve_enrichments',
        ['requires_authentication'],
        unique=False
    )
    op.create_index(
        'ix_enrichments_network_accessible',
        'cve_enrichments',
        ['network_accessible'],
        unique=False
    )

    # Create GIN indexes for JSONB columns for efficient querying
    op.create_index(
        'ix_enrichments_attack_vectors',
        'cve_enrichments',
        ['attack_vectors'],
        unique=False,
        postgresql_using='gin'
    )
    op.create_index(
        'ix_enrichments_technical_keywords',
        'cve_enrichments',
        ['technical_keywords'],
        unique=False,
        postgresql_using='gin'
    )
    op.create_index(
        'ix_enrichments_cia_impact',
        'cve_enrichments',
        ['cia_impact'],
        unique=False,
        postgresql_using='gin'
    )


def downgrade() -> None:
    """
    Remove NLP enrichment fields from cve_enrichments table.
    """
    # Drop indexes
    op.drop_index('ix_enrichments_cia_impact', table_name='cve_enrichments', postgresql_using='gin')
    op.drop_index('ix_enrichments_technical_keywords', table_name='cve_enrichments', postgresql_using='gin')
    op.drop_index('ix_enrichments_attack_vectors', table_name='cve_enrichments', postgresql_using='gin')
    op.drop_index('ix_enrichments_network_accessible', table_name='cve_enrichments')
    op.drop_index('ix_enrichments_requires_auth', table_name='cve_enrichments')
    op.drop_index('ix_enrichments_attack_type', table_name='cve_enrichments')

    # Drop columns
    op.drop_column('cve_enrichments', 'processing_time_ms')
    op.drop_column('cve_enrichments', 'ner_model')
    op.drop_column('cve_enrichments', 'vulnerability_types')
    op.drop_column('cve_enrichments', 'technical_protocols')
    op.drop_column('cve_enrichments', 'technical_keywords')
    op.drop_column('cve_enrichments', 'cve_references')
    op.drop_column('cve_enrichments', 'versions')
    op.drop_column('cve_enrichments', 'organizations')
    op.drop_column('cve_enrichments', 'affected_products_ner')
    op.drop_column('cve_enrichments', 'cia_impact')
    op.drop_column('cve_enrichments', 'network_accessible')
    op.drop_column('cve_enrichments', 'requires_authentication')
    op.drop_column('cve_enrichments', 'attack_vectors')
    op.drop_column('cve_enrichments', 'attack_type')
    op.drop_column('cve_enrichments', 'translation_model')
    op.drop_column('cve_enrichments', 'translation_confidence')
    op.drop_column('cve_enrichments', 'description_es')

    # Restore NOT NULL constraints on original fields
    op.alter_column('cve_enrichments', 'model_version',
                    existing_type=sa.String(length=50),
                    nullable=False)
    op.alter_column('cve_enrichments', 'model_name',
                    existing_type=sa.String(length=255),
                    nullable=False)
    op.alter_column('cve_enrichments', 'severity_confidence',
                    existing_type=sa.Float(),
                    nullable=False)
    op.alter_column('cve_enrichments', 'predicted_severity',
                    existing_type=sa.String(length=20),
                    nullable=False)
