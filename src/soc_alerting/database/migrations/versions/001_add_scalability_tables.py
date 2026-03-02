"""add scalability tables: CPE, CISA metadata, references

Revision ID: 001_scalability
Revises:
Create Date: 2026-03-02

This migration creates 3 new tables for scalability:
1. cisa_kev_metadata - Separates CISA KEV fields from main CVE table
2. affected_products - CPE data for vulnerability management
3. cve_references - Normalized references with types
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001_scalability'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Apply migration: create new tables and migrate data."""

    # Enable pg_trgm extension for fuzzy search
    op.execute('CREATE EXTENSION IF NOT EXISTS pg_trgm')

    # ============================================================================
    # 1. Create cisa_kev_metadata table
    # ============================================================================
    op.create_table(
        'cisa_kev_metadata',
        sa.Column('cve_id', sa.String(length=20), nullable=False, comment='Associated CVE ID'),
        sa.Column('exploit_add', sa.DateTime(), nullable=False, comment='Date added to CISA KEV'),
        sa.Column('action_due', sa.DateTime(), nullable=True, comment='CISA remediation due date'),
        sa.Column('required_action', sa.Text(), nullable=False, comment='CISA required action'),
        sa.Column('vulnerability_name', sa.String(length=255), nullable=True, comment='CISA vulnerability name'),
        sa.Column('known_ransomware', sa.Boolean(), nullable=False, server_default='false', comment='Known ransomware campaign use'),
        sa.Column('notes', sa.Text(), nullable=True, comment='Additional notes from CISA'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='Last update timestamp'),
        sa.ForeignKeyConstraint(['cve_id'], ['cves.cve_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('cve_id')
    )

    # Indexes for cisa_kev_metadata
    op.create_index('ix_cisa_kev_exploit_add', 'cisa_kev_metadata', ['exploit_add'])
    op.create_index('ix_cisa_kev_action_due', 'cisa_kev_metadata', ['action_due'])
    op.create_index('ix_cisa_kev_ransomware', 'cisa_kev_metadata', ['known_ransomware'])

    # ============================================================================
    # 2. Create affected_products table (CPE)
    # ============================================================================
    op.create_table(
        'affected_products',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, server_default=sa.text('gen_random_uuid()'), comment='Product record ID'),
        sa.Column('cve_id', sa.String(length=20), nullable=False, comment='Associated CVE ID'),
        sa.Column('cpe_uri', sa.Text(), nullable=False, comment='Full CPE URI: cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'),
        sa.Column('part', sa.String(length=1), nullable=False, comment='Part: a=application, h=hardware, o=OS'),
        sa.Column('vendor', sa.String(length=255), nullable=False, comment='Vendor name (e.g., apache, microsoft)'),
        sa.Column('product', sa.String(length=255), nullable=False, comment='Product name (e.g., log4j, windows_10)'),
        sa.Column('version', sa.String(length=100), nullable=True, comment='Specific version (e.g., 2.14.1) or * for any'),
        sa.Column('update_version', sa.String(length=100), nullable=True, comment='Update/patch level'),
        sa.Column('edition', sa.String(length=100), nullable=True, comment='Edition (e.g., enterprise, professional)'),
        sa.Column('language', sa.String(length=50), nullable=True, comment='Language code'),
        sa.Column('sw_edition', sa.String(length=100), nullable=True, comment='Software edition'),
        sa.Column('target_sw', sa.String(length=100), nullable=True, comment='Target software'),
        sa.Column('target_hw', sa.String(length=100), nullable=True, comment='Target hardware'),
        sa.Column('other', sa.String(length=100), nullable=True, comment='Other attributes'),
        sa.Column('version_start_including', sa.String(length=100), nullable=True, comment='Start version (inclusive)'),
        sa.Column('version_start_excluding', sa.String(length=100), nullable=True, comment='Start version (exclusive)'),
        sa.Column('version_end_including', sa.String(length=100), nullable=True, comment='End version (inclusive)'),
        sa.Column('version_end_excluding', sa.String(length=100), nullable=True, comment='End version (exclusive)'),
        sa.Column('vulnerable', sa.Boolean(), nullable=False, server_default='true', comment='Whether this config is vulnerable (vs. not vulnerable)'),
        sa.Column('configuration_node', postgresql.JSONB(), nullable=True, comment='Complex configuration logic (AND/OR/NOT)'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='Record creation timestamp'),
        sa.ForeignKeyConstraint(['cve_id'], ['cves.cve_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Indexes for affected_products
    op.create_index('ix_affected_cve_id', 'affected_products', ['cve_id'])
    op.create_index('ix_affected_vendor_product', 'affected_products', ['vendor', 'product'])
    op.create_index('ix_affected_product_version', 'affected_products', ['product', 'version'])
    op.create_index('ix_affected_vendor', 'affected_products', ['vendor'])
    # GIN index for fuzzy CPE search
    op.create_index('ix_affected_cpe_uri', 'affected_products', ['cpe_uri'], postgresql_using='gin', postgresql_ops={'cpe_uri': 'gin_trgm_ops'})

    # ============================================================================
    # 3. Create cve_references table
    # ============================================================================
    op.create_table(
        'cve_references',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, server_default=sa.text('gen_random_uuid()'), comment='Reference record ID'),
        sa.Column('cve_id', sa.String(length=20), nullable=False, comment='Associated CVE ID'),
        sa.Column('url', sa.Text(), nullable=False, comment='Reference URL'),
        sa.Column('source', sa.String(length=100), nullable=True, comment='Source: NIST, vendor, researcher, etc.'),
        sa.Column('reference_type', sa.String(length=50), nullable=True, comment='Type: patch, exploit, advisory, mitigation, etc.'),
        sa.Column('tags', postgresql.JSONB(), nullable=True, comment='Array of tags: [exploit-db, github-poc, vendor-patch]'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='Record creation timestamp'),
        sa.ForeignKeyConstraint(['cve_id'], ['cves.cve_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Indexes for cve_references
    op.create_index('ix_ref_cve_id', 'cve_references', ['cve_id'])
    op.create_index('ix_ref_type', 'cve_references', ['reference_type'])
    op.create_index('ix_ref_source', 'cve_references', ['source'])
    op.create_index('ix_ref_tags', 'cve_references', ['tags'], postgresql_using='gin')
    op.create_index('uq_cve_ref_url', 'cve_references', ['cve_id', 'url'], unique=True)

    # ============================================================================
    # 4. Migrate existing CISA KEV data from cves table
    # ============================================================================
    op.execute("""
        INSERT INTO cisa_kev_metadata (
            cve_id,
            exploit_add,
            action_due,
            required_action,
            vulnerability_name,
            known_ransomware
        )
        SELECT
            cve_id,
            cisa_exploit_add,
            cisa_action_due,
            COALESCE(cisa_required_action, 'Apply updates per vendor instructions'),
            cisa_vulnerability_name,
            COALESCE(cisa_known_ransomware, false)
        FROM cves
        WHERE is_in_cisa_kev = true
          AND cisa_exploit_add IS NOT NULL
    """)

    # ============================================================================
    # 5. Migrate existing references from cves.references JSONB to cve_references table
    # ============================================================================
    op.execute("""
        INSERT INTO cve_references (cve_id, url, source, reference_type)
        SELECT
            c.cve_id,
            jsonb_array_elements_text(c.references) as url,
            'NIST' as source,
            NULL as reference_type
        FROM cves c
        WHERE c.references IS NOT NULL
          AND jsonb_array_length(c.references) > 0
        ON CONFLICT (cve_id, url) DO NOTHING
    """)

    # ============================================================================
    # 6. Drop CISA KEV columns from cves table (now in separate table)
    # ============================================================================
    op.drop_column('cves', 'cisa_exploit_add')
    op.drop_column('cves', 'cisa_action_due')
    op.drop_column('cves', 'cisa_required_action')
    op.drop_column('cves', 'cisa_vulnerability_name')
    op.drop_column('cves', 'cisa_known_ransomware')

    # ============================================================================
    # 7. Drop references column from cves (now in cve_references table)
    # ============================================================================
    op.drop_column('cves', 'references')


def downgrade() -> None:
    """Revert migration: restore columns and drop new tables."""

    # Add back references column to cves
    op.add_column('cves', sa.Column('references', postgresql.JSONB(), nullable=True, comment='Array of reference URLs'))

    # Add back CISA columns to cves
    op.add_column('cves', sa.Column('cisa_known_ransomware', sa.Boolean(), nullable=True, comment='Known ransomware campaign use'))
    op.add_column('cves', sa.Column('cisa_vulnerability_name', sa.String(length=255), nullable=True, comment='CISA vulnerability name'))
    op.add_column('cves', sa.Column('cisa_required_action', sa.Text(), nullable=True, comment='CISA required action'))
    op.add_column('cves', sa.Column('cisa_action_due', sa.DateTime(), nullable=True, comment='CISA remediation due date'))
    op.add_column('cves', sa.Column('cisa_exploit_add', sa.DateTime(), nullable=True, comment='Date added to CISA KEV'))

    # Restore data from cisa_kev_metadata back to cves
    op.execute("""
        UPDATE cves c
        SET
            cisa_exploit_add = k.exploit_add,
            cisa_action_due = k.action_due,
            cisa_required_action = k.required_action,
            cisa_vulnerability_name = k.vulnerability_name,
            cisa_known_ransomware = k.known_ransomware
        FROM cisa_kev_metadata k
        WHERE c.cve_id = k.cve_id
    """)

    # Restore references from cve_references back to cves
    op.execute("""
        UPDATE cves c
        SET references = (
            SELECT jsonb_agg(r.url)
            FROM cve_references r
            WHERE r.cve_id = c.cve_id
        )
        WHERE EXISTS (
            SELECT 1 FROM cve_references r WHERE r.cve_id = c.cve_id
        )
    """)

    # Drop new tables
    op.drop_index('uq_cve_ref_url', table_name='cve_references')
    op.drop_index('ix_ref_tags', table_name='cve_references')
    op.drop_index('ix_ref_source', table_name='cve_references')
    op.drop_index('ix_ref_type', table_name='cve_references')
    op.drop_index('ix_ref_cve_id', table_name='cve_references')
    op.drop_table('cve_references')

    op.drop_index('ix_affected_cpe_uri', table_name='affected_products')
    op.drop_index('ix_affected_vendor', table_name='affected_products')
    op.drop_index('ix_affected_product_version', table_name='affected_products')
    op.drop_index('ix_affected_vendor_product', table_name='affected_products')
    op.drop_index('ix_affected_cve_id', table_name='affected_products')
    op.drop_table('affected_products')

    op.drop_index('ix_cisa_kev_ransomware', table_name='cisa_kev_metadata')
    op.drop_index('ix_cisa_kev_action_due', table_name='cisa_kev_metadata')
    op.drop_index('ix_cisa_kev_exploit_add', table_name='cisa_kev_metadata')
    op.drop_table('cisa_kev_metadata')
