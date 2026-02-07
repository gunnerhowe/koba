"""Initial schema - Multi-tenant Koba with blockchain anchoring

Revision ID: 001_initial
Revises:
Create Date: 2026-01-06

Creates all tables for:
- Multi-tenancy (tenants, users, api_keys)
- Authentication (sessions, refresh_tokens)
- Policy management (policy_bundles)
- Audit trail (receipts, audit_entries)
- Blockchain anchoring (blockchain_anchors)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # =========================================================================
    # TENANTS
    # =========================================================================
    op.create_table(
        'tenants',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('slug', sa.String(100), unique=True, nullable=False, index=True),
        sa.Column('status', sa.String(20), nullable=False, default='active'),
        sa.Column('plan', sa.String(20), nullable=False, default='free'),
        sa.Column('settings', sa.Text(), nullable=True),  # JSON
        sa.Column('metadata', sa.Text(), nullable=True),  # JSON
        sa.Column('resource_limits', sa.Text(), nullable=True),  # JSON
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )

    # =========================================================================
    # USERS
    # =========================================================================
    op.create_table(
        'users',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('tenant_id', sa.String(64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=True, index=True),
        sa.Column('username', sa.String(255), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('role', sa.String(50), nullable=False, default='user'),
        sa.Column('permissions', sa.Text(), nullable=True),  # JSON array
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('is_system_admin', sa.Boolean(), nullable=False, default=False),
        sa.Column('metadata', sa.Text(), nullable=True),  # JSON
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    )

    # Unique constraint on username per tenant (or globally for system admins)
    op.create_index(
        'ix_users_tenant_username',
        'users',
        ['tenant_id', 'username'],
        unique=True
    )

    op.create_index(
        'ix_users_email',
        'users',
        ['email']
    )

    # =========================================================================
    # SESSIONS
    # =========================================================================
    op.create_table(
        'sessions',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('user_id', sa.String(64), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('tenant_id', sa.String(64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=True, index=True),
        sa.Column('token_hash', sa.String(255), nullable=False, unique=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(512), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
    )

    # =========================================================================
    # REFRESH TOKENS
    # =========================================================================
    op.create_table(
        'refresh_tokens',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('user_id', sa.String(64), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('tenant_id', sa.String(64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=True, index=True),
        sa.Column('token_hash', sa.String(255), nullable=False, unique=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    )

    # =========================================================================
    # API KEYS
    # =========================================================================
    op.create_table(
        'api_keys',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('tenant_id', sa.String(64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('key_hash', sa.String(255), nullable=False, unique=True),
        sa.Column('key_prefix', sa.String(16), nullable=False),  # First chars for identification
        sa.Column('permissions', sa.Text(), nullable=True),  # JSON array
        sa.Column('rate_limit', sa.Integer(), nullable=True),  # Requests per minute
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_by', sa.String(64), sa.ForeignKey('users.id'), nullable=True),
    )

    # =========================================================================
    # POLICY BUNDLES
    # =========================================================================
    op.create_table(
        'policy_bundles',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('tenant_id', sa.String(64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False, default=1),
        sa.Column('bundle_data', sa.Text(), nullable=False),  # JSON policy rules
        sa.Column('is_active', sa.Boolean(), nullable=False, default=False),
        sa.Column('hash', sa.String(64), nullable=False),  # SHA-256 of bundle_data
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_by', sa.String(64), sa.ForeignKey('users.id'), nullable=True),
    )

    # Only one active policy per tenant
    op.create_index(
        'ix_policy_bundles_tenant_active',
        'policy_bundles',
        ['tenant_id', 'is_active'],
        unique=False
    )

    # =========================================================================
    # RECEIPTS (Action Audit Trail)
    # =========================================================================
    op.create_table(
        'receipts',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('tenant_id', sa.String(64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('log_index', sa.BigInteger(), nullable=False),
        sa.Column('receipt_data', sa.Text(), nullable=False),  # Full JSON receipt
        sa.Column('receipt_hash', sa.String(64), nullable=False, index=True),
        sa.Column('tool_id', sa.String(255), nullable=True, index=True),
        sa.Column('decision', sa.String(20), nullable=False),  # allow, deny, require_approval
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column('anchor_id', sa.String(64), nullable=True, index=True),  # Foreign key added later
    )

    # Unique log index per tenant
    op.create_index(
        'ix_receipts_tenant_log_index',
        'receipts',
        ['tenant_id', 'log_index'],
        unique=True
    )

    # =========================================================================
    # AUDIT ENTRIES (General Audit Log)
    # =========================================================================
    op.create_table(
        'audit_entries',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('tenant_id', sa.String(64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=True, index=True),
        sa.Column('event_type', sa.String(100), nullable=False, index=True),
        sa.Column('actor_id', sa.String(64), nullable=True),  # User or API key ID
        sa.Column('actor_type', sa.String(20), nullable=True),  # user, api_key, system
        sa.Column('resource_type', sa.String(100), nullable=True),
        sa.Column('resource_id', sa.String(64), nullable=True),
        sa.Column('action', sa.String(50), nullable=False),
        sa.Column('details', sa.Text(), nullable=True),  # JSON
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(512), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False, index=True),
    )

    # =========================================================================
    # BLOCKCHAIN ANCHORS
    # =========================================================================
    op.create_table(
        'blockchain_anchors',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('tenant_id', sa.String(64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=True, index=True),
        sa.Column('tree_size', sa.BigInteger(), nullable=False),
        sa.Column('merkle_root', sa.String(64), nullable=False),
        sa.Column('tree_head_signature', sa.Text(), nullable=False),
        sa.Column('blockchain', sa.String(50), nullable=False, default='hedera'),  # hedera, ethereum, etc.
        sa.Column('network', sa.String(50), nullable=False),  # mainnet, testnet
        sa.Column('transaction_id', sa.String(255), nullable=False, index=True),
        sa.Column('topic_id', sa.String(100), nullable=True),  # Hedera topic
        sa.Column('sequence_number', sa.BigInteger(), nullable=True),  # Hedera sequence
        sa.Column('consensus_timestamp', sa.String(50), nullable=True),  # Hedera timestamp
        sa.Column('block_number', sa.BigInteger(), nullable=True),  # Ethereum block
        sa.Column('anchor_data', sa.Text(), nullable=True),  # Full JSON anchor message
        sa.Column('status', sa.String(20), nullable=False, default='pending'),  # pending, confirmed, failed
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    # Add foreign key from receipts to anchors
    op.create_foreign_key(
        'fk_receipts_anchor',
        'receipts',
        'blockchain_anchors',
        ['anchor_id'],
        ['id']
    )

    # =========================================================================
    # KILL SWITCH STATE (for multi-party containment)
    # =========================================================================
    op.create_table(
        'kill_switch_state',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('tenant_id', sa.String(64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=True, index=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=False),
        sa.Column('activated_by', sa.String(64), nullable=True),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('votes', sa.Text(), nullable=True),  # JSON: {user_id: vote_time}
        sa.Column('required_votes', sa.Integer(), nullable=False, default=2),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )

    # =========================================================================
    # PENDING APPROVALS
    # =========================================================================
    op.create_table(
        'pending_approvals',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('tenant_id', sa.String(64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('request_id', sa.String(64), nullable=False, unique=True),
        sa.Column('tool_id', sa.String(255), nullable=False),
        sa.Column('request_data', sa.Text(), nullable=False),  # JSON
        sa.Column('context', sa.Text(), nullable=True),  # JSON
        sa.Column('status', sa.String(20), nullable=False, default='pending'),  # pending, approved, denied, expired
        sa.Column('decided_by', sa.String(64), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('decision_reason', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    # Drop tables in reverse order (respecting foreign keys)
    op.drop_table('pending_approvals')
    op.drop_table('kill_switch_state')
    op.drop_constraint('fk_receipts_anchor', 'receipts', type_='foreignkey')
    op.drop_table('blockchain_anchors')
    op.drop_table('audit_entries')
    op.drop_table('receipts')
    op.drop_table('policy_bundles')
    op.drop_table('api_keys')
    op.drop_table('refresh_tokens')
    op.drop_table('sessions')
    op.drop_table('users')
    op.drop_table('tenants')
