"""Add redteam_user and redteam_api_key tables

Revision ID: 38514c6ebd6c
Revises: dd83ad78a3f6
Create Date: 2025-11-04 12:10:23.582716

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '38514c6ebd6c'
down_revision = 'dd83ad78a3f6'
branch_labels = None
depends_on = None


def upgrade():
    # Create redteam_user table
    op.create_table('redteam_user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=80), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('role', sa.String(length=50), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('last_login', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('redteam_user', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_redteam_user_email'), ['email'], unique=True)
        batch_op.create_index(batch_op.f('ix_redteam_user_username'), ['username'], unique=True)

    # Create redteam_api_key table
    op.create_table('redteam_api_key',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('key_hash', sa.String(length=255), nullable=False),
    sa.Column('key_prefix', sa.String(length=20), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('last_used', sa.DateTime(), nullable=True),
    sa.Column('expires_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['redteam_user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('redteam_api_key', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_redteam_api_key_key_hash'), ['key_hash'], unique=True)

    # Add end_date column to engagement table
    with op.batch_alter_table('engagement', schema=None) as batch_op:
        batch_op.add_column(sa.Column('end_date', sa.DateTime(), nullable=True))


def downgrade():
    # Remove end_date column from engagement table
    with op.batch_alter_table('engagement', schema=None) as batch_op:
        batch_op.drop_column('end_date')

    # Drop redteam_api_key table
    with op.batch_alter_table('redteam_api_key', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_redteam_api_key_key_hash'))
    op.drop_table('redteam_api_key')

    # Drop redteam_user table
    with op.batch_alter_table('redteam_user', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_redteam_user_username'))
        batch_op.drop_index(batch_op.f('ix_redteam_user_email'))
    op.drop_table('redteam_user')
