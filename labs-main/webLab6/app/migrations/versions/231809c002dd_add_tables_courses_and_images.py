"""Add tables courses and images

Revision ID: 231809c002dd
Revises: e31df7a80f7a
Create Date: 2022-05-24 13:37:42.801341

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '231809c002dd'
down_revision = 'e31df7a80f7a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('images',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('file_name', sa.String(length=100), nullable=False),
    sa.Column('mime_type', sa.String(length=100), nullable=False),
    sa.Column('md5_hash', sa.String(length=200), nullable=False),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
    sa.Column('object_type', sa.String(length=100), nullable=True),
    sa.Column('object_id', sa.Integer(), nullable=True),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_images')),
    sa.UniqueConstraint('md5_hash', name=op.f('uq_images_md5_hash'))
    )
    op.create_table('courses',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('short_desc', sa.Text(), nullable=False),
    sa.Column('full_desc', sa.Text(), nullable=False),
    sa.Column('rating_sum', sa.Integer(), nullable=False),
    sa.Column('rating_num', sa.Integer(), nullable=False),
    sa.Column('category_id', sa.Integer(), nullable=False),
    sa.Column('author_id', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['author_id'], ['users.id'], name=op.f('fk_courses_author_id_users')),
    sa.ForeignKeyConstraint(['category_id'], ['categories.id'], name=op.f('fk_courses_category_id_categories')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_courses'))
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('courses')
    op.drop_table('images')
    # ### end Alembic commands ###