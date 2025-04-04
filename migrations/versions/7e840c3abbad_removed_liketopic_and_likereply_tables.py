"""removed LikeTopic and LikeReply tables

Revision ID: 7e840c3abbad
Revises: 0ba557dbbd1e
Create Date: 2025-03-02 23:00:09.255844

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7e840c3abbad'
down_revision = '0ba557dbbd1e'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('like_topic')
    op.drop_table('like_reply')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('like_reply',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('user_id', sa.INTEGER(), nullable=False),
    sa.Column('reply_id', sa.INTEGER(), nullable=False),
    sa.ForeignKeyConstraint(['reply_id'], ['reply.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('like_topic',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('user_id', sa.INTEGER(), nullable=False),
    sa.Column('topic_id', sa.INTEGER(), nullable=False),
    sa.ForeignKeyConstraint(['topic_id'], ['topic.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###
