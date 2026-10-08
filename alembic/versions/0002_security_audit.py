"""security audit log"""
from alembic import op
import sqlalchemy as sa
revision = "0002_security_audit"
down_revision = "0001_p0_persistence"
branch_labels = None

def upgrade():
    op.create_table(
        "audit_logs",
        sa.Column("pk", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("record_id", sa.String(64), nullable=False, unique=True),
        sa.Column("workspace_id", sa.String(255), nullable=False),
        sa.Column("actor_id", sa.String(255)),
        sa.Column("role", sa.String(32)),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("request_id", sa.String(128)),
        sa.Column("event_id", sa.String(128)),
        sa.Column("incident_id", sa.String(512)),
        sa.Column("ai_request_id", sa.String(128)),
        sa.Column("decision_id", sa.String(128)),
        sa.Column("execution_id", sa.String(128)),
        sa.Column("previous_hash", sa.String(64), nullable=False, server_default=""),
        sa.Column("record_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_logs_workspace_id", "audit_logs", ["workspace_id"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])

def downgrade():
    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_workspace_id", table_name="audit_logs")
    op.drop_table("audit_logs")
