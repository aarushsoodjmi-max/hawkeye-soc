"""p0 durable tenant-scoped state
Revision ID: 0001_p0_persistence
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_p0_persistence"
down_revision = None
branch_labels = None
depends_on = None

TABLES = [
    ("events", True), ("normalized_events", False), ("incidents", False), ("assets", False),
    ("entities", False), ("knowledge_graph", False), ("threat_intelligence", False), ("risk", False),
    ("prediction", False), ("confidence", False), ("incident_memory", False), ("decisions", False),
    ("simulations", False), ("playbooks", False), ("playbook_executions", False), ("event_dispatches", False),
]

def upgrade():
    for name, event in TABLES:
        cols = [
            sa.Column("pk", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("workspace_id", sa.String(255), nullable=False),
            sa.Column("object_id", sa.String(512), nullable=False),
            sa.Column("payload", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        ]
        if event:
            cols += [sa.Column("fingerprint", sa.String(128), nullable=False), sa.Column("status", sa.String(32), nullable=False)]
        if name == "normalized_events": cols += [sa.Column("source_event_id", sa.String(512), nullable=False), sa.UniqueConstraint("workspace_id", "source_event_id", name="uq_normalized_workspace_source")]
        if name == "event_dispatches": cols += [sa.Column("topic", sa.String(255), nullable=False), sa.Column("status", sa.String(32), nullable=False)]
        if event:
            cols += [sa.UniqueConstraint("workspace_id", "fingerprint", name="uq_events_workspace_fingerprint"), sa.UniqueConstraint("workspace_id", "object_id", name="uq_events_workspace_object")]
        elif name != "normalized_events":
            cols += [sa.UniqueConstraint("workspace_id", "object_id", name=f"uq_{name}_workspace_object")]
        op.create_table(name, *cols)
        op.create_index(f"ix_{name}_workspace", name, ["workspace_id"])

def downgrade():
    for name, _ in reversed(TABLES):
        op.drop_table(name)
