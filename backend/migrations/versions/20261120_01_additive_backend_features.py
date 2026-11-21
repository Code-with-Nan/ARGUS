"""Add ARGUS scan metadata, remediation, and verification structures.

Revision ID: 20261120_01
Revises:
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "20261120_01"
down_revision = None
branch_labels = None
depends_on = None


def _tables() -> set[str]:
    return set(inspect(op.get_bind()).get_table_names())


def _columns(table: str) -> set[str]:
    return {column["name"] for column in inspect(op.get_bind()).get_columns(table)}


def _add_column_if_missing(table: str, column: sa.Column) -> None:
    if table in _tables() and column.name not in _columns(table):
        op.add_column(table, column)


def upgrade() -> None:
    tables = _tables()

    if "users" not in tables:
        op.create_table(
            "users",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("email", sa.String(length=320), nullable=False),
            sa.Column("display_name", sa.String(length=255), nullable=False),
            sa.Column("password_hash", sa.String(length=255), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_users_email", "users", ["email"], unique=True)

    if "login_attempts" not in tables:
        op.create_table(
            "login_attempts",
            sa.Column("key", sa.String(length=512), nullable=False),
            sa.Column("failed_attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("blocked_until", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.PrimaryKeyConstraint("key"),
        )

    if "user_sessions" not in tables:
        op.create_table(
            "user_sessions",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("user_id", sa.String(length=36), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])
        op.create_index("ix_user_sessions_token_hash", "user_sessions", ["token_hash"], unique=True)

    if "projects" not in tables:
        op.create_table(
            "projects",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("owner_user_id", sa.String(length=36), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_projects_owner_user_id", "projects", ["owner_user_id"])

    if "scans" not in tables:
        op.create_table(
            "scans",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("project_name", sa.String(length=255), nullable=False),
            sa.Column("status", sa.String(length=50), nullable=False),
            sa.Column("scanner", sa.String(length=100), nullable=False),
            sa.Column("total_findings", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("project_id", sa.String(length=36), nullable=True),
            sa.Column("initiated_by_user_id", sa.String(length=36), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["initiated_by_user_id"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_scans_created_at", "scans", ["created_at"])
        op.create_index("ix_scans_project_id", "scans", ["project_id"])
        op.create_index("ix_scans_initiated_by_user_id", "scans", ["initiated_by_user_id"])

    if "findings" not in tables:
        op.create_table(
            "findings",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("scan_id", sa.String(length=36), nullable=False),
            sa.Column("title", sa.Text(), nullable=False),
            sa.Column("severity", sa.String(length=20), nullable=False),
            sa.Column("confidence", sa.String(length=20), nullable=False),
            sa.Column("file", sa.Text(), nullable=False),
            sa.Column("line", sa.Integer(), nullable=False),
            sa.Column("test_id", sa.String(length=20), nullable=False),
            sa.Column("code", sa.Text(), nullable=False),
            sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_findings_scan_id", "findings", ["scan_id"])

    if "scan_metadata" not in tables:
        op.create_table(
            "scan_metadata",
            sa.Column("scan_id", sa.String(length=36), nullable=False),
            sa.Column("source_path", sa.Text(), nullable=True),
            sa.Column("source_filename", sa.Text(), nullable=True),
            sa.Column("source_sha256", sa.String(length=64), nullable=True),
            sa.Column("scanner_results", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("scan_id"),
        )

    if "finding_details" not in _tables():
        op.create_table(
            "finding_details",
            sa.Column("finding_id", sa.Integer(), nullable=False),
            sa.Column("scanner", sa.String(length=100), nullable=False),
            sa.Column("rule_id", sa.String(length=255), nullable=True),
            sa.Column("package", sa.String(length=255), nullable=True),
            sa.Column("installed_version", sa.String(length=100), nullable=True),
            sa.Column("fixed_version", sa.String(length=100), nullable=True),
            sa.Column("references", sa.JSON(), nullable=False),
            sa.Column("metadata_json", sa.JSON(), nullable=False),
            sa.Column("explanation", sa.Text(), nullable=True),
            sa.Column("explanation_source", sa.String(length=100), nullable=True),
            sa.Column("description", sa.Text(), nullable=True),
            sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("finding_id"),
        )

    if "remediations" not in _tables():
        op.create_table(
            "remediations",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("finding_id", sa.Integer(), nullable=False),
            sa.Column("source_scan_id", sa.String(length=36), nullable=False),
            sa.Column("rationale", sa.Text(), nullable=False),
            sa.Column("suggested_fix", sa.Text(), nullable=False),
            sa.Column("patch", sa.Text(), nullable=True),
            sa.Column("original_code", sa.Text(), nullable=True),
            sa.Column("proposed_code", sa.Text(), nullable=True),
            sa.Column("affected_file", sa.Text(), nullable=True),
            sa.Column("affected_line", sa.Integer(), nullable=True),
            sa.Column("working_copy_path", sa.Text(), nullable=True),
            sa.Column("status", sa.String(length=30), server_default="pending", nullable=False),
            sa.Column("approved_by", sa.String(length=255), nullable=True),
            sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("applied_scan_id", sa.String(length=36), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["source_scan_id"], ["scans.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["applied_scan_id"], ["scans.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_remediations_finding_id", "remediations", ["finding_id"])

    if "verification_results" not in _tables():
        op.create_table(
            "verification_results",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("remediation_id", sa.String(length=36), nullable=False),
            sa.Column("followup_scan_id", sa.String(length=36), nullable=True),
            sa.Column("status", sa.String(length=30), nullable=False),
            sa.Column("target_finding_present", sa.Boolean(), nullable=True),
            sa.Column("message", sa.Text(), nullable=False),
            sa.Column("evidence", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["remediation_id"], ["remediations.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["followup_scan_id"], ["scans.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_verification_results_remediation_id", "verification_results", ["remediation_id"])

    _add_column_if_missing(
        "scans",
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    _add_column_if_missing("scans", sa.Column("project_id", sa.String(length=36), nullable=True))
    _add_column_if_missing("scans", sa.Column("initiated_by_user_id", sa.String(length=36), nullable=True))
    _add_column_if_missing("finding_details", sa.Column("description", sa.Text(), nullable=True))
    _add_column_if_missing("verification_results", sa.Column("evidence", sa.JSON(), nullable=False, server_default="{}"))
    for column in (
        sa.Column("original_code", sa.Text(), nullable=True),
        sa.Column("proposed_code", sa.Text(), nullable=True),
        sa.Column("affected_file", sa.Text(), nullable=True),
        sa.Column("affected_line", sa.Integer(), nullable=True),
        sa.Column("working_copy_path", sa.Text(), nullable=True),
    ):
        _add_column_if_missing("remediations", column)

    indexes = {index["name"] for index in inspect(op.get_bind()).get_indexes("findings")}
    if "ix_findings_scan_id" not in indexes:
        op.create_index("ix_findings_scan_id", "findings", ["scan_id"])


def downgrade() -> None:
    tables = _tables()
    if "verification_results" in tables:
        op.drop_table("verification_results")
    if "remediations" in tables:
        op.drop_table("remediations")
    if "finding_details" in tables:
        op.drop_table("finding_details")
    if "scan_metadata" in tables:
        op.drop_table("scan_metadata")
    if "projects" in tables:
        op.drop_table("projects")
    if "user_sessions" in tables:
        op.drop_table("user_sessions")
    if "login_attempts" in tables:
        op.drop_table("login_attempts")
    if "users" in tables:
        op.drop_table("users")
    indexes = {index["name"] for index in inspect(op.get_bind()).get_indexes("findings")}
    if "ix_findings_scan_id" in indexes:
        op.drop_index("ix_findings_scan_id", table_name="findings")
    if "updated_at" in _columns("scans"):
        op.drop_column("scans", "updated_at")