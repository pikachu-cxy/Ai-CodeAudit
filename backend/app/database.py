from collections.abc import AsyncGenerator
from threading import Lock

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import build_database_url, database_backend_name, settings
from app.migrations.runner import run_pending_migrations

class Base(DeclarativeBase):
    pass


def _create_engine() -> AsyncEngine:
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    url = build_database_url()
    kwargs: dict = {
        # SQL echo floods the event loop under UI polling; keep off even if debug=True.
        "echo": False,
    }
    if database_backend_name() == "mysql":
        kwargs.update(
            pool_pre_ping=True,
            pool_recycle=280,
            pool_size=5,
            max_overflow=10,
        )
    return create_async_engine(url, **kwargs)


def _attach_sqlite_pragmas(eng: AsyncEngine) -> None:
    @event.listens_for(eng.sync_engine, "connect")
    def _sqlite_pragma(dbapi_conn, _connection_record) -> None:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        # WAL keeps API reads (health / polling) responsive while scans write.
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()


def _make_session_factory(eng: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(eng, class_=AsyncSession, expire_on_commit=False)


class _SessionFactoryProxy:
    """Delegates to the current sessionmaker so callers keep working after a live switch."""

    def __call__(self, **kwargs):
        return _session_factory(**kwargs)


_bind_lock = Lock()
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None
async_session = _SessionFactoryProxy()


def get_engine() -> AsyncEngine:
    if _engine is None:
        raise RuntimeError("database engine is not configured")
    return _engine


def configure_engine(eng: AsyncEngine | None = None) -> AsyncEngine:
    """Bind process-wide engine + session factory to current settings."""
    global _engine, _session_factory
    created = eng or _create_engine()
    if database_backend_name() == "sqlite":
        _attach_sqlite_pragmas(created)
    factory = _make_session_factory(created)
    with _bind_lock:
        _engine = created
        _session_factory = factory
    return created


configure_engine()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session


async def init_db(eng: AsyncEngine | None = None) -> None:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    settings.repos_dir.mkdir(parents=True, exist_ok=True)

    from app import models  # noqa: F401

    target = eng or get_engine()
    async with target.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        if database_backend_name() == "sqlite":
            await _migrate_schema_legacy_sqlite(conn)
        await run_pending_migrations(conn)


async def reconfigure_database() -> str:
    """Switch the live engine to current settings without restarting the process."""
    from app.services.scan_runtime import has_any_active_pipeline

    if has_any_active_pipeline():
        raise RuntimeError("有扫描任务进行中，请等待或暂停后再切换数据库")

    new_engine = _create_engine()
    try:
        await init_db(new_engine)
    except Exception:
        await new_engine.dispose()
        raise

    old_engine = get_engine()
    configure_engine(new_engine)
    if old_engine is not None and old_engine is not new_engine:
        await old_engine.dispose()
    return database_backend_name()


async def _migrate_schema_legacy_sqlite(conn) -> None:
    """Legacy incremental alters for SQLite DBs created before versioned SQL migrations."""
    def _backfill_classification(connection):
        from sqlalchemy import text as sql_text

        from app.services.owasp_classifier import classify_finding

        rows = connection.execute(sql_text(
            "SELECT id, rule_id, message, metadata_json, tool, category FROM findings"
        )).fetchall()
        for row in rows:
            fields = classify_finding(
                rule_id=row.rule_id or "",
                message=row.message or "",
                metadata_json=row.metadata_json,
                tool=row.tool or "",
                category=row.category or "sast",
            )
            connection.execute(
                sql_text(
                    "UPDATE findings SET owasp_id = :oid, owasp_name = :oname, "
                    "vuln_subtype = :sub, vuln_subtype_name = :subname WHERE id = :id"
                ),
                {
                    "oid": fields["owasp_id"],
                    "oname": fields["owasp_name"],
                    "sub": fields["vuln_subtype"],
                    "subname": fields["vuln_subtype_name"],
                    "id": row.id,
                },
            )

    def _backfill_owasp(connection):
        _backfill_classification(connection)

    def _run(connection):
        from sqlalchemy import inspect

        inspector = inspect(connection)
        if "findings" in inspector.get_table_names():
            cols = {c["name"] for c in inspector.get_columns("findings")}
            if "category" not in cols:
                connection.execute(text(
                    "ALTER TABLE findings ADD COLUMN category VARCHAR(20) DEFAULT 'sast'"
                ))
            if "message_zh" not in cols:
                connection.execute(text(
                    "ALTER TABLE findings ADD COLUMN message_zh TEXT"
                ))
            if "review_status" not in cols:
                connection.execute(text(
                    "ALTER TABLE findings ADD COLUMN review_status VARCHAR(20) DEFAULT 'unreviewed'"
                ))
            if "review_note" not in cols:
                connection.execute(text(
                    "ALTER TABLE findings ADD COLUMN review_note TEXT"
                ))
            if "reviewed_at" not in cols:
                connection.execute(text(
                    "ALTER TABLE findings ADD COLUMN reviewed_at DATETIME"
                ))
            if "external_status" not in cols:
                connection.execute(text(
                    "ALTER TABLE findings ADD COLUMN external_status VARCHAR(20) DEFAULT 'unreviewed'"
                ))
            if "external_note" not in cols:
                connection.execute(text(
                    "ALTER TABLE findings ADD COLUMN external_note TEXT"
                ))
            if "external_updated_at" not in cols:
                connection.execute(text(
                    "ALTER TABLE findings ADD COLUMN external_updated_at DATETIME"
                ))
            if "external_updated_by" not in cols:
                connection.execute(text(
                    "ALTER TABLE findings ADD COLUMN external_updated_by VARCHAR(255)"
                ))
            if "external_review_token" not in cols:
                connection.execute(text(
                    "ALTER TABLE findings ADD COLUMN external_review_token VARCHAR(128)"
                ))
            if "external_review_expires_at" not in cols:
                connection.execute(text(
                    "ALTER TABLE findings ADD COLUMN external_review_expires_at DATETIME"
                ))
            if "external_review_revoked_at" not in cols:
                connection.execute(text(
                    "ALTER TABLE findings ADD COLUMN external_review_revoked_at DATETIME"
                ))
            if "owasp_id" not in cols:
                connection.execute(text(
                    "ALTER TABLE findings ADD COLUMN owasp_id VARCHAR(8)"
                ))
            if "owasp_name" not in cols:
                connection.execute(text(
                    "ALTER TABLE findings ADD COLUMN owasp_name VARCHAR(128)"
                ))
            if "vuln_subtype" not in cols:
                connection.execute(text(
                    "ALTER TABLE findings ADD COLUMN vuln_subtype VARCHAR(64)"
                ))
            if "vuln_subtype_name" not in cols:
                connection.execute(text(
                    "ALTER TABLE findings ADD COLUMN vuln_subtype_name VARCHAR(128)"
                ))
            connection.execute(text(
                "UPDATE findings SET review_status = 'unreviewed' WHERE review_status IS NULL"
            ))
            connection.execute(text(
                "UPDATE findings SET review_status = 'unreviewed' WHERE review_status = 'pending'"
            ))
            connection.execute(text(
                "UPDATE findings SET external_status = 'unreviewed' WHERE external_status IS NULL"
            ))
            connection.execute(text(
                "UPDATE findings SET external_status = 'unreviewed' WHERE external_status = 'UNREVIEWED'"
            ))
            connection.execute(text(
                "UPDATE findings SET external_status = 'vuln_exists' WHERE external_status = 'VULN_EXISTS'"
            ))
            connection.execute(text(
                "UPDATE findings SET external_status = 'false_positive' WHERE external_status = 'FALSE_POSITIVE'"
            ))
            connection.execute(text(
                "UPDATE findings SET external_status = 'fixed_claimed' WHERE external_status = 'FIXED_CLAIMED'"
            ))
            _backfill_owasp(connection)
        if "scan_tasks" in inspector.get_table_names():
            cols = {c["name"] for c in inspector.get_columns("scan_tasks")}
            if "scanner_summary" not in cols:
                connection.execute(text(
                    "ALTER TABLE scan_tasks ADD COLUMN scanner_summary TEXT"
                ))
            if "project_review_token" not in cols:
                connection.execute(text(
                    "ALTER TABLE scan_tasks ADD COLUMN project_review_token VARCHAR(128)"
                ))
            if "project_review_expires_at" not in cols:
                connection.execute(text(
                    "ALTER TABLE scan_tasks ADD COLUMN project_review_expires_at DATETIME"
                ))
            if "project_review_revoked_at" not in cols:
                connection.execute(text(
                    "ALTER TABLE scan_tasks ADD COLUMN project_review_revoked_at DATETIME"
                ))
            connection.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_scan_tasks_project_review_token "
                "ON scan_tasks (project_review_token)"
            ))
            if "notes" not in cols:
                connection.execute(text(
                    "ALTER TABLE scan_tasks ADD COLUMN notes TEXT"
                ))
            if "archived_at" not in cols:
                connection.execute(text(
                    "ALTER TABLE scan_tasks ADD COLUMN archived_at DATETIME"
                ))
            if "project_id" not in cols:
                connection.execute(text(
                    "ALTER TABLE scan_tasks ADD COLUMN project_id INTEGER"
                ))
            if "parent_scan_id" not in cols:
                connection.execute(text(
                    "ALTER TABLE scan_tasks ADD COLUMN parent_scan_id INTEGER"
                ))
            if "scan_kind" not in cols:
                connection.execute(text(
                    "ALTER TABLE scan_tasks ADD COLUMN scan_kind VARCHAR(20) DEFAULT 'baseline'"
                ))
            if "version_label" not in cols:
                connection.execute(text(
                    "ALTER TABLE scan_tasks ADD COLUMN version_label VARCHAR(64)"
                ))
            connection.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_scan_tasks_project_id ON scan_tasks (project_id)"
            ))
            connection.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_scan_tasks_parent_scan_id ON scan_tasks (parent_scan_id)"
            ))
            connection.execute(text(
                "UPDATE scan_tasks SET scan_kind = 'baseline' WHERE scan_kind IS NULL OR scan_kind = ''"
            ))
            if "retest_strategy" not in cols:
                connection.execute(text(
                    "ALTER TABLE scan_tasks ADD COLUMN retest_strategy VARCHAR(20)"
                ))
            if "retest_options_json" not in cols:
                connection.execute(text(
                    "ALTER TABLE scan_tasks ADD COLUMN retest_options_json TEXT"
                ))
            orphan_rows = connection.execute(text(
                "SELECT id, name, notes, source, source_url, branch, archived_at, created_at, updated_at "
                "FROM scan_tasks WHERE project_id IS NULL"
            )).fetchall()
            for row in orphan_rows:
                connection.execute(
                    text(
                        "INSERT INTO projects "
                        "(name, notes, source_type, source_url, default_branch, archived_at, created_at, updated_at) "
                        "VALUES (:name, :notes, :source_type, :source_url, :default_branch, :archived_at, "
                        ":created_at, :updated_at)"
                    ),
                    {
                        "name": row.name or f"scan-{row.id}",
                        "notes": row.notes,
                        "source_type": row.source or "upload",
                        "source_url": row.source_url,
                        "default_branch": row.branch,
                        "archived_at": row.archived_at,
                        "created_at": row.created_at,
                        "updated_at": row.updated_at or row.created_at,
                    },
                )
                project_id = connection.execute(text("SELECT last_insert_rowid()")).scalar()
                connection.execute(
                    text(
                        "UPDATE scan_tasks SET project_id = :pid, scan_kind = COALESCE(scan_kind, 'baseline'), "
                        "version_label = COALESCE(version_label, 'v1') WHERE id = :sid"
                    ),
                    {"pid": project_id, "sid": row.id},
                )
        if "projects" in inspector.get_table_names():
            project_cols = {c["name"] for c in inspector.get_columns("projects")}
            if "scan_languages_json" not in project_cols:
                connection.execute(text(
                    "ALTER TABLE projects ADD COLUMN scan_languages_json TEXT"
                ))
        if "scan_events" not in inspector.get_table_names():
            connection.execute(text(
                """
                CREATE TABLE scan_events (
                    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    level VARCHAR(16) NOT NULL DEFAULT 'info',
                    phase VARCHAR(64),
                    tool VARCHAR(64),
                    file_path VARCHAR(1024),
                    message TEXT NOT NULL,
                    created_at DATETIME NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scan_tasks (id) ON DELETE CASCADE
                )
                """
            ))
            connection.execute(text(
                "CREATE INDEX ix_scan_events_scan_id ON scan_events (scan_id)"
            ))
        if "retest_verifications" not in inspector.get_table_names():
            connection.execute(text(
                """
                CREATE TABLE retest_verifications (
                    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    baseline_scan_id INTEGER NOT NULL,
                    baseline_finding_id INTEGER NOT NULL,
                    verdict VARCHAR(32) NOT NULL,
                    method VARCHAR(32) NOT NULL,
                    evidence_json TEXT,
                    created_at DATETIME NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scan_tasks (id) ON DELETE CASCADE,
                    FOREIGN KEY(baseline_scan_id) REFERENCES scan_tasks (id) ON DELETE CASCADE,
                    FOREIGN KEY(baseline_finding_id) REFERENCES findings (id) ON DELETE CASCADE
                )
                """
            ))
            connection.execute(text(
                "CREATE INDEX ix_retest_verifications_scan_id ON retest_verifications (scan_id)"
            ))
            connection.execute(text(
                "CREATE INDEX ix_retest_verifications_baseline_finding_id "
                "ON retest_verifications (baseline_finding_id)"
            ))

    await conn.run_sync(_run)
