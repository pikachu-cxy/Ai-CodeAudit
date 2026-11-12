-- 004_notify_emails_suppressions.sql
-- Scan report recipients + project-level false-positive suppression registry.
-- notify_emails_json is added idempotently via Python hook (004) — create_all may
-- already have the column on SQLite when this migration runs.

CREATE TABLE IF NOT EXISTS project_suppressions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    fingerprint_strict VARCHAR(1024) NOT NULL,
    fingerprint_relaxed VARCHAR(1024),
    rule_id VARCHAR(512),
    file_path VARCHAR(1024),
    status VARCHAR(32) NOT NULL DEFAULT 'false_positive',
    reason TEXT NOT NULL,
    source_scan_id INTEGER REFERENCES scan_tasks (id) ON DELETE SET NULL,
    source_finding_id INTEGER REFERENCES findings (id) ON DELETE SET NULL,
    created_by VARCHAR(255),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME
);

CREATE INDEX IF NOT EXISTS ix_project_suppressions_project_id ON project_suppressions (project_id);
CREATE INDEX IF NOT EXISTS ix_project_suppressions_fingerprint_strict ON project_suppressions (fingerprint_strict);
CREATE INDEX IF NOT EXISTS ix_project_suppressions_fingerprint_relaxed ON project_suppressions (fingerprint_relaxed);
