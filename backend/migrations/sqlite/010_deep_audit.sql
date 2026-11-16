-- 010_deep_audit.sql (sqlite)
-- Deep Audit V1: Planner/Worker shared code-fact blackboard.
-- app.database.init_db() runs Base.metadata.create_all BEFORE this migration,
-- so these statements are an idempotent safety net for existing installations.

CREATE TABLE IF NOT EXISTS audit_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    config_snapshot TEXT NOT NULL DEFAULT '{}',
    scope_json TEXT NOT NULL DEFAULT '{}',
    repository_revision VARCHAR(128) NOT NULL DEFAULT '',
    agent_slug VARCHAR(64) NOT NULL DEFAULT '',
    agent_definition_id INTEGER NULL,
    budget_usage TEXT NOT NULL DEFAULT '{}',
    error_message TEXT NULL,
    started_at DATETIME NULL,
    finished_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scan_tasks(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_audit_runs_scan_id ON audit_runs (scan_id);
CREATE INDEX IF NOT EXISTS ix_audit_runs_scan_created ON audit_runs (scan_id, created_at);

CREATE TABLE IF NOT EXISTS audit_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    agent_id VARCHAR(64) NOT NULL DEFAULT '',
    task_type VARCHAR(32) NOT NULL,
    goal TEXT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    priority INTEGER NOT NULL DEFAULT 0,
    result_summary TEXT NOT NULL DEFAULT '',
    fingerprint VARCHAR(64) NOT NULL,
    scope_json TEXT NOT NULL DEFAULT '{}',
    budget_usage TEXT NOT NULL DEFAULT '{}',
    started_at DATETIME NULL,
    finished_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE (run_id, fingerprint),
    FOREIGN KEY (run_id) REFERENCES audit_runs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_audit_tasks_run_status ON audit_tasks (run_id, status);

CREATE TABLE IF NOT EXISTS audit_facts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    task_id INTEGER NULL,
    fact_type VARCHAR(32) NOT NULL,
    summary TEXT NOT NULL,
    source VARCHAR(255) NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 0.5,
    fingerprint VARCHAR(64) NOT NULL,
    finding_id INTEGER NULL,
    metadata_json TEXT NULL,
    created_at DATETIME NOT NULL,
    UNIQUE (run_id, fingerprint),
    FOREIGN KEY (run_id) REFERENCES audit_runs(id) ON DELETE CASCADE,
    FOREIGN KEY (task_id) REFERENCES audit_tasks(id) ON DELETE SET NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_facts_run_type ON audit_facts (run_id, fact_type);
CREATE INDEX IF NOT EXISTS ix_audit_facts_fingerprint ON audit_facts (fingerprint);
CREATE INDEX IF NOT EXISTS ix_audit_facts_task_id ON audit_facts (task_id);
CREATE INDEX IF NOT EXISTS ix_audit_facts_finding_id ON audit_facts (finding_id);

CREATE TABLE IF NOT EXISTS audit_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fact_id INTEGER NOT NULL,
    fingerprint VARCHAR(64) NOT NULL DEFAULT '',
    repository_revision VARCHAR(128) NOT NULL DEFAULT '',
    file_path VARCHAR(1024) NOT NULL,
    line_start INTEGER NOT NULL DEFAULT 0,
    line_end INTEGER NOT NULL DEFAULT 0,
    content_hash VARCHAR(64) NOT NULL DEFAULT '',
    evidence_type VARCHAR(32) NOT NULL DEFAULT 'code_slice',
    evidence_summary TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    UNIQUE (fact_id, fingerprint),
    FOREIGN KEY (fact_id) REFERENCES audit_facts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_audit_evidence_fact ON audit_evidence (fact_id);
CREATE INDEX IF NOT EXISTS ix_audit_evidence_revision ON audit_evidence (repository_revision);
