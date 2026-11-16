-- 010_deep_audit.sql (mysql)
-- Deep Audit V1: Planner/Worker shared code-fact blackboard.
-- app.database.init_db() runs Base.metadata.create_all BEFORE this migration,
-- so these statements are an idempotent safety net for existing installations.
-- NOTE: no DEFAULT on TEXT columns (MySQL < 8.0.13 rejects it).
-- All KEY/UNIQUE KEY definitions live in CREATE TABLE, so `IF NOT EXISTS`
-- keeps the whole statement atomic on fresh installs too.

CREATE TABLE IF NOT EXISTS audit_runs (
    id INT NOT NULL AUTO_INCREMENT,
    scan_id INT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    config_snapshot TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    repository_revision VARCHAR(128) NOT NULL DEFAULT '',
    agent_slug VARCHAR(64) NOT NULL DEFAULT '',
    agent_definition_id INT NULL,
    budget_usage TEXT NOT NULL,
    error_message TEXT NULL,
    started_at DATETIME NULL,
    finished_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    KEY ix_audit_runs_scan_id (scan_id),
    KEY ix_audit_runs_scan_created (scan_id, created_at),
    CONSTRAINT fk_audit_runs_scan FOREIGN KEY (scan_id) REFERENCES scan_tasks(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS audit_tasks (
    id INT NOT NULL AUTO_INCREMENT,
    run_id INT NOT NULL,
    agent_id VARCHAR(64) NOT NULL DEFAULT '',
    task_type VARCHAR(32) NOT NULL,
    goal TEXT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    priority INT NOT NULL DEFAULT 0,
    result_summary TEXT NOT NULL,
    fingerprint VARCHAR(64) NOT NULL,
    scope_json TEXT NOT NULL,
    budget_usage TEXT NOT NULL,
    started_at DATETIME NULL,
    finished_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_audit_task_run_fingerprint (run_id, fingerprint),
    KEY ix_audit_tasks_run_status (run_id, status),
    CONSTRAINT fk_audit_tasks_run FOREIGN KEY (run_id) REFERENCES audit_runs(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS audit_facts (
    id INT NOT NULL AUTO_INCREMENT,
    run_id INT NOT NULL,
    task_id INT NULL,
    fact_type VARCHAR(32) NOT NULL,
    summary TEXT NOT NULL,
    source VARCHAR(255) NOT NULL DEFAULT '',
    confidence DOUBLE NOT NULL DEFAULT 0.5,
    fingerprint VARCHAR(64) NOT NULL,
    finding_id INT NULL,
    metadata_json TEXT NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_audit_fact_run_fingerprint (run_id, fingerprint),
    KEY ix_audit_facts_run_type (run_id, fact_type),
    KEY ix_audit_facts_fingerprint (fingerprint),
    KEY ix_audit_facts_task_id (task_id),
    KEY ix_audit_facts_finding_id (finding_id),
    CONSTRAINT fk_audit_facts_run FOREIGN KEY (run_id) REFERENCES audit_runs(id) ON DELETE CASCADE,
    CONSTRAINT fk_audit_facts_task FOREIGN KEY (task_id) REFERENCES audit_tasks(id) ON DELETE SET NULL,
    CONSTRAINT fk_audit_facts_finding FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS audit_evidence (
    id INT NOT NULL AUTO_INCREMENT,
    fact_id INT NOT NULL,
    fingerprint VARCHAR(64) NOT NULL DEFAULT '',
    repository_revision VARCHAR(128) NOT NULL DEFAULT '',
    file_path VARCHAR(1024) NOT NULL,
    line_start INT NOT NULL DEFAULT 0,
    line_end INT NOT NULL DEFAULT 0,
    content_hash VARCHAR(64) NOT NULL DEFAULT '',
    evidence_type VARCHAR(32) NOT NULL DEFAULT 'code_slice',
    evidence_summary TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_audit_evidence_fact_fingerprint (fact_id, fingerprint),
    KEY ix_audit_evidence_fact (fact_id),
    KEY ix_audit_evidence_revision (repository_revision),
    CONSTRAINT fk_audit_evidence_fact FOREIGN KEY (fact_id) REFERENCES audit_facts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
