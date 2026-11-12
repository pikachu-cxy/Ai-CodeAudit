-- 004_notify_emails_suppressions.sql
-- Scan report recipients + project-level false-positive suppression registry.

SET @db = DATABASE();
SET @col_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db
      AND TABLE_NAME = 'scan_tasks'
      AND COLUMN_NAME = 'notify_emails_json'
);
SET @add_col = IF(
    @col_exists = 0,
    'ALTER TABLE scan_tasks ADD COLUMN notify_emails_json TEXT NULL',
    'SELECT 1'
);
PREPARE stmt_add_col FROM @add_col;
EXECUTE stmt_add_col;
DEALLOCATE PREPARE stmt_add_col;

CREATE TABLE IF NOT EXISTS project_suppressions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    project_id INT NOT NULL,
    fingerprint_strict VARCHAR(1024) NOT NULL,
    fingerprint_relaxed VARCHAR(1024) NULL,
    rule_id VARCHAR(512) NULL,
    file_path VARCHAR(1024) NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'false_positive',
    reason TEXT NOT NULL,
    source_scan_id INT NULL,
    source_finding_id INT NULL,
    created_by VARCHAR(255) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    expires_at DATETIME(6) NULL,
    CONSTRAINT fk_project_suppressions_project FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE,
    CONSTRAINT fk_project_suppressions_scan FOREIGN KEY (source_scan_id) REFERENCES scan_tasks (id) ON DELETE SET NULL,
    CONSTRAINT fk_project_suppressions_finding FOREIGN KEY (source_finding_id) REFERENCES findings (id) ON DELETE SET NULL
);

SET @idx_project = (
    SELECT COUNT(*)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db
      AND TABLE_NAME = 'project_suppressions'
      AND INDEX_NAME = 'ix_project_suppressions_project_id'
);
SET @q_project = IF(
    @idx_project = 0,
    'CREATE INDEX ix_project_suppressions_project_id ON project_suppressions (project_id)',
    'SELECT 1'
);
PREPARE stmt_project FROM @q_project;
EXECUTE stmt_project;
DEALLOCATE PREPARE stmt_project;

SET @idx_strict = (
    SELECT COUNT(*)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db
      AND TABLE_NAME = 'project_suppressions'
      AND INDEX_NAME = 'ix_project_suppressions_fingerprint_strict'
);
SET @q_strict = IF(
    @idx_strict = 0,
    'CREATE INDEX ix_project_suppressions_fingerprint_strict ON project_suppressions (fingerprint_strict(255))',
    'SELECT 1'
);
PREPARE stmt_strict FROM @q_strict;
EXECUTE stmt_strict;
DEALLOCATE PREPARE stmt_strict;

SET @idx_relaxed = (
    SELECT COUNT(*)
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db
      AND TABLE_NAME = 'project_suppressions'
      AND INDEX_NAME = 'ix_project_suppressions_fingerprint_relaxed'
);
SET @q_relaxed = IF(
    @idx_relaxed = 0,
    'CREATE INDEX ix_project_suppressions_fingerprint_relaxed ON project_suppressions (fingerprint_relaxed(255))',
    'SELECT 1'
);
PREPARE stmt_relaxed FROM @q_relaxed;
EXECUTE stmt_relaxed;
DEALLOCATE PREPARE stmt_relaxed;
