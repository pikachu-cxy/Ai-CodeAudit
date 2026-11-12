-- 002_normalize_source_url.sql
-- Index GitLab source_url for faster duplicate detection (data backfill runs in Python hook).

CREATE INDEX IF NOT EXISTS ix_projects_gitlab_source_url ON projects (source_url);
CREATE INDEX IF NOT EXISTS ix_scan_tasks_gitlab_source_url ON scan_tasks (source_url);
