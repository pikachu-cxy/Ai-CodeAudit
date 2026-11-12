-- 005_project_scan_languages.sql
-- Optional multi-select scan language scope on projects (NULL/empty = auto).
-- Added idempotently via Python hook (005) — create_all / legacy sqlite migrate
-- may already have the column when this migration runs.

SELECT 1;
