-- 003_unique_project_name.sql
-- Rename duplicate project names, then enforce case-insensitive uniqueness.

UPDATE projects
SET name = substr(name, 1, 240) || ' (' || id || ')'
WHERE id NOT IN (
    SELECT keep_id FROM (
        SELECT MIN(id) AS keep_id FROM projects GROUP BY lower(name)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_projects_name_lower ON projects (lower(name));
