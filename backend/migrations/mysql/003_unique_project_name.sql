-- 003_unique_project_name.sql
-- Rename duplicate project names, then enforce uniqueness.

UPDATE projects p
INNER JOIN (
    SELECT LOWER(name) AS n, MIN(id) AS keep_id
    FROM projects
    GROUP BY LOWER(name)
    HAVING COUNT(*) > 1
) d ON LOWER(p.name) = d.n AND p.id <> d.keep_id
SET p.name = CONCAT(LEFT(p.name, 240), ' (', p.id, ')');

CREATE UNIQUE INDEX ux_projects_name ON projects (name);
