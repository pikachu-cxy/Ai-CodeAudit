-- 005_project_scan_languages.sql
-- Optional multi-select scan language scope on projects (NULL/empty = auto).

SET @db = DATABASE();
SET @col_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db
      AND TABLE_NAME = 'projects'
      AND COLUMN_NAME = 'scan_languages_json'
);
SET @add_col = IF(
    @col_exists = 0,
    'ALTER TABLE projects ADD COLUMN scan_languages_json TEXT NULL',
    'SELECT 1'
);
PREPARE stmt_add_col FROM @add_col;
EXECUTE stmt_add_col;
DEALLOCATE PREPARE stmt_add_col;
