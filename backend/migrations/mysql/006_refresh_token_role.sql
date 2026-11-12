-- Add role column to refresh_tokens for RBAC persistence across renewals.
-- Applied idempotently via Python hook (006) when create_all already added the column.

SET @db = DATABASE();
SET @col_exists = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db
      AND TABLE_NAME = 'refresh_tokens'
      AND COLUMN_NAME = 'role'
);
SET @add_col = IF(
    @col_exists = 0,
    'ALTER TABLE refresh_tokens ADD COLUMN role VARCHAR(32) NOT NULL DEFAULT ''user''',
    'SELECT 1'
);
PREPARE stmt_add_col FROM @add_col;
EXECUTE stmt_add_col;
DEALLOCATE PREPARE stmt_add_col;
