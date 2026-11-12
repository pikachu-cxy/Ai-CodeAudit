-- Add role column to refresh_tokens for RBAC persistence across renewals.
-- Added idempotently via Python hook (006) — create_all may already have the column.

SELECT 1;
