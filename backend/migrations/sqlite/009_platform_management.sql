-- 009_platform_management.sql (sqlite)
-- Phase 2 platform management: Agent definitions, MCP server registry, audit trail.
-- app.database.init_db() runs Base.metadata.create_all BEFORE this migration, so
-- these statements are an idempotent safety net for existing installations.

CREATE TABLE IF NOT EXISTS agent_definitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(128) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'worker',
    description TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT 1,
    model_task VARCHAR(32) NOT NULL DEFAULT 'agent',
    model_override VARCHAR(128) NOT NULL DEFAULT '',
    system_prompt TEXT NOT NULL DEFAULT '',
    max_tool_rounds INTEGER NOT NULL DEFAULT 10,
    max_files INTEGER NOT NULL DEFAULT 16,
    max_tokens INTEGER NOT NULL DEFAULT 8192,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_agent_definitions_slug ON agent_definitions (slug);

CREATE TABLE IF NOT EXISTS mcp_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(128) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    transport VARCHAR(16) NOT NULL DEFAULT 'http',
    endpoint VARCHAR(512) NOT NULL DEFAULT '',
    command VARCHAR(512) NOT NULL DEFAULT '',
    args_json TEXT NOT NULL DEFAULT '[]',
    headers_json TEXT NOT NULL DEFAULT '{}',
    timeout_seconds INTEGER NOT NULL DEFAULT 5,
    enabled BOOLEAN NOT NULL DEFAULT 0,
    last_test_at DATETIME,
    last_test_ok BOOLEAN,
    last_test_message TEXT NOT NULL DEFAULT '',
    last_test_latency_ms INTEGER,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_mcp_servers_slug ON mcp_servers (slug);

CREATE TABLE IF NOT EXISTS platform_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor VARCHAR(100) NOT NULL,
    action VARCHAR(64) NOT NULL,
    target_type VARCHAR(32) NOT NULL DEFAULT '',
    target_id VARCHAR(64),
    detail TEXT NOT NULL DEFAULT '{}',
    created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_platform_audit_logs_actor ON platform_audit_logs (actor);
CREATE INDEX IF NOT EXISTS ix_platform_audit_logs_action ON platform_audit_logs (action);
CREATE INDEX IF NOT EXISTS ix_platform_audit_logs_created_at ON platform_audit_logs (created_at);
