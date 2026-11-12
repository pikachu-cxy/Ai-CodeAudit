-- 009_platform_management.sql (mysql)
-- Phase 2 platform management: Agent definitions, MCP server registry, audit trail.
-- app.database.init_db() runs Base.metadata.create_all BEFORE this migration, so
-- these statements are an idempotent safety net for existing installations.
-- NOTE: no DEFAULT on TEXT columns (MySQL < 8.0.13 rejects it).

CREATE TABLE IF NOT EXISTS agent_definitions (
    id INT NOT NULL AUTO_INCREMENT,
    slug VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'worker',
    description TEXT NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    model_task VARCHAR(32) NOT NULL DEFAULT 'agent',
    model_override VARCHAR(128) NOT NULL DEFAULT '',
    system_prompt TEXT NOT NULL,
    max_tool_rounds INT NOT NULL DEFAULT 10,
    max_files INT NOT NULL DEFAULT 16,
    max_tokens INT NOT NULL DEFAULT 8192,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY ix_agent_definitions_slug (slug)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS mcp_servers (
    id INT NOT NULL AUTO_INCREMENT,
    slug VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    description TEXT NOT NULL,
    transport VARCHAR(16) NOT NULL DEFAULT 'http',
    endpoint VARCHAR(512) NOT NULL DEFAULT '',
    command VARCHAR(512) NOT NULL DEFAULT '',
    args_json TEXT NOT NULL,
    headers_json TEXT NOT NULL,
    timeout_seconds INT NOT NULL DEFAULT 5,
    enabled TINYINT(1) NOT NULL DEFAULT 0,
    last_test_at DATETIME NULL,
    last_test_ok TINYINT(1) NULL,
    last_test_message TEXT NOT NULL,
    last_test_latency_ms INT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY ix_mcp_servers_slug (slug)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS platform_audit_logs (
    id INT NOT NULL AUTO_INCREMENT,
    actor VARCHAR(100) NOT NULL,
    action VARCHAR(64) NOT NULL,
    target_type VARCHAR(32) NOT NULL DEFAULT '',
    target_id VARCHAR(64) NULL,
    detail TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    KEY ix_platform_audit_logs_actor (actor),
    KEY ix_platform_audit_logs_action (action),
    KEY ix_platform_audit_logs_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
