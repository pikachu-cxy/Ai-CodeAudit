CREATE TABLE IF NOT EXISTS asset_graph_snapshots (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scan_tasks(id) ON DELETE CASCADE,
    snapshot_key VARCHAR(64) NOT NULL UNIQUE,
    repository_revision VARCHAR(128) NOT NULL,
    scope_json TEXT NOT NULL,
    extractor_version VARCHAR(32) NOT NULL,
    graph JSON NOT NULL,
    created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_asset_graph_snapshots_scan_id ON asset_graph_snapshots (scan_id);
