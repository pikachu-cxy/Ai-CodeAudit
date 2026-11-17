CREATE TABLE IF NOT EXISTS asset_graph_snapshots (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    snapshot_key VARCHAR(64) NOT NULL UNIQUE,
    repository_revision VARCHAR(128) NOT NULL,
    scope_json TEXT NOT NULL,
    extractor_version VARCHAR(32) NOT NULL,
    graph JSON NOT NULL,
    created_at DATETIME NOT NULL,
    INDEX ix_asset_graph_snapshots_scan_id (scan_id),
    FOREIGN KEY (scan_id) REFERENCES scan_tasks(id) ON DELETE CASCADE
) ENGINE=InnoDB;
