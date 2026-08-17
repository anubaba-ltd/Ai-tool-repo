-- AIANUBABA extension authentication migration (safe to run more than once where supported)
-- The Node server also creates/migrates this table automatically.
CREATE TABLE IF NOT EXISTS extension_sessions (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id VARCHAR(36) NOT NULL,
  device_id VARCHAR(255) NOT NULL,
  session_token_hash VARCHAR(255) NOT NULL,
  uninstall_token_hash VARCHAR(255) NULL,
  portal_session_id VARCHAR(100) NULL,
  browser_name VARCHAR(100) DEFAULT NULL,
  extension_version VARCHAR(50) DEFAULT NULL,
  last_heartbeat TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NULL DEFAULT NULL,
  active TINYINT(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (id),
  UNIQUE KEY unique_user_session (user_id),
  KEY idx_device_id (device_id),
  KEY idx_session_token (session_token_hash),
  KEY idx_last_heartbeat (last_heartbeat)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
