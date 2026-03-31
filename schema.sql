PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS sensor_data;
DROP TABLE IF EXISTS logs;
DROP TABLE IF EXISTS protocol_messages;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS devices;

CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    vault BLOB NOT NULL,
    vault_version INTEGER NOT NULL DEFAULT 1,
    n_keys INTEGER NOT NULL,
    key_size_bytes INTEGER NOT NULL,
    device_online INTEGER NOT NULL DEFAULT 0,
    polling_interval_seconds INTEGER DEFAULT 5,
    last_heartbeat_at TEXT,
    pending_command INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    protocol_phase TEXT NOT NULL DEFAULT 'idle',
    r1 BLOB,
    r2 BLOB,
    t1 BLOB,
    t2 BLOB,
    session_key_generated INTEGER NOT NULL DEFAULT 0,
    auth_device_status TEXT NOT NULL DEFAULT 'pending',
    auth_server_status TEXT NOT NULL DEFAULT 'pending',
    vault_status TEXT NOT NULL DEFAULT 'unchanged',
    started_at TEXT NOT NULL,
    completed_at TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(device_id)
);

CREATE TABLE protocol_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    message_type TEXT NOT NULL,
    direction TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'waiting',
    percent INTEGER NOT NULL DEFAULT 0,
    title TEXT NOT NULL,
    subtitle TEXT,
    detail TEXT,
    payload_preview TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT,
    session_id TEXT,
    level TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(device_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE sensor_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    session_id TEXT,
    temperature REAL,
    humidity REAL,
    battery REAL,
    payload_json TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(device_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);