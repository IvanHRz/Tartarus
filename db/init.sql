-- TARTARUS — Phase 0 Initial Schema
-- Runs automatically via docker-entrypoint-initdb.d

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── Raw honeypot events from Beelzebub ──────────────
CREATE TABLE IF NOT EXISTS events (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip       INET NOT NULL,
    source_port     INTEGER,
    dest_port       INTEGER,
    protocol        VARCHAR(16) NOT NULL,
    session_id      VARCHAR(128),
    honeypot_id     VARCHAR(64),
    command         TEXT,
    payload         JSONB,
    sha256          VARCHAR(64),
    risk_score      SMALLINT DEFAULT 0,
    mitre_tactic    VARCHAR(64),
    mitre_technique VARCHAR(64),
    tags            TEXT[] DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Time-range queries (primary access pattern)
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp DESC);

-- IP lookups (correlation)
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events (source_ip);

-- Protocol filtering
CREATE INDEX IF NOT EXISTS idx_events_protocol ON events (protocol);

-- Session grouping
CREATE INDEX IF NOT EXISTS idx_events_session ON events (session_id);

-- ── Network topology hosts ──────────────────────────
CREATE TABLE IF NOT EXISTS hosts (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip              INET NOT NULL UNIQUE,
    hostname        VARCHAR(256),
    mac_address     VARCHAR(17),
    os_fingerprint  VARCHAR(128),
    host_type       VARCHAR(32) DEFAULT 'unknown',
    open_ports      JSONB DEFAULT '[]',
    is_honeypot     BOOLEAN DEFAULT FALSE,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts (ip);

COMMENT ON TABLE events IS 'Raw honeypot interaction events from Beelzebub via RabbitMQ';
COMMENT ON TABLE hosts IS 'Network topology hosts discovered by nmap scanner';
