CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS workspace_settings (id text PRIMARY KEY, data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS targets (id text PRIMARY KEY, workspace_id text NOT NULL DEFAULT 'default', data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS scans (id text PRIMARY KEY, workspace_id text NOT NULL DEFAULT 'default', target_id text NOT NULL REFERENCES targets(id), data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS assets (id text PRIMARY KEY, workspace_id text NOT NULL DEFAULT 'default', target_id text NOT NULL REFERENCES targets(id), data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS findings (id text PRIMARY KEY, workspace_id text NOT NULL DEFAULT 'default', target_id text NOT NULL REFERENCES targets(id), data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS historical_endpoints (id text PRIMARY KEY, workspace_id text NOT NULL DEFAULT 'default', target_id text NOT NULL REFERENCES targets(id), data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS workspace_runtime (id text PRIMARY KEY, data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS change_events (id text PRIMARY KEY, workspace_id text NOT NULL DEFAULT 'default', data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (id text PRIMARY KEY, workspace_id text NOT NULL DEFAULT 'default', data jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS scans_status_idx ON scans ((data->>'status'));
CREATE INDEX IF NOT EXISTS assets_target_idx ON assets(target_id);
CREATE INDEX IF NOT EXISTS findings_target_idx ON findings(target_id);
CREATE INDEX IF NOT EXISTS findings_status_idx ON findings ((data->>'status'));
CREATE OR REPLACE FUNCTION reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit_log is append-only'; END $$;
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='audit_append_only') THEN CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation(); END IF; END $$;
INSERT INTO schema_migrations(version) VALUES(1) ON CONFLICT DO NOTHING;

INSERT INTO schema_migrations(version) VALUES(2) ON CONFLICT DO NOTHING;

CREATE OR REPLACE VIEW v_scans AS
SELECT
    id,
    workspace_id,
    target_id,
    data->>'domain' AS domain,
    data->>'status' AS status,
    data->>'error' AS error,
    data->>'startedAt' AS created_at,
    data->>'startedAt' AS started_at,
    data->>'finishedAt' AS finished_at,
    (data->>'progress')::int AS progress,
    data
FROM scans;

CREATE OR REPLACE VIEW v_audit_log AS
SELECT
    id,
    workspace_id,
    data->>'at' AS created_at,
    data->>'actor' AS actor,
    data->>'kind' AS action,
    data->>'title' AS summary,
    data->>'detail' AS detail,
    data
FROM audit_log;

CREATE OR REPLACE VIEW v_scan_stages AS
SELECT
    s.id AS scan_id,
    s.workspace_id,
    s.target_id,
    s.data->>'domain' AS domain,
    stage->>'name' AS stage_name,
    stage->>'status' AS stage_status,
    stage->>'tool' AS tool,
    stage->>'log' AS log,
    (stage->>'attempts')::int AS attempts
FROM scans s,
LATERAL jsonb_array_elements(s.data->'stages') AS stage;

INSERT INTO schema_migrations(version) VALUES(3) ON CONFLICT DO NOTHING;

-- Migration 4: DNS Posture, Subdomain Takeovers, Endpoint Hazards, and Notification Webhooks
CREATE TABLE IF NOT EXISTS domain_dns_posture (
    id text PRIMARY KEY,
    scan_id text NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    spf_record TEXT,
    spf_status VARCHAR(50) NOT NULL,
    dmarc_record TEXT,
    dmarc_policy VARCHAR(50) NOT NULL,
    dkim_detected BOOLEAN DEFAULT FALSE,
    mx_records JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_domain_dns_posture_scan ON domain_dns_posture(scan_id);
CREATE INDEX IF NOT EXISTS idx_domain_dns_posture_domain ON domain_dns_posture(domain);

CREATE TABLE IF NOT EXISTS subdomain_takeovers (
    id text PRIMARY KEY,
    scan_id text NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    subdomain VARCHAR(255) NOT NULL,
    cname VARCHAR(255) NOT NULL,
    service_provider VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reopen_count INTEGER NOT NULL DEFAULT 0,
    missing_scans INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT uq_takeover_subdomain UNIQUE(subdomain, service_provider)
);
CREATE INDEX IF NOT EXISTS idx_takeovers_scan ON subdomain_takeovers(scan_id);
CREATE INDEX IF NOT EXISTS idx_takeovers_status ON subdomain_takeovers(status);

CREATE TABLE IF NOT EXISTS endpoint_hazards (
    id text PRIMARY KEY,
    scan_id text NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    parameter VARCHAR(100) NOT NULL,
    hazard_class VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_endpoint_hazards_scan ON endpoint_hazards(scan_id);
CREATE INDEX IF NOT EXISTS idx_endpoint_hazards_class ON endpoint_hazards(hazard_class);

CREATE TABLE IF NOT EXISTS notification_webhooks (
    id text PRIMARY KEY,
    url TEXT NOT NULL,
    webhook_type VARCHAR(50) NOT NULL DEFAULT 'generic',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    notify_on_new_assets BOOLEAN NOT NULL DEFAULT TRUE,
    notify_on_new_ports BOOLEAN NOT NULL DEFAULT TRUE,
    notify_on_high_findings BOOLEAN NOT NULL DEFAULT TRUE,
    notify_on_takeovers BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO schema_migrations(version) VALUES(4) ON CONFLICT DO NOTHING;

-- Migration 5: Add missing_scans column to subdomain_takeovers for two-scan confirmation
ALTER TABLE subdomain_takeovers ADD COLUMN IF NOT EXISTS missing_scans INTEGER NOT NULL DEFAULT 0;
INSERT INTO schema_migrations(version) VALUES(5) ON CONFLICT DO NOTHING;

