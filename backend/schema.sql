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
