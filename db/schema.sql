CREATE TABLE IF NOT EXISTS schema_versions (version integer PRIMARY KEY, applied_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS organizations (id uuid PRIMARY KEY, name text NOT NULL, created_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS memberships (
  organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL, role text NOT NULL CHECK (role IN ('owner','maintainer','viewer')),
  PRIMARY KEY (organization_id,user_id)
);
CREATE TABLE IF NOT EXISTS projects (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL, source_type text NOT NULL CHECK (source_type IN ('local','github')),
  source_ref text NOT NULL, github_installation_id bigint, default_branch text DEFAULT 'main',
  components jsonb NOT NULL DEFAULT '[]', target jsonb, metadata_only boolean DEFAULT false,
  ai_enabled boolean DEFAULT false, policy jsonb NOT NULL,
  created_at timestamptz DEFAULT now()
);
CREATE TABLE IF NOT EXISTS runners (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL, token_hash text UNIQUE NOT NULL, project_ids jsonb NOT NULL,
  revoked_at timestamptz, last_seen timestamptz, created_at timestamptz DEFAULT now()
);
CREATE TABLE IF NOT EXISTS scans (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','failed','cancelled')),
  runner_id uuid REFERENCES runners(id) ON DELETE SET NULL, lease_token uuid,
  lease_until timestamptz, attempts integer DEFAULT 0, cancel_requested boolean DEFAULT false,
  requested_revision text, revision text, gate text CHECK (gate IN ('pass','fail','incomplete')),
  policy jsonb NOT NULL, inventory jsonb, metrics jsonb, error text,
  created_at timestamptz DEFAULT now(), started_at timestamptz, finished_at timestamptz
);
CREATE INDEX IF NOT EXISTS scans_queue ON scans(status,lease_until,created_at);
CREATE TABLE IF NOT EXISTS executions (
  id uuid PRIMARY KEY, scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  engine text NOT NULL, version text NOT NULL, status text NOT NULL,
  duration_ms integer NOT NULL, coverage jsonb NOT NULL, limitations jsonb NOT NULL,
  error text, database_updated_at timestamptz
);
CREATE TABLE IF NOT EXISTS findings (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  fingerprint text NOT NULL, rule text NOT NULL, engine text NOT NULL,
  severity text NOT NULL, category text NOT NULL, title text NOT NULL, data jsonb NOT NULL,
  status text NOT NULL DEFAULT 'open', first_seen timestamptz DEFAULT now(),
  last_seen timestamptz DEFAULT now(), revision text NOT NULL,
  UNIQUE(project_id,fingerprint)
);
CREATE TABLE IF NOT EXISTS scan_findings (
  scan_id uuid REFERENCES scans(id) ON DELETE CASCADE,
  finding_id uuid REFERENCES findings(id) ON DELETE CASCADE,
  data jsonb NOT NULL, is_new boolean NOT NULL,
  PRIMARY KEY(scan_id,finding_id)
);
CREATE TABLE IF NOT EXISTS suppressions (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  finding_id uuid UNIQUE NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  reason text NOT NULL, expires_at timestamptz NOT NULL, created_by uuid NOT NULL
);
CREATE TABLE IF NOT EXISTS runtime_events (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  event_key text NOT NULL, occurred_at timestamptz NOT NULL, environment text NOT NULL,
  actor_hash text NOT NULL, path text NOT NULL, status integer, auth_outcome text,
  security_event text, revision text, indicators jsonb NOT NULL DEFAULT '[]',
  UNIQUE(project_id,event_key)
);
CREATE INDEX IF NOT EXISTS events_window ON runtime_events(project_id,occurred_at);
ALTER TABLE runtime_events ADD COLUMN IF NOT EXISTS endpoint text;
CREATE TABLE IF NOT EXISTS alerts (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  fingerprint text NOT NULL, kind text NOT NULL, severity text NOT NULL, title text NOT NULL,
  evidence jsonb NOT NULL, status text DEFAULT 'open', first_seen timestamptz DEFAULT now(),
  last_seen timestamptz DEFAULT now(), UNIQUE(project_id,fingerprint)
);
CREATE TABLE IF NOT EXISTS audit_events (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  actor text NOT NULL, action text NOT NULL, resource text, created_at timestamptz DEFAULT now()
);
CREATE TABLE IF NOT EXISTS github_deliveries (id text PRIMARY KEY, received_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS rate_limits (key text PRIMARY KEY, count integer NOT NULL, resets_at timestamptz NOT NULL);
INSERT INTO schema_versions(version) VALUES (1) ON CONFLICT DO NOTHING;

ALTER TABLE projects ADD COLUMN IF NOT EXISTS security_context jsonb NOT NULL DEFAULT '{"criticality":"standard","exposure":"unknown","owner":"","sla_days":{"critical":7,"high":30,"medium":90,"low":180,"info":365}}';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS assignee text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS due_at timestamptz;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS resolved_at timestamptz;
CREATE INDEX IF NOT EXISTS findings_org_project ON findings(organization_id,project_id,status,last_seen DESC,id);
CREATE TABLE IF NOT EXISTS finding_notes (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  finding_id uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  author uuid NOT NULL, body text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS saved_views (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL, name text NOT NULL, filters jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(organization_id,user_id,name)
);
CREATE TABLE IF NOT EXISTS threat_intelligence (
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  cve text NOT NULL, kev boolean, epss double precision, percentile double precision,
  kev_checked_at timestamptz, epss_date date, epss_checked_at timestamptz,
  PRIMARY KEY(organization_id,cve)
);
INSERT INTO schema_versions(version) VALUES (2) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS github_installations (
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  installation_id bigint NOT NULL, account_login text NOT NULL, connected_by uuid NOT NULL,
  repositories jsonb NOT NULL DEFAULT '[]', connected_at timestamptz NOT NULL DEFAULT now(), revoked_at timestamptz,
  PRIMARY KEY(organization_id,installation_id)
);
CREATE TABLE IF NOT EXISTS github_connect_states (
  state_hash text PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL, installation_id bigint, code_verifier text, expires_at timestamptz NOT NULL
);
INSERT INTO schema_versions(version) VALUES (3) ON CONFLICT DO NOTHING;

-- The app uses a privileged server connection and explicit tenant predicates. Direct
-- Supabase clients have no table access; all access is mediated by authenticated APIs.
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['organizations','memberships','projects','runners','scans','executions','findings',
    'scan_findings','suppressions','runtime_events','alerts','audit_events','github_deliveries','rate_limits',
    'finding_notes','saved_views','threat_intelligence','github_installations','github_connect_states'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN
      EXECUTE format('REVOKE ALL ON %I FROM anon', t);
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN
      EXECUTE format('REVOKE ALL ON %I FROM authenticated', t);
    END IF;
  END LOOP;
END $$;
