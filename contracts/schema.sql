-- 数据库表结构 v1（由成员C 建表并提供数据 API，三人共用同一套表）

CREATE TABLE assets (
  id BIGSERIAL PRIMARY KEY,
  url TEXT UNIQUE NOT NULL,
  host TEXT NOT NULL,
  fingerprint JSONB DEFAULT '{}',
  status_code INT,
  page_hash TEXT,
  title TEXT,
  discovered_at TIMESTAMPTZ DEFAULT now(),
  last_seen TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE risks (
  id BIGSERIAL PRIMARY KEY,
  asset_url TEXT NOT NULL REFERENCES assets(url),
  category TEXT NOT NULL,            -- vuln|weak_config|tamper|malware|leak|bad_link
  severity TEXT NOT NULL,            -- critical|high|medium|low
  title TEXT NOT NULL,
  description TEXT,
  evidence JSONB DEFAULT '{}',
  raw_output TEXT,
  tool TEXT,
  template TEXT,
  signature TEXT UNIQUE NOT NULL,
  status TEXT DEFAULT 'active',      -- active|confirmed|false_positive|fixed
  ai_explanation JSONB DEFAULT '{}', -- {impact, remediation, evidence_summary}
  job_id TEXT,                       -- 记录该风险由哪次巡检写入（成员C 扩展）
  first_seen TIMESTAMPTZ DEFAULT now(),
  last_seen TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_risks_asset ON risks(asset_url);
CREATE INDEX idx_risks_status ON risks(status);
CREATE INDEX idx_risks_job ON risks(job_id);

CREATE TABLE baselines (
  id BIGSERIAL PRIMARY KEY,
  asset_url TEXT NOT NULL REFERENCES assets(url),
  page_hash TEXT NOT NULL,
  snapshot_ref TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  is_current BOOLEAN DEFAULT true
);

CREATE TABLE jobs (
  id BIGSERIAL PRIMARY KEY,
  job_id TEXT UNIQUE,                -- 巡检任务 ID（成员C 扩展）
  job_type TEXT NOT NULL,            -- scheduled|manual|retest
  target_scope JSONB,
  status TEXT DEFAULT 'pending',     -- pending|running|done|failed
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  triggered_by TEXT,
  report_ref TEXT
);

CREATE TABLE audit_logs (
  id BIGSERIAL PRIMARY KEY,
  operator TEXT NOT NULL,
  action TEXT NOT NULL,              -- config_change|scan_start|scan_done|alert|report_export
  target TEXT,
  detail JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE sensitive_rules (
  id BIGSERIAL PRIMARY KEY,
  rule_type TEXT NOT NULL,           -- keyword|regex|file_type|sample
  name TEXT NOT NULL,
  pattern TEXT,
  severity TEXT DEFAULT 'medium',
  enabled BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT now()
);
