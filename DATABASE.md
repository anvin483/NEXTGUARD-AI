# NEXTGUARD AI — Database Design

The current MVP persists append-only JSONL files for local development. The production design should use PostgreSQL for structured records and Neo4j for relationship traversal.

## PostgreSQL entities

```sql
CREATE TABLE assets (
  id TEXT PRIMARY KEY,
  ip INET,
  mac TEXT,
  hostname TEXT,
  device_type TEXT,
  operating_system TEXT,
  asset_role TEXT,
  criticality TEXT NOT NULL DEFAULT 'medium',
  confidence TEXT NOT NULL DEFAULT 'low',
  first_seen TIMESTAMPTZ,
  last_observed TIMESTAMPTZ,
  source JSONB NOT NULL DEFAULT '[]',
  raw JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE security_events (
  id TEXT PRIMARY KEY,
  source_sensor TEXT NOT NULL,
  event_type TEXT NOT NULL,
  category TEXT,
  observed_at TIMESTAMPTZ NOT NULL,
  source_ip INET,
  destination_ip INET,
  source_asset_id TEXT REFERENCES assets(id),
  destination_asset_id TEXT REFERENCES assets(id),
  protocol TEXT,
  source_port INTEGER,
  destination_port INTEGER,
  raw JSONB NOT NULL,
  fingerprint TEXT UNIQUE,
  telemetry_class TEXT NOT NULL DEFAULT 'production'
);

CREATE TABLE network_connections (
  id TEXT PRIMARY KEY,
  source_asset_id TEXT REFERENCES assets(id),
  destination_asset_id TEXT REFERENCES assets(id),
  source_port INTEGER,
  destination_port INTEGER,
  protocol TEXT,
  bytes_transferred BIGINT,
  connected_at TIMESTAMPTZ,
  data_source TEXT,
  event_id TEXT REFERENCES security_events(id)
);

CREATE TABLE alerts (
  id TEXT PRIMARY KEY,
  category TEXT,
  severity TEXT,
  confidence TEXT,
  classification TEXT,
  affected_asset_id TEXT REFERENCES assets(id),
  detection_method TEXT,
  evidence JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'New',
  created_at TIMESTAMPTZ NOT NULL,
  related_event_ids TEXT[] NOT NULL DEFAULT '{}'
);

CREATE TABLE vulnerabilities (
  id TEXT PRIMARY KEY,
  cve_id TEXT,
  affected_asset_id TEXT REFERENCES assets(id),
  cvss NUMERIC(3,1),
  epss NUMERIC(5,4),
  kev BOOLEAN NOT NULL DEFAULT FALSE,
  internet_facing BOOLEAN NOT NULL DEFAULT FALSE,
  risk_score INTEGER,
  remediation_recommendation TEXT,
  evidence JSONB NOT NULL
);

CREATE TABLE incidents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'New',
  analyst_notes TEXT,
  findings TEXT,
  resolution_details TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE attack_paths (
  id TEXT PRIMARY KEY,
  entry_point TEXT,
  intermediate_assets TEXT[] NOT NULL DEFAULT '{}',
  target_asset_id TEXT REFERENCES assets(id),
  related_vulnerability_ids TEXT[] NOT NULL DEFAULT '{}',
  risk_score INTEGER,
  evidence JSONB NOT NULL,
  inferred BOOLEAN NOT NULL DEFAULT TRUE,
  remediation_status TEXT
);
```

Recommended indexes include `security_events(observed_at)`, `security_events(source_sensor)`, `security_events(source_ip, destination_ip)`, `alerts(status, severity)`, `vulnerabilities(risk_score)`, and `assets(criticality, last_observed)`.

## Neo4j relationship projection

```text
(Asset)-[:COMMUNICATES_WITH]->(Asset)
(Asset)-[:EXPOSES_SERVICE]->(Service)
(Identity)-[:AUTHENTICATED_FROM]->(Asset)
(Vulnerability)-[:AFFECTS_ASSET]->(Asset)
(Alert)-[:OBSERVED_ON]->(Asset)
(Incident)-[:GROUPS_ACTIVITY]->(Asset)
(AttackPath)-[:PASSES_THROUGH]->(Asset)
(AttackPath)-[:TARGETS]->(Asset)
```

## MVP mapping

- `data/assets.jsonl` → `assets`
- `data/events.jsonl` → `security_events` and `network_connections`
- Detection output → `alerts`
- Vulnerability endpoint output → `vulnerabilities`
- `data/cases.jsonl` → `incidents`
- `/api/attack-paths` output → `attack_paths`
- `/api/graph` → Neo4j node and relationship projection

The API should remain stable during migration so the frontend does not need to know whether data comes from JSONL, PostgreSQL, Neo4j, or an event stream.
