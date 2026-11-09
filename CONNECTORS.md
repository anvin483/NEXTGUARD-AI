# NEXTGUARD AI — External Connector Contracts

The MVP accepts normalized source payloads through `POST /api/ingest/:source`. Production adapters should translate each external system into that contract while preserving the original payload under `raw`.

| Tool | Role | MVP source route | Production adapter |
|---|---|---|---|
| Suricata | IDS/IPS signatures and EVE JSON alerts | `/api/ingest/suricata` | EVE JSON file tailer, webhook, or message consumer |
| Zeek | Connection, DNS, HTTP, TLS, and protocol telemetry | `/api/ingest/zeek` | Zeek log tailer or Security Onion export consumer |
| Security Onion | Integrated lab and telemetry source | `/api/ingest/security-onion` | API/export connector |
| Splunk | SIEM search and alert retrieval | `/api/ingest/splunk` | Authenticated Splunk REST polling or webhook |
| Greenbone/OpenVAS | Vulnerability and exposure findings | `/api/ingest/openvas` or `/api/ingest/greenbone` | Authenticated scan-result importer |
| Neo4j | Persistent graph storage target | `/api/graph` currently derives the graph | Graph writer for nodes and relationships |

## Optional direct connectors

The ingestion API remains the stable integration boundary. For local labs, the server also includes disabled-by-default polling adapters. Configure them in `.env` and restart `npm run server`:

- `SURICATA_EVE_FILE` tails newline-delimited Suricata EVE JSON.
- `ZEEK_CONN_FILE` tails a Zeek `conn.log` file, including standard `#fields` headers.
- `OPENVAS_JSON_FILE` and `GREENBONE_JSON_FILE` read newline-delimited vulnerability records.
- `SPLUNK_URL`, `SPLUNK_TOKEN`, and `SPLUNK_QUERY` enable authenticated Splunk REST polling.
- `NEXTGUARD_CONNECTOR_INTERVAL_MS` controls the polling interval.

Connector state is available at `GET /api/connectors` and is included in `GET /api/sources`. Credentials are read only from environment variables and are never placed in telemetry payloads.

## Source-specific mapping

### Suricata EVE JSON

Map `timestamp`, `src_ip`, `dest_ip`, `proto`, `dest_port`, and `alert.signature` / `alert.severity`. The normalized result becomes an `ids_alert` event and retains the complete EVE record in `raw`.

### Zeek logs

Map `ts`, `id.orig_h`, `id.resp_h`, `proto`, `service`, `id.resp_p`, and the connection UID. The normalized result becomes a network event and contributes device relationships and service dependencies.

### OpenVAS / Greenbone

Map host, port, service, CVE, CVSS, EPSS, KEV, exposure, and misconfiguration fields. The vulnerability assessment layer associates the finding with discovered assets and prioritizes it using multiple risk factors.

### Neo4j

The current `/api/graph` response is the compatibility boundary. A Neo4j adapter can persist its `nodes` and `edges` without requiring frontend changes.

## Safety and provenance

- Connector credentials must be supplied through environment or secret management, never event payloads.
- Source identity is preserved in `source` and `raw`.
- Simulation and PCAP replay events use `telemetry_class: simulation`.
- External connectors should retry safely using event IDs and fingerprints.
- No connector is allowed to make remediation changes; remediation remains approval-gated.
