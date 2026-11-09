# NEXTGUARD AI

## Project overview

NEXTGUARD AI is an AI-assisted 3D cybersecurity intelligence and SOC investigation platform. Its purpose is to bring network telemetry, asset discovery, threat detection, vulnerability context, attack-path analysis, and analyst-approved remediation into one evidence-driven workspace.

Traditional security information is split across IDS alerts, network logs, SIEM dashboards, vulnerability scanners, asset inventories, and incident tools. NEXTGUARD AI provides an intelligence layer that correlates those sources and represents the resulting devices, services, communication relationships, alerts, vulnerabilities, and inferred attack paths in an interactive 3D security digital twin.

The platform is designed to help analysts answer:

- What assets and services are being observed?
- Which devices are communicating and how often?
- Why was an event classified as normal, suspicious, or malicious?
- Which vulnerabilities and exposed services increase the risk?
- What possible route could connect an entry point to a critical asset?
- What evidence supports the alert, and what should the analyst investigate next?
- Did an approved remediation reduce the observed exposure or inferred attack path?

### Core workflow

```text
Authorized sensors and data sources
        ↓
Ingestion and validation
        ↓
Normalization and evidence preservation
        ↓
Asset discovery and confidence scoring
        ↓
Communication mapping and Security Knowledge Graph
        ↓
Hybrid detection and event correlation
        ↓
Explainable findings and risk prioritization
        ↓
Vulnerability and attack-path analysis
        ↓
3D visualization, SOC investigation, and guided remediation
        ↓
Continuous verification
```

### Main modules

1. **3D Network Intelligence** — interactive topology, node selection, device metadata, communication links, search, filters, and traffic animation.
2. **Real-Time Security Monitoring** — Suricata EVE, Zeek logs, normalized events, WebSocket updates, timelines, and traffic counters.
3. **Hybrid Threat Detection** — signatures, rules, sensitive-service checks, behavioural context, adaptive baselines, anomaly signals, and event correlation.
4. **Explainable Security Intelligence** — human-readable reasons, supporting raw evidence, severity, confidence, related alerts, and investigation recommendations.
5. **Vulnerability Management** — CVE, CVSS, EPSS, KEV, exposed-service, misconfiguration, and asset-criticality context.
6. **Security Knowledge Graph** — relationships between devices, services, identities, vulnerabilities, alerts, incidents, and communication paths.
7. **Attack-Path Intelligence** — inferred entry points, lateral movement routes, critical targets, segmentation gaps, and what-if patch analysis.
8. **SOC Investigation** — incidents, event timelines, cases, analyst notes, evidence, reports, and investigation status.
9. **PCAP Replay and Training** — isolated PCAP import, scripted scenarios, replay, ground-truth comparison, precision/recall, and training evaluation.
10. **Guided Remediation** — prioritized recommendations, dry runs, approval workflows, status tracking, and post-remediation verification.

### What makes the project different

NEXTGUARD AI is not intended to replace Suricata, Zeek, Splunk, Greenbone, or other security tools. It connects their information and adds context. The main differentiators are unified visibility, an interactive 3D representation of relationships, evidence-backed explanations, context-aware false-positive handling, proactive inferred attack paths, and one investigation workflow from detection to verification.

### Evidence and classification principles

The platform keeps three concepts separate:

- **Observed evidence:** a record received from a sensor, including its preserved raw payload.
- **Inferred risk:** a rule, signature, baseline, vulnerability, or correlation-based assessment that requires analyst review.
- **Confirmed compromise:** only used when an upstream source explicitly provides confirmation; an anomaly or alert alone does not prove compromise.

A traffic spike, failed login, unfamiliar destination, or vulnerable service is therefore not automatically treated as a successful attack. The system can classify activity as `Normal`, `Suspicious`, `High Confidence Malicious`, or `Unknown` depending on the available evidence and context.

## Quick start

NEXTGUARD AI has two processes: a Node ingestion API and a Vite frontend. Start them in separate terminals.

### Terminal 1 — backend/API

Command Prompt:

```cmd
cd /d "C:\Users\Anvin\OneDrive\Desktop\NEXTGUARD AI"
npm run server
```

The API listens on `http://localhost:4000`.

### Terminal 2 — frontend/dashboard

```cmd
cd /d "C:\Users\Anvin\OneDrive\Desktop\NEXTGUARD AI"
npm run dev
```

Open the Vite URL printed by the command, such as `http://localhost:5175/`. The port may vary because Vite uses an available port.

Stop either process with `Ctrl+C` in its own terminal.

Verify the backend before testing the dashboard:

```cmd
curl http://localhost:4000/api/health
curl http://localhost:4000/api/connectors
```

PowerShell equivalents are:

```powershell
Invoke-RestMethod http://localhost:4000/api/health
Invoke-RestMethod http://localhost:4000/api/connectors
```

`LOCAL FALLBACK` means the frontend cannot reach `/api/health`. It does not mean that the API is reachable but that a sensor is quiet.

## Live API connection

The Live API is a local HTTP/WebSocket integration layer. It does not automatically see network traffic. An authorized Suricata, Zeek, SIEM, or other sensor must deliver telemetry to it.

### Suricata EVE JSON file connector

The backend polls the configured EVE JSON file and broadcasts newly ingested events over `ws://localhost:4000/ws`. Set the environment variable before starting the backend.

Command Prompt:

```cmd
cd /d "C:\Users\Anvin\OneDrive\Desktop\NEXTGUARD AI"
set "SURICATA_EVE_FILE=C:\Users\Anvin\OneDrive\Desktop\NEXTGUARD AI\data\suricata-log\eve.json"
set "NEXTGUARD_CONNECTOR_INTERVAL_MS=5000"
npm run server
```

PowerShell:

```powershell
Set-Location "C:\Users\Anvin\OneDrive\Desktop\NEXTGUARD AI"
$env:SURICATA_EVE_FILE = "$PWD\data\suricata-log\eve.json"
$env:NEXTGUARD_CONNECTOR_INTERVAL_MS = "5000"
npm run server
```

Do not use `$env:` or `$PWD` in Command Prompt. Do not use `cd /d` or `^` line continuation in PowerShell. If the backend was already running, stop and restart it after setting the variable.

Check the connector:

```powershell
Invoke-RestMethod http://localhost:4000/api/connectors | ConvertTo-Json -Depth 6
```

The Suricata connector should report `configured: true`. A continuously changing `eve.json` indicates that new telemetry is available.

### PCAP replay versus actual live monitoring

This command replays a recorded file and is **lab data**, not live monitoring:

```powershell
$projectDir = "C:\Users\Anvin\OneDrive\Desktop\NEXTGUARD AI"
$pcap = "C:\Users\Anvin\Downloads\nextguard-test.pcapng"
$logDir = "$projectDir\data\suricata-log"
New-Item -ItemType Directory -Force -Path $logDir

suricata -T -c "$projectDir\data\suricata-test.yaml" -l $logDir
suricata -r $pcap -c "$projectDir\data\suricata-test.yaml" -l $logDir
```

The PCAP path must point to a real `.pcap` or `.pcapng` file. The included test configuration has no rule files, so it can produce normal flow telemetry without producing IDS alerts. For actual live monitoring, an authorized sensor must capture from an approved interface/TAP/SPAN and continuously write EVE JSON; the application cannot observe traffic that the sensor cannot see.

### Controlled test mix

The dashboard should not label every ordinary packet as malicious. To demonstrate all three classifications, send controlled test records through the same ingestion API. Run the following in PowerShell while the backend is running:

```powershell
$stamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$now = (Get-Date).ToUniversalTime().ToString("o")

Invoke-RestMethod -Method Post -Uri "http://localhost:4000/api/ingest/suricata" -ContentType "application/json" -Body (@{
  id = "normal-$stamp"; timestamp = $now; src_ip = "192.168.1.10"; dest_ip = "192.168.1.20"; proto = "tcp"; dest_port = 443; event_type = "flow"
} | ConvertTo-Json)

Invoke-RestMethod -Method Post -Uri "http://localhost:4000/api/ingest/zeek" -ContentType "application/json" -Body (@{
  id = "suspicious-$stamp"; timestamp = $now; "id.orig_h" = "192.168.1.30"; "id.resp_h" = "192.168.1.20"; dest_port = 22; proto = "tcp"; service = "ssh"
} | ConvertTo-Json)

Invoke-RestMethod -Method Post -Uri "http://localhost:4000/api/ingest/suricata" -ContentType "application/json" -Body (@{
  id = "malicious-$stamp"; timestamp = $now; src_ip = "192.168.1.25"; dest_ip = "192.168.1.20"; proto = "tcp"; dest_port = 22; event_type = "alert"; alert = @{ signature = "NEXTGUARD test SSH attack"; severity = 1 }
} | ConvertTo-Json -Depth 5)
```

Select **Live API** and click **Analyze now**. These are synthetic authorized test events, not evidence of a real compromise.

## Implementation status

### Implemented in this repository

- Normalized ingestion for Suricata, Zeek, PCAP, vulnerability, firewall, cloud, identity, and asset records.
- Suricata EVE and Zeek file connectors plus WebSocket updates.
- Asset discovery, confidence scoring, Security Knowledge Graph, and relationship mapping.
- Signature, rule, behavioural, baseline, and event-correlation detection.
- Evidence-backed alert explanations with severity and confidence.
- Vulnerability/exposure prioritization and inferred attack-path analysis.
- SOC incidents, cases, timelines, reports, remediation approval, and verification snapshots.
- Three.js 3D topology with device selection, filtering, packet activity, status colours, and malicious-node heartbeat animation.
- PCAP import, scripted simulations, training scenarios, and ground-truth evaluation.
- Local fallback display when the backend API cannot be reached.

### Integration-dependent or partially implemented

- Live monitoring requires an authorized sensor with network visibility; starting Node alone does not create visibility.
- Suricata live IDS results require valid installed rules. The local test YAML intentionally has no rules.
- Splunk polling requires `SPLUNK_URL`, `SPLUNK_TOKEN`, and `SPLUNK_QUERY`.
- OpenVAS/Greenbone requires a configured JSON export path.
- Neo4j, CISA KEV, EPSS, CVE feeds, and response webhooks are optional integrations.
- The current default storage is local JSONL under `data/`; it is not a production-scale PostgreSQL/event-streaming deployment.
- Remediation is approval-gated; the application does not change production systems automatically.

### Future work

- PostgreSQL/ClickHouse or another production event store, retention, and distributed streaming.
- Direct Security Onion, EDR, cloud, identity-provider, and additional SIEM adapters.
- Production identity-provider authentication, multi-tenant isolation, secret management, and deployment observability.
- Larger-scale graph processing and measured performance benchmarks.
- Advanced trained anomaly models validated against labelled organizational datasets.

## Common troubleshooting

- If `/api/health` fails, start or restart `npm run server` on port `4000`.
- If a connector is `configured: false`, the environment variable was not present when the backend started.
- If Suricata reports a missing PCAP, replace placeholder paths with the actual file path and verify with `Test-Path`.
- If PowerShell reports that `-c` or `-l` is not recognized, the command was split with Command Prompt syntax. Use a PowerShell backtick or one line.
- If all PCAP events are normal, inspect EVE JSON for `event_type: alert`; ordinary flow records are not malicious evidence.
- If the browser still shows an old layout after a code change, restart `npm run dev` and refresh with `Ctrl+F5`.

## Step 1 — Data collection

The project now includes a local ingestion API that accepts telemetry from the planned source categories and normalizes them into a common event model.

Step 2 processing is included in the same service. Every incoming record is validated, timestamps are converted to UTC ISO-8601, IP addresses and protocols are standardized, ports are converted to valid integers, duplicate fingerprints are suppressed, and the original source payload is retained under `raw`. Events are correlated against ingested assets and receive `related_assets` plus a `correlation_status` of `matched` or `unmatched`.

Step 3 asset intelligence is exposed through `GET /api/discovery` (also available through `GET /api/assets`). It merges explicit asset inventory with observed source and destination entities from network events, infers likely device/service types from ports and service names, tracks first/last seen times, records source evidence, and assigns identification confidence. An IP or MAC alone is therefore represented as low confidence until stronger evidence is available.

Step 4 is exposed through `GET /api/graph`. It derives a Security Knowledge Graph from the normalized event and asset stores. Graph nodes include devices, services, alerts, vulnerabilities, and identities; edges include communication, service exposure, alert observation, and identity authentication relationships. Repeated relationships are aggregated with counts, timestamps, protocols, sources, and a suspicious flag based on critical/high event severity.

Step 5 detection is exposed through `GET /api/detections` and `GET /api/incidents`. It runs signature matching, explainable rules, contextual behaviour checks, adaptive time/day/device/port baselines, and event correlation. Baseline observations are separated from findings, and each finding includes its detection type, score, severity, and explanation. Correlated incidents group related findings by device or source context.

Step 6 explainability is included in every finding and incident. Results separate `observed_evidence` (the source event and preserved raw payload), `inferred_risk` (method, reason, score, severity, confidence), and `classification` (`inferred_risk` by default or `confirmed_compromise` only when an upstream source explicitly confirms it). Results also include affected device, source/destination context, related alerts, and recommended investigation steps.

Step 7 vulnerability assessment is exposed through `GET /api/vulnerabilities`. OpenVAS/Greenbone and vulnerability events are correlated with discovered assets and prioritized using CVSS, EPSS, CISA KEV status, internet exposure, asset criticality, and service reachability. Each result includes its evidence and a remediation recommendation; CVSS is one factor rather than the complete risk decision.

Module 5 vulnerability management is covered by the same endpoint and additionally records `misconfiguration` and `exposure_reasons` such as `internet_exposed`, `reachable_service`, `misconfiguration`, and `known_exploited`.

Module 6 is represented by `GET /api/graph`. The graph includes device relationships, device-to-service dependencies, identity relationships, vulnerability-to-asset `affects_asset` edges, alert relationships, correlated incident nodes, and incident activity edges used by attack-path construction.

Module 7 attack-path intelligence is exposed through `GET /api/attack-paths`. Each path reports entry points, vulnerable nodes, critical assets, lateral-movement edges, and observed segmentation gaps. Passing `patched_asset_id` performs a what-if simulation and returns path removal and risk-score reduction metrics.

Module 8 SOC investigation is provided by `/api/incidents`, `/api/timeline`, `/api/cases`, and `/api/cases/<id>/report`. Reports combine incident status, affected assets, chronological events, preserved evidence, related vulnerabilities, impact context, and remediation guidance.

Module 9 controlled replay and simulation is supported through `/api/pcap/import` and `/api/simulations`. Scenarios can contain extracted PCAP events or scripted traffic, run through the same normalization and detection pipeline, and compare detections against `ground_truth_labels`. All replayed events carry `telemetry_class: simulation`, `simulation_id`, and `simulation_label: SIMULATION — LAB DATA`; they are never treated as production telemetry.

Classic libpcap binary uploads are supported with `Content-Type: application/octet-stream` and an `x-pcap-filename` header. The parser extracts Ethernet/IPv4/TCP/UDP metadata into the same event contract. Scenario runs retain a `runs` history with detection counts and ground-truth match rates.

Testing and evaluation are exposed through `GET /api/evaluation`. Simulation runs record ingestion latency, detection latency, and events per second. Precision and recall are reported for the available ground-truth label sets. False-positive rate, asset-discovery accuracy, attack-path accuracy, scalability, and analyst investigation time remain explicitly marked `not_measured` until independently labeled datasets or benchmark instrumentation are supplied.

False-positive handling is included in `/api/detections`. Events are classified as `Normal`, `Suspicious`, `High Confidence Malicious`, or `Unknown` using baseline context, unusual destinations/services, signatures, correlated findings, device context, and exposure data. A single traffic spike or failed login is not sufficient to establish compromise.

The UI and API distinguish `realtime` and `simulation` operating modes. Real telemetry uses `telemetry_class: production` and requires authorized sensor visibility; replayed or scripted events use `telemetry_class: simulation` and are labelled as lab data. Ground-truth labels are only compared after detection and are never supplied to the detector. `GET /api/operating-mode` describes the mode contract.

Performance safeguards include aggregated graph relationships instead of per-packet objects, client-side search/filtering, WebSocket refresh throttling at 250 ms, and measured FPS in the twin footer. `GET /api/performance` reports current event, node, and edge counts plus the rendering model and update throttle.

Neo4j production support is available when `NEO4J_URI`, `NEO4J_USER`, and `NEO4J_PASSWORD` are configured. `POST /api/neo4j/sync` persists the current graph with constraints and indexes; `GET /api/graph` reads from Neo4j when configured and falls back to the local derived graph otherwise. `GET /api/neo4j/status` reports connection state.

Enhancement APIs now include `/api/threat-intel` and `/api/threat-intel/matches` for IOC storage/matching, `/api/graph/risk` for graph centrality plus vulnerability risk ranking, `/api/posture/history` for historical snapshots, and `/api/feedback` for analyst tuning feedback. Approval-gated response plans support `POST /api/remediation/<id>/dry-run`; this returns a plan only and never changes infrastructure.

Security controls and production requirements are documented in [SECURITY.md](./SECURITY.md). Set `NEXTGUARD_API_KEY` to require `x-api-key` authentication for mutating endpoints and `NEXTGUARD_ALLOWED_ORIGIN` to restrict browser origins.

Step 8 attack-path analysis is exposed through `GET /api/attack-paths`. It derives inferred routes from an external network entry point through observed communications and exposed services toward high/critical assets, then scores the route using correlated vulnerability risk. What-if remediation is supported with `GET /api/attack-paths?patched_asset_id=<asset-id>`, which removes the selected asset from the inferred route and recalculates the result. Paths are explicitly marked `inferred: true`; they do not prove an attacker used the route.

Step 10 incident management is exposed through the case endpoints. Analysts can create and update an investigation case, set status to `New`, `Investigating`, `Confirmed`, `False Positive`, or `Resolved`, record findings, analyst notes, and remediation, then retrieve supporting events and related vulnerability context. Case versions are persisted in `data/cases.jsonl`.

Step 11 guided remediation is exposed through `/api/remediation`. Recommendations are generated from vulnerabilities, detections, and high-risk incidents. Every action is `requires_approval: true`, starts as `Proposed`, and has `execution_status: Not executed`. Analysts can approve or reject a recommendation, but this MVP does not modify production infrastructure.

Step 12 continuous verification is exposed through `/api/monitoring` and `/api/verification`. The service calculates current event, detection, incident, vulnerability, attack-path, and aggregate risk metrics. Analysts can create a verification snapshot before remediation, then compare current telemetry with `?baseline_id=<snapshot-id>` to see whether findings, vulnerabilities, attack paths, and risk have decreased.

Module 4 explainable security intelligence is provided by the detection and incident APIs. Findings preserve source evidence, explain the detection reason, correlate related events, assign context-aware severity and confidence, and include recommended investigation steps. Correlated incidents also include an `investigation_summary` and `risk_explanation` suitable for analyst review.

Module 2 real-time monitoring is supported by the existing `POST /api/ingest/suricata` and `POST /api/ingest/zeek` endpoints plus `ws://localhost:4000/ws`. Accepted normalized event batches are broadcast to connected dashboard clients. `GET /api/timeline` provides a security event timeline and `GET /api/traffic` provides source/category counters and suspicious-event totals.

Start the ingestion service:

```bash
npm run server
```

The API runs at `http://localhost:4000`.

Run the repeatable end-to-end lab demonstration after starting the API:

```bash
npm run demo
```

It uses authorized private lab addresses and the normal ingestion, detection, vulnerability, incident, graph, attack-path, and what-if APIs. The generated records are demonstration telemetry and should not be interpreted as live production evidence.

For a single-container deployment, build and run the included image:

```bash
docker build -t nextguard-ai .
docker run --rm -p 4000:4000 --env-file .env nextguard-ai
```

The API serves the built frontend at `http://localhost:4000/`. Mount a persistent `data` volume for event, case, remediation, simulation, feedback, and audit history.

The active Three.js dashboard supports two modes. `AUTHORIZED LIVE` reads the graph, normalized events, findings, vulnerabilities, incidents, attack paths, monitoring snapshots, and WebSocket telemetry from the API. `SIMULATION — LAB DATA` uses isolated generated traffic and never presents it as production telemetry. If the API is unavailable, the dashboard clearly shows `LOCAL FALLBACK` and keeps the lab visualization usable.

Copy `.env.example` to `.env` to configure optional direct file connectors, Splunk polling, Neo4j persistence, API-key protection, CORS, and role enforcement. Set `NEXTGUARD_RBAC=true` to require `x-nextguard-role: analyst`, `admin`, or `sensor` on mutating requests; Neo4j synchronization requires `admin`. This is an authorization gate and should be placed behind an authenticated identity provider in production.

Optional vulnerability-intelligence synchronization is available through `POST /api/intelligence/feeds/sync` when `CISA_KEV_URL`, `EPSS_URL`, or `CVE_FEED_URL` are configured. Feed status and record counts are available through `GET /api/intelligence/feeds`; synchronized KEV and EPSS context is applied to vulnerability risk scoring.

Approved response actions can be submitted to an authorized adapter with `POST /api/remediation/<id>/execute` only after the action is `Approved` and the request body contains `{ "confirm": true }`. Set `NEXTGUARD_RESPONSE_WEBHOOK` to enable this adapter. The server never executes response actions automatically; the adapter is responsible for validating the action and applying its own rollback and authorization controls.

### Endpoints

- `GET /api/health` — service health
- `GET /api/sources` — connector readiness and ingest counters
- `GET /api/events?source=zeek&limit=100` — normalized events
- `GET /api/assets` — normalized asset inventory
- `GET /api/discovery` — correlated asset inventory with type, confidence, evidence, services, and observation counts
- `GET /api/graph` — current Security Knowledge Graph nodes and edges
- `GET /api/detections` — explainable signature, rule, behaviour, and baseline findings
- `GET /api/incidents` — correlated incidents built from detection findings
- `GET /api/vulnerabilities` — prioritized vulnerability and exposure findings
- `GET /api/attack-paths` — inferred external-to-critical attack paths
- `GET /api/attack-paths?patched_asset_id=<id>` — what-if path recalculation after patching an asset
- `GET /api/cases` — investigation cases
- `POST /api/cases` — create a case from an incident
- `GET /api/cases/<id>` — case with supporting evidence and vulnerabilities
- `PATCH /api/cases/<id>` — update status, notes, findings, or remediation
- `GET /api/cases/<id>/report` — generate an investigation report
- `POST /api/pcap/import` — prepare an extracted PCAP event set for replay
- `POST /api/simulations` — create a scripted lab scenario
- `GET /api/simulations` — list scenarios and results
- `POST /api/simulations/<id>/run` — replay a scenario through detection
- `GET /api/evaluation` — measured simulation evaluation results and honest measurement gaps
- `GET /api/remediation` — generated remediation recommendations
- `POST /api/remediation` — create a proposed remediation action
- `GET/PATCH /api/remediation/<id>` — inspect or approve/reject an action
- `GET /api/monitoring` — current continuous security posture snapshot
- `POST /api/verification/snapshots` — create a pre-remediation baseline
- `GET /api/verification?baseline_id=<id>` — compare current posture with a baseline
- `GET /api/verification/snapshots` — list stored verification baselines
- `WS /ws` — live normalized telemetry updates
- `GET /api/timeline` — recent event timeline
- `GET /api/traffic` — traffic and event counters
- `POST /api/ingest/:source` — ingest JSON object, JSON array, or newline-delimited JSON

The ingest response reports `accepted`, `duplicates`, and `rejected` counts so source integrations can retry or monitor data quality.

Supported `:source` values:

`suricata`, `zeek`, `security-onion`, `splunk`, `pcap`, `openvas`, `greenbone`, `firewall`, `cloud`, `identity`, `assets`

Example Suricata event:

```bash
curl -X POST http://localhost:4000/api/ingest/suricata -H "content-type: application/json" -d "{\"timestamp\":\"2026-10-31T10:20:00Z\",\"src_ip\":\"10.42.18.44\",\"dest_ip\":\"10.42.0.18\",\"alert\":{\"signature\":\"ET POLICY SMB lateral movement\",\"severity\":1},\"proto\":\"TCP\",\"dest_port\":445}"
```

Raw normalized events are persisted as append-only JSON Lines in `data/events.jsonl`; assets are persisted in `data/assets.jsonl`. These files are local development storage and should be replaced with PostgreSQL/ClickHouse or another production data store before deployment.
