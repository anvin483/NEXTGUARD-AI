# NEXTGUARD AI — System Architecture

## Current implementation flow

```text
Suricata / Zeek / SIEM / PCAP / OpenVAS / Cloud / Assets
                         |
                  POST /api/ingest/:source
                         |
              Validation + normalization + deduplication
                         |
                 data/events.jsonl + assets.jsonl
                         |
        Asset intelligence + Security Knowledge Graph
                         |
     Detection + vulnerability risk + attack-path analysis
                         |
     Explainability + cases + remediation + verification
                         |
       REST APIs + WebSocket telemetry + 3D twin frontend
```

## Architecture layers

### 1. Data source layer

Source categories are accepted through the ingestion API: Suricata, Zeek, Security Onion, Splunk, PCAP metadata/replay, OpenVAS/Greenbone, firewalls, cloud, identity, and asset inventory.

### 2. Ingestion layer

`server/index.js` receives JSON or newline-delimited JSON. `server/ingestion.js` validates records, normalizes timestamps/IPs/ports/protocols, preserves `raw` evidence, suppresses production duplicates, and correlates known assets.

### 3. Intelligence layer

`server/ingestion.js` builds asset intelligence and confidence levels. `server/detection.js` performs signature, rule, behavioural, baseline, anomaly, and event-correlation analysis. `server/vulnerabilities.js` calculates vulnerability and exposure risk.

### 4. Knowledge graph layer

`GET /api/graph` derives device, service, identity, alert, vulnerability, and incident nodes with communication, service exposure, identity, vulnerability, and incident relationships.

### 5. Analysis layer

`server/detection.js`, `server/vulnerabilities.js`, and `server/attackpaths.js` provide explainable findings, risk scoring, vulnerability prioritization, inferred attack paths, and what-if remediation analysis.

### 6. Visualization layer

The React frontend renders the interactive canvas-based 3D twin in `src/main.jsx`. It supports rotation, zoom, search, status filters, node inspection, live graph refresh, and WebSocket telemetry updates.

### 7. SOC operations layer

Cases, investigation reports, remediation approvals, continuous monitoring snapshots, and verification comparisons are implemented in `server/index.js` and persisted as JSONL development stores.

## Important trust boundaries

- Sensor observations remain in `raw` and `observed_evidence`.
- Inferred analysis is labelled separately as `inferred_risk`.
- Confirmed compromise requires explicit upstream confirmation.
- Simulation events are labelled `telemetry_class: simulation`.
- Remediation is approval-gated and never changes infrastructure automatically.
- Attack paths are labelled inferred and do not prove attacker activity.

## Production evolution

The current implementation is a local MVP. For production deployment, replace JSONL storage with PostgreSQL/ClickHouse or a security data lake, move graph state to a graph-capable store, add authenticated source connectors, introduce a queue for ingestion, and run detection/graph/visualization services independently.
