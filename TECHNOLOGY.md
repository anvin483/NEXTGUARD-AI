# NEXTGUARD AI — Technology Roadmap

## Current MVP stack

| Area | Current implementation | Purpose |
|---|---|---|
| Frontend | React + Vite + JavaScript | Dashboard and 3D-style twin |
| Visualization | Canvas-based projection | Lightweight interactive topology |
| Backend | Node.js HTTP API | Ingestion, detection, graph, SOC APIs |
| Real time | WebSockets via `ws` | Telemetry broadcasts |
| Storage | JSONL files | Local development persistence |
| Detection | Deterministic JavaScript engine | Signatures, rules, baselines, correlation |
| Replay | Scenario and extracted-event replay | Controlled lab testing |
| Version control | Git-ready workspace | Source management |

## Target production stack

| Area | Target technology |
|---|---|
| Frontend | React + TypeScript |
| 3D visualization | Three.js + React Three Fiber + Drei |
| State | Zustand |
| Backend | Python + FastAPI |
| Real time | WebSockets |
| IDS / network analysis | Suricata + Zeek + Security Onion |
| SIEM | Splunk REST API |
| Graph | Neo4j |
| Relational data | PostgreSQL |
| Event streaming | Redis Streams |
| Anomaly detection | scikit-learn |
| Vulnerability management | Greenbone/OpenVAS + CVE/CVSS/KEV/EPSS |
| Packet analysis | Wireshark + Arkime |
| Deployment | Docker |
| Version control | Git + GitHub |

## Incremental migration plan

1. Keep the current Node.js MVP as the local integration harness.
2. Replace JSONL event and asset stores with PostgreSQL or ClickHouse.
3. Move graph derivation into Neo4j while preserving `/api/graph` compatibility.
4. Add Redis Streams between connectors and normalization workers.
5. Add authenticated Suricata, Zeek, Splunk, and OpenVAS connectors.
6. Move detection workers to Python/FastAPI and scikit-learn-backed models.
7. Upgrade the canvas twin to Three.js/R3F when graph scale requires GPU rendering.
8. Containerize the services and add GitHub CI/CD, observability, and secrets management.

Neo4j adapter support is now included behind `NEO4J_URI`, `NEO4J_USER`, and `NEO4J_PASSWORD`. The sync endpoint creates graph constraints/indexes and persists the current graph; local graph derivation remains the fallback when Neo4j is unavailable.

The current MVP deliberately does not claim live access to external security products. Each connector should be added behind the existing normalized event contract and should preserve source evidence and telemetry provenance.
