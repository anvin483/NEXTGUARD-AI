# NEXTGUARD AI — Scope, Limitations, and Status

## Implemented in the MVP

- React SOC dashboard and interactive canvas-based 3D-style twin.
- Normalized ingestion APIs for Suricata, Zeek, OpenVAS/Greenbone, SIEM, firewall, cloud, identity, asset, and PCAP-derived event payloads.
- Validation, UTC timestamps, deduplication for production telemetry, raw evidence preservation, and asset correlation.
- Asset intelligence with confidence levels.
- Derived Security Knowledge Graph with optional Neo4j persistence.
- Signature, rule, behavioural, baseline, anomaly, and correlation detection.
- Explainable findings, investigation summaries, cases, reports, remediation proposals, and verification snapshots.
- Vulnerability prioritization using CVSS, EPSS, KEV, exposure, criticality, reachability, and misconfiguration context.
- Inferred attack paths and what-if remediation comparison.
- WebSocket telemetry updates, simulation mode, classic PCAP parsing, scripted scenarios, and evaluation metrics.

## Partially implemented

- Live monitoring: the API accepts real sensor output, but direct EVE JSON/Zeek tailers and authorized lab connectors are not bundled.
- 3D visualization: the current twin is a lightweight Canvas projection; Three.js/React Three Fiber remains the production-scale renderer.
- AI assistance: current explanations are deterministic and evidence-based; no external LLM is connected.
- Vulnerability intelligence: source payloads can include CVE/EPSS/KEV context; automated enrichment feeds are not bundled.
- Evaluation: label-set precision/recall and run latency are measured; full false-positive, scalability, asset-accuracy, path-accuracy, and analyst-time studies require labeled datasets.
- Security: optional API-key protection and audit logging exist; full SSO/RBAC, TLS, secrets management, retention enforcement, and deployment hardening remain.

## Planned or deployment-dependent

- Security Onion lab setup and direct sensor connectors.
- Splunk REST polling and webhook adapters.
- PostgreSQL event storage and Redis Streams.
- Neo4j is supported through an optional adapter but requires an external Neo4j deployment.
- Docker/Kubernetes deployment, centralized observability, and CI security testing.

## Interpretation boundaries

- The twin represents collected intelligence; it does not prove complete device discovery.
- A sensor can only observe traffic within its authorized visibility, such as a TAP or SPAN port.
- An anomaly is not automatically an attack, and an alert is not proof of compromise.
- Asset identity can remain uncertain without inventory or fingerprint evidence.
- Attack paths are inferred possibilities, not evidence that an attacker used them.
- Explanations are investigative assistance and must be checked against the preserved evidence.
- PCAP replay and generated traffic are simulation data, clearly labelled and excluded from production telemetry.
- Infrastructure-changing remediation remains approval-based and is not automatically executed.
