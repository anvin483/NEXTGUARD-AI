# NEXTGUARD AI Specification Status

This checklist reflects the current repository implementation.

## Implemented in the integrated MVP

- Source ingestion for Suricata, Zeek, Security Onion, Splunk payloads, PCAP-derived events, OpenVAS/Greenbone, firewall, cloud, identity, and asset records.
- Validation, UTC timestamp normalization, IP/port/protocol normalization, production deduplication, raw evidence preservation, and asset correlation.
- Asset discovery with inferred device/service type and confidence levels.
- Asset enrichment preserves MAC, DNS/hostname, operating system, services, criticality, and raw inventory evidence when supplied.
- Derived security graph containing devices, services, identities, vulnerabilities, alerts, incidents, and communication relationships.
- Signature, rule, behavioural, adaptive baseline, anomaly, and event-correlation detection.
- Evidence-based findings with observed evidence, inferred risk, classification, confidence, explanations, related alerts, and investigation recommendations.
- CVE, CVSS, EPSS, CISA KEV, exposure, reachability, criticality, and misconfiguration-aware vulnerability prioritization.
- Inferred entry points, lateral movement, critical asset routes, segmentation gaps, and patched-asset what-if analysis.
- Interactive Three.js topology with labels, device/service filters, search, camera controls, selection, vulnerable-asset colours, inferred attack-path overlays, path highlighting, traffic animation, status colours, and heartbeat alerts.
- Live API mode, isolated simulation mode, WebSocket updates, source counters, event timeline, incidents, cases, reports, remediation approval, dry runs, PCAP import, scripted training, and ground-truth evaluation.
- Continuous monitoring snapshots, post-remediation comparison, audit logging, optional API-key protection, optional role authorization, and approval-gated remediation.
- Optional Suricata EVE, Zeek conn.log, OpenVAS/Greenbone file connectors and Splunk REST polling.
- Optional CISA KEV, EPSS, and CVE feed synchronization with cached risk enrichment.
- Dockerfile, static frontend serving from the API container, repeatable `npm run demo`, and `.env.example` configuration.

## Implemented with external configuration required

- Real-time monitoring requires an authorized sensor, TAP/SPAN visibility, SIEM feed, or configured connector.
- Neo4j persistence requires `NEO4J_URI`, `NEO4J_USER`, and `NEO4J_PASSWORD`.
- Splunk, OpenVAS/Greenbone, Suricata, and Zeek direct connectors require their environment variables and accessible source files or services.
- RBAC enforcement can be enabled with `NEXTGUARD_RBAC=true`; production deployments should place it behind authenticated SSO/OIDC identity.

## Deliberately not claimed as complete

- The current default persistence is append-only JSONL; PostgreSQL/Redis production storage still requires deployment integration.
- AI explanations are deterministic and evidence-based; no external LLM is connected.
- Infrastructure-changing remediation is not automatically executed.
- Large-network clustering, GPU instancing, measured scalability, asset-discovery accuracy, attack-path accuracy, false-positive rate, and analyst-time studies require controlled benchmarks and labeled datasets.
- The platform represents collected evidence and inferred relationships; it does not prove complete discovery, compromise, or attacker use of an inferred path.
