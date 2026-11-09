# NEXTGUARD AI — Security and Privacy Controls

## Implemented MVP controls

- Input validation and normalization on ingestion.
- Original source evidence retained separately from inferred analysis.
- Optional API-key authentication for all `POST`, `PATCH`, and `DELETE` endpoints using `NEXTGUARD_API_KEY` and the `x-api-key` header.
- Configurable CORS origin using `NEXTGUARD_ALLOWED_ORIGIN`.
- Audit records for mutating and denied API requests in `data/audit.jsonl`.
- Simulation telemetry explicitly separated from production telemetry.
- Remediation actions require analyst approval and are never executed automatically.
- Attack paths are labelled inferred and do not prove attacker activity.

## Production requirements

Before exposing the service outside a trusted development machine, add:

- SSO/OIDC authentication and role-based authorization for analysts, administrators, and viewers.
- TLS termination and encrypted WebSocket connections (`wss://`).
- A secrets manager for connector credentials and API keys.
- PostgreSQL/Neo4j access controls and encryption at rest.
- Configurable retention and deletion workflows for raw telemetry and packet-derived data.
- Audit review, alerting, tamper-resistant log storage, and clock synchronization.
- Network isolation for raw PCAP access and least-privilege service accounts.
- Rate limits, request-size limits, structured error handling, and dependency scanning.
- Explicit authorization records for every monitored network and every simulation target.

Development mode intentionally remains open when `NEXTGUARD_API_KEY` is unset. This is not an acceptable production configuration.
