# NEXTGUARD AI — Enhancement Backlog

## Integrations

- Additional SIEM connectors beyond Splunk.
- Cloud security posture monitoring for AWS, Azure, and GCP.
- Identity-provider and access-relationship integrations.
- Endpoint detection and response telemetry.
- Threat-intelligence feeds with indicator lifecycle management.

## Intelligence

- Graph-based risk propagation and centrality analysis.
- More advanced anomaly models with scikit-learn or dedicated streaming ML.
- Analyst feedback loops for rule tuning and false-positive suppression.
- Historical security-posture comparison and trend reporting.
- Automated incident report generation with evidence citations.

## Platform

- Multi-tenant isolation with tenant-scoped graph, data, and credentials.
- Role-based access control and SSO/OIDC.
- Production event streaming and data retention policies.
- Larger-network GPU rendering with Three.js instancing and level of detail.

## Response

- Controlled response automation behind explicit authorization, approval, dry-run, rollback, and audit controls.
- Integrations for firewall changes, endpoint isolation, identity lockout, and ticketing systems.
- Post-action verification gates before considering a response complete.

Enhancements should preserve the project's trust boundaries: source observations remain distinguishable from inference, simulation remains separate from production, and infrastructure-changing actions remain approval-based.
