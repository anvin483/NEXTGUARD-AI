export function buildRecommendations({ detections, vulnerabilities, incidents }) {
  const recommendations = []
  for (const vulnerability of vulnerabilities) {
    recommendations.push({
      id: `remediate:${vulnerability.id}`, type: vulnerability.kev ? 'emergency_patch' : 'patch_software', target: vulnerability.affected_device,
      title: vulnerability.kev ? `Patch known exploited vulnerability${vulnerability.cve ? ` ${vulnerability.cve}` : ''}` : `Patch vulnerable service${vulnerability.service ? ` on ${vulnerability.service}` : ''}`,
      priority: vulnerability.priority, risk_score: vulnerability.risk_score, rationale: vulnerability.recommendation,
      evidence: [vulnerability.evidence], requires_approval: true, status: 'Proposed', execution_status: 'Not executed'
    })
  }
  for (const finding of detections) {
    const actions = finding.rule_id === 'port-sweep' ? ['restrict_open_ports', 'review_firewall_rules'] : finding.rule_id === 'sensitive-service-access' ? ['restrict_sensitive_service', 'review_network_segmentation'] : finding.rule_id === 'repeated-failed-login' ? ['strengthen_authentication', 'review_account_lockout'] : finding.rule_id === 'large-external-transfer' ? ['isolate_endpoint', 'review_egress_controls'] : finding.rule_id === 'new-external-destination' ? ['review_external_destination', 'apply_egress_control'] : ['investigate_endpoint', 'review_access_permissions']
    recommendations.push({ id: `remediate:${finding.id}`, type: actions[0], target: finding.affected_device, title: finding.title, priority: finding.severity, risk_score: finding.score, rationale: finding.explanation, evidence: [finding.observed_evidence], suggested_actions: actions, requires_approval: true, status: 'Proposed', execution_status: 'Not executed' })
  }
  for (const incident of incidents.filter((item) => item.severity === 'critical' || item.severity === 'high')) {
    recommendations.push({ id: `remediate:${incident.id}`, type: 'contain_endpoint', target: incident.host, title: `Contain suspicious activity on ${incident.host}`, priority: incident.severity, risk_score: incident.score, rationale: 'Correlated high-risk incident requires containment review before further investigation.', evidence: incident.findings, requires_approval: true, status: 'Proposed', execution_status: 'Not executed' })
  }
  return recommendations.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
}
