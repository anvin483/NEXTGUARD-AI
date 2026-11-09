export function buildMonitoringSnapshot({ detections, incidents, vulnerabilities, attackPaths, events }) {
  const criticalVulnerabilities = vulnerabilities.filter((item) => item.priority === 'critical').length
  const highVulnerabilities = vulnerabilities.filter((item) => item.priority === 'high').length
  const activeFindings = detections.filter((item) => item.severity === 'critical' || item.severity === 'high').length
  const riskScore = Math.min(100, criticalVulnerabilities * 18 + highVulnerabilities * 10 + activeFindings * 8 + attackPaths.path_count * 12)
  return {
    captured_at: new Date().toISOString(),
    events_observed: events.length,
    active_findings: detections.length,
    active_high_risk_findings: activeFindings,
    open_incidents: incidents.filter((item) => item.classification !== 'false_positive').length,
    critical_vulnerabilities: criticalVulnerabilities,
    high_vulnerabilities: highVulnerabilities,
    inferred_attack_paths: attackPaths.path_count,
    highest_attack_path_score: attackPaths.paths[0]?.risk_score || 0,
    aggregate_risk_score: riskScore
  }
}

export function compareMonitoringSnapshots(before, after) {
  const fields = ['active_findings', 'active_high_risk_findings', 'open_incidents', 'critical_vulnerabilities', 'high_vulnerabilities', 'inferred_attack_paths', 'highest_attack_path_score', 'aggregate_risk_score']
  const changes = Object.fromEntries(fields.map((field) => [field, { before: before?.[field] || 0, after: after?.[field] || 0, delta: (after?.[field] || 0) - (before?.[field] || 0), improved: (after?.[field] || 0) < (before?.[field] || 0) }]))
  return { improved: Object.values(changes).filter((item) => item.improved).length > 0 && Object.values(changes).every((item) => item.delta <= 0), changes }
}
