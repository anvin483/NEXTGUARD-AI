export function graphRisk(graph, vulnerabilities = []) {
  const degree = new Map()
  for (const edge of graph.edges) { const weight = edge.count || 1; degree.set(edge.source, (degree.get(edge.source) || 0) + weight); degree.set(edge.target, (degree.get(edge.target) || 0) + weight) }
  const vulnByAsset = new Map()
  for (const finding of vulnerabilities) vulnByAsset.set(finding.asset_id, Math.max(vulnByAsset.get(finding.asset_id) || 0, finding.risk_score || 0))
  const ranked = graph.nodes.map((node) => ({ id: node.id, label: node.label, type: node.type, degree: degree.get(node.id) || 0, vulnerability_risk: vulnByAsset.get(node.asset_id) || 0, criticality: node.severity === 'critical' ? 'critical' : 'normal', composite_risk: Math.min(100, (degree.get(node.id) || 0) * 4 + (vulnByAsset.get(node.asset_id) || 0)) })).sort((a, b) => b.composite_risk - a.composite_risk)
  return { generated_at: new Date().toISOString(), method: 'degree centrality + vulnerability risk', ranked_nodes: ranked.slice(0, 100), high_risk_nodes: ranked.filter((node) => node.composite_risk >= 60).length }
}

export function matchThreatIntel(events, indicators) {
  return events.flatMap((event) => indicators.filter((indicator) => [event.src_ip, event.dest_ip, event.raw?.domain, event.raw?.hostname].filter(Boolean).some((value) => String(value).toLowerCase() === String(indicator.value).toLowerCase())).map((indicator) => ({ event_id: event.id, indicator_id: indicator.id, indicator: indicator.value, indicator_type: indicator.type, confidence: indicator.confidence || 'medium', source: indicator.source || 'internal' })))
}
