const PRIVATE_IP = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|127\.)/

const externalIp = (ip) => Boolean(ip && !PRIVATE_IP.test(String(ip)) && ip !== '::1')

function pathScore(path, vulnerabilities) {
  const assetIds = new Set(path.map((node) => node.asset_id).filter(Boolean))
  const scores = vulnerabilities.filter((finding) => assetIds.has(finding.asset_id)).map((finding) => finding.risk_score)
  return Math.min(100, Math.max(scores.length ? Math.max(...scores) : 20, scores.reduce((sum, score) => sum + score, 0) * 0.6))
}

export function analyzeAttackPaths({ graph, events, assets, vulnerabilities, patchedAssetId = null }) {
  const nodeMap = new Map(graph.nodes.map((node) => [node.id, node]))
  const excluded = new Set()
  if (patchedAssetId) {
    for (const node of graph.nodes) if (node.asset_id === patchedAssetId || node.id === `device:${patchedAssetId}`) excluded.add(node.id)
  }
  const edges = graph.edges.filter((edge) => !excluded.has(edge.source) && !excluded.has(edge.target))
  const adjacency = new Map()
  for (const edge of edges) {
    if (!adjacency.has(edge.source)) adjacency.set(edge.source, [])
    adjacency.get(edge.source).push(edge)
  }
  const criticalTargets = graph.nodes.filter((node) => node.type === 'device' && !excluded.has(node.id) && assets.some((asset) => asset.id === node.asset_id && ['critical', 'high'].includes(asset.criticality)))
  const entryEdges = []
  for (const event of events) {
    if (!externalIp(event.src_ip) || !event.dest_ip) continue
    const target = `device:${event.dest_ip}`
    if (nodeMap.has(target) && !excluded.has(target)) entryEdges.push({ source: 'external:internet', target, type: 'external_access', count: 1, suspicious: false, protocols: event.protocol ? [event.protocol] : [], sources: [event.source] })
  }
  if (!entryEdges.length) {
    for (const node of graph.nodes.filter((item) => item.type === 'device' && item.confidence !== 'high' && !excluded.has(item.id))) entryEdges.push({ source: 'external:internet', target: node.id, type: 'inferred_entry', count: 0, suspicious: false, protocols: [], sources: [] })
  }
  nodeMap.set('external:internet', { id: 'external:internet', type: 'external', label: 'External network', confidence: 'inferred' })
  const searchEdges = [...edges, ...entryEdges]
  const searchAdjacency = new Map()
  for (const edge of searchEdges) { if (!searchAdjacency.has(edge.source)) searchAdjacency.set(edge.source, []); searchAdjacency.get(edge.source).push(edge) }
  const paths = []
  const walk = (current, path, visited) => {
    if (path.length > 7 || paths.length >= 50) return
    if (criticalTargets.some((target) => target.id === current) && path.length > 1) {
      const nodes = path.map((id) => nodeMap.get(id)).filter(Boolean)
      const pathEdges = path.slice(1).map((id, index) => searchEdges.find((edge) => edge.source === path[index] && edge.target === id)).filter(Boolean)
      const vulnerableIds = new Set(vulnerabilities.filter((finding) => finding.risk_score >= 35).map((finding) => finding.asset_id))
      paths.push({ id: `path-${paths.length + 1}`, nodes, edges: pathEdges, entry_points: nodes.slice(1, 2).map((node) => node.label), vulnerable_nodes: nodes.filter((node) => vulnerableIds.has(node.asset_id)).map((node) => node.label), critical_assets: nodes.filter((node) => assets.some((asset) => asset.id === node.asset_id && asset.criticality === 'critical')).map((node) => node.label), lateral_movement_edges: pathEdges.filter((edge) => edge.type === 'communicates_with'), segmentation_gaps: pathEdges.filter((edge) => edge.type === 'communicates_with').map((edge) => ({ source: edge.source, target: edge.target, reason: 'Observed cross-device communication is reachable in the inferred route.' })), risk_score: Math.round(pathScore(nodes, vulnerabilities)), inferred: true, evidence: 'Derived from observed communication, exposed services, asset criticality, and vulnerability data.' })
      return
    }
    for (const edge of searchAdjacency.get(current) || []) {
      if (!visited.has(edge.target)) walk(edge.target, [...path, edge.target], new Set([...visited, edge.target]))
    }
  }
  walk('external:internet', ['external:internet'], new Set(['external:internet']))
  return { generated_at: new Date().toISOString(), inferred: true, what_if: Boolean(patchedAssetId), patched_asset_id: patchedAssetId, path_count: paths.length, paths: paths.sort((a, b) => b.risk_score - a.risk_score) }
}
