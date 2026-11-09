import neo4j from 'neo4j-driver'

const uri = process.env.NEO4J_URI || ''
const user = process.env.NEO4J_USER || 'neo4j'
const password = process.env.NEO4J_PASSWORD || ''
let driver = null
export const neo4jConfigured = Boolean(uri && password)
const getDriver = () => { if (!neo4jConfigured) return null; if (!driver) driver = neo4j.driver(uri, neo4j.auth.basic(user, password), { maxConnectionPoolSize: 50, connectionAcquisitionTimeout: 3000 }); return driver }
const labelFor = (type) => ({ device: 'Asset', service: 'Service', identity: 'Identity', alert: 'Alert', vulnerability: 'Vulnerability', incident: 'Incident', external: 'External' }[type] || 'Entity')
const relationshipFor = (type) => ({ communicates_with: 'COMMUNICATES_WITH', exposes_service: 'EXPOSES_SERVICE', authenticated_from: 'AUTHENTICATED_FROM', affects_asset: 'AFFECTS_ASSET', observed_on: 'OBSERVED_ON', groups_activity: 'GROUPS_ACTIVITY', inferred_entry: 'INFERRED_ENTRY', external_access: 'EXTERNAL_ACCESS' }[type] || 'RELATED_TO')

export async function initializeNeo4j() {
  const active = getDriver(); if (!active) return { configured: false, connected: false, reason: 'NEO4J_URI and NEO4J_PASSWORD are not configured' }
  const session = active.session()
  try { for (const query of ['CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (n:Asset) REQUIRE n.id IS UNIQUE','CREATE CONSTRAINT event_id IF NOT EXISTS FOR (n:SecurityEvent) REQUIRE n.id IS UNIQUE','CREATE CONSTRAINT alert_id IF NOT EXISTS FOR (n:Alert) REQUIRE n.id IS UNIQUE','CREATE CONSTRAINT vulnerability_id IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.id IS UNIQUE','CREATE CONSTRAINT incident_id IF NOT EXISTS FOR (n:Incident) REQUIRE n.id IS UNIQUE','CREATE INDEX asset_ip IF NOT EXISTS FOR (n:Asset) ON (n.ip)']) await session.run(query); return { configured: true, connected: true, uri } } finally { await session.close() }
}
export async function syncGraph(graph) {
  const active = getDriver(); if (!active) return { configured: false, synced: false, reason: 'Neo4j is not configured' }; const session = active.session()
  try { for (const node of graph.nodes) { const label = labelFor(node.type); const properties = { ...node }; delete properties.id; await session.run(`MERGE (n:${label} {id: $id}) SET n += $properties`, { id: node.id, properties }) }; for (const edge of graph.edges) { const relationship = relationshipFor(edge.type); const properties = { ...edge }; delete properties.id; delete properties.source; delete properties.target; await session.run(`MATCH (a {id: $source}), (b {id: $target}) MERGE (a)-[r:${relationship}]->(b) SET r += $properties`, { source: edge.source, target: edge.target, properties }) }; return { configured: true, synced: true, nodes: graph.nodes.length, edges: graph.edges.length } } finally { await session.close() }
}
export async function readGraph() { const active = getDriver(); if (!active) return null; const session = active.session(); try { const result = await session.run('MATCH (n) OPTIONAL MATCH (n)-[r]->(m) RETURN collect(DISTINCT n) AS nodes, collect(DISTINCT {source:n.id,target:m.id,type:type(r),properties:properties(r)}) AS relationships'); const record = result.records[0]; if (!record) return { nodes: [], edges: [] }; const nodes = record.get('nodes').map((node) => ({ id: node.properties.id, ...node.properties })); const edges = record.get('relationships').filter((edge) => edge.target).map((edge) => ({ source: edge.source, target: edge.target, type: edge.type, ...edge.properties })); return { generated_at: new Date().toISOString(), node_count: nodes.length, edge_count: edges.length, nodes, edges } } finally { await session.close() } }
export async function neo4jStatus() { if (!neo4jConfigured) return { configured: false, connected: false, storage: 'local-derived-graph' }; try { return { ...(await initializeNeo4j()), storage: 'neo4j' } } catch (error) { return { configured: true, connected: false, storage: 'local-derived-graph', error: error.message } } }
