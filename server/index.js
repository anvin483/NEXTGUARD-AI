import http from 'node:http'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { normalizeAsset, normalizeRecord, SUPPORTED_SOURCES, validateRecord } from './ingestion.js'
import { detect } from './detection.js'
import { assessVulnerabilities } from './vulnerabilities.js'
import { analyzeAttackPaths } from './attackpaths.js'
import { buildRecommendations } from './remediation.js'
import { buildMonitoringSnapshot, compareMonitoringSnapshots } from './monitoring.js'
import { WebSocketServer } from 'ws'
import { neo4jConfigured, neo4jStatus, readGraph, syncGraph } from './neo4j.js'
import { parsePcap } from './pcap.js'
import { evaluateSimulations } from './evaluation.js'
import { graphRisk, matchThreatIntel } from './enhancements.js'
import { getConnectorStatus, startConnectors } from './connectors.js'
import { enrichVulnerabilities, getFeedContext, syncConfiguredFeeds } from './intelligence-feeds.js'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const distDir = path.join(root, 'dist')
const dataDir = path.join(root, 'data')
const eventsFile = path.join(dataDir, 'events.jsonl')
const assetsFile = path.join(dataDir, 'assets.jsonl')
const casesFile = path.join(dataDir, 'cases.jsonl')
const remediationFile = path.join(dataDir, 'remediation.jsonl')
const snapshotsFile = path.join(dataDir, 'monitoring-snapshots.jsonl')
const simulationsFile = path.join(dataDir, 'simulations.jsonl')
const feedbackFile = path.join(dataDir, 'analyst-feedback.jsonl')
const intelFile = path.join(dataDir, 'threat-intel.jsonl')
const port = Number(process.env.PORT || 4000)
const apiKey = process.env.NEXTGUARD_API_KEY || null
const allowedOrigin = process.env.NEXTGUARD_ALLOWED_ORIGIN || '*'
const rbacEnabled = String(process.env.NEXTGUARD_RBAC || '').toLowerCase() === 'true'
const auditFile = path.join(dataDir, 'audit.jsonl')
const sourceState = new Map(SUPPORTED_SOURCES.map((source) => [source, { source, status: 'ready', events: 0, last_ingested_at: null }]))
const rejected = []
const seenFingerprints = new Set()
const realtimeClients = new Set()

function broadcast(message) {
  const payload = JSON.stringify(message)
  for (const client of realtimeClients) if (client.readyState === 1) client.send(payload)
}

await fs.mkdir(dataDir, { recursive: true })

async function readJsonLines(file) {
  try {
    const text = await fs.readFile(file, 'utf8')
    return text.split('\n').filter(Boolean).map((line) => JSON.parse(line))
  } catch (error) {
    if (error.code === 'ENOENT') return []
    throw error
  }
}

async function appendLines(file, records) {
  if (records.length) await fs.appendFile(file, records.map((record) => JSON.stringify(record)).join('\n') + '\n')
}

async function latestCases() {
  const versions = await readJsonLines(casesFile)
  const cases = new Map()
  for (const item of versions) cases.set(item.id, item)
  return [...cases.values()]
}

async function latestSimulations() {
  const versions = await readJsonLines(simulationsFile)
  const simulations = new Map()
  for (const item of versions) simulations.set(item.id, item)
  return [...simulations.values()]
}

const CASE_STATUSES = new Set(['New', 'Investigating', 'Confirmed', 'False Positive', 'Resolved'])
const REMEDIATION_STATUSES = new Set(['Proposed', 'Approved', 'Rejected'])

const existingEvents = await readJsonLines(eventsFile)
existingEvents.forEach((event) => event.fingerprint && seenFingerprints.add(event.fingerprint))

async function currentVulnerabilities(events, assets) {
  return enrichVulnerabilities(assessVulnerabilities(events, assets), await getFeedContext())
}

function send(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'access-control-allow-origin': allowedOrigin, 'access-control-allow-headers': 'content-type,x-api-key,x-nextguard-role,x-tenant-id', 'access-control-allow-methods': 'GET,POST,PATCH,OPTIONS' })
  res.end(JSON.stringify(body))
}

async function serveStatic(req, res, url) {
  if (req.method !== 'GET' || url.pathname.startsWith('/api') || url.pathname === '/ws') return false
  try {
    const requested = decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname)
    const candidate = path.resolve(distDir, `.${requested}`)
    if (!candidate.startsWith(distDir)) return false
    let file = candidate
    try { if (!(await fs.stat(file)).isFile()) file = path.join(distDir, 'index.html') } catch { file = path.join(distDir, 'index.html') }
    const content = await fs.readFile(file)
    const type = file.endsWith('.html') ? 'text/html; charset=utf-8' : file.endsWith('.css') ? 'text/css; charset=utf-8' : file.endsWith('.js') ? 'text/javascript; charset=utf-8' : 'application/octet-stream'
    res.writeHead(200, { 'content-type': type, 'cache-control': file.endsWith('index.html') ? 'no-cache' : 'public, max-age=31536000, immutable' })
    res.end(content)
    return true
  } catch { return false }
}

async function audit(req, outcome, details = {}) {
  await fs.appendFile(auditFile, JSON.stringify({ timestamp: new Date().toISOString(), method: req.method, path: req.url, source_ip: req.socket.remoteAddress, role: req.headers['x-nextguard-role'] || 'development', outcome, ...details }) + '\n')
}

function roleAllowed(req) {
  if (!rbacEnabled || req.method === 'GET' || req.method === 'OPTIONS') return true
  const role = String(req.headers['x-nextguard-role'] || '').toLowerCase()
  if (!role) return false
  if (req.url.startsWith('/api/neo4j/') && role !== 'admin') return false
  return ['analyst', 'admin', 'sensor'].includes(role)
}

async function readBody(req) {
  const chunks = []
  for await (const chunk of req) chunks.push(chunk)
  const text = Buffer.concat(chunks).toString('utf8')
  if (!text) return {}
  try { return JSON.parse(text) } catch { return text.split('\n').filter(Boolean).map((line) => JSON.parse(line)) }
}

async function readRawBody(req) { const chunks = []; for await (const chunk of req) chunks.push(chunk); return Buffer.concat(chunks) }

async function ingest(source, payload, context = {}) {
  if (!SUPPORTED_SOURCES.includes(source)) throw new Error(`Unsupported source: ${source}`)
  const records = Array.isArray(payload) ? payload : [payload]
  const normalized = []
  let duplicates = 0
  for (const record of records) {
    const validation = validateRecord(record)
    if (!validation.valid) { rejected.push({ source, error: validation.error, received_at: new Date().toISOString() }); continue }
    const event = normalizeRecord(source, record)
    Object.assign(event, { tenant_id: context.tenant_id || 'default', telemetry_class: context.telemetry_class || 'production', simulation_id: context.simulation_id || null, simulation_label: context.simulation_label || null })
    if (context.telemetry_class !== 'simulation' && seenFingerprints.has(event.fingerprint)) { duplicates += 1; continue }
    if (context.telemetry_class !== 'simulation') seenFingerprints.add(event.fingerprint)
    normalized.push(event)
  }
  await appendLines(eventsFile, normalized)
  const state = sourceState.get(source)
  state.events += normalized.length
  state.last_ingested_at = new Date().toISOString()
  if (source === 'assets') await appendLines(assetsFile, records.filter((record) => validateRecord(record).valid).map((record) => normalizeAsset(record, source)))
  const knownAssets = await readJsonLines(assetsFile)
  for (const event of normalized) {
    const matches = knownAssets.filter((asset) => [asset.ip, asset.hostname].filter(Boolean).some((value) => [event.src_ip, event.dest_ip, event.host].includes(String(value).toLowerCase())))
    event.related_assets = matches.slice(0, 5).map((asset) => ({ id: asset.id, hostname: asset.hostname, ip: asset.ip, type: asset.type }))
    event.correlation_status = event.related_assets.length ? 'matched' : 'unmatched'
  }
  if (normalized.length) broadcast({ type: 'telemetry', source, received_at: new Date().toISOString(), accepted: normalized.length, duplicates, events: normalized })
  return { events: normalized, duplicates, rejected: records.length - normalized.length - duplicates }
}

async function buildAssetIntelligence() {
  const [storedAssets, events] = await Promise.all([readJsonLines(assetsFile), readJsonLines(eventsFile)])
  const inventory = new Map()
  const upsert = (candidate, source) => {
    const key = String(candidate.ip || candidate.hostname || candidate.id || 'unknown').toLowerCase()
    if (key === 'unknown') return
    const existing = inventory.get(key)
    const asset = normalizeAsset({ ...(existing?.raw || {}), ...(candidate.raw || {}), ...candidate }, source)
    asset.id = existing?.id || candidate.id || asset.id
    asset.first_seen = existing?.first_seen || candidate.first_seen || asset.first_seen
    asset.last_seen = candidate.last_seen || asset.last_seen
    asset.observation_count = (existing?.observation_count || 0) + (candidate.observation_count || 1)
    asset.sources = [...new Set([...(existing?.sources || []), source, candidate.source].filter(Boolean))]
    inventory.set(key, asset)
  }
  storedAssets.forEach((asset) => upsert(asset, asset.source || 'asset_inventory'))
  events.forEach((event) => {
    if (event.src_ip) upsert({ ip: event.src_ip, hostname: event.host !== 'unknown' ? event.host : null, port: event.port, service: event.protocol, last_seen: event.timestamp, raw: event.raw }, event.source)
    if (event.dest_ip) upsert({ ip: event.dest_ip, port: event.port, service: event.protocol, last_seen: event.timestamp, raw: event.raw }, event.source)
  })
  return [...inventory.values()].sort((a, b) => String(a.hostname).localeCompare(String(b.hostname)))
}

async function buildSecurityGraph() {
  const [events, assets] = await Promise.all([readJsonLines(eventsFile), buildAssetIntelligence()])
  const nodes = new Map()
  const edges = new Map()
  const assetByIp = new Map(assets.filter((asset) => asset.ip).map((asset) => [asset.ip, asset]))
  const addNode = (id, type, label, metadata = {}) => {
    if (!id) return null
    const existing = nodes.get(id)
    nodes.set(id, { id, type, label, ...existing, ...metadata, observed_count: (existing?.observed_count || 0) + 1 })
    return id
  }
  const addEdge = (source, target, type, event) => {
    if (!source || !target) return
    const id = `${source}->${target}:${type}`
    const existing = edges.get(id)
    const suspicious = ['critical', 'high'].includes(event.severity)
    edges.set(id, {
      id, source, target, type,
      count: (existing?.count || 0) + 1,
      suspicious: Boolean(existing?.suspicious || suspicious),
      first_seen: existing?.first_seen || event.timestamp,
      last_seen: event.timestamp,
      protocols: [...new Set([...(existing?.protocols || []), event.protocol].filter(Boolean))],
      sources: [...new Set([...(existing?.sources || []), event.source].filter(Boolean))]
    })
  }
  for (const event of events) {
    const sourceAsset = assetByIp.get(event.src_ip)
    const destAsset = assetByIp.get(event.dest_ip)
    const sourceId = event.src_ip ? addNode(`device:${event.src_ip}`, 'device', sourceAsset?.hostname || event.host || event.src_ip, { ip: event.src_ip, asset_id: sourceAsset?.id, confidence: sourceAsset?.confidence || 'low', mac: sourceAsset?.mac || null, os: sourceAsset?.os || null, services: sourceAsset?.services || [], criticality: sourceAsset?.criticality || 'unknown' }) : null
    const destId = event.dest_ip ? addNode(`device:${event.dest_ip}`, 'device', destAsset?.hostname || event.dest_ip, { ip: event.dest_ip, asset_id: destAsset?.id, confidence: destAsset?.confidence || 'low', mac: destAsset?.mac || null, os: destAsset?.os || null, services: destAsset?.services || [], criticality: destAsset?.criticality || 'unknown' }) : null
    if (sourceId && destId) addEdge(sourceId, destId, 'communicates_with', event)
    if (destId && event.port) {
      const serviceId = addNode(`service:${event.dest_ip}:${event.port}`, 'service', `${event.protocol || 'network'}:${event.port}`, { ip: event.dest_ip, port: event.port, protocol: event.protocol })
      addEdge(destId, serviceId, 'exposes_service', event)
    }
    if (['intrusion', 'vulnerability', 'identity'].includes(event.category)) {
      const alertId = addNode(`alert:${event.id}`, event.category === 'vulnerability' ? 'vulnerability' : 'alert', event.title, { severity: event.severity, source: event.source, event_id: event.id })
      addEdge(alertId, sourceId || destId, event.category === 'vulnerability' ? 'affects_asset' : 'observed_on', event)
    }
    const identity = event.raw?.user || event.raw?.username || event.raw?.user_name || event.raw?.['user.name']
    if (identity) {
      const userId = addNode(`identity:${identity}`, 'identity', identity, {})
      addEdge(userId, sourceId || destId, 'authenticated_from', event)
    }
  }
  const correlated = detect(events).incidents
  for (const incident of correlated) {
    const incidentId = addNode(`incident:${incident.id}`, 'incident', incident.title, { severity: incident.severity, score: incident.score, classification: incident.classification })
    for (const eventId of incident.event_ids) {
      const event = events.find((candidate) => candidate.id === eventId)
      const deviceId = event?.src_ip ? `device:${event.src_ip}` : event?.dest_ip ? `device:${event.dest_ip}` : null
      addEdge(incidentId, deviceId, 'groups_activity', event || { severity: incident.severity, timestamp: incident.last_seen, source: 'correlation' })
    }
  }
  return { generated_at: new Date().toISOString(), node_count: nodes.size, edge_count: edges.size, nodes: [...nodes.values()], edges: [...edges.values()] }
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return send(res, 204, {})
  if (apiKey && ['POST', 'PATCH', 'DELETE'].includes(req.method) && req.headers['x-api-key'] !== apiKey) { await audit(req, 'denied', { reason: 'invalid_api_key' }); return send(res, 401, { error: 'Authentication required' }) }
  if (!roleAllowed(req)) { await audit(req, 'denied', { reason: 'insufficient_role', required: req.url.startsWith('/api/neo4j/') ? 'admin' : 'analyst' }); return send(res, 403, { error: 'Role authorization required', required_role: req.url.startsWith('/api/neo4j/') ? 'admin' : 'analyst' }) }
  if (['POST', 'PATCH', 'DELETE'].includes(req.method)) await audit(req, 'accepted', { auth: apiKey ? 'api_key' : 'development_open_mode' })
  try {
    const url = new URL(req.url, `http://${req.headers.host}`)
    if (await serveStatic(req, res, url)) return
    if (req.method === 'GET' && url.pathname === '/api/health') return send(res, 200, { ok: true, service: 'nextguard-ingestion', timestamp: new Date().toISOString(), neo4j: await neo4jStatus(), rbac_enabled: rbacEnabled, enhancements: ['threat-intel', 'graph-risk', 'posture-history', 'analyst-feedback', 'remediation-dry-run', 'direct-connectors', 'cve-kev-epss-feed-sync'] })
    if (req.method === 'GET' && url.pathname === '/api/operating-mode') return send(res, 200, { modes: [{ id: 'realtime', label: 'Real-Time Monitoring', telemetry_class: 'production', requires_authorized_visibility: true }, { id: 'simulation', label: 'Simulation and Training', telemetry_class: 'simulation', ground_truth_used_after_detection: true }], rule: 'Simulation labels are never passed into detection as input.' })
    if (req.method === 'GET' && url.pathname === '/api/sources') return send(res, 200, { sources: [...sourceState.values()], connectors: getConnectorStatus() })
    if (req.method === 'GET' && url.pathname === '/api/connectors') return send(res, 200, { connectors: getConnectorStatus(), interval_ms: Number(process.env.NEXTGUARD_CONNECTOR_INTERVAL_MS || 5000) })
    if (req.method === 'GET' && url.pathname === '/api/events') {
      const limit = Math.min(Number(url.searchParams.get('limit') || 100), 1000)
      const source = url.searchParams.get('source')
      let events = await readJsonLines(eventsFile)
      if (source) events = events.filter((event) => event.source === source)
      return send(res, 200, { count: events.length, events: events.slice(-limit).reverse() })
    }
    if (req.method === 'GET' && url.pathname === '/api/timeline') {
      const limit = Math.min(Number(url.searchParams.get('limit') || 250), 1000)
      const events = await readJsonLines(eventsFile)
      const timeline = events.slice(-limit).reverse().map((event) => ({ id: event.id, timestamp: event.timestamp, source: event.source, type: event.event_type, category: event.category, title: event.title, host: event.host, severity: event.severity, src_ip: event.src_ip, dest_ip: event.dest_ip, port: event.port, protocol: event.protocol }))
      return send(res, 200, { count: timeline.length, timeline })
    }
    if (req.method === 'GET' && url.pathname === '/api/traffic') {
      const events = await readJsonLines(eventsFile)
      const bySource = Object.fromEntries(SUPPORTED_SOURCES.map((source) => [source, events.filter((event) => event.source === source).length]))
      const byCategory = events.reduce((result, event) => { result[event.category] = (result[event.category] || 0) + 1; return result }, {})
      return send(res, 200, { total_events: events.length, by_source: bySource, by_category: byCategory, suspicious_events: events.filter((event) => ['critical', 'high'].includes(event.severity)).length })
    }
    if (req.method === 'GET' && url.pathname === '/api/performance') {
      const [events, graph] = await Promise.all([readJsonLines(eventsFile), buildSecurityGraph()])
      return send(res, 200, { measured_at: new Date().toISOString(), event_count: events.length, node_count: graph.node_count, edge_count: graph.edge_count, rendering_model: 'aggregated nodes and relationships; no per-packet 3D objects', frontend_render_caps: { max_nodes: 350, max_edges: 1200, service_labels_disabled_above_nodes: 120 }, websocket_update_throttle_ms: 250, frontend_fps: 'measured in the browser twin footer' })
    }
    if (req.method === 'GET' && url.pathname === '/api/assets') {
      const assets = await buildAssetIntelligence()
      return send(res, 200, { count: assets.length, assets: assets.slice(-1000).reverse() })
    }
    if (req.method === 'GET' && url.pathname === '/api/discovery') {
      const assets = await buildAssetIntelligence()
      return send(res, 200, { count: assets.length, assets, generated_at: new Date().toISOString() })
    }
    if (req.method === 'GET' && url.pathname === '/api/graph') return send(res, 200, (neo4jConfigured && await readGraph()) || await buildSecurityGraph())
    if (req.method === 'GET' && url.pathname === '/api/graph/risk') { const [graph, events, assets] = await Promise.all([buildSecurityGraph(), readJsonLines(eventsFile), buildAssetIntelligence()]); return send(res, 200, graphRisk(graph, await currentVulnerabilities(events, assets))) }
    if (req.method === 'GET' && url.pathname === '/api/intelligence/feeds') { const feed = await getFeedContext(); return send(res, 200, { updated_at: feed.updated_at, configured: { cisa_kev: Boolean(process.env.CISA_KEV_URL), epss: Boolean(process.env.EPSS_URL), cve: Boolean(process.env.CVE_FEED_URL) }, counts: { kev: Object.keys(feed.kev || {}).length, epss: Object.keys(feed.epss || {}).length, cve: Object.keys(feed.cve || {}).length } }) }
    if (req.method === 'POST' && url.pathname === '/api/intelligence/feeds/sync') return send(res, 200, await syncConfiguredFeeds())
    if (req.method === 'GET' && url.pathname === '/api/neo4j/status') return send(res, 200, await neo4jStatus())
    if (req.method === 'POST' && url.pathname === '/api/neo4j/sync') {
      const graph = await buildSecurityGraph()
      try { return send(res, 200, await syncGraph(graph)) } catch (error) { return send(res, 503, { configured: true, synced: false, error: error.message }) }
    }
    if (req.method === 'GET' && url.pathname === '/api/posture/history') return send(res, 200, { snapshots: await readJsonLines(snapshotsFile) })
    if (req.method === 'GET' && url.pathname === '/api/threat-intel') return send(res, 200, { indicators: await readJsonLines(intelFile) })
    if (req.method === 'POST' && url.pathname === '/api/threat-intel') { const body = await readBody(req); const indicators = Array.isArray(body) ? body : [body]; const stored = indicators.map((indicator) => ({ id: indicator.id || `IOC-${Date.now()}-${Math.random().toString(16).slice(2)}`, type: indicator.type || 'ip', value: indicator.value, confidence: indicator.confidence || 'medium', source: indicator.source || 'internal', created_at: new Date().toISOString() })); await appendLines(intelFile, stored); return send(res, 201, { accepted: stored.length, indicators: stored }) }
    if (req.method === 'GET' && url.pathname === '/api/threat-intel/matches') { const [events, indicators] = await Promise.all([readJsonLines(eventsFile), readJsonLines(intelFile)]); return send(res, 200, { matches: matchThreatIntel(events, indicators) }) }
    if (req.method === 'GET' && url.pathname === '/api/feedback') return send(res, 200, { feedback: await readJsonLines(feedbackFile) })
    if (req.method === 'POST' && url.pathname === '/api/feedback') { const body = await readBody(req); const record = { id: `FB-${Date.now()}`, finding_id: body.finding_id, decision: body.decision || 'reviewed', analyst: body.analyst || null, reason: body.reason || '', created_at: new Date().toISOString() }; await appendLines(feedbackFile, [record]); return send(res, 201, record) }
    if (req.method === 'GET' && (url.pathname === '/api/detections' || url.pathname === '/api/incidents')) {
      const events = await readJsonLines(eventsFile)
      const result = detect(events)
      if (url.pathname === '/api/incidents') {
        const cases = await latestCases()
        const caseByIncident = new Map(cases.map((item) => [item.incident_id, item]))
        const incidents = result.incidents.map((incident) => ({ ...incident, case: caseByIncident.get(incident.id) || null }))
        return send(res, 200, { count: incidents.length, incidents })
      }
      return send(res, 200, { finding_count: result.findings.length, findings: result.findings, classifications: result.classifications, baseline: result.baseline })
    }
    if (req.method === 'GET' && url.pathname === '/api/vulnerabilities') {
      const [events, assets] = await Promise.all([readJsonLines(eventsFile), buildAssetIntelligence()])
      const vulnerabilities = await currentVulnerabilities(events, assets)
      return send(res, 200, { count: vulnerabilities.length, critical: vulnerabilities.filter((item) => item.priority === 'critical').length, high: vulnerabilities.filter((item) => item.priority === 'high').length, vulnerabilities })
    }
    if (req.method === 'GET' && url.pathname === '/api/attack-paths') {
      const [events, assets, graph] = await Promise.all([readJsonLines(eventsFile), buildAssetIntelligence(), buildSecurityGraph()])
      const vulnerabilities = await currentVulnerabilities(events, assets)
      const patchedAssetId = url.searchParams.get('patched_asset_id')
      const result = analyzeAttackPaths({ graph, events, assets, vulnerabilities, patchedAssetId })
      if (patchedAssetId) {
        const before = analyzeAttackPaths({ graph, events, assets, vulnerabilities })
        result.risk_reduction = { paths_before: before.path_count, paths_after: result.path_count, paths_removed: Math.max(0, before.path_count - result.path_count), max_score_before: before.paths[0]?.risk_score || 0, max_score_after: result.paths[0]?.risk_score || 0, score_delta: (result.paths[0]?.risk_score || 0) - (before.paths[0]?.risk_score || 0), reduced: result.path_count < before.path_count || (result.paths[0]?.risk_score || 0) < (before.paths[0]?.risk_score || 0) }
      }
      return send(res, 200, result)
    }
    if (req.method === 'GET' && url.pathname === '/api/cases') return send(res, 200, { count: (await latestCases()).length, cases: await latestCases() })
    if (req.method === 'POST' && url.pathname === '/api/cases') {
      const body = await readBody(req)
      const events = await readJsonLines(eventsFile)
      const derived = detect(events).incidents.find((incident) => incident.id === body.incident_id)
      const id = body.id || `CASE-${Date.now()}`
      const record = {
        id, incident_id: body.incident_id || derived?.id || null,
        title: body.title || derived?.title || 'Security investigation',
        status: CASE_STATUSES.has(body.status) ? body.status : 'New',
        assignee: body.assignee || null, created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
        findings: body.findings || '', remediation: body.remediation || '', analyst_notes: body.analyst_notes || '',
        affected_device: body.affected_device || derived?.host || null, event_ids: body.event_ids || derived?.event_ids || [],
        related_alerts: body.related_alerts || derived?.findings?.map((finding) => finding.id) || [],
        evidence_refs: body.evidence_refs || []
      }
      await appendLines(casesFile, [record])
      return send(res, 201, record)
    }
    if (url.pathname.startsWith('/api/cases/') && !url.pathname.match(/^\/api\/cases\/[^/]+\/report$/)) {
      const caseId = url.pathname.split('/').pop()
      const cases = await latestCases()
      const current = cases.find((item) => item.id === caseId)
      if (!current) return send(res, 404, { error: 'Case not found' })
      if (req.method === 'GET') {
        const [events, assets] = await Promise.all([readJsonLines(eventsFile), buildAssetIntelligence()])
        const vulnerabilities = await currentVulnerabilities(events, assets)
        return send(res, 200, { ...current, supporting_events: events.filter((event) => current.event_ids.includes(event.id)), related_vulnerabilities: vulnerabilities.filter((finding) => current.affected_device === finding.affected_device) })
      }
      if (req.method === 'PATCH') {
        const body = await readBody(req)
        if (body.status && !CASE_STATUSES.has(body.status)) return send(res, 400, { error: `Invalid status. Use: ${[...CASE_STATUSES].join(', ')}` })
        const updated = { ...current, ...body, id: current.id, updated_at: new Date().toISOString() }
        await appendLines(casesFile, [updated])
        return send(res, 200, updated)
      }
    }
    if (req.method === 'GET' && url.pathname === '/api/simulations') return send(res, 200, { simulations: await latestSimulations() })
    if (req.method === 'GET' && url.pathname === '/api/evaluation') return send(res, 200, evaluateSimulations(await latestSimulations()))
    if (req.method === 'POST' && (url.pathname === '/api/simulations' || url.pathname === '/api/pcap/import')) {
      const isBinaryPcap = url.pathname === '/api/pcap/import' && String(req.headers['content-type'] || '').includes('octet-stream')
      const body = isBinaryPcap ? { name: req.headers['x-pcap-filename'] || 'uploaded.pcap', pcap_file_name: req.headers['x-pcap-filename'] || 'uploaded.pcap', events: parsePcap(await readRawBody(req)) } : await readBody(req)
      const scenario = { id: `SIM-${Date.now()}`, name: body.name || body.pcap_file_name || 'Security training scenario', type: url.pathname.endsWith('/import') ? 'pcap_replay' : (body.type || 'scripted_simulation'), label: body.label || 'SIMULATION — LAB DATA', status: 'Ready', created_at: new Date().toISOString(), pcap_file_name: body.pcap_file_name || null, events: Array.isArray(body.events) ? body.events : [], ground_truth_labels: body.ground_truth_labels || body.ground_truth || [], last_run: null }
      await appendLines(simulationsFile, [scenario])
      return send(res, 201, scenario)
    }
    if (req.method === 'POST' && url.pathname.match(/^\/api\/simulations\/[^/]+\/run$/)) {
      const simulationId = url.pathname.split('/')[3]
      const simulations = await readJsonLines(simulationsFile)
      const scenario = simulations.reverse().find((item) => item.id === simulationId)
      if (!scenario) return send(res, 404, { error: 'Simulation not found' })
      const ingestionStarted = performance.now()
      const result = await ingest('pcap', scenario.events, { telemetry_class: 'simulation', simulation_id: scenario.id, simulation_label: scenario.label })
      const ingestionLatency = performance.now() - ingestionStarted
      const detectionStarted = performance.now()
      const simulationEvents = result.events
      const detectionResult = detect(simulationEvents)
      const detectionLatency = performance.now() - detectionStarted
      const expected = new Set(scenario.ground_truth_labels)
      const detected = new Set(detectionResult.findings.map((finding) => finding.rule_id))
      const matched = [...expected].filter((label) => detected.has(label))
      const run = { run_id: `RUN-${Date.now()}`, completed_at: new Date().toISOString(), accepted: result.events.length, duplicates: result.duplicates, rejected: result.rejected, detected_findings: detectionResult.findings.length, expected_labels: [...expected], detected_labels: [...detected], matched_labels: matched, ground_truth_match_rate: expected.size ? matched.length / expected.size : null, ingestion_latency_ms: Number(ingestionLatency.toFixed(2)), detection_latency_ms: Number(detectionLatency.toFixed(2)), events_per_second: result.events.length ? Number((result.events.length / ((ingestionLatency + detectionLatency) / 1000)).toFixed(2)) : 0 }
      const updated = { ...scenario, status: 'Completed', last_run: run.completed_at, result: run, runs: [...(scenario.runs || []), run] }
      await appendLines(simulationsFile, [updated])
      return send(res, 202, updated)
    }
    if (req.method === 'GET' && url.pathname.match(/^\/api\/cases\/[^/]+\/report$/)) {
      const caseId = url.pathname.split('/')[3]
      const current = (await latestCases()).find((item) => item.id === caseId)
      if (!current) return send(res, 404, { error: 'Case not found' })
      const [events, assets] = await Promise.all([readJsonLines(eventsFile), buildAssetIntelligence()])
      const vulnerabilities = await currentVulnerabilities(events, assets)
      const supportingEvents = events.filter((event) => current.event_ids.includes(event.id)).sort((a, b) => a.timestamp.localeCompare(b.timestamp))
      const relatedVulnerabilities = vulnerabilities.filter((finding) => current.affected_device === finding.affected_device)
      return send(res, 200, { report_id: `REPORT-${current.id}`, generated_at: new Date().toISOString(), case: current, executive_summary: `${current.title} affected ${current.affected_device || 'an unidentified asset'} and is currently marked ${current.status}. This report contains observed telemetry and associated risk context for analyst review.`, timeline: supportingEvents.map((event) => ({ timestamp: event.timestamp, source: event.source, type: event.event_type, title: event.title, severity: event.severity, src_ip: event.src_ip, dest_ip: event.dest_ip, port: event.port })), evidence: supportingEvents.map((event) => ({ event_id: event.id, source: event.source, raw: event.raw })), related_vulnerabilities: relatedVulnerabilities, impact_assessment: { affected_asset: current.affected_device, vulnerability_count: relatedVulnerabilities.length, event_count: supportingEvents.length }, recommendations: current.remediation ? [current.remediation] : ['Review the supporting evidence and document the approved remediation plan.'] })
    }
    if (req.method === 'GET' && url.pathname === '/api/remediation') {
      const [events, assets] = await Promise.all([readJsonLines(eventsFile), buildAssetIntelligence()])
      const detectionResult = detect(events)
      const vulnerabilities = await currentVulnerabilities(events, assets)
      const proposed = buildRecommendations({ detections: detectionResult.findings, vulnerabilities, incidents: detectionResult.incidents })
      const saved = await readJsonLines(remediationFile)
      const savedById = new Map(saved.map((item) => [item.id, item]))
      const recommendations = proposed.map((item) => ({ ...item, ...(savedById.get(item.id) || {}) }))
      return send(res, 200, { count: recommendations.length, approval_required: recommendations.filter((item) => item.status === 'Proposed').length, recommendations })
    }
    if (req.method === 'POST' && url.pathname === '/api/remediation') {
      const body = await readBody(req)
      const record = { ...body, id: body.id || `ACTION-${Date.now()}`, status: 'Proposed', requires_approval: true, execution_status: 'Not executed', created_at: new Date().toISOString(), updated_at: new Date().toISOString() }
      await appendLines(remediationFile, [record])
      return send(res, 201, record)
    }
    if (req.method === 'POST' && url.pathname.match(/^\/api\/remediation\/[^/]+\/dry-run$/)) {
      const actionId = url.pathname.split('/')[3]; const saved = await readJsonLines(remediationFile); const action = saved.reverse().find((item) => item.id === actionId)
      if (!action) return send(res, 404, { error: 'Remediation action not found' })
      if (action.status !== 'Approved') return send(res, 409, { error: 'Analyst approval is required before a dry run', status: action.status })
      return send(res, 200, { action_id: action.id, dry_run: true, executed: false, target: action.target, type: action.type, planned_change: action.title, safety_note: 'No infrastructure was modified.' })
    }
    if (req.method === 'POST' && url.pathname.match(/^\/api\/remediation\/[^/]+\/execute$/)) {
      const actionId = url.pathname.split('/')[3]
      const saved = await readJsonLines(remediationFile)
      const action = saved.reverse().find((item) => item.id === actionId)
      if (!action) return send(res, 404, { error: 'Remediation action not found' })
      if (action.status !== 'Approved') return send(res, 409, { error: 'Analyst approval is required before execution', status: action.status })
      if (!process.env.NEXTGUARD_RESPONSE_WEBHOOK) return send(res, 503, { error: 'No response adapter configured', required_env: 'NEXTGUARD_RESPONSE_WEBHOOK', executed: false })
      const body = await readBody(req)
      if (body.confirm !== true) return send(res, 400, { error: 'Explicit confirmation is required', confirm: true, executed: false })
      const response = await fetch(process.env.NEXTGUARD_RESPONSE_WEBHOOK, { method: 'POST', headers: { 'content-type': 'application/json', 'x-nextguard-action': action.id }, body: JSON.stringify({ action_id: action.id, type: action.type, target: action.target, title: action.title, evidence: action.evidence, approved: true, approval_required: true }) })
      const executionStatus = response.ok ? 'Submitted' : 'AdapterRejected'
      const updated = { ...action, execution_status: executionStatus, adapter_status: response.status, executed_at: new Date().toISOString(), updated_at: new Date().toISOString() }
      await appendLines(remediationFile, [updated])
      await audit(req, response.ok ? 'remediation_submitted' : 'remediation_rejected', { action_id: action.id, adapter_status: response.status })
      return send(res, response.ok ? 202 : 502, { action_id: action.id, executed: response.ok, execution_status: executionStatus, adapter_status: response.status, safety_note: 'Submitted only to the configured, authorized response adapter.' })
    }
    if (url.pathname.startsWith('/api/remediation/')) {
      const actionId = url.pathname.split('/').pop()
      const saved = await readJsonLines(remediationFile)
      const current = saved.reverse().find((item) => item.id === actionId)
      if (!current) return send(res, 404, { error: 'Remediation action not found' })
      if (req.method === 'PATCH') {
        const body = await readBody(req)
        if (body.status && !REMEDIATION_STATUSES.has(body.status)) return send(res, 400, { error: `Invalid status. Use: ${[...REMEDIATION_STATUSES].join(', ')}` })
        const updated = { ...current, ...body, id: current.id, requires_approval: true, execution_status: 'Not executed', updated_at: new Date().toISOString() }
        await appendLines(remediationFile, [updated])
        return send(res, 200, updated)
      }
      if (req.method === 'GET') return send(res, 200, current)
    }
    if (req.method === 'GET' && (url.pathname === '/api/monitoring' || url.pathname === '/api/verification')) {
      const [events, assets] = await Promise.all([readJsonLines(eventsFile), buildAssetIntelligence()])
      const detectionResult = detect(events)
      const vulnerabilities = await currentVulnerabilities(events, assets)
      const graph = await buildSecurityGraph()
      const attackPaths = analyzeAttackPaths({ graph, events, assets, vulnerabilities, patchedAssetId: url.searchParams.get('patched_asset_id') })
      const current = buildMonitoringSnapshot({ detections: detectionResult.findings, incidents: detectionResult.incidents, vulnerabilities, attackPaths, events })
      const baselineId = url.searchParams.get('baseline_id')
      let comparison = null
      if (baselineId) {
        const snapshots = await readJsonLines(snapshotsFile)
        comparison = compareMonitoringSnapshots(snapshots.find((snapshot) => snapshot.id === baselineId), current)
      }
      return send(res, 200, { current, comparison })
    }
    if (req.method === 'GET' && url.pathname === '/api/verification/snapshots') return send(res, 200, { snapshots: await readJsonLines(snapshotsFile) })
    if (req.method === 'POST' && url.pathname === '/api/verification/snapshots') {
      const [events, assets] = await Promise.all([readJsonLines(eventsFile), buildAssetIntelligence()])
      const detectionResult = detect(events)
      const vulnerabilities = await currentVulnerabilities(events, assets)
      const graph = await buildSecurityGraph()
      const attackPaths = analyzeAttackPaths({ graph, events, assets, vulnerabilities })
      const snapshot = { id: `SNAP-${Date.now()}`, label: (await readBody(req)).label || 'Verification baseline', ...buildMonitoringSnapshot({ detections: detectionResult.findings, incidents: detectionResult.incidents, vulnerabilities, attackPaths, events }) }
      await appendLines(snapshotsFile, [snapshot])
      return send(res, 201, snapshot)
    }
    if (req.method === 'POST' && url.pathname.startsWith('/api/ingest/')) {
      const source = url.pathname.split('/').pop()
      const simulation = String(req.headers['x-telemetry-class'] || '').toLowerCase() === 'simulation'
      const result = await ingest(source, await readBody(req), { tenant_id: req.headers['x-tenant-id'] || 'default', telemetry_class: simulation ? 'simulation' : 'production', simulation_id: simulation ? (req.headers['x-simulation-id'] || 'SIM-INGEST') : null, simulation_label: simulation ? (req.headers['x-simulation-label'] || 'SIMULATION — LAB DATA') : null })
      return send(res, 202, { accepted: result.events.length, duplicates: result.duplicates, rejected: result.rejected, source, events: result.events })
    }
    send(res, 404, { error: 'Route not found' })
  } catch (error) {
    send(res, 400, { error: error.message })
  }
})

const websocketServer = new WebSocketServer({ server, path: '/ws' })
websocketServer.on('connection', (socket) => {
  realtimeClients.add(socket)
  socket.send(JSON.stringify({ type: 'connected', service: 'nextguard-realtime', timestamp: new Date().toISOString() }))
  socket.on('close', () => realtimeClients.delete(socket))
  socket.on('error', () => realtimeClients.delete(socket))
})

server.listen(port, () => {
  console.log(`NEXTGUARD ingestion API listening on http://localhost:${port}`)
  startConnectors({ ingest })
})
