import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import * as THREE from 'three'
import { OrbitControls } from 'three/addons/controls/OrbitControls.js'
import {
  Activity, AlertTriangle, Database, Pause, Play, RefreshCw, Route, Search,
  Shield, ShieldAlert, Trash2, Wifi, WifiOff
} from 'lucide-react'
import './attack-viz.css'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:4000'

const FALLBACK_NODES = [
  { id: 'fallback:internet', name: 'Internet', ip: '8.8.8.8', type: 'internet', pos: [0, 4.4, -7.6] },
  { id: 'fallback:laptop', name: 'Laptop', ip: '192.168.1.10', type: 'laptop', pos: [-6.6, 0, -2.3] },
  { id: 'fallback:server', name: 'Server', ip: '192.168.1.20', type: 'server', pos: [6.6, 0, -2.3] },
  { id: 'fallback:infected', name: 'Infected', ip: '192.168.1.25', type: 'laptop', pos: [0, 0, 1] },
  { id: 'fallback:desktop', name: 'Desktop', ip: '192.168.1.30', type: 'desktop', pos: [-6.9, 0, 3.5] },
  { id: 'fallback:mobile', name: 'Mobile', ip: '192.168.1.50', type: 'mobile', pos: [6.9, 0, 3.5] },
  { id: 'fallback:database', name: 'Database', ip: '192.168.1.40', type: 'database', pos: [0, 0, 6.9] }
]

const FALLBACK_LINKS = [
  ['Internet', 'Laptop'], ['Internet', 'Server'], ['Infected', 'Internet'],
  ['Infected', 'Laptop'], ['Infected', 'Server'], ['Infected', 'Desktop'],
  ['Infected', 'Mobile'], ['Infected', 'Database'], ['Desktop', 'Database'],
  ['Mobile', 'Database']
]

const COLORS = { normal: 0x22ff66, suspicious: 0xffa726, malicious: 0xff3b3b }
const MAX_RENDER_NODES = 80
const MAX_RENDER_EDGES = 160
const EMPTY_COUNTS = { normal: 0, suspicious: 0, malicious: 0 }

const normalized = (value) => String(value || '').trim().toLowerCase()

const statusLabel = (value) => value === 'Malicious' ? 'Malicious' : value === 'Suspicious' ? 'Suspicious' : value === 'Vulnerable' ? 'Vulnerable' : 'Normal'

const statusClass = (value) => statusLabel(value).toLowerCase()

const nodeKind = (node) => {
  const value = normalized(`${node?.type || ''} ${node?.name || ''}`)
  if (value.includes('infected') || normalized(node?.ip) === '192.168.1.25') return 'hub'
  if (value.includes('internet') || value.includes('external') || value.includes('globe')) return 'globe'
  if (value.includes('database') || value.includes('db')) return 'database'
  if (value.includes('server') || value.includes('api')) return 'server'
  if (value.includes('mobile') || value.includes('phone')) return 'mobile'
  if (value.includes('laptop') || value.includes('workstation')) return 'laptop'
  if (value.includes('desktop') || value.includes('endpoint')) return 'desktop'
  if (value.includes('hub') || value.includes('router') || value.includes('firewall')) return 'hub'
  return 'device'
}

const stableHash = (value) => [...String(value || '')].reduce((sum, character) => ((sum * 31) + character.charCodeAt(0)) >>> 0, 7)

function classifyEvent(event) {
  const isSuricataAlert = event?.source !== 'suricata' || Boolean(event?.raw?.alert) || Boolean(event?.raw?.signature) || event?.raw?.event_type === 'alert'
  if (event?.source === 'suricata' && !isSuricataAlert) return 'normal'
  const severity = String(event?.severity || '').toLowerCase()
  if (severity === 'critical' || severity === 'high' || event?.category === 'intrusion') return 'malicious'
  if (severity === 'medium' || event?.category === 'vulnerability') return 'suspicious'
  return 'normal'
}

function mergeEvents(current, incoming) {
  const byId = new Map()
  ;[...current, ...incoming].forEach((event) => {
    const key = event?.id || `${event?.timestamp}|${event?.source}|${event?.src_ip}|${event?.dest_ip}|${event?.port}`
    byId.set(key, event)
  })
  return [...byId.values()].sort((a, b) => new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime()).slice(0, 250)
}

function labelForNode(node) {
  return node.label || node.hostname || node.name || node.ip || node.id
}

async function requestApi(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, { headers: { 'content-type': 'application/json', ...(options.headers || {}) }, ...options })
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(body.error || `${response.status} ${path}`)
  return body
}

export function AttackVizDashboard() {
  const canvasHost = useRef(null)
  const labelsHost = useRef(null)
  const sparkRef = useRef(null)
  const resetViewRef = useRef(() => {})
  const focusNodeRef = useRef(() => {})
  const zoomViewRef = useRef(() => {})
  const autoRotateControlRef = useRef(null)
  const autoRotateRef = useRef(true)
  const modeRef = useRef('realtime')
  const selectedRef = useRef(null)
  const cameraViewRef = useRef({ position: [0, 9.5, 16.5], target: [0, 1.3, 0] })
  const alertTargetRef = useRef(null)
  const selectionHideTimerRef = useRef(null)
  const pausedRef = useRef(false)
  const refreshTimerRef = useRef(null)
  const [paused, setPaused] = useState(false)
  const [autoRotate, setAutoRotate] = useState(true)
  const [mode, setMode] = useState('realtime')
  const [filter, setFilter] = useState('all')
  const [query, setQuery] = useState('')
  const [topologyFilter, setTopologyFilter] = useState('all')
  const [topologyQuery, setTopologyQuery] = useState('')
  const [activeTab, setActiveTab] = useState('logs')
  const [counts, setCounts] = useState({ normal: 0, suspicious: 0, malicious: 0 })
  const [logs, setLogs] = useState([])
  const [alerts, setAlerts] = useState([])
  const [selected, setSelected] = useState(null)
  const [alert, setAlert] = useState(null)
  const [stats, setStats] = useState({ total: 0, pps: 0, rate: 0, level: 'LOW' })
  const [history, setHistory] = useState([])
  const [graph, setGraph] = useState({ nodes: [], edges: [] })
  const [backendEvents, setBackendEvents] = useState([])
  const [timeline, setTimeline] = useState([])
  const [findings, setFindings] = useState([])
  const [incidents, setIncidents] = useState([])
  const [vulnerabilities, setVulnerabilities] = useState([])
  const [attackPaths, setAttackPaths] = useState({ paths: [], path_count: 0 })
  const [monitoring, setMonitoring] = useState(null)
  const [traffic, setTraffic] = useState(null)
  const [sources, setSources] = useState([])
  const [cases, setCases] = useState([])
  const [remediation, setRemediation] = useState([])
  const [simulations, setSimulations] = useState([])
  const [evaluation, setEvaluation] = useState(null)
  const [actionMessage, setActionMessage] = useState('')
  const [actionBusy, setActionBusy] = useState(false)
  const [backend, setBackend] = useState({ connected: false, websocket: false, lastSync: null, error: '' })

  const showSelectedNode = useCallback((node) => {
    window.clearTimeout(selectionHideTimerRef.current)
    setSelected(node)
    selectionHideTimerRef.current = window.setTimeout(() => {
      setSelected(null)
      selectionHideTimerRef.current = null
    }, 6500)
  }, [])

  useEffect(() => () => window.clearTimeout(selectionHideTimerRef.current), [])

  useEffect(() => {
    if (!actionMessage) return undefined
    const timer = window.setTimeout(() => setActionMessage(''), 1000)
    return () => window.clearTimeout(timer)
  }, [actionMessage])

  useEffect(() => {
    if (!backend.connected && activeTab !== 'logs') setActiveTab('logs')
  }, [activeTab, backend.connected])

  useEffect(() => {
    modeRef.current = mode
  }, [mode])

  useEffect(() => {
    selectedRef.current = selected
  }, [selected])

  const refreshBackend = useCallback(async () => {
    const paths = ['/api/health', '/api/graph', '/api/events?limit=250', '/api/detections', '/api/incidents', '/api/vulnerabilities', '/api/attack-paths', '/api/monitoring', '/api/traffic', '/api/sources', '/api/timeline?limit=250', '/api/cases', '/api/remediation', '/api/simulations', '/api/evaluation']
    const request = async (path) => {
      const response = await fetch(`${API_BASE}${path}`)
      if (!response.ok) throw new Error(`${path} returned ${response.status}`)
      return response.json()
    }
    const results = await Promise.allSettled(paths.map(request))
    const value = (index, fallback) => results[index].status === 'fulfilled' ? results[index].value : fallback
    const health = value(0, null)
    const nextGraph = value(1, { nodes: [], edges: [] })
    const eventPayload = value(2, { events: [] })
    const detectionPayload = value(3, { findings: [], classifications: [] })
    const incidentPayload = value(4, { incidents: [] })
    const vulnerabilityPayload = value(5, { vulnerabilities: [] })
    const pathPayload = value(6, { paths: [], path_count: 0 })
    const monitoringPayload = value(7, null)
    const trafficPayload = value(8, null)
    const sourcePayload = value(9, { sources: [] })
    const timelinePayload = value(10, { timeline: [] })
    const casePayload = value(11, { cases: [] })
    const remediationPayload = value(12, { recommendations: [] })
    const simulationPayload = value(13, { simulations: [] })
    const evaluationPayload = value(14, null)
    const apiReachable = results[0].status === 'fulfilled' && health?.ok !== false
    setBackend((current) => ({ ...current, connected: apiReachable, websocket: apiReachable ? current.websocket : false, error: apiReachable ? '' : 'API unavailable', lastSync: apiReachable ? new Date().toISOString() : current.lastSync }))
    if (nextGraph?.nodes) setGraph({ nodes: nextGraph.nodes || [], edges: nextGraph.edges || [] })
    if (eventPayload?.events) setBackendEvents((current) => mergeEvents(current, eventPayload.events))
    if (detectionPayload?.findings) setFindings(detectionPayload.findings)
    if (incidentPayload?.incidents) setIncidents(incidentPayload.incidents)
    if (vulnerabilityPayload?.vulnerabilities) setVulnerabilities(vulnerabilityPayload.vulnerabilities)
    if (pathPayload) setAttackPaths(pathPayload)
    if (monitoringPayload) setMonitoring(monitoringPayload.current || monitoringPayload)
    if (trafficPayload) setTraffic(trafficPayload)
    if (sourcePayload?.sources) setSources(sourcePayload.sources)
    if (timelinePayload?.timeline) setTimeline(timelinePayload.timeline)
    if (casePayload?.cases) setCases(casePayload.cases)
    if (remediationPayload?.recommendations) setRemediation(remediationPayload.recommendations)
    if (simulationPayload?.simulations) setSimulations(simulationPayload.simulations)
    if (evaluationPayload) setEvaluation(evaluationPayload)
    return apiReachable
  }, [])

  const analyzeNow = useCallback(() => {
    if (mode === 'simulation') {
      const total = counts.normal + counts.suspicious + counts.malicious
      const threatEvents = counts.suspicious + counts.malicious
      const rate = total ? (threatEvents / total) * 100 : 0
      setStats((current) => ({
        ...current,
        total,
        rate,
        level: rate < 12 ? 'LOW' : rate < 28 ? 'MEDIUM' : 'HIGH'
      }))
      setActionMessage('Simulation analyzed from current demo data.')
      return
    }
    refreshBackend()
  }, [counts, mode, refreshBackend])

  useEffect(() => {
    refreshBackend()
    const timer = window.setInterval(() => {
      if (modeRef.current === 'realtime') refreshBackend()
    }, 10000)
    return () => window.clearInterval(timer)
  }, [refreshBackend])

  const performAction = useCallback(async (path, options, message) => {
    setActionBusy(true)
    try {
      await requestApi(path, options)
      setActionMessage(message)
      await refreshBackend()
    } catch (error) {
      setActionMessage(`Action failed: ${error.message}`)
    } finally {
      setActionBusy(false)
    }
  }, [refreshBackend])

  const openCase = useCallback((incident) => performAction('/api/cases', { method: 'POST', body: JSON.stringify({ incident_id: incident.id, title: incident.title, affected_device: incident.host, status: 'New', findings: incident.investigation_summary || '', analyst_notes: 'Opened from the live threat dashboard.' }) }, `Investigation case opened for ${incident.host || incident.id}.`), [performAction])
  const updateCase = useCallback((item, status) => performAction(`/api/cases/${item.id}`, { method: 'PATCH', body: JSON.stringify({ status }) }, `Case ${item.id} moved to ${status}.`), [performAction])
  const viewReport = useCallback(async (item) => {
    setActionBusy(true)
    try {
      const report = await requestApi(`/api/cases/${item.id}/report`)
      setActionMessage(report.executive_summary || `Report ${report.report_id} generated.`)
    } catch (error) { setActionMessage(`Report failed: ${error.message}`) } finally { setActionBusy(false) }
  }, [])
  const approveRemediation = useCallback((item) => performAction(`/api/remediation/${item.id}`, { method: 'PATCH', body: JSON.stringify({ status: 'Approved' }) }, `Remediation ${item.id} approved for analyst-controlled execution.`), [performAction])
  const dryRunRemediation = useCallback((item) => performAction(`/api/remediation/${item.id}/dry-run`, { method: 'POST' }, `Dry run prepared for ${item.target || item.id}; no infrastructure was changed.`), [performAction])
  const executeRemediation = useCallback((item) => performAction(`/api/remediation/${item.id}/execute`, { method: 'POST', body: JSON.stringify({ confirm: true }) }, `Approved action ${item.id} submitted to the configured response adapter.`), [performAction])
  const runTrainingScenario = useCallback(async () => {
    setActionBusy(true)
    try {
      const scenario = await requestApi('/api/simulations', { method: 'POST', body: JSON.stringify({ name: 'Dashboard controlled threat scenario', type: 'scripted_simulation', label: 'SIMULATION — DASHBOARD TRAINING', events: [{ id: `training-${Date.now()}`, timestamp: new Date().toISOString(), src_ip: '10.50.0.44', dest_ip: '10.50.0.10', dest_port: 22, proto: 'tcp', message: 'failed login attempt' }, { id: `training-${Date.now()}-2`, timestamp: new Date().toISOString(), src_ip: '10.50.0.44', dest_ip: '10.50.0.10', dest_port: 22, proto: 'tcp', message: 'failed login attempt' }, { id: `training-${Date.now()}-3`, timestamp: new Date().toISOString(), src_ip: '10.50.0.44', dest_ip: '10.50.0.10', dest_port: 22, proto: 'tcp', message: 'failed login attempt' }], ground_truth_labels: ['repeated-failed-login'] }) })
      await requestApi(`/api/simulations/${scenario.id}/run`, { method: 'POST' })
      setActionMessage('Controlled training scenario replayed and evaluated against ground truth.')
      await refreshBackend()
    } catch (error) { setActionMessage(`Training failed: ${error.message}`) } finally { setActionBusy(false) }
  }, [refreshBackend])
  const importPcap = useCallback(async (event) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    setActionBusy(true)
    try {
      const buffer = await file.arrayBuffer()
      await requestApi('/api/pcap/import', { method: 'POST', headers: { 'content-type': 'application/octet-stream', 'x-pcap-filename': file.name }, body: buffer })
      setActionMessage(`${file.name} imported as isolated PCAP training data.`)
      await refreshBackend()
    } catch (error) { setActionMessage(`PCAP import failed: ${error.message}`) } finally { setActionBusy(false) }
  }, [refreshBackend])

  useEffect(() => {
    if (mode !== 'realtime') {
      setBackend((current) => ({ ...current, connected: false, websocket: false }))
      return undefined
    }
    let socket
    try { socket = new WebSocket(`${API_BASE.replace(/^http/, 'ws')}/ws`) } catch { return undefined }
    socket.onopen = () => setBackend((current) => ({ ...current, websocket: true }))
    socket.onclose = () => setBackend((current) => ({ ...current, websocket: false }))
    socket.onerror = () => setBackend((current) => ({ ...current, websocket: false }))
    socket.onmessage = (message) => {
      try {
        const payload = JSON.parse(message.data)
        if (payload.type !== 'telemetry') return
        setBackend((current) => ({ ...current, lastSync: new Date().toISOString() }))
        if (payload.events?.length) setBackendEvents((current) => mergeEvents(current, payload.events))
        window.clearTimeout(refreshTimerRef.current)
        refreshTimerRef.current = window.setTimeout(refreshBackend, 900)
      } catch { /* Ignore malformed sensor messages. */ }
    }
    return () => { window.clearTimeout(refreshTimerRef.current); socket?.close() }
  }, [mode, refreshBackend])

  const statusByKey = useMemo(() => {
    const result = new Map()
    const rank = { Normal: 0, Unknown: 0, Vulnerable: 1, Suspicious: 2, Malicious: 3 }
    const setStatus = (value, status) => { if (value && (rank[status] || 0) >= (rank[result.get(normalized(value))] || 0)) result.set(normalized(value), status) }
    const eventsById = new Map(backendEvents.map((event) => [event.id, event]))
    findings.forEach((finding) => {
      const event = eventsById.get(finding.event_id)
      const activeMalicious = event ? classifyEvent(event) === 'malicious' : false
      const status = activeMalicious && (finding.alert_classification === 'High Confidence Malicious' || ['critical', 'high'].includes(finding.severity)) ? 'Malicious' : 'Suspicious'
      setStatus(finding.affected_device, status); setStatus(finding.source_ip, status); setStatus(finding.destination_ip, status)
    })
    incidents.forEach((incident) => {
      const activeMalicious = (incident.event_ids || []).some((eventId) => classifyEvent(eventsById.get(eventId)) === 'malicious')
      setStatus(incident.host, activeMalicious && ['critical', 'high'].includes(incident.severity) ? 'Malicious' : 'Suspicious')
    })
    vulnerabilities.forEach((item) => { if (['critical', 'high'].includes(item.priority)) setStatus(item.affected_device, 'Vulnerable') })
    return result
  }, [backendEvents, findings, incidents, vulnerabilities])

  const visualGraph = useMemo(() => {
    const graphNodes = (graph.nodes || []).filter((node) => ['device', 'external', 'service'].includes(node.type))
    const useBackendGraph = mode === 'realtime' && backend.connected && graphNodes.length > 0
    const nodeMatches = (node) => `${labelForNode(node)} ${node.ip || ''} ${node.type || ''}`.toLowerCase().includes(topologyQuery.toLowerCase())
    const filterMatches = (node) => {
      if (topologyFilter === 'all') return true
      const kind = nodeKind(node)
      const hasServiceData = node.type === 'service' || (Array.isArray(node.services) && node.services.length > 0) || ['server', 'database'].includes(kind)
      if (topologyFilter === 'services') return hasServiceData
      if (topologyFilter === 'devices') return !hasServiceData && ['device', 'external', 'laptop', 'desktop', 'mobile', 'computer', 'workstation'].includes(normalized(node.type))
      const status = statusByKey.get(normalized(node.ip)) || statusByKey.get(normalized(labelForNode(node))) || node.status
      const criticality = normalized(node.criticality || node.priority || node.asset_role)
      const name = normalized(labelForNode(node))
      return node.critical === true || ['critical', 'high', 'tier0', 'tier_0'].includes(criticality) || ['Malicious', 'Vulnerable'].includes(status) || name.includes('infected') || name.includes('database')
    }
    const filteredGraphNodes = graphNodes.filter((node) => nodeMatches(node) && filterMatches(node))
    const filteredFallbackNodes = FALLBACK_NODES.filter((node) => nodeMatches(node) && filterMatches(node))
    const sourceNodes = useBackendGraph ? filteredGraphNodes.sort((a, b) => {
      const score = (node) => { const status = statusByKey.get(normalized(node.ip)) || statusByKey.get(normalized(labelForNode(node))); return ['Malicious', 'Suspicious'].includes(status) ? 4 : node.type === 'device' ? 3 : node.type === 'external' ? 2 : 1 }
      return score(b) - score(a)
    }).slice(0, MAX_RENDER_NODES) : filteredFallbackNodes
    const nodes = useBackendGraph ? sourceNodes.map((node, index) => {
      const known = FALLBACK_NODES.find((item) => normalized(item.name) === normalized(labelForNode(node)))
      const infectedIdentity = normalized(labelForNode(node)).includes('infected') || normalized(node.ip) === '192.168.1.25'
      const angle = (stableHash(node.id) % 360) * Math.PI / 180
      const radius = Math.max(3.5, Math.min(8, graphNodes.length * .65))
      const layer = stableHash(`${node.id}:layer`) % 3
      return { id: node.id, name: labelForNode(node), ip: node.ip || '', type: node.type, mac: node.mac || '', os: node.os || '', services: node.services || [], criticality: node.criticality || '', pos: infectedIdentity ? [0, 0, 1] : known?.pos || [Math.cos(angle) * radius, layer === 0 ? 1.2 : 0, Math.sin(angle) * radius], status: statusByKey.get(normalized(node.ip)) || statusByKey.get(normalized(labelForNode(node))) || 'Normal', confidence: node.confidence }
    }) : sourceNodes.map((node) => ({ ...node, status: statusByKey.get(normalized(node.name)) || 'Normal', confidence: 'demo' }))
    const ids = new Set(nodes.map((node) => node.id))
    const pathEdgeIds = new Set((attackPaths.paths?.[0]?.edges || []).map((edge) => edge.id))
    const nodeByEndpoint = (value) => nodes.find((node) => node.id === value || normalized(node.name) === normalized(value) || normalized(node.ip) === normalized(value))
    const endpointStatus = (value) => nodeByEndpoint(value)?.status || 'Normal'
    const linkStatus = (edge) => {
      if (pathEdgeIds.has(edge.id)) return 'path'
      if (edge.suspicious && [endpointStatus(edge.source), endpointStatus(edge.target)].includes('Malicious')) return 'malicious'
      if (edge.suspicious) return 'suspicious'
      return 'normal'
    }
    const links = useBackendGraph
      ? (graph.edges || []).filter((edge) => ids.has(edge.source) && ids.has(edge.target)).sort((a, b) => Number(Boolean(b.suspicious || pathEdgeIds.has(b.id))) - Number(Boolean(a.suspicious || pathEdgeIds.has(a.id))) || (b.count || 0) - (a.count || 0)).slice(0, MAX_RENDER_EDGES).map((edge) => ({ a: edge.source, b: edge.target, type: linkStatus(edge), relation: edge.type }))
      : FALLBACK_LINKS.filter(([a, b]) => nodes.some((node) => node.name === a) && nodes.some((node) => node.name === b)).map(([a, b]) => ({ a, b, type: [endpointStatus(a), endpointStatus(b)].includes('Malicious') ? 'malicious' : [endpointStatus(a), endpointStatus(b)].includes('Suspicious') ? 'suspicious' : 'normal', relation: 'communicates_with' }))
    return { nodes, links, useBackendGraph }
  }, [attackPaths, backend.connected, graph, mode, statusByKey, topologyFilter, topologyQuery])

  const backendLogs = useMemo(() => backendEvents.map((event) => ({
    time: event.timestamp || Date.now(),
    type: classifyEvent(event),
    fromName: event.host || event.src_ip || 'unknown',
    fromIp: event.src_ip || 'unknown',
    toName: event.dest_ip || 'unknown',
    toIp: event.dest_ip || 'unknown',
    source: event.source,
    title: event.title || event.event_type || 'Network event'
  })), [backendEvents])
  const liveThreatStats = useMemo(() => {
    const counts = backendLogs.reduce((result, item) => {
      result[item.type] = (result[item.type] || 0) + 1
      return result
    }, { normal: 0, suspicious: 0, malicious: 0 })
    const total = counts.normal + counts.suspicious + counts.malicious
    const threats = counts.suspicious + counts.malicious
    const now = Date.now()
    const recentItems = backendLogs.filter((item) => { const age = now - new Date(item.time).getTime(); return age >= 0 && age <= 10000 })
    const recentThreats = recentItems.filter((item) => item.type !== 'normal').length
    const recentRate = recentItems.length ? (recentThreats / recentItems.length) * 100 : 0
    return { total, threats, rate: recentRate, eventsPerSecond: recentItems.length / 10, level: recentRate < 12 ? 'LOW' : recentRate < 28 ? 'MEDIUM' : 'HIGH', counts }
  }, [backendLogs])
  const threatHistory = useMemo(() => {
    const buckets = Array.from({ length: 30 }, () => ({ total: 0, suspicious: 0, malicious: 0 }))
    if (mode === 'realtime' && backend.connected) {
      const now = Date.now()
      backendLogs.forEach((item) => {
        const age = now - new Date(item.time).getTime()
        if (age < 0 || age > 30000) return
        const bucket = Math.min(29, Math.floor(age / 1000))
        buckets[29 - bucket].total += 1
        if (item.type === 'suspicious') buckets[29 - bucket].suspicious += 1
        if (item.type === 'malicious') buckets[29 - bucket].malicious += 1
      })
      return buckets
    }
    if (mode === 'simulation') return Array.from({ length: 30 }, (_, index) => history[index] || { total: 0, suspicious: 0, malicious: history[index]?.threat || 0 })
    return buckets
  }, [backend.connected, backendLogs, history, mode])
  const shownTimeline = useMemo(() => (timeline.length ? timeline : backendEvents).filter((item) => `${item.source || ''} ${item.title || ''} ${item.host || ''} ${item.src_ip || ''} ${item.dest_ip || ''}`.toLowerCase().includes(query.toLowerCase())).slice(0, 100), [backendEvents, query, timeline])

  const liveTelemetryVisible = mode === 'realtime' && backend.connected
  const simulationVisible = mode === 'simulation'
  const displayLogs = liveTelemetryVisible ? backendLogs : simulationVisible ? logs : []
  const displayCounts = liveTelemetryVisible
    ? backendLogs.reduce((result, item) => ({ ...result, [item.type]: result[item.type] + 1 }), { normal: 0, suspicious: 0, malicious: 0 })
    : simulationVisible ? counts : EMPTY_COUNTS
  const shownLogs = useMemo(() => displayLogs.filter((item) => filter === 'all' || item.type === filter).filter((item) => `${item.fromName} ${item.fromIp} ${item.toName} ${item.toIp} ${item.title || ''}`.toLowerCase().includes(query.toLowerCase())).slice(0, 80), [displayLogs, filter, query])
  const shownAlerts = useMemo(() => incidents.filter((item) => `${item.title} ${item.host} ${item.severity}`.toLowerCase().includes(query.toLowerCase())).slice(0, 60), [incidents, query])
  const shownVulnerabilities = useMemo(() => vulnerabilities.filter((item) => `${item.title} ${item.cve} ${item.affected_device} ${item.priority}`.toLowerCase().includes(query.toLowerCase())).slice(0, 60), [vulnerabilities, query])
  const shownPaths = useMemo(() => (attackPaths.paths || []).filter((item) => JSON.stringify(item).toLowerCase().includes(query.toLowerCase())).slice(0, 30), [attackPaths, query])
  const selectedGraphNode = useMemo(() => {
    if (!selected) return null
    const graphNode = visualGraph.nodes.find((node) => node.id === selected.id) || visualGraph.nodes.find((node) => normalized(node.ip) === normalized(selected.ip)) || visualGraph.nodes.find((node) => normalized(node.name) === normalized(selected.name))
    return graphNode ? { ...graphNode, ...selected, status: selected.status || graphNode.status || 'Normal' } : selected
  }, [selected, visualGraph.nodes])
  const selectedConnections = useMemo(() => {
    if (!selectedGraphNode) return []
    return visualGraph.links.map((link) => {
      const isSource = link.a === selectedGraphNode.id || normalized(link.a) === normalized(selectedGraphNode.name) || normalized(link.a) === normalized(selectedGraphNode.ip)
      const isTarget = link.b === selectedGraphNode.id || normalized(link.b) === normalized(selectedGraphNode.name) || normalized(link.b) === normalized(selectedGraphNode.ip)
      if (!isSource && !isTarget) return null
      const endpoint = isSource ? link.b : link.a
      const node = visualGraph.nodes.find((item) => item.id === endpoint || normalized(item.name) === normalized(endpoint) || normalized(item.ip) === normalized(endpoint))
      return node ? { node, relation: link.type === 'path' ? 'Inferred attack path' : link.type === 'malicious' ? 'Malicious traffic' : link.type === 'suspicious' ? 'Suspicious traffic' : 'Normal traffic' } : null
    }).filter(Boolean)
  }, [selectedGraphNode, visualGraph.links, visualGraph.nodes])

  useEffect(() => {
    const canvas = sparkRef.current
    if (!canvas) return
    const context = canvas.getContext('2d')
    context.clearRect(0, 0, canvas.width, canvas.height)
    const max = Math.max(4, ...history.map((item) => item.total))
    history.forEach((item, index) => {
      const width = canvas.width / 30
      context.fillStyle = 'rgba(77,163,255,.35)'
      context.fillRect(index * width, canvas.height - (item.total / max) * canvas.height, width - 2, (item.total / max) * canvas.height)
      context.fillStyle = '#ff3b3b'
      context.fillRect(index * width, canvas.height - (item.threat / max) * canvas.height, width - 2, (item.threat / max) * canvas.height)
    })
  }, [history])

  useEffect(() => {
    const host = canvasHost.current
    if (!host) return undefined
    const scene = new THREE.Scene()
    scene.background = new THREE.Color(0x050b1a)
    scene.fog = new THREE.Fog(0x050b1a, 18, 45)
    const camera = new THREE.PerspectiveCamera(42, host.clientWidth / host.clientHeight, .1, 200)
    camera.position.fromArray(cameraViewRef.current.position)
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    renderer.setSize(host.clientWidth, host.clientHeight)
    renderer.setClearColor(0x000000, 0)
    host.appendChild(renderer.domElement)
    scene.add(new THREE.AmbientLight(0xffffff, .5))
    const point = new THREE.PointLight(0x4da3ff, 80, 50)
    point.position.set(0, 8, 4)
    scene.add(point)
    const grid = new THREE.GridHelper(44, 44, 0x1f6fff, 0x12306a)
    grid.position.y = -1
    grid.material.transparent = true
    grid.material.opacity = .34
    scene.add(grid)
    const floorGlow = new THREE.Mesh(new THREE.CircleGeometry(24, 64), new THREE.MeshBasicMaterial({ color: 0x123a91, transparent: true, opacity: .12, blending: THREE.AdditiveBlending, depthWrite: false }))
    floorGlow.rotation.x = -Math.PI / 2
    floorGlow.position.y = -1.02
    scene.add(floorGlow)
    ;[5, 10, 15, 20].forEach((radius, index) => {
      const ring = new THREE.Mesh(new THREE.RingGeometry(radius, radius + .025, 96), new THREE.MeshBasicMaterial({ color: 0x2a6df4, transparent: true, opacity: .2 - index * .03, side: THREE.DoubleSide, depthWrite: false }))
      ring.rotation.x = -Math.PI / 2
      ring.position.y = -1.01
      scene.add(ring)
    })
    const starsPosition = []
    for (let index = 0; index < 300; index += 1) starsPosition.push((Math.random() - .5) * 60, Math.random() * 20 + 2, (Math.random() - .5) * 60)
    const starGeometry = new THREE.BufferGeometry()
    starGeometry.setAttribute('position', new THREE.Float32BufferAttribute(starsPosition, 3))
    const stars = new THREE.Points(starGeometry, new THREE.PointsMaterial({ color: 0x4da3ff, size: .08, transparent: true, opacity: .6 }))
    scene.add(stars)
    const controls = new OrbitControls(camera, renderer.domElement)
    controls.target.fromArray(cameraViewRef.current.target)
    controls.enableDamping = true
    controls.dampingFactor = .08
    controls.minDistance = 6
    controls.maxDistance = 32
    controls.maxPolarAngle = 1.45
    controls.enablePan = false
    controls.autoRotate = autoRotateRef.current
    controls.autoRotateSpeed = .45
    autoRotateControlRef.current = controls
    let resumeTimer = null
    controls.addEventListener('start', () => { controls.autoRotate = false; window.clearTimeout(resumeTimer) })
    controls.addEventListener('end', () => { window.clearTimeout(resumeTimer); resumeTimer = window.setTimeout(() => { controls.autoRotate = autoRotateRef.current }, 5000) })
    const nodeMap = {}
    const nodeList = []
    const linkObjects = []
    const packets = []
    let last = performance.now()
    let elapsed = 0
    let spawnTimer = 0
    let total = 0
    let windowTotal = 0
    let windowThreat = 0
    let statsTimer = 0
    const cleanupFns = []
    resetViewRef.current = () => {
      camera.position.set(0, 9.5, 16.5)
      controls.target.set(0, 1.3, 0)
      controls.update()
    }
    zoomViewRef.current = (factor) => {
      const offset = camera.position.clone().sub(controls.target)
      offset.setLength(Math.min(Math.max(offset.length() * factor, controls.minDistance), controls.maxDistance))
      camera.position.copy(controls.target).add(offset)
      controls.update()
    }
    focusNodeRef.current = (target) => {
      const mesh = target && (nodeMap[target.id] || nodeMap[normalized(target.ip)] || nodeMap[normalized(target.name)])
      if (!mesh) return false
      const focus = mesh.position.clone()
      const offset = new THREE.Vector3(0, 3.6, 6.4)
      camera.position.copy(focus).add(offset)
      controls.target.copy(focus)
      controls.update()
      showSelectedNode(serializable(mesh))
      return true
    }
    const glowTexture = (() => {
      const canvas = document.createElement('canvas')
      canvas.width = canvas.height = 96
      const context = canvas.getContext('2d')
      const gradient = context.createRadialGradient(48, 48, 0, 48, 48, 48)
      gradient.addColorStop(0, 'rgba(255,255,255,1)')
      gradient.addColorStop(.3, 'rgba(255,255,255,.35)')
      gradient.addColorStop(1, 'rgba(255,255,255,0)')
      context.fillStyle = gradient
      context.fillRect(0, 0, 96, 96)
      return new THREE.CanvasTexture(canvas)
    })()
    const makeGlow = (color, size = 2.8) => {
      const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTexture, color, transparent: true, opacity: .28, blending: THREE.AdditiveBlending, depthWrite: false }))
      sprite.scale.set(size, size, 1)
      return sprite
    }
    const makeLabel = (node) => {
      const canvas = document.createElement('canvas')
      canvas.width = 800
      canvas.height = 150
      const context = canvas.getContext('2d')
      context.textAlign = 'center'
      context.textBaseline = 'middle'
      context.font = '700 42px Arial'
      context.fillStyle = '#f5f8ff'
      context.shadowColor = 'rgba(0,0,0,.95)'
      context.shadowBlur = 10
      context.fillText(node.name, 400, 48)
      context.shadowBlur = 6
      context.font = '28px Arial'
      context.fillStyle = '#b7c9e4'
      context.fillText(node.ip || node.type || '', 400, 106)
      const texture = new THREE.CanvasTexture(canvas)
      texture.colorSpace = THREE.SRGBColorSpace
      const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: texture, transparent: true, depthTest: false, depthWrite: false }))
      sprite.scale.set(4.2, .78, 1)
      sprite.position.set(0, node.type === 'internet' ? 1.35 : 1.42, 0)
      sprite.userData.labelTexture = texture
      return sprite
    }
    const createModel = (type, color) => {
      const model = new THREE.Group()
      const bodyMaterials = []
      const statusMaterials = []
      const bodyMaterial = () => { const material = new THREE.MeshStandardMaterial({ color, metalness: .55, roughness: .38, emissive: 0x0a2f8a, emissiveIntensity: .55 }); bodyMaterials.push(material); return material }
      const statusMaterial = (options) => { const material = new THREE.MeshBasicMaterial(options); statusMaterials.push(material); return material }
      const edge = (mesh) => mesh.add(new THREE.LineSegments(new THREE.EdgesGeometry(mesh.geometry, 25), new THREE.LineBasicMaterial({ color: 0x7fd6ff, transparent: true, opacity: .85 })))
      const box = (width, height, depth, x, y, z) => { const mesh = new THREE.Mesh(new THREE.BoxGeometry(width, height, depth), bodyMaterial()); mesh.position.set(x, y, z); edge(mesh); model.add(mesh); return mesh }
      const cylinder = (top, bottom, height, x, y, z) => { const mesh = new THREE.Mesh(new THREE.CylinderGeometry(top, bottom, height, 40), bodyMaterial()); mesh.position.set(x, y, z); edge(mesh); model.add(mesh); return mesh }
      const screen = (width, height, x, y, z, rotationX = 0) => { const mesh = new THREE.Mesh(new THREE.PlaneGeometry(width, height), new THREE.MeshBasicMaterial({ color: 0x1a4f9c })); mesh.position.set(x, y, z); mesh.rotation.x = rotationX; model.add(mesh); return mesh }
      if (type === 'laptop') {
        box(1.8, .12, 1.2, 0, .26, .1)
        const display = box(1.8, 1.1, .07, 0, .87, -.5)
        display.rotation.x = -.3
        screen(1.6, .9, 0, .87, -.45, -.3)
      } else if (type === 'server') {
        for (let index = 0; index < 3; index += 1) {
          const rack = box(1.35, .42, 1, 0, .42 + index * .5, 0)
          const led = new THREE.Mesh(new THREE.BoxGeometry(.09, .09, .02), new THREE.MeshBasicMaterial({ color: index === 1 ? 0xffb84d : 0x3ddc97 }))
          led.position.set(-.5, rack.position.y, .51)
          model.add(led)
          const secondLed = led.clone()
          secondLed.material = led.material.clone()
          secondLed.material.color.set(0x4cc9f0)
          secondLed.position.x = -.3
          model.add(secondLed)
        }
      } else if (type === 'desktop') {
        box(2, 1.2, .1, 0, 1.25, 0)
        screen(1.8, 1, 0, 1.25, .06)
        box(.12, .5, .12, 0, .5, 0)
        box(.9, .06, .55, 0, .27, 0)
      } else if (type === 'database') {
        for (let index = 0; index < 3; index += 1) cylinder(.8, .8, .4, 0, .45 + index * .48, 0)
      } else if (type === 'mobile') {
        box(.75, 1.35, .1, 0, 1, 0)
        screen(.62, 1.15, 0, 1, .06)
        model.rotation.y = .5
      } else if (type === 'globe') {
        const globe = new THREE.Mesh(new THREE.SphereGeometry(1.05, 32, 24), bodyMaterial())
        globe.material.color.set(0x10285e)
        globe.material.emissive.set(0x0b2f78)
        globe.material.emissiveIntensity = .7
        model.add(globe)
        model.add(new THREE.Mesh(new THREE.SphereGeometry(1.14, 18, 12), new THREE.MeshBasicMaterial({ color: 0x4cc9f0, wireframe: true, transparent: true, opacity: .55 })))
        const orbit = new THREE.Mesh(new THREE.TorusGeometry(1.75, .02, 8, 96), new THREE.MeshBasicMaterial({ color: 0xffb84d, transparent: true, opacity: .8 }))
        orbit.rotation.x = 1.2
        model.add(orbit)
      } else if (type === 'hub') {
        const hub = new THREE.Mesh(new THREE.IcosahedronGeometry(1.05, 2), bodyMaterial())
        hub.material.color.set(color)
        hub.material.emissive.set(color)
        hub.material.emissiveIntensity = .75
        model.add(hub)
        model.add(new THREE.Mesh(new THREE.IcosahedronGeometry(1.14, 2), statusMaterial({ color, wireframe: true, transparent: true, opacity: .68 })))
        const halo = new THREE.Mesh(new THREE.TorusGeometry(1.72, .04, 10, 112), statusMaterial({ color, transparent: true, opacity: .85 }))
        halo.rotation.set(1.25, .12, .1)
        model.add(halo)
        const orbitA = new THREE.Mesh(new THREE.TorusGeometry(1.42, .03, 10, 112), statusMaterial({ color, transparent: true, opacity: .68 }))
        orbitA.rotation.set(.58, .2, .35)
        model.add(orbitA)
        const orbitB = new THREE.Mesh(new THREE.TorusGeometry(1.58, .025, 10, 112), statusMaterial({ color, transparent: true, opacity: .58 }))
        orbitB.rotation.set(1.02, -.45, -.15)
        model.add(orbitB)
        const equator = new THREE.Mesh(new THREE.TorusGeometry(1.18, .045, 10, 112), statusMaterial({ color, transparent: true, opacity: .78 }))
        equator.rotation.x = Math.PI / 2
        model.add(equator)
      } else box(1.45, .92, .55, 0, .45, 0)
      model.userData.bodyMaterials = bodyMaterials
      model.userData.statusMaterials = statusMaterials
      return model
    }
    const serializable = (mesh) => ({ id: mesh.userData.id, name: mesh.userData.name, ip: mesh.userData.ip, mac: mesh.userData.mac, os: mesh.userData.os, services: mesh.userData.services, criticality: mesh.userData.criticality, type: mesh.userData.type, status: mesh.userData.status, confidence: mesh.userData.confidence, sent: mesh.userData.sent, received: mesh.userData.received, threats: mesh.userData.threats })
    const highDensity = visualGraph.nodes.length > 120
    const labelBudget = visualGraph.nodes.length > 70 ? 24 : visualGraph.nodes.length > 35 ? 36 : visualGraph.nodes.length
    const labelPriority = (node) => (node.status === 'Malicious' ? 100 : node.status === 'Suspicious' ? 80 : node.status === 'Vulnerable' ? 70 : 0) + (node.type === 'device' ? 20 : node.type === 'external' ? 15 : 0)
    const labelNodeIds = new Set(visualGraph.nodes.slice().sort((a, b) => labelPriority(b) - labelPriority(a)).slice(0, labelBudget).map((node) => node.id))
    visualGraph.nodes.forEach((node) => {
      const kind = nodeKind(node)
      const infectedNode = node.status === 'Malicious'
      const bodyColor = infectedNode ? 0xff2222 : node.status === 'Suspicious' ? 0xffa726 : node.status === 'Vulnerable' ? 0xb46cff : node.status === 'Unknown' ? 0x72809a : 0x2b5fd9
      const mesh = createModel(kind, bodyColor)
      mesh.position.set(...node.pos)
      if (kind === 'hub') mesh.position.y += 2.35
      const statusColor = infectedNode ? 0xff5c6c : node.status === 'Suspicious' ? 0xffb84d : node.status === 'Vulnerable' ? 0xb28dff : 0x3ddc97
      const platform = kind === 'globe' ? null : new THREE.Mesh(new THREE.CylinderGeometry(1.35, 1.5, .16, 56), new THREE.MeshStandardMaterial({ color: 0x0b1530, metalness: .6, roughness: .5, emissive: 0x0a1a3c, emissiveIntensity: .6 }))
      if (platform) { platform.position.y = .08; mesh.add(platform) }
      const statusRing = kind === 'globe' ? null : new THREE.Mesh(new THREE.RingGeometry(1.05, 1.24, 64), new THREE.MeshBasicMaterial({ color: statusColor, transparent: true, opacity: .95, side: THREE.DoubleSide }))
      if (statusRing) { statusRing.rotation.x = -Math.PI / 2; statusRing.position.y = kind === 'hub' ? 0 : .17; mesh.add(statusRing) }
      const outerRing = kind === 'globe' ? null : new THREE.Mesh(new THREE.RingGeometry(1.75, 1.8, 64), new THREE.MeshBasicMaterial({ color: statusColor, transparent: true, opacity: .35, side: THREE.DoubleSide }))
      if (outerRing) { outerRing.rotation.x = -Math.PI / 2; outerRing.position.y = kind === 'hub' ? 0 : .05; mesh.add(outerRing) }
      const vulnRing = node.status === 'Vulnerable' ? new THREE.Mesh(new THREE.RingGeometry(2.05, 2.14, 64), new THREE.MeshBasicMaterial({ color: 0xb28dff, transparent: true, opacity: .9, side: THREE.DoubleSide })) : null
      if (vulnRing) { vulnRing.rotation.x = -Math.PI / 2; vulnRing.position.y = .06; mesh.add(vulnRing) }
      const glow = makeGlow(bodyColor, kind === 'globe' ? 7 : kind === 'hub' ? 5.8 : 5.5)
      glow.position.y = kind === 'globe' || kind === 'hub' ? 0 : .9
      mesh.add(glow)
      const label = null
      const selectionRing = new THREE.Mesh(new THREE.RingGeometry(1.95, 2.03, 64), new THREE.MeshBasicMaterial({ color: 0x4cc9f0, transparent: true, opacity: selectedRef.current?.id === node.id ? .9 : 0, side: THREE.DoubleSide }))
      selectionRing.rotation.x = -Math.PI / 2
      selectionRing.position.y = kind === 'hub' ? 0 : .12
      const infectedRing = infectedNode ? new THREE.Mesh(new THREE.RingGeometry(1.25, 1.31, 48), new THREE.MeshBasicMaterial({ color: 0xff3b55, transparent: true, opacity: .7, side: THREE.DoubleSide })) : null
      if (infectedRing) { infectedRing.rotation.x = -Math.PI / 2; infectedRing.position.y = kind === 'hub' ? 0 : .12; mesh.add(infectedRing) }
      if (label) mesh.add(label)
      mesh.add(selectionRing)
      mesh.userData = { ...node, kind, baseY: mesh.position.y, status: node.status || 'Normal', infected: infectedNode, level: node.status === 'Malicious' ? 2 : node.status === 'Suspicious' ? 1 : 0, timer: 0, sent: 0, received: 0, threats: 0, bodyMaterials: mesh.userData.bodyMaterials || [], statusMaterials: mesh.userData.statusMaterials || [], glow, label, selectionRing, infectedRing, statusRing, outerRing, vulnRing }
      mesh.traverse((child) => { child.userData.nodeId = node.id })
      scene.add(mesh)
      nodeMap[node.id] = mesh
      nodeMap[normalized(node.name)] = mesh
      if (node.ip) nodeMap[normalized(node.ip)] = mesh
      nodeList.push(mesh)
    })
    const labelItems = []
    if (labelsHost.current) {
      labelsHost.current.replaceChildren()
      visualGraph.nodes.forEach((node) => {
        const label = document.createElement('button')
        label.type = 'button'
        label.className = `attack-network-label ${statusClass(node.status)}`
        label.setAttribute('aria-label', `${node.name}${node.ip ? ` ${node.ip}` : ''}, ${statusLabel(node.status)}`)
        const dot = document.createElement('i')
        const name = document.createElement('span')
        const ip = document.createElement('small')
        dot.className = 'attack-network-label-dot'
        name.textContent = node.name
        ip.textContent = node.ip || node.type || ''
        label.append(dot, name, ip)
        if (!labelNodeIds.has(node.id)) label.style.display = 'none'
        label.addEventListener('click', () => { const mesh = nodeMap[node.id]; if (mesh) focusNodeRef.current(node) })
        labelsHost.current.append(label)
        if (nodeMap[node.id]) nodeMap[node.id].userData.networkLabel = label
        labelItems.push({ node, mesh: nodeMap[node.id], label })
      })
    }
    const placeNetworkLabels = () => {
      const width = host.clientWidth
      const height = host.clientHeight
      const projected = new THREE.Vector3()
      labelItems.forEach(({ node, mesh, label }) => {
        if (!mesh || !width || !height) return
        const kind = mesh.userData.kind
        projected.set(mesh.position.x, mesh.position.y + (kind === 'globe' ? 1.55 : kind === 'hub' ? 2.35 : 1.75), mesh.position.z).project(camera)
        const hidden = projected.z > 1 || projected.x < -1.15 || projected.x > 1.15 || projected.y < -1.15 || projected.y > 1.15
        label.style.visibility = hidden ? 'hidden' : 'visible'
        label.style.transform = `translate(${Math.round((projected.x * .5 + .5) * width)}px,${Math.round((-projected.y * .5 + .5) * height)}px) translate(-50%,-50%)`
        label.setAttribute('aria-pressed', String(selected?.id === node.id))
      })
    }
    const baseLink = new THREE.Color(0x2a6fb0)
    const linkColor = { normal: new THREE.Color(0x3ddc97), suspicious: new THREE.Color(0xffb84d), malicious: new THREE.Color(0xff5c6c), path: new THREE.Color(0xff5c6c), selected: new THREE.Color(0x5eeaff) }
    const linkAnchor = (mesh) => mesh.position.clone().add(new THREE.Vector3(0, mesh.userData.kind === 'globe' ? 0 : mesh.userData.kind === 'hub' ? .8 : .9, 0))
    const makeCurve = (a, b) => { const control = a.clone().lerp(b, .5); control.y += Math.max(.65, a.distanceTo(b) * .12); return new THREE.QuadraticBezierCurve3(a.clone(), control, b.clone()) }
    const tube = (curve, radius, material) => new THREE.Mesh(new THREE.TubeGeometry(curve, 24, radius, 6, false), material)
    const nodeForLink = (value) => nodeMap[value] || nodeMap[normalized(value)]
    visualGraph.links.forEach((link) => {
      const source = nodeForLink(link.a)
      const target = nodeForLink(link.b)
      if (!source || !target) return
      const curve = makeCurve(linkAnchor(source), linkAnchor(target))
      const coreMaterial = new THREE.MeshBasicMaterial({ color: baseLink.clone(), transparent: true, opacity: .7 })
      const haloMaterial = new THREE.MeshBasicMaterial({ color: baseLink.clone(), transparent: true, opacity: .08, blending: THREE.AdditiveBlending })
      const core = link.type === 'path' ? null : tube(curve, .025, coreMaterial)
      const halo = link.type === 'path' ? null : tube(curve, .09, haloMaterial)
      if (link.type === 'path') {
        const dashMaterial = new THREE.MeshBasicMaterial({ color: 0xff5c6c, transparent: true, opacity: .95 })
        for (let index = 0; index < 26; index += 1) {
          const point = (index + .5) / 26
          const dash = new THREE.Mesh(new THREE.CylinderGeometry(.04, .04, .26, 6), dashMaterial)
          dash.position.copy(curve.getPoint(point))
          dash.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), curve.getTangent(point).normalize())
          scene.add(dash)
        }
      } else scene.add(core, halo)
      const selectedLink = Boolean(selectedRef.current?.id && (source.userData.id === selectedRef.current.id || target.userData.id === selectedRef.current.id))
      linkObjects.push({ a: source, b: target, curve, core, halo, heat: link.type === 'suspicious' || link.type === 'path' || link.type === 'malicious' ? .6 : 0, baseType: link.type || 'normal', type: selectedLink ? 'selected' : link.type || 'normal', selected: selectedLink })
    })
    const findLink = (from, to) => linkObjects.find((link) => (link.a === from && link.b === to) || (link.a === to && link.b === from))
    const addPacket = (type, from, to) => {
      if (!from || !to) return
      const link = findLink(from, to)
      if (!link) return
      const packet = new THREE.Mesh(new THREE.SphereGeometry(type === 'malicious' ? .18 : .12, 12, 12), new THREE.MeshBasicMaterial({ color: COLORS[type] }))
      packet.position.copy(link.curve.getPoint(0))
      packet.add(makeGlow(COLORS[type], 1))
      scene.add(packet)
      packets.push({ mesh: packet, curve: link.curve, type, progress: 0, direction: from === link.a ? 1 : -1, speed: type === 'malicious' ? .1 : .085 + Math.random() * .09 })
      if (link) { link.heat = Math.max(link.heat, type === 'malicious' ? 1 : .6); link.type = link.baseType === 'path' ? 'path' : type }
    }
    const pushLocalLog = (type, from, to) => {
      const entry = { time: Date.now(), type, fromName: from.userData.name, fromIp: from.userData.ip, toName: to.userData.name, toIp: to.userData.ip, title: `${type} simulated connection` }
      setLogs((current) => [entry, ...current].slice(0, 300))
      if (type === 'malicious') { alertTargetRef.current = { id: from.userData.id, name: from.userData.name, ip: from.userData.ip }; setAlerts((current) => [entry, ...current].slice(0, 50)); setAlert(`Malicious traffic detected from ${from.userData.ip} (${from.userData.name})`) }
    }
    const spawnLocal = () => {
      const roll = Math.random()
      const type = roll < .8 ? 'normal' : roll < .95 ? 'suspicious' : 'malicious'
      const link = linkObjects[Math.floor(Math.random() * linkObjects.length)]
      if (!link) return
      let from = link.a
      let to = link.b
      if (Math.random() < .5) [from, to] = [to, from]
      if (type === 'malicious') {
        const infected = nodeMap[normalized('Infected')]
        if (infected && (link.a === infected || link.b === infected)) { from = infected; to = link.a === infected ? link.b : link.a }
      }
      addPacket(type, from, to)
      total += 1; windowTotal += 1
      setCounts((current) => ({ ...current, [type]: current[type] + 1 }))
      from.userData.sent += 1; to.userData.received += 1
      if (type !== 'normal') { windowThreat += 1; from.userData.threats += 1; from.userData.status = type === 'malicious' ? 'Malicious' : 'Suspicious'; from.userData.level = type === 'malicious' ? 2 : 1; from.userData.timer = type === 'malicious' ? 18 : 10; setSelected((current) => current?.id === from.userData.id ? { ...current, status: from.userData.status, threats: from.userData.threats } : current); if (type === 'malicious') { alertTargetRef.current = { id: from.userData.id, name: from.userData.name, ip: from.userData.ip }; setAlert(`Malicious traffic detected from ${from.userData.ip} (${from.userData.name})`) } }
      pushLocalLog(type, from, to)
    }
    if (mode === 'realtime' && backend.connected) {
      backendEvents.slice(-30).forEach((event) => {
        const from = nodeMap[normalized(event.src_ip)] || nodeMap[normalized(event.host)]
        const to = nodeMap[normalized(event.dest_ip)] || nodeList.find((node) => node !== from)
        const type = classifyEvent(event)
        addPacket(type, from, to)
      })
    } else if (mode === 'simulation') {
      for (let index = 0; index < 4; index += 1) spawnLocal()
    }
    const raycaster = new THREE.Raycaster()
    const pointer = new THREE.Vector2()
    let downX = 0
    let downY = 0
    const pick = (event) => {
      const rect = renderer.domElement.getBoundingClientRect()
      pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1
      pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1
      raycaster.setFromCamera(pointer, camera)
      const hit = raycaster.intersectObjects(nodeList, true).find((item) => item.object.userData.nodeId)
      return hit ? nodeMap[hit.object.userData.nodeId] : null
    }
    const click = (event) => {
      if (Math.abs(event.clientX - downX) > 5 || Math.abs(event.clientY - downY) > 5) return
      const mesh = pick(event)
      if (mesh) showSelectedNode(serializable(mesh))
    }
    let hoverFrame = 0
    let pendingHoverEvent = null
    const move = (event) => {
      pendingHoverEvent = event
      if (hoverFrame) return
      hoverFrame = window.requestAnimationFrame(() => {
        hoverFrame = 0
        const currentEvent = pendingHoverEvent
        pendingHoverEvent = null
        if (currentEvent) renderer.domElement.style.cursor = pick(currentEvent) ? 'pointer' : ''
      })
    }
    const pointerDown = (event) => { downX = event.clientX; downY = event.clientY }
    renderer.domElement.addEventListener('pointerdown', pointerDown)
    renderer.domElement.addEventListener('click', click)
    renderer.domElement.addEventListener('pointermove', move)
    cleanupFns.push(() => { renderer.domElement.removeEventListener('pointerdown', pointerDown); renderer.domElement.removeEventListener('click', click); renderer.domElement.removeEventListener('pointermove', move); if (hoverFrame) window.cancelAnimationFrame(hoverFrame) })
    const resize = () => { const width = host.clientWidth; const height = host.clientHeight; if (!width || !height) return; camera.aspect = width / height; camera.updateProjectionMatrix(); renderer.setSize(width, height) }
    const observer = new ResizeObserver(resize)
    observer.observe(host)
    cleanupFns.push(() => observer.disconnect())
    let active = true
    let animationFrame = 0
    const animate = (now) => {
      if (!active) return
      const delta = Math.min((now - last) / 1000, .1)
      last = now
      if (!pausedRef.current) {
        elapsed += delta; spawnTimer += delta; statsTimer += delta
        if (mode === 'simulation' && spawnTimer > 1.3) { spawnTimer = 0; spawnLocal() }
        packets.forEach((packet, index) => { packet.progress += packet.speed * delta * packet.direction; if (packet.progress >= 1) packet.progress -= 1; if (packet.progress < 0) packet.progress += 1; packet.mesh.position.copy(packet.curve.getPoint(packet.progress)) })
        nodeList.forEach((node) => {
          if (node.userData.level) { node.userData.timer -= delta; if (node.userData.timer <= 0) { node.userData.level = 0; node.userData.status = 'Normal'; setSelected((current) => current?.id === node.userData.id ? { ...current, status: 'Normal' } : current) } }
          if (node.userData.kind === 'hub') {
            node.position.y = node.userData.baseY
            node.rotation.y += delta * .42
          }
          const malicious = node.userData.status === 'Malicious'
          const suspicious = node.userData.status === 'Suspicious'
          const infected = malicious || node.userData.infected
          const liveStatusColor = infected ? 0xff5c6c : suspicious ? 0xffb84d : node.userData.status === 'Vulnerable' ? 0xb28dff : 0x3ddc97
          const beat = infected ? Math.pow(Math.max(0, Math.sin(elapsed * 7)), 10) : 0
          const pulse = 1 + beat * .28
          node.scale.setScalar(pulse)
          node.userData.glow.scale.set(2.8 * pulse, 2.8 * pulse, 1)
          const vulnerable = node.userData.status === 'Vulnerable'
          const unknown = node.userData.status === 'Unknown'
          const body = infected ? 0xff2222 : suspicious ? 0xffa726 : vulnerable ? 0xb46cff : unknown ? 0x72809a : 0x22aaff
          const glow = infected ? 0xaa0000 : suspicious ? 0x8a4b00 : vulnerable ? 0x5b2c80 : unknown ? 0x39495e : 0x0a4a88
          node.userData.bodyMaterials?.forEach((material) => { material.color.lerp(new THREE.Color(body), Math.min(1, delta * 5)); material.emissive.lerp(new THREE.Color(glow), Math.min(1, delta * 5)) })
          node.userData.statusMaterials?.forEach((material) => material.color.lerp(new THREE.Color(body), Math.min(1, delta * 7)))
          node.userData.glow.material.color.lerp(new THREE.Color(body), Math.min(1, delta * 5))
          node.userData.glow.material.opacity = infected ? .5 + beat * .4 : suspicious ? .36 : vulnerable ? .42 : .28
          if (node.userData.statusRing) node.userData.statusRing.material.color.lerp(new THREE.Color(liveStatusColor), Math.min(1, delta * 8))
          if (node.userData.outerRing) node.userData.outerRing.material.color.lerp(new THREE.Color(liveStatusColor), Math.min(1, delta * 8))
          if (node.userData.networkLabel) { node.userData.networkLabel.className = `attack-network-label ${statusClass(node.userData.status)}`; const dot = node.userData.networkLabel.firstChild; if (dot) dot.className = `attack-network-label-dot ${statusClass(node.userData.status)}` }
          if (node.userData.selectionRing) { node.userData.selectionRing.material.opacity = selectedRef.current?.id === node.userData.id ? .85 : 0; node.userData.selectionRing.rotation.z += delta * .35 }
          if (node.userData.infectedRing) { node.userData.infectedRing.rotation.z -= delta * .55; node.userData.infectedRing.material.opacity = .45 + beat * .45 }
        })
        linkObjects.forEach((link) => { link.heat = Math.max(0, link.heat - delta * .06); const color = baseLink.clone().lerp(linkColor[link.type] || linkColor.normal, Math.min(1, link.heat * 1.5)); if (link.core && link.halo) { link.core.material.color.copy(color); link.halo.material.color.copy(color); link.halo.material.opacity = link.selected ? .4 : link.type === 'path' ? .28 + link.heat * .35 : .08 + link.heat * .35 } })
        stars.rotation.y += delta * .02
        if (statsTimer >= 1) { const threatRate = windowTotal ? (windowThreat / windowTotal) * 100 : 0; setStats({ total, pps: windowTotal, rate: threatRate, level: threatRate < 12 ? 'LOW' : threatRate < 28 ? 'MEDIUM' : 'HIGH' }); setHistory((current) => [...current, { total: windowTotal, threat: windowThreat }].slice(-30)); windowTotal = 0; windowThreat = 0; statsTimer = 0 }
      }
      controls.update()
      placeNetworkLabels()
      renderer.render(scene, camera)
      animationFrame = requestAnimationFrame(animate)
    }
    animationFrame = requestAnimationFrame(animate)
    cleanupFns.push(() => cancelAnimationFrame(animationFrame))
    cleanupFns.push(() => { cameraViewRef.current = { position: camera.position.toArray(), target: controls.target.toArray() }; active = false; cancelAnimationFrame(animationFrame); window.clearTimeout(resumeTimer); autoRotateControlRef.current = null; zoomViewRef.current = () => {}; focusNodeRef.current = () => {}; scene.clear(); renderer.dispose(); host.replaceChildren(); labelsHost.current?.replaceChildren() })
    return () => cleanupFns.forEach((cleanup) => cleanup())
  }, [backend.connected, backendEvents, mode, showSelectedNode, visualGraph])

  useEffect(() => {
    if (!selected?.id) return undefined
    const frame = window.requestAnimationFrame(() => focusNodeRef.current(selected))
    return () => window.cancelAnimationFrame(frame)
  }, [selected?.id])

  const togglePause = () => { pausedRef.current = !pausedRef.current; setPaused((value) => !value) }
  const modeLabel = mode === 'realtime' ? 'AUTHORIZED LIVE' : 'SIMULATION · LAB DATA'
  const connectionLabel = mode === 'simulation' ? 'SIMULATION ACTIVE' : backend.connected ? (backend.websocket ? 'LIVE API + WS' : 'API CONNECTED') : 'LOCAL FALLBACK'
  const availableTabs = new Set(['logs'])
  if (backend.connected && (timeline.length || backendEvents.length)) availableTabs.add('timeline')
  if (backend.connected && incidents.length) availableTabs.add('incidents')
  if (backend.connected && vulnerabilities.length) availableTabs.add('vulnerabilities')
  if (backend.connected && attackPaths.path_count) availableTabs.add('paths')
  if (backend.connected && cases.length) availableTabs.add('cases')
  if (backend.connected && remediation.length) availableTabs.add('remediation')
  if (mode === 'simulation' || simulations.length) availableTabs.add('training')
  const liveMode = mode === 'realtime' && backend.connected
  const visibleStats = liveMode ? liveThreatStats : mode === 'simulation' ? stats : { total: 0, pps: 0, rate: 0, level: 'LOW', counts: EMPTY_COUNTS }
  const currentCounts = visibleStats.counts || displayCounts
  const observedCount = Math.max(1, Number(currentCounts.normal || 0) + Number(currentCounts.suspicious || 0) + Number(currentCounts.malicious || 0))
  const maliciousRisk = Number(currentCounts.malicious || 0) > 0 ? Math.min(100, 70 + Math.round((Number(currentCounts.malicious) / observedCount) * 30)) : 0
  const suspiciousRisk = Number(currentCounts.suspicious || 0) > 0 ? Math.min(69, 30 + Math.round((Number(currentCounts.suspicious) / observedCount) * 39)) : 0
  const monitoringScore = Math.max(maliciousRisk, suspiciousRisk)
  const riskLevel = monitoringScore >= 70 ? 'HIGH' : monitoringScore >= 30 ? 'MEDIUM' : 'LOW'
  const visibleTotal = liveMode ? (traffic?.total_events ?? liveThreatStats.total) : mode === 'simulation' ? stats.total : 0
  const visibleRate = liveMode ? liveThreatStats.eventsPerSecond : mode === 'simulation' ? stats.pps : 0
  const toggleAutoRotate = () => {
    const next = !autoRotateRef.current
    autoRotateRef.current = next
    setAutoRotate(next)
    if (autoRotateControlRef.current) autoRotateControlRef.current.autoRotate = next
  }

  return <div className="attack-app"><header className="attack-topbar"><div className="attack-top-brand"><div className="attack-logo"><Shield size={21} /></div><div><b>NEXTGUARD AI</b><span>3D SECURITY INTELLIGENCE</span></div></div><div className="attack-top-mode"><button className={mode === 'realtime' ? 'active' : ''} aria-pressed={mode === 'realtime'} onClick={() => setMode('realtime')}><Wifi size={14} /> Live API</button><button className={mode === 'simulation' ? 'active' : ''} aria-pressed={mode === 'simulation'} onClick={() => setMode('simulation')}><Activity size={14} /> Simulation</button></div><div className={'attack-top-api ' + (mode === 'simulation' || backend.connected ? 'online' : 'offline')}><span className="attack-status-dot" />{connectionLabel}<button onClick={analyzeNow} title="Analyze current mode"><RefreshCw size={14} /></button></div><label className="attack-top-search"><Search size={15} /><input value={query} onChange={(event) => { setQuery(event.target.value); setTopologyQuery(event.target.value) }} placeholder="Find node, IP or severity" /></label><div className={'attack-top-level ' + visibleStats.level.toLowerCase()}><small>Threat level</small><strong>{visibleStats.level}</strong></div><span className="attack-top-lab">{mode === 'realtime' ? 'AUTHORIZED LIVE' : 'LAB'}</span></header><div className="attack-viz-shell">
    <aside className="attack-sidebar">
      {((mode === 'simulation') || backend.connected) && alert && <section className="attack-left-alert" role="alert"><div className="attack-eyebrow">Alert</div><p>{alert}</p><div className="attack-alert-actions"><button className="attack-danger-btn" onClick={() => { const target = alertTargetRef.current || visualGraph.nodes.find((node) => node.status === 'Malicious') || visualGraph.nodes.find((node) => normalized(node.name).includes('infected')); if (target) focusNodeRef.current(target) }}>View on map</button><button className="attack-ghost-btn" onClick={() => { setLogs([]); setAlerts([]); setAlert(null); alertTargetRef.current = null }}>Dismiss</button></div></section>}
      <section className="attack-left-card attack-traffic-card"><div className="attack-eyebrow">Traffic mix</div><div className="attack-mix"><div><span><i className="ok" />Normal</span><b>{displayCounts.normal}</b></div><div><span><i className="warn" />Suspicious</span><b>{displayCounts.suspicious}</b></div><div><span><i className="bad" />Malicious</span><b>{displayCounts.malicious}</b></div></div><div className="attack-stack"><i className="ok" style={{ flexGrow: displayCounts.normal }} /><i className="warn" style={{ flexGrow: displayCounts.suspicious }} /><i className="bad" style={{ flexGrow: displayCounts.malicious }} /></div></section>
      <section className="attack-left-card attack-risk-card"><div className="attack-two"><div><div className="attack-eyebrow">Risk score <span className={`attack-risk-level ${riskLevel.toLowerCase()}`}>{riskLevel}</span></div><div className="attack-big">{monitoringScore} <small>/ 100</small></div><div className="attack-meter"><i className={riskLevel.toLowerCase()} style={{ width: `${Math.min(100, Number(monitoringScore) || 0)}%` }} /></div></div><div><div className="attack-eyebrow">Events / sec</div><div className="attack-big">{Number(visibleRate).toFixed(1)}</div><div className="attack-sub"><b>{visibleTotal}</b> total events</div></div></div></section>
      <section className="attack-left-card attack-traffic-legend" aria-label="Traffic colors"><div className="attack-legend-list"><div><span className="ok" />Normal traffic</div><div><span className="warn" />Suspicious traffic</div><div><span className="bad" />Malicious traffic</div></div></section>
    </aside>
    <main className="attack-stage">
      <div className="attack-topology-toolbar"><span>3D FILTER</span>{['all', 'devices', 'services', 'critical'].map((value) => <button key={value} className={topologyFilter === value ? 'active' : ''} onClick={() => setTopologyFilter(value)}>{value[0].toUpperCase() + value.slice(1)}</button>)}<input value={topologyQuery} onChange={(event) => setTopologyQuery(event.target.value)} placeholder="Find node or service" /><span className={'attack-toolbar-live ' + (paused ? 'paused' : '')}><i />{paused ? 'PAUSED' : mode === 'realtime' ? 'LIVE' : 'LAB'}</span><button className="attack-toolbar-btn" onClick={togglePause}>{paused ? <Play size={14} /> : <Pause size={14} />} {paused ? 'Resume' : 'Pause'}</button><button className="attack-toolbar-btn" onClick={() => resetViewRef.current()}>Reset view</button></div>
      <div ref={canvasHost} className="attack-canvas" />
      <div ref={labelsHost} className="attack-network-labels" aria-label="Network device labels" />
      {selectedGraphNode && <section className="attack-network-card attack-glass" aria-live="polite"><div className="attack-eyebrow">Selected device</div><h2>{selectedGraphNode.name} <span className={`attack-pill ${statusClass(selectedGraphNode.status)}`}>{statusLabel(selectedGraphNode.status)}</span>{selectedGraphNode.status === 'Vulnerable' && <span className="attack-pill vulnerable">Vulnerable asset</span>}</h2><dl className="attack-network-grid"><div><dt>IP address</dt><dd>{selectedGraphNode.ip || '—'}</dd></div><div><dt>Device type</dt><dd>{selectedGraphNode.type || 'device'}</dd></div></dl><div className="attack-network-connections"><div className="attack-eyebrow">Connected to</div>{selectedConnections.length ? selectedConnections.map(({ node, relation }) => <button key={node.id} type="button" onClick={() => showSelectedNode(node)}><span><i className={`attack-network-label-dot ${statusClass(node.status)}`} />{node.name}</span><small>{relation}</small></button>) : <p>No observed connections.</p>}</div></section>}
      <button className="attack-toggle" onClick={togglePause}>{paused ? <Play size={14} /> : <Pause size={14} />} {paused ? 'Play' : 'Pause'}</button><button className="attack-reset" onClick={() => resetViewRef.current()}>Reset view</button>
    </main>
    <aside className="attack-panel"><section className="attack-detection-panel">
      <div className="attack-panel-title"><h2>Threat detection</h2><span className="attack-mode-badge">{mode === 'realtime' ? 'REALTIME' : 'LAB'}</span></div>
      <div className="attack-filters">{['all', 'normal', 'suspicious', 'malicious'].map((value) => <button key={value} className={filter === value ? 'active' : ''} onClick={() => setFilter(value)}>{value[0].toUpperCase() + value.slice(1)}</button>)}</div>
      <div className="attack-search"><Search size={14} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search IP, node, severity..." /></div>
      <div className="attack-tabs"><button className={activeTab === 'logs' ? 'active' : ''} onClick={() => setActiveTab('logs')}>Live logs</button>{availableTabs.has('timeline') && <button className={activeTab === 'timeline' ? 'active' : ''} onClick={() => setActiveTab('timeline')}>Timeline</button>}{availableTabs.has('incidents') && <button className={activeTab === 'incidents' ? 'active' : ''} onClick={() => setActiveTab('incidents')}>Incidents ({incidents.length})</button>}{availableTabs.has('vulnerabilities') && <button className={activeTab === 'vulnerabilities' ? 'active' : ''} onClick={() => setActiveTab('vulnerabilities')}>Exposure ({vulnerabilities.length})</button>}{availableTabs.has('paths') && <button className={activeTab === 'paths' ? 'active' : ''} onClick={() => setActiveTab('paths')}>Paths ({attackPaths.path_count || 0})</button>}{availableTabs.has('cases') && <button className={activeTab === 'cases' ? 'active' : ''} onClick={() => setActiveTab('cases')}>Cases ({cases.length})</button>}{availableTabs.has('remediation') && <button className={activeTab === 'remediation' ? 'active' : ''} onClick={() => setActiveTab('remediation')}>Remediation ({remediation.length})</button>}{availableTabs.has('training') && <button className={activeTab === 'training' ? 'active' : ''} onClick={() => setActiveTab('training')}>Training ({simulations.length})</button>}</div>
      {activeTab === 'logs' && <ul className="attack-list">{shownLogs.map((item, index) => <li key={`${item.time}-${index}`} className={'attack-log ' + item.type}><time>{new Date(item.time).toLocaleTimeString([], { hour12: false })}</time><div className="attack-log-content"><div className="attack-log-line"><b>{item.type.toUpperCase()}</b><em>{item.fromIp} → {item.toIp}</em></div><small>{item.source || item.title}</small></div></li>)}{!shownLogs.length && <li className="attack-empty">No telemetry records match.</li>}</ul>}
      {activeTab === 'timeline' && <ul className="attack-list">{shownTimeline.map((item, index) => <li key={item.id || index} className={'attack-timeline-row ' + classifyEvent(item)}><div><b>{String(item.source || 'sensor').toUpperCase()}</b><span>{new Date(item.timestamp || Date.now()).toLocaleTimeString([], { hour12: false })}</span></div><strong>{item.title || item.type || 'Security event'}</strong><small>{item.host || item.src_ip || 'unknown host'} {item.dest_ip ? `→ ${item.dest_ip}` : ''}{item.port ? `:${item.port}` : ''} · {item.protocol || 'protocol unknown'}</small></li>)}{!shownTimeline.length && <li className="attack-empty">No timeline events match.</li>}</ul>}
      {activeTab === 'incidents' && <ul className="attack-list">{shownAlerts.map((item, index) => <li key={item.id || index} className="attack-incident-row"><b>{item.severity || 'ALERT'}</b><strong>{item.title}</strong><span>{item.host || 'unknown asset'} · score {item.score ?? '—'}</span><small>{item.investigation_summary || item.classification || 'Analyst review required.'}</small><div className="attack-row-actions"><button onClick={() => openCase(item)}>Open case</button><button onClick={() => setActiveTab('paths')}>Explore path</button></div></li>)}{!shownAlerts.length && <li className="attack-empty">No correlated incidents.</li>}</ul>}
      {activeTab === 'vulnerabilities' && <ul className="attack-list">{shownVulnerabilities.map((item, index) => <li key={item.id || index} className="attack-vuln-row"><b>{String(item.priority || 'unknown').toUpperCase()}</b><strong>{item.cve || item.title || 'Vulnerability finding'}</strong><span>{item.affected_device || 'unknown asset'} · risk {item.risk_score ?? '—'}</span><small>{item.recommendation || item.exposure_reasons?.join(', ') || 'Review finding evidence.'}</small></li>)}{!shownVulnerabilities.length && <li className="attack-empty">No vulnerability findings.</li>}</ul>}
      {activeTab === 'paths' && <ul className="attack-list">{shownPaths.map((path, index) => <li key={path.id || index} className="attack-path-row"><b><Route size={13} /> PATH {index + 1} · RISK {path.risk_score}</b><strong>{(path.nodes || []).map((node) => node.label).join(' → ')}</strong><small>{path.inferred ? 'Inferred from observed relationships and exposure data.' : 'Analyst validated path.'}</small></li>)}{!shownPaths.length && <li className="attack-empty">No inferred attack paths.</li>}</ul>}
      {activeTab === 'cases' && <ul className="attack-list">{cases.filter((item) => `${item.id} ${item.title} ${item.status} ${item.affected_device}`.toLowerCase().includes(query.toLowerCase())).map((item, index) => <li key={item.id || index} className="attack-case-row"><b>{item.status}</b><strong>{item.title}</strong><span>{item.id} · {item.affected_device || 'unassigned'}</span><small>{item.analyst_notes || item.findings || 'No analyst notes yet.'}</small><div className="attack-row-actions"><button onClick={() => updateCase(item, 'Investigating')}>Investigate</button><button onClick={() => updateCase(item, 'Resolved')}>Resolve</button><button onClick={() => viewReport(item)}>Report</button></div></li>)}{!cases.length && <li className="attack-empty">No investigation cases yet. Open one from an incident.</li>}</ul>}
      {activeTab === 'remediation' && <ul className="attack-list">{remediation.filter((item) => `${item.id} ${item.title} ${item.target} ${item.status}`.toLowerCase().includes(query.toLowerCase())).map((item, index) => <li key={item.id || index} className="attack-remediation-row"><b>{String(item.priority || item.status || 'PROPOSED').toUpperCase()}</b><strong>{item.title}</strong><span>{item.target || 'unassigned target'} · {item.status}</span><small>{item.rationale || 'Evidence-backed recommendation requiring analyst approval.'}</small><div className="attack-row-actions">{item.status !== 'Approved' && <button onClick={() => approveRemediation(item)}>Approve</button>}{item.status === 'Approved' && <><button onClick={() => dryRunRemediation(item)}>Dry run</button><button onClick={() => executeRemediation(item)}>Submit adapter</button></>}</div></li>)}{!remediation.length && <li className="attack-empty">No remediation recommendations available.</li>}</ul>}
      {activeTab === 'training' && <div className="attack-training"><div className="attack-training-actions"><button disabled={actionBusy} onClick={runTrainingScenario}><Activity size={13} /> Run controlled scenario</button><label><Database size={13} /> Import PCAP<input type="file" accept=".pcap,.cap,application/octet-stream" onChange={importPcap} /></label></div><div className="attack-training-score"><strong>Evaluation</strong><span>Runs: {evaluation?.run_count ?? 0}</span><span>Precision: {evaluation?.detection_accuracy?.precision == null ? '—' : `${Math.round(evaluation.detection_accuracy.precision * 100)}%`}</span><span>Recall: {evaluation?.detection_accuracy?.recall == null ? '—' : `${Math.round(evaluation.detection_accuracy.recall * 100)}%`}</span></div><ul className="attack-training-list">{simulations.slice(0, 8).map((item, index) => <li key={item.id || index}><strong>{item.name || item.id}</strong><span>{item.label} · {item.status}</span><small>{item.result ? `Detected ${item.result.detected_findings} findings · match ${item.result.ground_truth_match_rate == null ? '—' : `${Math.round(item.result.ground_truth_match_rate * 100)}%`}` : 'Not run'}</small></li>)}{!simulations.length && <li className="attack-empty">No training scenarios yet.</li>}</ul></div>}
      {actionMessage && <div className={'attack-action-message ' + (actionMessage.startsWith('Action failed') || actionMessage.includes('failed') ? 'error' : '')}>{actionBusy ? 'Working…' : actionMessage}</div>}
      <div className="attack-panel-actions"><button onClick={analyzeNow}><RefreshCw size={13} /> Analyze now</button><button onClick={() => { setLogs([]); setAlerts([]); setAlert(null) }}><Trash2 size={13} /> Clear local</button></div>
      </section><section className="attack-node-panel"><div className="attack-eyebrow">Node details</div><div className="attack-node-heading">{selected ? <><h3>{selected.name}</h3><span className={'attack-pill ' + selected.status.toLowerCase()}>{selected.status}</span></> : <h3>No node selected</h3>}</div><div className="attack-details">{selected ? <><p><span>IP address</span><b>{selected.ip || '—'}</b></p><p><span>MAC address</span><b>{selected.mac || '—'}</b></p><p><span>Operating system</span><b>{selected.os || '—'}</b></p><p><span>Device type</span><b>{selected.type || 'device'}</b></p><p><span>Criticality</span><b>{selected.criticality || '—'}</b></p><p><span>Confidence</span><b>{selected.confidence || '—'}</b></p><p><span>Services</span><b>{Array.isArray(selected.services) ? selected.services.join(', ') || '—' : selected.services || '—'}</b></p><p><span>Packets sent</span><b>{selected.sent}</b></p><p><span>Packets received</span><b>{selected.received}</b></p><p><span>Threat events</span><b>{selected.threats}</b></p></> : <p className="attack-empty">Click any labelled device in the 3D view to inspect its evidence context.</p>}</div><div className="attack-footer-status"><ShieldAlert size={13} /> {findings.length} findings · {incidents.length} incidents · {vulnerabilities.length} exposures</div></section>
    </aside>
  </div></div>
}
