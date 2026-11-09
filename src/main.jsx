import React, { useEffect, useMemo, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  Activity, AlertTriangle, ArrowUpRight, Bell, Bot, Box, ChevronDown,
  CircleDot, Cloud, Crosshair, Database, Eye, FileWarning, Gauge,
  Globe2, LayoutDashboard, LockKeyhole, Menu, Network, Radar, Search,
  Server, Settings, ShieldCheck, Sparkles, Target, Users, X, Zap,
  Brain, Filter, GitBranch, PlayCircle, Radio, Route, Trash2, UserRound,
  CheckCircle2, PenLine, CircleX, Shield, Terminal as TerminalIcon, Laptop
} from 'lucide-react'
import './styles.css'
import './twin.css'
import './modules.css'
import './prototype-theme.css'
import './prototype-rail.css'
import './soc-prototype.css'
import './soc-reference-overrides.css'
import './cyberwatch-ui.css'
import { AttackVizDashboard } from './attack-viz-connected.jsx'

const incidents = [
  { id: 'INC-2048', title: 'Lateral movement suspected', host: 'db-prod-01', severity: 'Critical', score: 94, age: '2m ago', source: 'Zeek', color: 'red' },
  { id: 'INC-2047', title: 'Credential spraying pattern', host: 'vpn-gateway', severity: 'High', score: 86, age: '11m ago', source: 'Suricata', color: 'orange' },
  { id: 'INC-2046', title: 'Unexpected outbound beacon', host: 'workstation-442', severity: 'Medium', score: 68, age: '24m ago', source: 'AI Baseline', color: 'yellow' },
  { id: 'INC-2045', title: 'New internet-facing service', host: 'api-edge-02', severity: 'Low', score: 34, age: '41m ago', source: 'OpenVAS', color: 'blue' },
]

const assets = [
  ['db-prod-01', 'Database', '10.42.0.18', 'Critical', '99.9%', 'red'],
  ['api-edge-02', 'Web service', '10.42.1.12', 'High', '99.8%', 'orange'],
  ['vpn-gateway', 'Network', '10.42.0.1', 'High', '100%', 'orange'],
  ['workstation-442', 'Endpoint', '10.42.18.44', 'Medium', '98.2%', 'yellow'],
]

function App() {
  return <AttackVizDashboard />
  const [active, setActive] = useState('Overview')
  const [selected, setSelected] = useState(null)
  const [query, setQuery] = useState('')
  const [isLive, setIsLive] = useState(true)
  const [mode, setMode] = useState('realtime')
  const [showNotifications, setShowNotifications] = useState(false)
  const [activeStage, setActiveStage] = useState(1)
  const [socMode, setSocMode] = useState('live')
  const [replayPlaying, setReplayPlaying] = useState(false)
  const [showSimulationMenu, setShowSimulationMenu] = useState(false)
  const [remediationNotice, setRemediationNotice] = useState('')
  const filteredAssets = useMemo(() => assets.filter((row) => row.join(' ').toLowerCase().includes(query.toLowerCase())), [query])
  useEffect(() => { const navigate = (event) => { const target = { 'Explore twin': 'Security Twin', 'View all': 'Incidents', 'Inventory': 'Assets' }[event.detail]; if (target) setActive(target) }; window.addEventListener('nextguard:navigate', navigate); return () => window.removeEventListener('nextguard:navigate', navigate) }, [])
  const stages = [
    ['1', 'Data Sources', 'Splunk, Zeek, PCAP', 'Telemetry', Database],
    ['2', 'Ingest & Correlate', 'JSON & Cross-Source', 'Assets', Filter],
    ['3', 'Knowledge Graph', 'Asset & Identity Context', 'Security Twin', GitBranch],
    ['4', 'Hybrid Threat AI', 'Adaptive ML Baselines', 'Threat Intelligence', Brain],
    ['5', 'Risk & Attack Path', 'Explainable Blast Radius', 'Attack Paths', Route],
    ['6', '3D Digital Twin', 'Interactive SOC View', 'Security Twin', Box]
  ]
  const stageContent = {
    1: ['Stage 1: Data Sources', 'Splunk / SIEM feeds are connected.', 'Suricata and Zeek telemetry is available.', 'Vulnerability scanners are synchronized.'],
    2: ['Stage 2: JSON Normalization & Correlation', 'Schema validation and timestamp normalization active.', 'Cross-source events are being correlated.'],
    3: ['Stage 3: Asset & Knowledge Graph', 'Devices, services, identities, and dependencies mapped.', 'Confidence levels are preserved for discovered assets.'],
    4: ['Stage 4: Hybrid Threat Detection', 'Adaptive baselines compare behaviour by device and time.', 'Rules, signatures, anomalies, and correlations are active.'],
    5: ['Stage 5: Risk & Attack-Path Analysis', 'Potential entry points and critical targets are ranked.', 'What-if remediation can recalculate the blast radius.'],
    6: ['Stage 6: 3D Digital Twin Interaction', 'Drag to rotate, scroll to zoom, and click any device.', 'Live and replayed network activity share the same twin.']
  }
  const stage = stageContent[activeStage]
  const navigateStage = (number, target) => { setActiveStage(number); if (number > 1) setActive(target) }
  const runThreat = (kind) => { setActiveStage(kind === 'ransomware' ? 5 : 4); setActive(kind === 'ransomware' ? 'Attack Paths' : 'Threat Intelligence') }
  const setReferenceMode = (nextMode) => { setSocMode(nextMode); if (nextMode === 'live') setActive('Overview'); if (nextMode === 'exposure') setActive('Attack Paths'); if (nextMode === 'investigate') setActive('Incidents'); if (nextMode === 'replay') setActive('Simulation') }
  const approveRemediation = (action) => { setRemediationNotice(action === 'approve' ? 'Approved response queued for analyst review.' : action === 'modify' ? 'Policy editor opened in remediation workspace.' : 'Feedback recorded for detection tuning.'); if (action !== 'approve') setActive('Threat Intelligence') }

  return <div className="cyberwatch-shell">
    <header className="cw-header">
      <div className="cw-brand"><div className="cw-brand-mark"><Shield size={20}/></div><div><div className="cw-brand-name">CYBERWATCH <span>AI</span><b>ENTERPRISE SOC</b></div><p><i/> 3D Security Intelligence &amp; Digital Twin</p></div></div>
      <div className="cw-mode-tabs">{[['live','Live SOC',Radio],['exposure','Exposure View',Radar],['investigate','Incident Investigation',GitBranch],['replay','Training & Replay',PlayCircle]].map(([key,label,Icon]) => <button key={key} className={socMode === key ? 'active' : ''} onClick={() => setReferenceMode(key)}><Icon size={14}/>{label}</button>)}</div>
      <div className="cw-header-actions"><div className="cw-risk"><small>GLOBAL RISK INDEX</small><strong>87<span>/100</span></strong><b>CRIT</b></div><div className="cw-sim-wrap"><button className="cw-sim" onClick={() => setShowSimulationMenu(!showSimulationMenu)}><Zap size={14}/> Simulate Attack <ChevronDown size={14}/></button>{showSimulationMenu && <div className="cw-sim-menu"><button onClick={() => runThreat('ransomware')}>APT29 Lateral Movement</button><button onClick={() => runThreat('pth')}>Domain Controller Ransomware</button><button onClick={() => { setShowSimulationMenu(false); setActive('Simulation') }}>S3 Bucket Data Exfiltration</button></div>}</div></div>
    </header>
    <section className="cw-stagebar">{stages.map(([number,label,detail,target,Icon], index) => <React.Fragment key={number}><button className={'cw-stage ' + (activeStage === index + 1 ? 'active' : '')} onClick={() => navigateStage(index + 1, target)}><span>STAGE 0{number}<Icon size={14}/></span><strong>{label}</strong><small>{detail}</small></button>{index < stages.length - 1 && <span className="cw-stage-arrow">➜</span>}</React.Fragment>)}</section>
    <main className="cw-main">
      <aside className="cw-left"><div className="cw-stage-card hud"><div className="cw-card-title"><strong>STAGE 0{activeStage} :: {stage[0].replace('Stage ' + activeStage + ': ', '').toUpperCase()} &amp; TELEMETRY</strong><span><i/> STREAMING</span></div><p>Real-time telemetry collectors listening to Splunk indexes, Suricata IDS alerts, Zeek network logs, full PCAP buffers, vulnerability scanners, and Cloud/Identity providers.</p><div className="cw-mini-stats"><StatusMetric label="INGEST RATE" value={activeStage === 1 ? '52,140 eps' : '12,400 query/s'} tone="cyan"/><StatusMetric label="PARSER LATENCY" value={activeStage === 1 ? '0.8 ms' : '3.4 ms'} tone="green"/></div></div><div className="cw-log-card hud"><div className="cw-card-title"><strong><TerminalIcon/> LOG CONSOLE</strong><button><Trash2 size={13}/></button></div><div className="cw-logs"><p><time>[12:34:50]</time> <b className="cw-amber">[AWS-TRAIL]</b> IAM Policy updated by user 'admin-temp'</p><p><time>[12:34:50]</time> <b className="cw-cyan">[ZEEK]</b> Connection summary: 10.0.4.12 → 185.220.101.5:443</p><p><time>[12:34:51]</time> <b className="cw-red">[SURICATA]</b> lateral movement signature matched</p><p><time>[12:34:52]</time> <b className="cw-green">[GRAPH]</b> incident path updated</p></div></div></aside>
      <section className="cw-center"><div className="cw-map-toolbar"><span>CAMERA:</span>{[['Global','global'],['Cloud Cluster','cloud'],['Datacenter','datacenter'],['Identity Hub','identity']].map(([label,key]) => <button key={key} onClick={() => document.dispatchEvent(new CustomEvent('nextguard:camera', {detail:key}))}>{label}</button>)}<em/><span>3D FILTER:</span><button className="selected" onClick={() => document.dispatchEvent(new CustomEvent('nextguard:filter',{detail:'all'}))}>All Nodes</button><button className="warning" onClick={() => document.dispatchEvent(new CustomEvent('nextguard:filter',{detail:'amber'}))}>Warnings</button></div>{active === 'Overview' || active === 'Security Twin' ? <NetworkMap onSelect={() => setSelected(incidents[0])}/> : <div className="cw-module"><ModuleView active={active} onSelect={() => setSelected(incidents[0])}/></div>}{socMode === 'replay' && <div className="cw-replay"><button onClick={() => setReplayPlaying(!replayPlaying)}>{replayPlaying ? 'PAUSE' : 'PLAY'}</button><input type="range" min="0" max="100" defaultValue="25"/><span>T-00:14:32</span></div>}</section>
      <aside className="cw-right"><section className="cw-active hud"><div className="cw-card-title"><strong className="cw-red"><AlertTriangle size={14}/> ACTIVE INCIDENTS (3)</strong><b>HIGH ALERT</b></div><IncidentTile color="red" title="#INC-8821 :: Credential Theft" age="2m ago" text="Pass-the-Hash onto Domain Controller from IP 10.0.4.12." onClick={() => setSelected(incidents[1])}/><IncidentTile color="amber" title="#INC-8819 :: S3 Exfiltration" age="14m ago" text="Anomalous volume export to unknown external IP 185.220.101.5." onClick={() => setSelected(incidents[2])}/></section><section className="cw-attack hud"><div className="cw-card-title"><strong className="cw-cyan"><GitBranch size={14}/> ATTACK VECTOR GRAPH</strong><span>Stage 05 AI Output</span></div><div className="cw-attack-visual"><div className="cw-attack-node red"><Laptop size={18}/><span>Phished User</span></div><div className="cw-attack-node amber"><Network size={18}/><span>Jump Host</span></div><div className="cw-attack-node purple"><Server size={18}/><span>Crown Jewel DB</span></div><div className="cw-xai"><strong>XAI RISK SCORE DRIVERS</strong><span>Privilege Escalation Propensity: <b>+42%</b></span><i><em style={{width:'84%'}}/></i><span>Network Reachability Blast Radius: <b className="cw-amber">+35%</b></span><i><em className="amber-fill" style={{width:'70%'}}/></i></div></div></section></aside>
    </main>
    <footer className="cw-remediation hud"><div className="cw-remediation-copy"><div className="cw-remediation-icon"><UserRound size={20}/></div><div><strong>ANALYST REMEDIATION ACTION CENTER <b>Human-In-The-Loop</b></strong><p>Recommended Response: Isolate host <code>10.0.4.12</code> and apply automated Suricata IP block policy.</p></div></div><div className="cw-remediation-actions"><button className="approve" onClick={() => approveRemediation('approve')}><CheckCircle2 size={15}/> Approve &amp; Execute</button><button onClick={() => approveRemediation('modify')}><PenLine size={15}/> Modify Policy</button><button className="reject" onClick={() => approveRemediation('reject')}><CircleX size={15}/> Reject &amp; Train Model</button></div>{remediationNotice && <span className="cw-remediation-notice">{remediationNotice}</span>}</footer>
    {selected && <div className="cw-selected"><button onClick={() => setSelected(null)}><X size={14}/></button><small>SELECTED INCIDENT · {selected.id}</small><strong>{selected.title}</strong><span>{selected.host} · Risk {selected.score}/100</span><button onClick={() => setActive('Incidents')}>Open investigation <ArrowUpRight size={13}/></button></div>}
  </div>
}

function StatusMetric({label, value, tone}) { return <div><small>{label}</small><strong className={'cw-' + tone}>{value}</strong></div> }
function IncidentTile({color, title, age, text, onClick}) { return <button className={'cw-incident ' + color} onClick={onClick}><span><strong>{title}</strong><small>{age}</small></span><p>{text}</p></button> }

function PathStep({n, title, value, tone, detail}) { return <div className="path-step"><div><i className={'path-dot ' + tone}/><b>{n}. {title}:</b><span className={tone}>{value}</span></div><small>{detail}</small></div> }
function RiskBar({label, value, width, tone}) { return <div className="risk-bar"><div><span>{label}</span><b className={tone}>{value}</b></div><i><em className={tone} style={{width}}/></i></div> }

function MoreDots() { return <span className="more-dots">•••</span> }
function StageButton({number, label, detail, active, onClick, icon}) { return <button className={'stage-button ' + (active ? 'active' : '')} onClick={onClick}><span className="stage-code">STAGE {number} {icon}</span><strong>{label}</strong><small>{detail}</small></button> }
function ModuleView({ active, onSelect }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(false)
  const [scenarioName, setScenarioName] = useState('SSH brute-force training scenario')
  const [scenarioEvents, setScenarioEvents] = useState('[{"timestamp":"2026-10-31T10:00:00Z","src_ip":"10.42.18.44","dest_ip":"10.42.0.1","proto":"TCP","dest_port":22,"message":"failed login"}]')
  const [scenarioLabels, setScenarioLabels] = useState('repeated-failed-login')
  const config = {
    'Security Twin': ['Security digital twin', 'Live infrastructure topology and communication paths', '/api/graph'],
    'Incidents': ['SOC investigation', 'Correlated incidents requiring analyst attention', '/api/incidents'],
    'Attack Paths': ['Attack-path intelligence', 'Inferred routes to critical assets', '/api/attack-paths'],
    'Assets': ['Asset intelligence', 'Discovered devices, services, and confidence levels', '/api/discovery'],
    'Vulnerabilities': ['Vulnerability management', 'Prioritized exposure and remediation queue', '/api/vulnerabilities'],
    'Telemetry': ['Security telemetry', 'Recent normalized activity across connected sources', '/api/timeline'],
    'Reports': ['Investigation reports', 'Cases and analyst-generated evidence packages', '/api/cases'],
    'Simulation': ['Simulation and training lab', 'Replay PCAPs and evaluate detection against ground truth', '/api/simulations']
  }[active] || ['Security workspace', 'NEXTGUARD AI intelligence module', '/api/health']
  useEffect(() => { const api = import.meta.env.VITE_API_URL || 'http://localhost:4000'; fetch(api + config[2]).then((response) => response.ok ? response.json() : Promise.reject()).then(setData).catch(() => setError(true)) }, [active])
  if (active === 'Security Twin') return <><div className="module-heading"><div><div className="eyebrow"><span className="green-dot"/> LIVE NETWORK INTELLIGENCE</div><h1>{config[0]}</h1><p>{config[1]}</p></div><button className="primary-button" onClick={() => document.documentElement.requestFullscreen?.()}><Box size={16}/> Fullscreen twin</button></div><section className="card module-twin"><div className="twin-toolbar"><span><span className="legend green"/> Healthy <span className="legend orange"/> Suspicious <span className="legend red"/> Critical</span><span className="module-endpoint">GET /api/graph</span></div><NetworkMap onSelect={onSelect}/></section></>
  const entries = active === 'Threat Intelligence' ? (data?.findings || []) : active === 'Vulnerabilities' ? (data?.vulnerabilities || []) : active === 'Attack Paths' ? (data?.paths || []) : active === 'Incidents' ? (data?.incidents || []) : active === 'Assets' ? (data?.assets || []) : active === 'Telemetry' ? (data?.timeline || []) : active === 'Reports' ? (data?.cases || []) : active === 'Simulation' ? (data?.simulations || []) : []
  const labelFor = (item) => item.title || item.name || item.hostname || item.label || item.id || 'Security record'
  const metaFor = (item) => active === 'Vulnerabilities' ? `${item.affected_device || 'unknown asset'} · risk ${item.risk_score ?? '—'} · ${item.priority || 'unclassified'}` : active === 'Attack Paths' ? `${item.nodes?.map((node) => node.label).join(' → ') || 'inferred route'} · risk ${item.risk_score ?? '—'}` : active === 'Assets' ? `${item.type || 'unknown'} · ${item.ip || 'no IP'} · confidence ${item.confidence || 'unknown'}` : active === 'Telemetry' ? `${item.timestamp || ''} · ${item.source || 'unknown source'} · ${item.severity || 'normal'}` : active === 'Simulation' ? `${item.type || 'scenario'} · ${item.status || 'Ready'} · ${item.label || 'LAB DATA'}` : `${item.affected_device || item.host || item.status || item.classification || 'Review details'}`
  if (active === 'Simulation') {
    const runs = entries.flatMap((scenario) => scenario.runs || (scenario.result ? [scenario.result] : []))
    const average = runs.length ? Math.round(runs.reduce((sum, run) => sum + ((run.ground_truth_match_rate || 0) * 100), 0) / runs.length) : 0
    const createScenario = async (event) => { event.preventDefault(); try { const api = import.meta.env.VITE_API_URL || 'http://localhost:4000'; await fetch(api + '/api/simulations', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ name:scenarioName, type:'scripted_simulation', events:JSON.parse(scenarioEvents), ground_truth_labels:scenarioLabels.split(',').map((label)=>label.trim()).filter(Boolean) }) }); const response=await fetch(api + '/api/simulations'); setData(await response.json()) } catch { setError(true) } }
    return <><div className="module-heading"><div><div className="eyebrow"><span className="green-dot"/> ISOLATED LAB · GROUND TRUTH AFTER DETECTION</div><h1>{config[0]}</h1><p>{config[1]}</p></div><span className="module-endpoint">/api/simulations</span></div><div className="module-stat-grid"><div className="card module-stat"><span>Scenarios</span><strong>{entries.length}</strong></div><div className="card module-stat"><span>Completed runs</span><strong>{runs.length}</strong></div><div className="card module-stat"><span>Average match rate</span><strong>{average}%</strong></div></div><div className="simulation-grid"><form className="card scenario-form" onSubmit={createScenario}><h2>Create training scenario</h2><p>Labels are evaluated only after detection.</p><input value={scenarioName} onChange={(event)=>setScenarioName(event.target.value)} placeholder="Scenario name"/><textarea value={scenarioEvents} onChange={(event)=>setScenarioEvents(event.target.value)} rows="8" aria-label="Scenario events JSON"/><input value={scenarioLabels} onChange={(event)=>setScenarioLabels(event.target.value)} placeholder="Ground-truth rule IDs, comma separated"/><button className="primary-button" type="submit"><Sparkles size={15}/> Create scenario</button></form><section className="card module-list"><div className="module-list-head"><h2>Scenario history</h2><span>{entries.length} scenarios</span></div>{entries.map((item,index)=><div className="module-row" key={item.id || index}><div className="module-dot purple"/><div><strong>{item.name || item.id}</strong><small>{item.type} · {item.status} · {item.runs?.length || (item.result ? 1 : 0)} runs · {item.label}</small></div><span className="module-endpoint">{item.result?.ground_truth_match_rate == null ? 'Not run' : `${Math.round(item.result.ground_truth_match_rate*100)}% match`}</span></div>)}{!entries.length && <div className="module-empty">Create a controlled scenario to begin training evaluation.</div>}</section></div></>
  }
  return <><div className="module-heading"><div><div className="eyebrow"><span className="green-dot"/> INTELLIGENCE WORKSPACE</div><h1>{config[0]}</h1><p>{config[1]}</p></div><span className="module-endpoint">{config[2]}</span></div><div className="module-stat-grid"><div className="card module-stat"><span>Records</span><strong>{data?.count ?? data?.finding_count ?? entries.length}</strong></div><div className="card module-stat"><span>Data source</span><strong>Live API</strong></div><div className="card module-stat"><span>Workspace state</span><strong>{error ? 'Offline' : 'Connected'}</strong></div></div><section className="card module-list"><div className="module-list-head"><h2>Recent {active.toLowerCase()}</h2><span>{entries.length} records</span></div>{error && <div className="module-empty">API unavailable. Start the ingestion service with <code>npm run server</code>.</div>}{!error && entries.slice(0, 20).map((item, index) => <button className="module-row" key={item.id || index} onClick={onSelect}><div className={'module-dot ' + String(item.priority || item.severity || item.status || 'green').toLowerCase().replace(' ', '-')}/><div><strong>{labelFor(item)}</strong><small>{metaFor(item)}</small></div><ArrowUpRight size={15}/></button>)}{!error && !entries.length && <div className="module-empty">No records available yet. Ingest telemetry or create a scenario to populate this workspace.</div>}</section></>
}
function Stat({icon: Icon, label, value, suffix, trend, note, color}) { return <div className="stat card"><div className={'stat-icon ' + color}><Icon size={18}/></div><div className="stat-copy"><span>{label}</span><strong>{value}<small>{suffix}</small></strong><div><em className={trend.startsWith('−') || trend.startsWith('+') ? 'positive' : ''}>{trend}</em> <small>{note}</small></div></div></div> }
function CardHeader({title, subtitle, action, onAction}) { return <div className="card-header"><div><h2>{title}</h2><p>{subtitle}</p></div>{action && <button className="text-button" onClick={() => onAction ? onAction() : window.dispatchEvent(new CustomEvent('nextguard:navigate', { detail: action }))}>{action} <ArrowUpRight size={14}/></button>}</div> }
function NetworkMap({onSelect}) {
  const canvasRef = useRef(null)
  const projectedRef = useRef([])
  const dragRef = useRef(null)
  const fpsRef = useRef({ frames: 0, last: 0, fps: 0 })
  const [rotation, setRotation] = useState(-0.35)
  const [zoom, setZoom] = useState(1)
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('all')
  const [selected, setSelected] = useState(null)
  const [liveNodes, setLiveNodes] = useState(null)
  const [liveLinks, setLiveLinks] = useState(null)
  const [realtimeTick, setRealtimeTick] = useState(0)
  useEffect(() => {
    const api = import.meta.env.VITE_API_URL || 'http://localhost:4000'
    fetch(`${api}/api/graph`).then((response) => response.ok ? response.json() : null).then((graph) => {
      if (!graph?.nodes?.length) return
      const graphNodes = graph.nodes.filter((node) => ['device', 'service', 'identity', 'external'].includes(node.type))
      const radius = Math.max(1.7, Math.min(3.2, graphNodes.length * .18))
      const mapped = graphNodes.map((node, index) => {
        const angle = (index / Math.max(graphNodes.length, 1)) * Math.PI * 2
        const status = node.type === 'service' ? 'purple' : node.severity === 'critical' ? 'red' : node.severity === 'high' ? 'amber' : node.confidence === 'low' ? 'unknown' : 'green'
        return { id: node.id, label: node.label || node.id, x: Math.cos(angle) * radius, y: Math.sin(angle) * radius * .7, z: Math.sin(angle * 1.7) * 1.2, status, color: status === 'red' ? '#ff6f78' : status === 'amber' ? '#ffae5c' : status === 'purple' ? '#a993ff' : status === 'unknown' ? '#7890ab' : '#45d7cf', type: node.type, critical: node.severity === 'critical', ip: node.ip }
      })
      setLiveNodes(mapped)
      setLiveLinks(graph.edges.map((edge) => [edge.source, edge.target]))
    }).catch(() => {})
  }, [realtimeTick])
  useEffect(() => {
    const api = import.meta.env.VITE_API_URL || 'http://localhost:4000'
    const wsUrl = (api.startsWith('https') ? api.replace('https', 'wss') : api.replace('http', 'ws')) + '/ws'
    let socket; let refreshTimer
    try {
      socket = new WebSocket(wsUrl)
      socket.onmessage = (message) => { try { if (JSON.parse(message.data).type === 'telemetry' && !refreshTimer) refreshTimer = setTimeout(() => { refreshTimer = null; setRealtimeTick((value) => value + 1) }, 250) } catch {} }
    } catch {}
    return () => { socket?.close(); if (refreshTimer) clearTimeout(refreshTimer) }
  }, [])
  useEffect(() => {
    const cameraHandler = (event) => { const angles = { global: -.35, cloud: .15, datacenter: 1.05, identity: -1.15 }; setRotation(angles[event.detail] ?? -.35) }
    const filterHandler = (event) => setFilter(event.detail === 'critical' ? 'red' : 'all')
    document.addEventListener('nextguard:camera', cameraHandler)
    document.addEventListener('nextguard:filter', filterHandler)
    return () => { document.removeEventListener('nextguard:camera', cameraHandler); document.removeEventListener('nextguard:filter', filterHandler) }
  }, [])
  const fallbackNodes = [
    { id:'internet', label:'internet', x:-2.8, y:0, z:0, status:'unknown', color:'#5da9ff', type:'external' },
    { id:'vpn-gateway', label:'vpn-gateway', x:-1.7, y:0.8, z:-.3, status:'amber', color:'#ffae5c', type:'network' },
    { id:'core-switch', label:'core-switch', x:0, y:0, z:0, status:'green', color:'#45d7cf', type:'network' },
    { id:'api-edge-02', label:'api-edge-02', x:1.7, y:1, z:.2, status:'amber', color:'#ffae5c', type:'web_service' },
    { id:'db-prod-01', label:'db-prod-01', x:2.8, y:0, z:0, status:'red', color:'#ff6f78', type:'database', critical:true },
    { id:'workstation-442', label:'workstation-442', x:-1.2, y:-1.2, z:.5, status:'amber', color:'#e8d765', type:'endpoint' },
    { id:'backup-node', label:'backup-node', x:1.4, y:-1.2, z:-.5, status:'green', color:'#45d7cf', type:'server' }
  ]
  const fallbackLinks = [['internet','vpn-gateway'],['vpn-gateway','core-switch'],['core-switch','api-edge-02'],['api-edge-02','db-prod-01'],['vpn-gateway','workstation-442'],['core-switch','workstation-442'],['core-switch','backup-node'],['backup-node','db-prod-01']]
  const twinNodes = liveNodes || fallbackNodes
  const links = liveLinks || fallbackLinks
  const visibleNodes = twinNodes.filter((node) => (filter === 'all' || node.status === filter) && node.label.toLowerCase().includes(query.toLowerCase()))
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    const draw = () => {
      const rect = canvas.getBoundingClientRect(), dpr = window.devicePixelRatio || 1
      canvas.width = rect.width * dpr; canvas.height = rect.height * dpr; ctx.setTransform(dpr,0,0,dpr,0,0)
      const w = rect.width, h = rect.height
      ctx.clearRect(0,0,w,h)
      ctx.fillStyle = '#0a1725'; ctx.fillRect(0,0,w,h)
      ctx.strokeStyle = '#23415933'; ctx.lineWidth = 1
      for (let x = -w; x < w*2; x += 32) { ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x+w*.25,h); ctx.stroke() }
      for (let y = 10; y < h*1.5; y += 26) { ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(w,y-35); ctx.stroke() }
      const activeIds = new Set(visibleNodes.map((node) => node.id)), centerX=w/2, centerY=h/2+8, scale=Math.min(w/7,h/4.3)*zoom
      const project = (node) => { const cos=Math.cos(rotation), sin=Math.sin(rotation), x=node.x*cos-node.z*sin, z=node.x*sin+node.z*cos; return { x:centerX+x*scale, y:centerY-node.y*scale-z*scale*.22, depth:z, node } }
      const projected = twinNodes.map(project); projectedRef.current = projected
      ctx.lineWidth=1.2
      links.forEach(([from,to], index) => { const a=projected.find((p)=>p.node.id===from), b=projected.find((p)=>p.node.id===to); if(!a||!b||!activeIds.has(from)||!activeIds.has(to)) return; const suspicious=(from==='api-edge-02'&&to==='db-prod-01') || (from==='vpn-gateway'&&to==='workstation-442'); ctx.strokeStyle=suspicious?'#ff6f78aa':'#3b7184aa'; ctx.setLineDash(suspicious?[5,4]:[3,6]); ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke(); ctx.setLineDash([]); if(index%2===0){const t=(Date.now()/900)%1; ctx.fillStyle=suspicious?'#ff6f78':'#45d7cf'; ctx.beginPath(); ctx.arc(a.x+(b.x-a.x)*t,a.y+(b.y-a.y)*t,2.2,0,Math.PI*2); ctx.fill()} })
      projected.sort((a,b)=>a.depth-b.depth).forEach(({x,y,node,depth}) => { if(!activeIds.has(node.id)) return; const radius=(node.critical?10:7)*Math.max(.65,1-depth*.08); ctx.globalAlpha=.55; ctx.fillStyle=node.color; ctx.beginPath(); ctx.arc(x,y,radius*2.2,0,Math.PI*2); ctx.fill(); ctx.globalAlpha=1; ctx.fillStyle=node.color; ctx.beginPath(); ctx.arc(x,y,radius,0,Math.PI*2); ctx.fill(); ctx.strokeStyle=selected?.id===node.id?'#ffffff':node.color; ctx.lineWidth=selected?.id===node.id?2:1; ctx.stroke(); ctx.fillStyle='#a8bfd2'; ctx.font='9px DM Mono, monospace'; ctx.textAlign='center'; ctx.fillText(node.label,x,y+22); if(node.critical){ctx.fillStyle='#ff6f78';ctx.font='8px DM Mono';ctx.fillText('CRITICAL',x,y-16)} })
      const clock = performance.now(); fpsRef.current.frames += 1; if (!fpsRef.current.last) fpsRef.current.last = clock; if (clock - fpsRef.current.last >= 1000) { fpsRef.current.fps = fpsRef.current.frames; fpsRef.current.frames = 0; fpsRef.current.last = clock }
      ctx.fillStyle='#718aa2';ctx.font='9px DM Mono, monospace';ctx.textAlign='left';ctx.fillText('3D SECURITY DIGITAL TWIN  ·  DRAG TO ROTATE  ·  SCROLL TO ZOOM',14,18); ctx.globalAlpha=.72;ctx.fillText(`${visibleNodes.length} / ${twinNodes.length} entities  ·  ${fpsRef.current.fps || '—'} FPS`,14,h-12);ctx.globalAlpha=1
    }
    let frame; const animate=()=>{draw();frame=requestAnimationFrame(animate)}; animate(); const resize=()=>draw(); window.addEventListener('resize',resize); return()=>{cancelAnimationFrame(frame);window.removeEventListener('resize',resize)}
  }, [rotation, zoom, query, filter, selected])
  const pointerDown=(event)=>{dragRef.current={x:event.clientX,rotation}; event.currentTarget.setPointerCapture(event.pointerId)}
  const pointerMove=(event)=>{if(dragRef.current)setRotation(dragRef.current.rotation+(event.clientX-dragRef.current.x)/180)}
  const pointerUp=()=>{dragRef.current=null}
  const click=(event)=>{const rect=canvasRef.current.getBoundingClientRect(), x=event.clientX-rect.left, y=event.clientY-rect.top; const hit=projectedRef.current.find((point)=>Math.hypot(point.x-x,point.y-y)<18); if(hit){setSelected(hit.node); onSelect?.()}}
  return <div className="network-map twin-3d"><canvas ref={canvasRef} onPointerDown={pointerDown} onPointerMove={pointerMove} onPointerUp={pointerUp} onPointerLeave={pointerUp} onWheel={(event)=>setZoom((value)=>Math.max(.65,Math.min(1.55,value-event.deltaY*.001)))} onClick={click} aria-label="Interactive 3D security digital twin"/><div className="twin-controls"><div className="twin-search"><Search size={12}/><input value={query} onChange={(event)=>setQuery(event.target.value)} placeholder="Find device or IP"/></div><select value={filter} onChange={(event)=>setFilter(event.target.value)}><option value="all">All statuses</option><option value="green">Healthy</option><option value="amber">Suspicious</option><option value="red">Critical</option><option value="purple">Vulnerability</option><option value="unknown">Unknown</option></select></div>{selected && <div className="node-inspector"><button onClick={()=>setSelected(null)}><X size={12}/></button><strong>{selected.label}</strong><span>{selected.type} · {selected.status}</span><small>{selected.critical?'Critical asset · exposure indicator':selected.ip || 'Observed network entity'}</small></div>}<div className="map-zoom"><button onClick={()=>setZoom((value)=>Math.min(1.55,value+.12))}>+</button><button onClick={()=>setZoom((value)=>Math.max(.65,value-.12))}>−</button></div></div>
}

createRoot(document.getElementById('root')).render(<App />)
