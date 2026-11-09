const API = process.env.NEXTGUARD_API_URL || 'http://localhost:4000'

const iso = (minutesAgo) => new Date(Date.now() - minutesAgo * 60_000).toISOString()

async function request(path, options = {}) {
  const response = await fetch(`${API}${path}`, { headers: { 'content-type': 'application/json', ...(options.headers || {}) }, ...options })
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(`${options.method || 'GET'} ${path} failed (${response.status}): ${body.error || 'unknown error'}`)
  return body
}

async function ingest(source, records) {
  return request(`/api/ingest/${source}`, { method: 'POST', headers: { 'x-telemetry-class': 'simulation', 'x-simulation-id': 'SIM-END-TO-END-DEMO', 'x-simulation-label': 'SIMULATION — END-TO-END LAB' }, body: JSON.stringify(records) })
}

try {
  console.log(`NEXTGUARD AI end-to-end lab demonstration against ${API}`)
  console.log('1/7 Connecting to the monitoring API...')
  await request('/api/health')

  console.log('2/7 Discovering the lab network...')
  await ingest('assets', [
    { id: 'demo-web-01', hostname: 'demo-web-01', ip: '10.20.0.10', type: 'web_server', criticality: 'high', services: ['https'] },
    { id: 'demo-app-01', hostname: 'demo-app-01', ip: '10.20.0.20', type: 'application_server', criticality: 'high', services: ['http'] },
    { id: 'demo-db-01', hostname: 'demo-db-01', ip: '10.20.0.30', type: 'database', criticality: 'critical', services: ['postgresql'] },
    { id: 'demo-workstation-01', hostname: 'demo-workstation-01', ip: '10.20.0.44', type: 'workstation', criticality: 'medium' }
  ])
  await ingest('zeek', [
    { id: 'demo-zeek-01', ts: iso(4), uid: 'demo-conn-01', 'id.orig_h': '185.220.101.5', 'id.resp_h': '10.20.0.10', 'id.resp_p': 443, proto: 'tcp', service: 'https', orig_bytes: 1200, message: 'external client reached public web service' },
    { id: 'demo-zeek-02', ts: iso(3), uid: 'demo-conn-02', 'id.orig_h': '10.20.0.10', 'id.resp_h': '10.20.0.20', 'id.resp_p': 8080, proto: 'tcp', service: 'http', orig_bytes: 4200, message: 'web server forwarded application request' },
    { id: 'demo-zeek-03', ts: iso(2), uid: 'demo-conn-03', 'id.orig_h': '10.20.0.20', 'id.resp_h': '10.20.0.30', 'id.resp_p': 5432, proto: 'tcp', service: 'postgresql', orig_bytes: 8800, message: 'application server connected to database' }
  ])

  console.log('3/7 Importing a controlled vulnerability finding...')
  await ingest('openvas', [{
    id: 'demo-vuln-01', timestamp: iso(1), host: 'demo-db-01', dest_ip: '10.20.0.30', port: 5432,
    cve: 'CVE-2025-DEMO-0001', cvss: 9.8, epss: .91, cisa_kev: true,
    misconfiguration: true, name: 'Demo database exposure', criticality: 'critical', service: 'postgresql'
  }])

  console.log('4/7 Sending controlled suspicious test traffic...')
  await ingest('suricata', [{
    id: 'demo-suricata-01', timestamp: iso(1), src_ip: '185.220.101.5', dest_ip: '10.20.0.10', dest_port: 443, proto: 'tcp',
    alert: { signature: 'DEMO known C2 beacon pattern', severity: 1 }, message: 'authorized demonstration signature'
  }])
  await ingest('identity', [
    { id: 'demo-auth-01', timestamp: iso(3), host: 'demo-workstation-01', src_ip: '10.20.0.44', dest_ip: '10.20.0.20', dest_port: 22, message: 'failed login attempt' },
    { id: 'demo-auth-02', timestamp: iso(2), host: 'demo-workstation-01', src_ip: '10.20.0.44', dest_ip: '10.20.0.20', dest_port: 22, message: 'failed login attempt' },
    { id: 'demo-auth-03', timestamp: iso(1), host: 'demo-workstation-01', src_ip: '10.20.0.44', dest_ip: '10.20.0.20', dest_port: 22, message: 'failed login attempt' }
  ])

  console.log('5/7 Running detection and incident correlation...')
  const detections = await request('/api/detections')
  const incidents = await request('/api/incidents')
  const vulnerabilities = await request('/api/vulnerabilities')
  console.log(`   Findings: ${detections.finding_count} · Incidents: ${incidents.count} · Vulnerabilities: ${vulnerabilities.count}`)

  console.log('6/7 Building the explainable attack path...')
  const paths = await request('/api/attack-paths')
  console.log(`   Inferred paths: ${paths.path_count}`)

  const target = vulnerabilities.vulnerabilities?.find((item) => item.asset_id)?.asset_id
  if (target) {
    const whatIf = await request(`/api/attack-paths?patched_asset_id=${encodeURIComponent(target)}`)
    console.log(`7/7 What-if patch: ${whatIf.risk_reduction?.paths_before ?? paths.path_count} → ${whatIf.risk_reduction?.paths_after ?? whatIf.path_count} paths; reduced=${Boolean(whatIf.risk_reduction?.reduced)}`)
  } else {
    console.log('7/7 What-if patch skipped: no asset-linked vulnerability was returned.')
  }

  console.log('Demo complete. Open the dashboard in AUTHORIZED LIVE mode and click Analyze now.')
} catch (error) {
  console.error(`Demo stopped: ${error.message}`)
  console.error('Start the API first with: npm run server')
  process.exitCode = 1
}
