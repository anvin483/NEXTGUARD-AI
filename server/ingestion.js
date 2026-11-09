import crypto from 'node:crypto'

const now = () => new Date().toISOString()
const first = (record, keys, fallback = null) => keys.map((key) => record?.[key]).find((value) => value !== undefined && value !== null && value !== '') ?? fallback
const hash = (value) => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex').slice(0, 20)
const normalizeIp = (value) => value == null ? null : String(value).trim().toLowerCase()
const normalizePort = (value) => {
  if (value == null || value === '') return null
  const port = Number.parseInt(String(value).replace(/[^0-9]/g, ''), 10)
  return Number.isInteger(port) && port >= 0 && port <= 65535 ? port : null
}
const normalizeProtocol = (value) => value == null ? null : String(value).trim().toLowerCase()
const normalizeTimestamp = (value) => {
  if (value == null || value === '') return now()
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid timestamp: ${value}`)
  return date.toISOString()
}

function inferAssetType(record) {
  const explicit = first(record, ['type', 'asset_type', 'category', 'device_type'])
  if (explicit) return { type: String(explicit).toLowerCase(), confidence: 'high', evidence: ['explicit_asset_type'] }
  const ports = [record.port, record.dest_port, record['destination.port']].map(normalizePort).filter(Boolean)
  const service = String(first(record, ['service', 'service.name', 'application', 'process'], '')).toLowerCase()
  const os = String(first(record, ['os', 'operating_system', 'os.name', 'host.os.name'], '')).toLowerCase()
  const vendor = String(first(record, ['vendor', 'manufacturer', 'mac_vendor'], '')).toLowerCase()
  if (ports.some((port) => [8291, 8728, 8729].includes(port)) || /router|switch|gateway|mikrotik|cisco|juniper/.test(service + os + vendor)) return { type: 'router_or_switch', confidence: 'medium', evidence: ['network_device_service_or_vendor'] }
  if (ports.some((port) => [135, 139, 445, 3389, 5985, 5986].includes(port)) || /windows server|domain controller|active directory/.test(service + os)) return { type: 'server_or_endpoint', confidence: 'medium', evidence: ['windows_or_server_service'] }
  if (/firewall|palo alto|fortigate|checkpoint|opnsense|iptables/.test(service + os + vendor)) return { type: 'firewall', confidence: 'medium', evidence: ['firewall_service_or_vendor'] }
  if (ports.some((port) => [3306, 5432, 1433, 6379, 27017].includes(port)) || /database|postgres|mysql|redis|mongo/.test(service)) return { type: 'database', confidence: 'medium', evidence: ['database_port_or_service'] }
  if (ports.some((port) => [80, 443, 8080, 8443].includes(port)) || /http|nginx|apache|web/.test(service)) return { type: 'web_service', confidence: 'medium', evidence: ['web_port_or_service'] }
  if (ports.some((port) => [53, 67, 68, 161].includes(port)) || /dns|dhcp|snmp/.test(service)) return { type: 'network_service', confidence: 'medium', evidence: ['network_service_port_or_service'] }
  if (ports.some((port) => [22, 3389, 5985, 5986].includes(port))) return { type: 'server_or_endpoint', confidence: 'low', evidence: ['remote_access_port'] }
  return { type: 'unknown', confidence: 'low', evidence: ['ip_or_hostname_only'] }
}

export function validateRecord(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) return { valid: false, error: 'Each event must be a JSON object' }
  if (record.timestamp || record['@timestamp'] || record.time || record.ts) {
    try { normalizeTimestamp(first(record, ['timestamp', '@timestamp', 'time', 'ts'])) } catch (error) { return { valid: false, error: error.message } }
  }
  const rawPort = first(record, ['dest_port', 'destination.port', 'port'])
  if (rawPort != null && normalizePort(rawPort) == null) return { valid: false, error: `Invalid port: ${rawPort}` }
  return { valid: true }
}

export const SUPPORTED_SOURCES = [
  'suricata', 'zeek', 'security-onion', 'splunk', 'pcap',
  'openvas', 'greenbone', 'firewall', 'cloud', 'identity', 'assets'
]

export function normalizeRecord(source, record) {
  const timestamp = normalizeTimestamp(first(record, ['timestamp', '@timestamp', 'time', 'ts']))
  const srcIp = normalizeIp(first(record, ['src_ip', 'srcip', 'id.orig_h', 'source.ip', 'sourceAddress']))
  const destIp = normalizeIp(first(record, ['dest_ip', 'dst_ip', 'id.resp_h', 'destination.ip', 'destinationAddress']))
  const host = first(record, ['host', 'hostname', 'asset', 'agent.name', 'id.orig_h'], srcIp || 'unknown')
  const suricataAlert = source === 'suricata' && (Boolean(record?.alert) || Boolean(record?.signature) || first(record, ['event_type', 'type', 'log_type'], '') === 'alert')
  const severityRaw = first(record, ['severity', 'alert.severity', 'risk', 'priority'], record?.alert?.severity ?? (source === 'suricata' && !suricataAlert ? 4 : 3))
  const severity = typeof severityRaw === 'number' ? (severityRaw <= 1 ? 'critical' : severityRaw === 2 ? 'high' : severityRaw === 3 ? 'medium' : 'low') : String(severityRaw).toLowerCase()

  let category = 'telemetry'
  let eventType = first(record, ['event_type', 'type', 'log_type'], 'network_event')
  let title = first(record, ['title', 'message', 'alert.signature', 'signature', 'name'], `${source} event`)
  if (source === 'suricata' && suricataAlert) { category = 'intrusion'; eventType = 'ids_alert'; title = record?.alert?.signature || first(record, ['signature'], title) }
  if (source === 'suricata' && !suricataAlert) { category = 'network'; eventType = eventType || 'network_event' }
  if (source === 'zeek') { category = 'network'; eventType = first(record, ['service', 'proto', 'event_type'], 'connection') }
  if (['openvas', 'greenbone'].includes(source)) { category = 'vulnerability'; eventType = 'vulnerability_finding'; title = first(record, ['name', 'nvt.name', 'cve', 'oid'], title) }
  if (source === 'firewall') { category = 'network'; eventType = 'firewall_event' }
  if (['cloud', 'identity'].includes(source)) { category = 'identity'; eventType = 'cloud_security_event' }
  if (source === 'pcap') { category = 'packet_capture'; eventType = 'pcap_metadata' }
  if (source === 'assets') { category = 'asset_inventory'; eventType = 'asset_discovered' }

  const normalized = {
    id: first(record, ['id', 'event_id', 'uid'], null) || `evt_${hash({ source, timestamp, record })}`,
    received_at: now(), timestamp, source, category, event_type: eventType, title,
    severity, host, src_ip: srcIp, dest_ip: destIp,
    protocol: normalizeProtocol(first(record, ['proto', 'protocol', 'network.protocol'])),
    port: normalizePort(first(record, ['dest_port', 'destination.port', 'port'])),
    message: first(record, ['message', 'msg', 'description']),
    raw: record
  }
  normalized.fingerprint = hash({ source, timestamp, event_type: eventType, title, host, src_ip: srcIp, dest_ip: destIp, port: normalized.port, message: normalized.message })
  return normalized
}

export function normalizeAsset(record, source = 'assets') {
  const enriched = { ...(record.raw || {}), ...record }
  const inferred = inferAssetType(enriched)
  const hostname = first(enriched, ['hostname', 'host', 'name', 'dns', 'dns_name', 'fqdn'], 'unknown')
  const ip = normalizeIp(first(enriched, ['ip', 'ip_address', 'address', 'source.ip', 'destination.ip']))
  return {
    id: first(enriched, ['id', 'asset_id', 'hostname', 'ip'], `asset_${hash(record)}`),
    hostname, ip,
    mac: first(enriched, ['mac', 'mac_address', 'macAddress', 'source.mac', 'destination.mac']),
    type: inferred.type,
    confidence: inferred.confidence,
    identification_evidence: [...inferred.evidence, ...(enriched.mac || enriched.mac_address ? ['mac_address'] : []), ...(enriched.os || enriched.operating_system ? ['operating_system'] : []), ...(enriched.hostname || enriched.dns || enriched.fqdn ? ['dns_or_hostname'] : [])],
    os: first(enriched, ['os', 'operating_system', 'os.name', 'host.os.name']),
    services: first(enriched, ['services', 'service', 'service.name', 'application'], []),
    criticality: String(first(enriched, ['criticality', 'risk', 'severity'], 'medium')).toLowerCase(),
    source, first_seen: first(enriched, ['first_seen', 'firstSeen'], now()), last_seen: now(), updated_at: now(), raw: record
  }
}
