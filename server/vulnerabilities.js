const PRIVATE_IP = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|127\.)/
const number = (value, fallback = 0) => {
  const parsed = Number.parseFloat(String(value ?? '').replace(/[^0-9.]/g, ''))
  return Number.isFinite(parsed) ? parsed : fallback
}
const boolean = (value) => value === true || value === 1 || /^(true|yes|y|known|exploited)$/i.test(String(value || ''))
const rawOf = (event) => event.raw || {}
const pick = (raw, keys, fallback = null) => keys.map((key) => raw[key]).find((value) => value !== undefined && value !== null && value !== '') ?? fallback

function priority(score) { return score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 35 ? 'medium' : 'low' }

export function assessVulnerabilities(events, assets) {
  const assetIndex = new Map()
  for (const asset of assets) for (const key of [asset.ip, asset.hostname, asset.id].filter(Boolean)) assetIndex.set(String(key).toLowerCase(), asset)
  const findings = []
  for (const event of events) {
    const raw = rawOf(event)
    const isVulnerability = event.category === 'vulnerability' || ['openvas', 'greenbone'].includes(event.source) || raw.cve || raw.cves || raw.cvss || raw.nvt || raw.misconfiguration || raw.configuration_issue || raw.exposed_port
    if (!isVulnerability) continue
    const ip = event.dest_ip || event.src_ip || pick(raw, ['ip', 'ip_address', 'host_ip'])
    const hostname = event.host || pick(raw, ['hostname', 'host', 'asset'])
    const asset = assetIndex.get(String(ip || '').toLowerCase()) || assetIndex.get(String(hostname || '').toLowerCase())
    const cvss = Math.min(10, number(pick(raw, ['cvss', 'cvss_score', 'cvss_v3', 'score']), event.severity === 'critical' ? 9 : 5))
    const epssRaw = number(pick(raw, ['epss', 'epss_score', 'exploit_probability']), 0)
    const epss = epssRaw > 1 ? Math.min(1, epssRaw / 100) : epssRaw
    const kev = boolean(pick(raw, ['kev', 'cisa_kev', 'known_exploited', 'known_exploited_vulnerability'], false))
    const internetFacing = boolean(pick(raw, ['internet_facing', 'internet_exposed', 'publicly_exposed'], false)) || Boolean(ip && !PRIVATE_IP.test(String(ip)))
    const assetCriticality = ['critical', 'high'].includes(String(asset?.criticality || raw.criticality || '').toLowerCase()) ? 1 : 0
    const reachable = Boolean(event.port || raw.port || raw.service || asset?.services?.length)
    const misconfiguration = boolean(pick(raw, ['misconfiguration', 'configuration_issue', 'weak_configuration'], false))
    const exposureReasons = [internetFacing ? 'internet_exposed' : null, reachable ? 'reachable_service' : null, misconfiguration ? 'misconfiguration' : null, kev ? 'known_exploited' : null].filter(Boolean)
    const score = Math.min(100, Math.round((cvss / 10) * 40 + epss * 20 + (kev ? 25 : 0) + (internetFacing ? 10 : 0) + (assetCriticality ? 5 : 0) + (reachable ? 5 : 0) + (misconfiguration ? 8 : 0)))
    findings.push({
      id: `vuln:${event.id}`, event_id: event.id, cve: pick(raw, ['cve', 'cve_id', 'CVE']), title: event.title || pick(raw, ['name', 'nvt', 'description'], 'Vulnerability finding'),
      asset_id: asset?.id || null, affected_device: asset?.hostname || hostname || ip || 'unknown', ip: asset?.ip || ip || null,
      service: pick(raw, ['service', 'service_name'], event.protocol), port: event.port || pick(raw, ['port']),
      cvss, epss, kev, misconfiguration, exposure_reasons: exposureReasons, internet_facing: internetFacing, asset_criticality: asset?.criticality || raw.criticality || 'unknown', reachable,
      risk_score: score, priority: priority(score), source: event.source, detected_at: event.timestamp,
      evidence: { event_id: event.id, source: event.source, raw },
      recommendation: kev ? 'Prioritize immediate remediation or compensating controls because this vulnerability is known to be exploited.' : internetFacing ? 'Remove unnecessary public exposure and patch the affected service as soon as possible.' : 'Validate the finding, schedule remediation, and verify the fix with a follow-up scan.'
    })
  }
  return findings.sort((a, b) => b.risk_score - a.risk_score)
}
