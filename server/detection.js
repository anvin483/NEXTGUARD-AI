const PRIVATE_IP = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|127\.)/
const SENSITIVE_PORTS = new Set([22, 23, 3389, 445, 1433, 3306, 5432, 6379, 27017])
const SIGNATURES = [
  { id: 'known-c2', name: 'Known command-and-control indicator', pattern: /c2|command.?and.?control|beacon|malware|trojan|botnet/i, severity: 'high', score: 35 },
  { id: 'smb-lateral', name: 'SMB lateral movement pattern', pattern: /smb|lateral movement|admin\$|psexec/i, severity: 'high', score: 32 },
  { id: 'credential-attack', name: 'Credential attack pattern', pattern: /brute.?force|credential spray|password spray|failed login/i, severity: 'high', score: 30 }
]

const textOf = (event) => [event.title, event.message, JSON.stringify(event.raw || {})].filter(Boolean).join(' ')
const keyOf = (event) => event.host || event.src_ip || 'unknown'
const external = (ip) => Boolean(ip && !PRIVATE_IP.test(ip) && ip !== '::1')
const severityFor = (score) => score >= 80 ? 'critical' : score >= 55 ? 'high' : score >= 30 ? 'medium' : 'low'
const confidenceFor = (type, score) => type === 'signature' ? 'high' : type === 'rule' && score >= 25 ? 'medium' : 'low'
const recommendationFor = (ruleId) => ({
  'repeated-failed-login': ['Verify the source device identity.', 'Review authentication logs for a successful login.', 'Temporarily restrict the source if activity continues.'],
  'port-sweep': ['Check whether the source is an authorized scanner.', 'Review destination services and firewall logs.', 'Investigate follow-on access after the scan.'],
  'sensitive-service-access': ['Confirm the device is authorized to access the service.', 'Review the service authentication and access logs.'],
  'large-external-transfer': ['Validate the transfer with the data owner.', 'Inspect destination reputation and proxy logs.', 'Preserve relevant packet and endpoint evidence.'],
  'new-external-destination': ['Identify the destination owner and reputation.', 'Compare the connection with the device role and business purpose.'],
  'new-service-for-device': ['Confirm the service is expected for this device role.', 'Review recent configuration and process changes.']
}[ruleId] || ['Review the supporting event evidence and surrounding telemetry.', 'Confirm whether the activity is expected for the affected device.'])

function enrichFinding(finding, event, allFindings, allEvents) {
  const related = allFindings.filter((candidate) => candidate !== finding).map((candidate) => {
    const relatedEvent = allEvents.find((item) => item.id === candidate.event_id)
    return relatedEvent && keyOf(relatedEvent) === keyOf(event) ? candidate.id : null
  }).filter(Boolean).slice(0, 10)
  const confirmed = event?.raw?.confirmed_compromise === true || event?.raw?.compromise_confirmed === true
  return {
    ...finding,
    category: finding.type === 'signature' ? 'known threat indicator' : finding.type === 'rule' ? 'policy or rule violation' : 'behavioural anomaly',
    affected_device: event?.host || event?.src_ip || event?.dest_ip || 'unknown',
    source_ip: event?.src_ip || null,
    destination_ip: event?.dest_ip || null,
    port: event?.port || null,
    protocol: event?.protocol || null,
    detection_method: finding.type,
    confidence: confidenceFor(finding.type, finding.score),
    related_alerts: related,
    recommendations: recommendationFor(finding.rule_id),
    classification: confirmed ? 'confirmed_compromise' : 'inferred_risk',
    alert_classification: confirmed ? 'High Confidence Malicious' : finding.type === 'signature' ? 'High Confidence Malicious' : 'Suspicious',
    observed_evidence: {
      event_id: event?.id,
      source: event?.source,
      timestamp: event?.timestamp,
      message: event?.message || event?.title,
      raw: event?.raw || {}
    },
    inferred_risk: {
      reason: finding.explanation,
      score: finding.score,
      severity: finding.severity,
      confidence: confidenceFor(finding.type, finding.score)
    },
    confirmed_compromise: confirmed
  }
}

function contextualClassifications(events, findings) {
  return events.map((event) => {
    const eventFindings = findings.filter((finding) => finding.event_id === event.id)
    const hasInternalContext = event.src_ip && event.dest_ip && !String(event.dest_ip).match(/^(?!10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.).+/)
    const classification = eventFindings.some((finding) => finding.alert_classification === 'High Confidence Malicious') ? 'High Confidence Malicious' : eventFindings.length >= 2 ? 'Suspicious' : eventFindings.length === 1 ? 'Suspicious' : hasInternalContext ? 'Normal' : 'Unknown'
    return { event_id: event.id, classification, reason: classification === 'Normal' ? 'No detection rule fired and the event is consistent with available internal context.' : classification === 'Unknown' ? 'Insufficient context or baseline evidence to classify reliably.' : 'One or more contextual indicators require analyst review.' }
  })
}

export function signatureFindings(event) {
  return SIGNATURES.filter((rule) => rule.pattern.test(textOf(event))).map((rule) => ({
    id: `sig:${rule.id}:${event.id}`, event_id: event.id, type: 'signature', rule_id: rule.id,
    title: rule.name, severity: rule.severity, score: rule.score, explanation: `Matched known indicator pattern: ${rule.name}.`
  }))
}

export function ruleFindings(event, allEvents) {
  const findings = []
  const source = keyOf(event)
  const related = allEvents.filter((candidate) => keyOf(candidate) === source)
  const failed = related.filter((candidate) => /failed|authentication failure|login failure/i.test(textOf(candidate)))
  if (failed.length >= 3 && /failed|authentication|login/i.test(textOf(event))) findings.push({ id: `rule:failed-login:${source}`, event_id: event.id, type: 'rule', rule_id: 'repeated-failed-login', title: 'Repeated failed login attempts', severity: 'high', score: 28, explanation: `${failed.length} failed authentication events observed for ${source}.` })
  const ports = new Set(related.map((candidate) => candidate.port).filter(Boolean))
  if (ports.size >= 5 && event.port) findings.push({ id: `rule:port-sweep:${source}`, event_id: event.id, type: 'rule', rule_id: 'port-sweep', title: 'Unusually broad port access', severity: 'high', score: 25, explanation: `${source} contacted ${ports.size} distinct ports.` })
  if (event.port && SENSITIVE_PORTS.has(event.port) && event.category === 'network' && event.source !== 'assets') findings.push({ id: `rule:sensitive-service:${event.id}`, event_id: event.id, type: 'rule', rule_id: 'sensitive-service-access', title: 'Sensitive service access', severity: 'medium', score: 16, explanation: `Observed access to protected service port ${event.port}.` })
  const bytes = Number(event.raw?.bytes || event.raw?.orig_bytes || event.raw?.outbound_bytes || 0)
  if (external(event.dest_ip) && bytes >= 10_000_000) findings.push({ id: `rule:large-egress:${event.id}`, event_id: event.id, type: 'rule', rule_id: 'large-external-transfer', title: 'Large outbound data transfer', severity: 'high', score: 30, explanation: `${(bytes / 1_000_000).toFixed(1)} MB sent to an external destination.` })
  return findings
}

export function buildBaseline(events) {
  const baseline = new Map()
  for (const event of events) {
    // Do not allow obvious threats to teach the normal model that the threat is normal.
    if (['critical', 'high'].includes(event.severity) || signatureFindings(event).length) continue
    const hour = new Date(event.timestamp).getUTCHours()
    const day = new Date(event.timestamp).getUTCDay()
    const key = `${keyOf(event)}|${day}|${hour}|${event.port || 'none'}`
    const bytes = Number(event.raw?.bytes || event.raw?.orig_bytes || event.raw?.outbound_bytes || 0)
    const item = baseline.get(key) || { key, host: keyOf(event), day_of_week: day, hour, port: event.port, count: 0, bytes: 0, mean_bytes: 0, variance_bytes: 0, destinations: new Set() }
    item.count += 1
    item.bytes += bytes
    const delta = bytes - item.mean_bytes
    item.mean_bytes += delta / item.count
    item.variance_bytes += delta * (bytes - item.mean_bytes)
    if (event.dest_ip) item.destinations.add(event.dest_ip)
    baseline.set(key, item)
  }
  return baseline
}

export function behaviourFindings(event, baseline) {
  const hour = new Date(event.timestamp).getUTCHours()
  const day = new Date(event.timestamp).getUTCDay()
  const key = `${keyOf(event)}|${day}|${hour}|${event.port || 'none'}`
  const expected = baseline.get(key)
  const findings = []
  if (external(event.dest_ip) && !expected?.destinations?.has(event.dest_ip)) findings.push({ id: `behaviour:new-external:${event.id}`, event_id: event.id, type: 'behaviour', rule_id: 'new-external-destination', title: 'Unfamiliar external destination', severity: 'medium', score: 18, explanation: `${keyOf(event)} has no established baseline for destination ${event.dest_ip}.` })
  if (!expected && event.port) findings.push({ id: `behaviour:new-service:${event.id}`, event_id: event.id, type: 'behaviour', rule_id: 'new-service-for-device', title: 'New service for device', severity: 'medium', score: 14, explanation: `${keyOf(event)} has no historical activity for port ${event.port} at this time.` })
  const bytes = Number(event.raw?.bytes || event.raw?.orig_bytes || event.raw?.outbound_bytes || 0)
  const standardDeviation = expected?.count > 1 ? Math.sqrt(expected.variance_bytes / (expected.count - 1)) : 0
  const adaptiveLimit = expected?.count >= 3 ? expected.mean_bytes + Math.max(3 * standardDeviation, expected.mean_bytes * .75) : 0
  if (adaptiveLimit > 0 && bytes > adaptiveLimit) findings.push({ id: `behaviour:volume-spike:${event.id}`, event_id: event.id, type: 'behaviour', rule_id: 'traffic-volume-spike', title: 'Traffic volume deviates from adaptive baseline', severity: 'medium', score: 20, explanation: `Observed volume ${bytes} bytes exceeded the contextual baseline limit of ${Math.round(adaptiveLimit)} bytes (${expected.count} trusted observations; mean ${Math.round(expected.mean_bytes)}, deviation ${Math.round(standardDeviation)}).` })
  return findings
}

export function detect(events) {
  const baseline = buildBaseline(events)
  const findings = []
  for (const event of events) {
    const signature = signatureFindings(event)
    const rules = ruleFindings(event, events)
    const behaviour = behaviourFindings(event, baseline)
    findings.push(...signature, ...rules, ...behaviour)
  }
  for (let index = 0; index < findings.length; index += 1) {
    const event = events.find((candidate) => candidate.id === findings[index].event_id)
    findings[index] = enrichFinding(findings[index], event, findings, events)
  }
  const incidents = new Map()
  for (const finding of findings) {
    const event = events.find((candidate) => candidate.id === finding.event_id)
    const group = keyOf(event || {})
    const incident = incidents.get(group) || { id: `INC-${group.replace(/[^a-z0-9]/gi, '-').slice(0, 18)}-${findings.length}`, title: 'Correlated suspicious activity', host: group, score: 0, findings: [], event_ids: new Set(), sources: new Set(), first_seen: event?.timestamp, last_seen: event?.timestamp }
    incident.score = Math.min(100, incident.score + finding.score)
    incident.findings.push(finding)
    if (event) { incident.event_ids.add(event.id); incident.sources.add(event.source); incident.first_seen = incident.first_seen < event.timestamp ? incident.first_seen : event.timestamp; incident.last_seen = incident.last_seen > event.timestamp ? incident.last_seen : event.timestamp }
    incidents.set(group, incident)
  }
  const outputIncidents = [...incidents.values()].map((incident) => ({
    ...incident,
    severity: severityFor(incident.score),
    confidence: incident.findings.some((finding) => finding.confidence === 'high') ? 'high' : incident.findings.some((finding) => finding.confidence === 'medium') ? 'medium' : 'low',
    classification: incident.findings.some((finding) => finding.confirmed_compromise) ? 'confirmed_compromise' : 'inferred_risk',
    alert_classification: incident.findings.some((finding) => finding.alert_classification === 'High Confidence Malicious') ? 'High Confidence Malicious' : 'Suspicious',
    event_ids: [...incident.event_ids], sources: [...incident.sources], finding_count: incident.findings.length,
    recommendations: [...new Set(incident.findings.flatMap((finding) => finding.recommendations))].slice(0, 6),
    observed_evidence_count: incident.findings.length,
    investigation_summary: `${incident.host} generated ${incident.findings.length} related detection finding${incident.findings.length === 1 ? '' : 's'} across ${incident.sources.size} telemetry source${incident.sources.size === 1 ? '' : 's'}. The activity is classified as ${incident.findings.some((finding) => finding.confirmed_compromise) ? 'confirmed compromise' : 'inferred risk'} and requires analyst validation.`,
    risk_explanation: incident.findings.map((finding) => finding.explanation).filter(Boolean).slice(0, 5)
  }))
  return { findings, incidents: outputIncidents.sort((a, b) => b.score - a.score), classifications: contextualClassifications(events, findings), baseline: [...baseline.values()].map((item) => ({ ...item, standard_deviation_bytes: item.count > 1 ? Math.sqrt(item.variance_bytes / (item.count - 1)) : 0, destinations: [...item.destinations] })) }
}
