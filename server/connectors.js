import fs from 'node:fs/promises'

const connectorState = new Map()
const cursors = new Map()

function stateFor(id, source, configured, type) {
  if (!connectorState.has(id)) connectorState.set(id, { id, source, type, configured, status: configured ? 'starting' : 'disabled', accepted: 0, last_ingested_at: null, last_error: null })
  return connectorState.get(id)
}

function parseJsonLines(text) {
  return text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).flatMap((line) => {
    try { return [JSON.parse(line)] } catch { return [] }
  })
}

function parseZeek(text) {
  const lines = text.split(/\r?\n/).filter(Boolean)
  const fieldsLine = lines.find((line) => line.startsWith('#fields'))
  const fields = fieldsLine ? fieldsLine.split('\t').slice(1) : ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'service', 'orig_bytes', 'resp_bytes']
  return lines.filter((line) => !line.startsWith('#')).map((line) => {
    const values = line.split('\t')
    return Object.fromEntries(fields.map((field, index) => [field, values[index] === '-' ? null : values[index]]))
  })
}

async function readIncrement(file, parser) {
  const buffer = await fs.readFile(file)
  const previousOffset = cursors.get(file) || 0
  const offset = previousOffset > buffer.length ? 0 : previousOffset
  const chunk = buffer.subarray(offset).toString('utf8')
  cursors.set(file, buffer.length)
  return parser(chunk)
}

async function pollFile(config, ingest) {
  const state = stateFor(config.id, config.source, Boolean(config.file), 'file')
  if (!config.file) return
  try {
    const records = await readIncrement(config.file, config.parser)
    if (!records.length) { state.status = 'ready'; return }
    const result = await ingest(config.source, records, { telemetry_class: 'production', connector: config.id })
    state.status = 'ready'
    state.accepted += result.events.length
    state.last_ingested_at = new Date().toISOString()
    state.last_error = null
  } catch (error) {
    state.status = 'error'
    state.last_error = error.message
  }
}

async function pollSplunk(ingest) {
  const configured = Boolean(process.env.SPLUNK_URL && process.env.SPLUNK_TOKEN && process.env.SPLUNK_QUERY)
  const state = stateFor('splunk-rest', 'splunk', configured, 'rest')
  if (!configured) return
  try {
    const response = await fetch(`${process.env.SPLUNK_URL.replace(/\/$/, '')}/services/search/jobs/export`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${process.env.SPLUNK_TOKEN}`, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ search: process.env.SPLUNK_QUERY, output_mode: 'json', exec_mode: 'oneshot' })
    })
    if (!response.ok) throw new Error(`Splunk returned ${response.status}`)
    const text = await response.text()
    const records = parseJsonLines(text).map((item) => item.result || item)
    if (records.length) {
      const result = await ingest('splunk', records, { telemetry_class: 'production', connector: 'splunk-rest' })
      state.accepted += result.events.length
      state.last_ingested_at = new Date().toISOString()
    }
    state.status = 'ready'
    state.last_error = null
  } catch (error) {
    state.status = 'error'
    state.last_error = error.message
  }
}

export function getConnectorStatus() {
  return [...connectorState.values()]
}

export function startConnectors({ ingest }) {
  const configs = [
    { id: 'suricata-eve-file', source: 'suricata', file: process.env.SURICATA_EVE_FILE, parser: parseJsonLines },
    { id: 'zeek-conn-file', source: 'zeek', file: process.env.ZEEK_CONN_FILE, parser: parseZeek },
    { id: 'openvas-json-file', source: 'openvas', file: process.env.OPENVAS_JSON_FILE, parser: parseJsonLines },
    { id: 'greenbone-json-file', source: 'greenbone', file: process.env.GREENBONE_JSON_FILE, parser: parseJsonLines }
  ]
  configs.forEach((config) => stateFor(config.id, config.source, Boolean(config.file), 'file'))
  stateFor('splunk-rest', 'splunk', Boolean(process.env.SPLUNK_URL && process.env.SPLUNK_TOKEN && process.env.SPLUNK_QUERY), 'rest')
  const interval = Math.max(1000, Number(process.env.NEXTGUARD_CONNECTOR_INTERVAL_MS || 5000))
  const poll = async () => { await Promise.all(configs.map((config) => pollFile(config, ingest))); await pollSplunk(ingest) }
  poll().catch(() => {})
  const timer = setInterval(() => { poll().catch(() => {}) }, interval)
  timer.unref?.()
  return { interval, connectors: getConnectorStatus() }
}
