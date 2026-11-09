import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const feedFile = path.join(root, 'data', 'intelligence-feeds.json')
let cache = { updated_at: null, kev: {}, epss: {}, cve: {} }
let loaded = false

async function load() {
  if (loaded) return cache
  loaded = true
  try { cache = { ...cache, ...JSON.parse(await fs.readFile(feedFile, 'utf8')) } } catch (error) { if (error.code !== 'ENOENT') throw error }
  return cache
}

function parseEpss(text) {
  const lines = text.split(/\r?\n/).filter((line) => line && !line.startsWith('#'))
  if (!lines.length) return {}
  const header = lines[0].split(',').map((value) => value.trim().toLowerCase())
  const cveIndex = header.indexOf('cve')
  const epssIndex = header.indexOf('epss')
  return Object.fromEntries(lines.slice(1).map((line) => line.split(',')).filter((parts) => cveIndex >= 0 && epssIndex >= 0 && parts[cveIndex]).map((parts) => [parts[cveIndex].trim().toUpperCase(), Number(parts[epssIndex])]).filter(([, value]) => Number.isFinite(value)))
}

async function fetchText(url) {
  const response = await fetch(url)
  if (!response.ok) throw new Error(`${url} returned ${response.status}`)
  return response.text()
}

export async function getFeedContext() { return load() }

export async function syncConfiguredFeeds() {
  const next = await load()
  const result = { synced: [], skipped: [], errors: [] }
  if (process.env.CISA_KEV_URL) {
    try {
      const body = JSON.parse(await fetchText(process.env.CISA_KEV_URL))
      next.kev = Object.fromEntries((body.vulnerabilities || []).map((item) => [String(item.cveID || item.cve || '').toUpperCase(), { vendor: item.vendorProject, product: item.product, due_date: item.dueDate, description: item.shortDescription }]).filter(([key]) => key))
      result.synced.push('cisa-kev')
    } catch (error) { result.errors.push({ feed: 'cisa-kev', error: error.message }) }
  } else result.skipped.push('cisa-kev')
  if (process.env.EPSS_URL) {
    try { next.epss = parseEpss(await fetchText(process.env.EPSS_URL)); result.synced.push('epss') } catch (error) { result.errors.push({ feed: 'epss', error: error.message }) }
  } else result.skipped.push('epss')
  if (process.env.CVE_FEED_URL) {
    try {
      const body = JSON.parse(await fetchText(process.env.CVE_FEED_URL))
      const records = Array.isArray(body) ? body : body.vulnerabilities || body.results || []
      next.cve = Object.fromEntries(records.map((item) => [String(item.cve || item.cveID || item.id || '').toUpperCase(), item]).filter(([key]) => key))
      result.synced.push('cve')
    } catch (error) { result.errors.push({ feed: 'cve', error: error.message }) }
  } else result.skipped.push('cve')
  next.updated_at = new Date().toISOString()
  await fs.mkdir(path.dirname(feedFile), { recursive: true })
  await fs.writeFile(feedFile, JSON.stringify(next, null, 2))
  cache = next
  return { ...result, updated_at: next.updated_at, counts: { kev: Object.keys(next.kev).length, epss: Object.keys(next.epss).length, cve: Object.keys(next.cve).length } }
}

export function enrichVulnerabilities(findings, context) {
  const kev = context?.kev || {}
  const epss = context?.epss || {}
  return findings.map((finding) => {
    const cve = String(finding.cve || '').toUpperCase()
    const kevRecord = kev[cve]
    const feedEpss = Number(epss[cve])
    const knownExploited = Boolean(finding.kev || kevRecord)
    const enrichedEpss = Number.isFinite(feedEpss) ? feedEpss : finding.epss
    const feedRisk = knownExploited ? Math.min(100, finding.risk_score + 15) : finding.risk_score
    const priority = feedRisk >= 80 ? 'critical' : feedRisk >= 60 ? 'high' : feedRisk >= 35 ? 'medium' : 'low'
    return { ...finding, kev: knownExploited, epss: enrichedEpss, risk_score: feedRisk, priority, intelligence: { kev_source: kevRecord ? 'CISA KEV feed' : null, kev_record: kevRecord || null, epss_source: Number.isFinite(feedEpss) ? 'EPSS feed' : null } }
  }).sort((a, b) => b.risk_score - a.risk_score)
}
