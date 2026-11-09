export function evaluateSimulations(simulations) {
  const runs = simulations.flatMap((scenario) => (scenario.runs || (scenario.result ? [scenario.result] : [])).map((run) => ({ ...run, scenario_id: scenario.id, scenario_name: scenario.name })))
  let truePositives = 0; let falsePositives = 0; let falseNegatives = 0
  for (const run of runs) {
    const expected = new Set(run.expected_labels || []); const detected = new Set(run.detected_labels || [])
    truePositives += [...expected].filter((label) => detected.has(label)).length
    falsePositives += [...detected].filter((label) => !expected.has(label)).length
    falseNegatives += [...expected].filter((label) => !detected.has(label)).length
  }
  const precision = truePositives + falsePositives ? truePositives / (truePositives + falsePositives) : null
  const recall = truePositives + falseNegatives ? truePositives / (truePositives + falseNegatives) : null
  const measuredRuns = runs.filter((run) => Number.isFinite(run.detection_latency_ms))
  const avg = (field) => { const values = measuredRuns.map((run) => Number(run[field])).filter(Number.isFinite); return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : null }
  return {
    generated_at: new Date().toISOString(), run_count: runs.length,
    detection_accuracy: { precision, recall, methodology: 'label-set comparison across simulation runs' },
    false_positives: { count: falsePositives, false_positive_rate: null, status: 'not_measured', reason: 'True-negative event labels are required for a defensible false-positive rate.' },
    detection_speed: { average_detection_latency_ms: avg('detection_latency_ms'), status: measuredRuns.length ? 'measured' : 'not_measured' },
    event_processing: { average_events_per_second: avg('events_per_second'), status: measuredRuns.length ? 'measured' : 'not_measured' },
    ingestion_performance: { average_ingestion_latency_ms: avg('ingestion_latency_ms'), status: measuredRuns.length ? 'measured' : 'not_measured' },
    asset_discovery_accuracy: { status: 'not_measured', reason: 'Requires an independently labeled asset inventory.' },
    attack_path_accuracy: { status: 'not_measured', reason: 'Requires validated route ground truth.' },
    visualization: { status: 'browser_measured', fps: 'Available in the 3D twin footer and /api/performance.' },
    scalability: { status: 'not_measured', reason: 'Requires controlled node-count and connection-count benchmarks.' },
    investigation_time: { status: 'not_measured', reason: 'Requires analyst study instrumentation.' },
    runs
  }
}
