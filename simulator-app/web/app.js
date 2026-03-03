const rulesFile = document.getElementById('rulesFile');
const stateful = document.getElementById('stateful');
const scenarioSelect = document.getElementById('scenarioSelect');
const latestResult = document.getElementById('latestResult');
const logList = document.getElementById('logList');
const scenarioDiff = document.getElementById('scenarioDiff');
const singleExpectedAction = document.getElementById('singleExpectedAction');

const customScenarioId = document.getElementById('customScenarioId');
const customScenarioName = document.getElementById('customScenarioName');
const customScenarioRules = document.getElementById('customScenarioRules');
const customScenarioStateful = document.getElementById('customScenarioStateful');
const customScenarioDescription = document.getElementById('customScenarioDescription');
const customScenarioEvents = document.getElementById('customScenarioEvents');

const scenariosById = new Map();

const singleFieldIds = [
  'ethertype', 'src_ip', 'dst_ip', 'ip_protocol', 'src_port', 'dst_port',
  'src_mac', 'dst_mac', 'tcp_flags', 'tcp_flags_mask',
];

function setBusy(button, isBusy) {
  if (!button) return;
  button.disabled = isBusy;
}

function collectPacketFromForm() {
  const packet = {};
  for (const id of singleFieldIds) {
    const value = document.getElementById(id).value.trim();
    if (value.length > 0) {
      packet[id] = value;
    }
  }
  return packet;
}

async function apiGet(path) {
  const res = await fetch(path);
  const data = await res.json();
  if (!res.ok || data.status === 'error') {
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data;
}

async function apiPost(path, payload) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok || data.status === 'error') {
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data;
}

function renderLatest(payload) {
  latestResult.textContent = JSON.stringify(payload, null, 2);
}

function renderScenarioDiff(result) {
  const rows = result?.results || [];
  if (!rows.length) {
    scenarioDiff.textContent = 'No scenario run yet.';
    return;
  }

  const table = document.createElement('table');
  table.className = 'diff-table';

  const head = document.createElement('thead');
  head.innerHTML = '<tr><th>Event</th><th>Expected</th><th>Actual</th><th>Match</th><th>Rule</th></tr>';
  table.appendChild(head);

  const body = document.createElement('tbody');
  for (const row of rows) {
    const tr = document.createElement('tr');
    const expected = row.expected_action || '(none)';
    const actual = row.actual_action || row.response?.action || '(none)';
    const match = row.action_matches !== false;
    tr.className = match ? 'match' : 'mismatch';
    tr.innerHTML = `
      <td>${row.event_name || ''}</td>
      <td>${expected}</td>
      <td>${actual}</td>
      <td>${match ? 'YES' : 'NO'}</td>
      <td>${row.response?.matched_rule || '(default)'}</td>
    `;
    body.appendChild(tr);
  }
  table.appendChild(body);

  const summary = document.createElement('div');
  const mismatchCount = Number(result.mismatch_count || 0);
  summary.className = mismatchCount > 0 ? 'summary-bad' : 'summary-good';
  summary.textContent = `Mismatches: ${mismatchCount}`;

  scenarioDiff.innerHTML = '';
  scenarioDiff.appendChild(summary);
  scenarioDiff.appendChild(table);
}

function renderLog(items) {
  logList.innerHTML = '';
  if (!items.length) {
    logList.textContent = 'No events yet.';
    return;
  }

  for (const item of items) {
    const div = document.createElement('div');
    div.className = 'log-item';

    const meta = document.createElement('div');
    meta.className = 'meta';
    const ts = new Date(item.ts * 1000).toLocaleTimeString();
    meta.textContent = `${ts} | ${item.kind} | ${item.rules_file}`;

    const spec = document.createElement('code');
    spec.textContent = item.packet_spec;

    const summary = document.createElement('div');
    const action = item.response.action || 'unknown';
    const rule = item.response.matched_rule || '(default)';
    summary.textContent = `Action: ${action} | Rule: ${rule}`;

    div.appendChild(meta);
    div.appendChild(spec);
    div.appendChild(summary);
    logList.appendChild(div);
  }
}

async function loadRulesFiles() {
  const data = await apiGet('/api/rules-files');
  rulesFile.innerHTML = '';
  for (const item of data.items) {
    const opt = document.createElement('option');
    opt.value = item;
    opt.textContent = item;
    rulesFile.appendChild(opt);
  }

  const preferred = 'rules/examples/allow_arp.yaml';
  if (data.items.includes(preferred)) {
    rulesFile.value = preferred;
  }
}

function selectedScenario() {
  return scenariosById.get(scenarioSelect.value) || null;
}

function applyScenarioDefaultsToControls() {
  const s = selectedScenario();
  if (!s) return;
  if (s.default_rules_file) {
    rulesFile.value = s.default_rules_file;
  }
  stateful.checked = Boolean(s.stateful);
}

function loadSelectedScenarioIntoEditor() {
  const s = selectedScenario();
  if (!s) return;
  customScenarioId.value = s.id || '';
  customScenarioName.value = s.name || '';
  customScenarioDescription.value = s.description || '';
  customScenarioRules.value = s.default_rules_file || '';
  customScenarioStateful.checked = Boolean(s.stateful);
  customScenarioEvents.value = JSON.stringify(s.events || [], null, 2);
}

async function loadScenarios(preferredId = null) {
  const data = await apiGet('/api/scenarios');
  scenarioSelect.innerHTML = '';
  scenariosById.clear();
  for (const item of data.items) {
    scenariosById.set(item.id, item);
    const opt = document.createElement('option');
    opt.value = item.id;
    const marker = item.source === 'custom' ? 'custom' : 'builtin';
    opt.textContent = `${item.name} (${marker})`;
    scenarioSelect.appendChild(opt);
  }

  if (preferredId && scenariosById.has(preferredId)) {
    scenarioSelect.value = preferredId;
  }
  applyScenarioDefaultsToControls();
}

async function refreshLog() {
  const data = await apiGet('/api/log');
  renderLog(data.items);
}

async function saveCustomScenario(ev) {
  const button = ev.currentTarget;
  try {
    setBusy(button, true);
    const scenario = {
      id: customScenarioId.value.trim(),
      name: customScenarioName.value.trim(),
      description: customScenarioDescription.value.trim(),
      default_rules_file: customScenarioRules.value.trim() || rulesFile.value,
      stateful: customScenarioStateful.checked,
      events: JSON.parse(customScenarioEvents.value),
    };

    if (!scenario.id) {
      throw new Error('Scenario id is required');
    }

    const data = await apiPost('/api/scenario/save', { scenario });
    renderLatest(data.result);
    await loadScenarios(scenario.id);
  } catch (err) {
    renderLatest({ error: String(err) });
  } finally {
    setBusy(button, false);
  }
}

async function deleteSelectedScenario(ev) {
  const button = ev.currentTarget;
  try {
    const s = selectedScenario();
    if (!s) throw new Error('No scenario selected');
    if (s.source !== 'custom') throw new Error('Only custom scenarios can be deleted');

    setBusy(button, true);
    const data = await apiPost('/api/scenario/delete', { scenario_id: s.id });
    renderLatest(data);
    await loadScenarios();
  } catch (err) {
    renderLatest({ error: String(err) });
  } finally {
    setBusy(button, false);
  }
}

document.getElementById('simulateBtn').addEventListener('click', async (ev) => {
  const button = ev.currentTarget;
  try {
    setBusy(button, true);
    const packet = collectPacketFromForm();
    const payload = {
      rules_file: rulesFile.value,
      stateful: stateful.checked,
      packet,
    };
    const expected = singleExpectedAction.value;
    if (expected) {
      payload.expected_action = expected;
    }
    const data = await apiPost('/api/simulate', payload);
    renderLatest(data.result);
    renderScenarioDiff(null);
    await refreshLog();
  } catch (err) {
    renderLatest({ error: String(err) });
  } finally {
    setBusy(button, false);
  }
});

document.getElementById('runScenarioBtn').addEventListener('click', async (ev) => {
  const button = ev.currentTarget;
  try {
    setBusy(button, true);
    const payload = {
      scenario_id: scenarioSelect.value,
      rules_file: rulesFile.value,
      stateful: stateful.checked,
    };

    const data = await apiPost('/api/scenario/run', payload);
    renderLatest(data.result);
    renderScenarioDiff(data.result);
    await refreshLog();
  } catch (err) {
    renderLatest({ error: String(err) });
  } finally {
    setBusy(button, false);
  }
});

document.getElementById('saveScenarioBtn').addEventListener('click', saveCustomScenario);
document.getElementById('deleteScenarioBtn').addEventListener('click', deleteSelectedScenario);
document.getElementById('loadScenarioBtn').addEventListener('click', loadSelectedScenarioIntoEditor);
document.getElementById('refreshLogBtn').addEventListener('click', refreshLog);
scenarioSelect.addEventListener('change', applyScenarioDefaultsToControls);

async function init() {
  try {
    await apiGet('/api/health');
    await Promise.all([loadRulesFiles(), loadScenarios()]);
    await refreshLog();
    renderScenarioDiff(null);
  } catch (err) {
    renderLatest({ error: `Failed to initialize UI: ${String(err)}` });
  }
}

init();
