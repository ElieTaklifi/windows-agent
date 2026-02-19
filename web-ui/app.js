/* ═══════════════════════════════════════════════
   Execution Surface Security Dashboard — app.js
   ═══════════════════════════════════════════════ */

const state = { entries: [], filtered: [] };

/* ── Fallback demo data ── */
const fallbackData = {
  entries: [
    {
      name: "Contoso Agent", type: "Win32", source: "registry",
      explanation: "Found in uninstall registry keys; indicates installed software with standard registration and likely regular execution footprint.",
      scope: "per-machine", userSID: "N/A",
      metadata: {
        path: "C:/Program Files/Contoso/agent.exe",
        publisher: "Contoso Corp",
        registryPath: "...Uninstall/ContosoAgent",
        displayVersion: "3.2.1",
        uninstallCmd: "MsiExec.exe /X{CONTOSO-GUID}"
      }
    },
    {
      name: "Tailspin.App", type: "UWP", source: "os_catalog",
      explanation: "Found in Windows AppX catalog; indicates packaged UWP app presence that can execute in user context.",
      scope: "per-machine", userSID: "N/A",
      metadata: {
        path: "C:/Program Files/WindowsApps/Tailspin.App",
        publisher: "Tailspin Toys",
        displayVersion: "1.0.0"
      }
    },
    {
      name: "OneDrive", type: "Service", source: "persistence",
      explanation: "Found in persistence surface (run_key); can auto-start and maintain recurring execution on this host.",
      scope: "per-user", userSID: "S-1-5-21...",
      metadata: {
        path: "C:/Users/user/AppData/Local/Microsoft/OneDrive/OneDrive.exe",
        publisher: "Microsoft Corporation",
        mechanism: "run_key",
        displayVersion: "23.201.1002.0005",
        uninstallCmd: "%LocalAppData%\\Microsoft\\OneDrive\\OneDriveSetup.exe /uninstall"
      }
    },
    {
      name: "7-Zip 22.01", type: "Win32", source: "registry",
      explanation: "Found in uninstall registry keys; indicates installed software with standard registration and likely regular execution footprint.",
      scope: "per-machine", userSID: "N/A",
      metadata: {
        path: "C:/Program Files/7-Zip",
        publisher: "Igor Pavlov",
        displayVersion: "22.01",
        uninstallCmd: "MsiExec.exe /I{23170F69-40C1-2702-2201-000001000000}"
      }
    },
    {
      name: "Chrome", type: "Win32", source: "registry",
      explanation: "Found in uninstall registry keys; indicates installed software with standard registration and likely regular execution footprint.",
      scope: "per-machine", userSID: "N/A",
      metadata: {
        path: "C:/Program Files/Google/Chrome/Application",
        publisher: "Google LLC",
        displayVersion: "119.0.6045.160",
        uninstallCmd: "MsiExec.exe /X{chrome-guid}"
      }
    },
    {
      name: "Slack", type: "Win32", source: "registry",
      explanation: "Found in uninstall registry keys; indicates installed software with standard registration and likely regular execution footprint.",
      scope: "per-user", userSID: "S-1-5-21...",
      metadata: {
        path: "C:/Users/user/AppData/Local/slack",
        publisher: "Slack Technologies",
        displayVersion: "4.35.126",
        uninstallCmd: "C:/Users/user/AppData/Local/slack/Update.exe --uninstall"
      }
    },
    {
      name: "vcredist_x64", type: "Win32", source: "registry-msi",
      explanation: "Found in MSI UserData registry records; confirms Windows Installer-managed software and potential machine-wide impact.",
      scope: "per-machine", userSID: "N/A",
      metadata: {
        path: "",
        publisher: "Microsoft Corporation",
        displayVersion: "14.36.32532.0"
      }
    },
  ]
};

/* ══════════════════════════════════════════════════════════
   QUERY BUILDER — field definitions
   Each field:
     key     → unique id used in rule objects
     label   → human-readable display name
     get(e)  → extracts the comparable string from an entry
     type    → "text" (free input) | "enum" (dropdown)
     options → static option list for enum (null = built from data)
══════════════════════════════════════════════════════════ */
const QB_FIELDS = [
  { key: 'name',      label: 'Name',      get: e => e.name || '',                                              type: 'text' },
  { key: 'publisher', label: 'Publisher', get: e => e.metadata?.publisher || e.rawMetadata?.publisher || '',   type: 'text' },
  { key: 'type',      label: 'Type',      get: e => e.type || '',                                              type: 'enum', options: null },
  { key: 'source',    label: 'Source',    get: e => e.source || '',                                            type: 'enum', options: null },
  { key: 'scope',     label: 'Scope',     get: e => e.scope || '',                                             type: 'enum', options: ['per-machine', 'per-user'] },
  { key: 'risk',      label: 'Risk',      get: e => computeRisk(e),                                            type: 'enum', options: ['high', 'medium', 'low'] },
  { key: 'path',      label: 'Path',      get: e => e.metadata?.path || '',                                    type: 'text' },
  { key: 'version',   label: 'Version',   get: e => e.metadata?.displayVersion || '',                          type: 'text' },
  { key: 'userSID',   label: 'User SID',  get: e => e.userSID || '',                                           type: 'text' },
];

/* Operators available per field type */
const OPS_TEXT = [
  { key: 'contains',     label: 'contains'        },
  { key: 'not_contains', label: 'does not contain' },
  { key: 'is',           label: 'is'               },
  { key: 'is_not',       label: 'is not'           },
  { key: 'starts_with',  label: 'starts with'      },
  { key: 'ends_with',    label: 'ends with'        },
  { key: 'is_empty',     label: 'is empty'         },
  { key: 'is_not_empty', label: 'is not empty'     },
];
const OPS_ENUM = [
  { key: 'is',     label: 'is'     },
  { key: 'is_not', label: 'is not' },
];

/* Rule state */
let qbRules   = [];
let qbLogic   = 'and';
let ruleIdSeq = 0;

/* ══════════════════════════════════════════
   Helpers
══════════════════════════════════════════ */
function computeRisk(entry) {
  const type   = (entry.type   || '').toLowerCase();
  const source = (entry.source || '').toLowerCase();
  const meta   = entry.metadata || {};
  const path   = (meta.path || '').toLowerCase();
  if (source === 'persistence' || meta.mechanism === 'run_key') return 'high';
  if (type === 'service' || type === 'driver')                   return 'high';
  if (source === 'filesystem' && path.includes('temp'))          return 'high';
  if (source === 'registry' || type === 'win32')                 return 'medium';
  return 'low';
}

function getPublisher(entry) {
  return entry.metadata?.publisher || entry.rawMetadata?.publisher || '';
}

function escHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fieldDef(key) {
  return QB_FIELDS.find(f => f.key === key) || QB_FIELDS[0];
}

/* ══════════════════════════════════════════
   Rule evaluation
══════════════════════════════════════════ */
function evalRule(entry, rule) {
  const fd  = fieldDef(rule.field);
  const raw = fd.get(entry);
  const a   = raw.toLowerCase();
  const b   = (rule.value || '').toLowerCase();

  switch (rule.op) {
    case 'is':           return a === b;
    case 'is_not':       return a !== b;
    case 'contains':     return a.includes(b);
    case 'not_contains': return !a.includes(b);
    case 'starts_with':  return a.startsWith(b);
    case 'ends_with':    return a.endsWith(b);
    case 'is_empty':     return a === '';
    case 'is_not_empty': return a !== '';
    default:             return true;
  }
}

/* ══════════════════════════════════════════
   Apply filters → state.filtered
══════════════════════════════════════════ */
function applyFilters() {
  const active = qbRules.filter(r => {
    if (['is_empty', 'is_not_empty'].includes(r.op)) return true;
    return (r.value || '').trim() !== '';
  });

  if (!active.length) {
    state.filtered = [...state.entries];
  } else if (qbLogic === 'and') {
    state.filtered = state.entries.filter(e => active.every(r => evalRule(e, r)));
  } else {
    state.filtered = state.entries.filter(e => active.some(r => evalRule(e, r)));
  }

  renderAll();
  renderChips(active);
}

/* ══════════════════════════════════════════
   Enum options (static + dynamic from data)
══════════════════════════════════════════ */
function enumOptions(fieldKey) {
  const fd = fieldDef(fieldKey);
  if (fd.options) return fd.options;
  return [...new Set(state.entries.map(e => fd.get(e)).filter(Boolean))].sort();
}

/* ══════════════════════════════════════════
   Render rules list
══════════════════════════════════════════ */
function renderRules() {
  const container = document.getElementById('qbRules');

  if (!qbRules.length) {
    container.innerHTML = `
      <div class="qb-empty-hint">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
          <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/>
        </svg>
        No filters active — all entries are shown. Click&nbsp;<strong>Add rule</strong>&nbsp;to start filtering.
      </div>`;
    return;
  }

  container.innerHTML = qbRules.map((rule, idx) => {
    const fd      = fieldDef(rule.field);
    const ops     = fd.type === 'enum' ? OPS_ENUM : OPS_TEXT;
    const noValue = ['is_empty', 'is_not_empty'].includes(rule.op);

    const fieldOpts = QB_FIELDS.map(f =>
      `<option value="${f.key}" ${f.key === rule.field ? 'selected' : ''}>${f.label}</option>`
    ).join('');

    const opOpts = ops.map(op =>
      `<option value="${op.key}" ${op.key === rule.op ? 'selected' : ''}>${op.label}</option>`
    ).join('');

    let valueWidget = '';
    if (!noValue) {
      if (fd.type === 'enum') {
        const opts = enumOptions(rule.field).map(v =>
          `<option value="${v}" ${v === rule.value ? 'selected' : ''}>${v}</option>`
        ).join('');
        valueWidget = `
          <select class="qb-select value-enum" data-id="${rule.id}" data-role="value">
            <option value="">— select —</option>${opts}
          </select>`;
      } else {
        valueWidget = `
          <input class="qb-input value" type="text"
            placeholder="value…"
            value="${escHtml(rule.value)}"
            data-id="${rule.id}" data-role="value" />`;
      }
    }

    const connector = idx > 0
      ? `<span class="qb-connector">${qbLogic.toUpperCase()}</span>`
      : `<span style="width:36px;flex-shrink:0"></span>`;

    return `
      <div class="qb-rule" data-rule-id="${rule.id}">
        ${connector}
        <select class="qb-select field"    data-id="${rule.id}" data-role="field">${fieldOpts}</select>
        <select class="qb-select operator" data-id="${rule.id}" data-role="op">${opOpts}</select>
        ${valueWidget}
        <button class="qb-rule-remove" data-id="${rule.id}" title="Remove rule">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>`;
  }).join('');

  /* Event delegation */
  container.querySelectorAll('[data-role]').forEach(el => {
    el.addEventListener(el.tagName === 'INPUT' ? 'input' : 'change', handleRuleChange);
  });
  container.querySelectorAll('.qb-rule-remove').forEach(btn => {
    btn.addEventListener('click', () => removeRule(btn.dataset.id));
  });
}

/* Handle a change inside any rule control */
function handleRuleChange(ev) {
  const id   = ev.target.dataset.id;
  const role = ev.target.dataset.role;
  const rule = qbRules.find(r => String(r.id) === id);
  if (!rule) return;

  if (role === 'field') {
    rule.field = ev.target.value;
    const fd   = fieldDef(rule.field);
    rule.op    = fd.type === 'enum' ? 'is' : 'contains';
    rule.value = '';
    renderRules();
  } else if (role === 'op') {
    rule.op = ev.target.value;
    renderRules();
  } else {
    rule.value = ev.target.value;
  }

  applyFilters();
}

/* ── Add / remove ── */
function addRule() {
  qbRules.push({ id: ++ruleIdSeq, field: 'name', op: 'contains', value: '' });
  renderRules();
  const inputs = document.querySelectorAll('#qbRules .qb-input.value');
  if (inputs.length) inputs[inputs.length - 1].focus();
}

function removeRule(id) {
  qbRules = qbRules.filter(r => String(r.id) !== id);
  renderRules();
  applyFilters();
}

/* ══════════════════════════════════════════
   Chips — active filter summary bar
══════════════════════════════════════════ */
function renderChips(active) {
  const container = document.getElementById('qbChips');
  if (!active.length) { container.innerHTML = ''; return; }

  const allOps = [...OPS_TEXT, ...OPS_ENUM];
  const chips = active.map(r => {
    const fd      = fieldDef(r.field);
    const opLabel = allOps.find(o => o.key === r.op)?.label || r.op;
    const valPart = ['is_empty', 'is_not_empty'].includes(r.op)
      ? '' : `<span class="qb-chip-val">${escHtml(r.value)}</span>`;
    return `
      <span class="qb-chip">
        <span class="qb-chip-field">${fd.label}</span>
        <span class="qb-chip-op">${opLabel}</span>
        ${valPart}
        <button class="qb-chip-remove" data-id="${r.id}" title="Remove">×</button>
      </span>`;
  }).join('');

  const badge = `<span class="qb-result-badge">
    <strong>${state.filtered.length}</strong> / ${state.entries.length} entries
  </span>`;

  container.innerHTML = chips + badge;
  container.querySelectorAll('.qb-chip-remove').forEach(btn => {
    btn.addEventListener('click', () => removeRule(btn.dataset.id));
  });
}

/* ══════════════════════════════════════════
   AND / OR toggle
══════════════════════════════════════════ */
document.getElementById('logicToggle').addEventListener('click', (ev) => {
  const opt = ev.target.closest('.qbl-opt');
  if (!opt) return;
  qbLogic = opt.dataset.logic;
  document.querySelectorAll('.qbl-opt').forEach(o =>
    o.classList.toggle('active', o.dataset.logic === qbLogic)
  );
  document.getElementById('matchLabel').textContent =
    qbLogic === 'and' ? 'All conditions must match' : 'Any condition must match';
  renderRules();
  applyFilters();
});

document.getElementById('qbAddRule').addEventListener('click', addRule);
document.getElementById('qbClearAll').addEventListener('click', () => {
  qbRules = [];
  renderRules();
  applyFilters();
});

/* ══════════════════════════════════════════
   Render — Stat Cards
══════════════════════════════════════════ */
function renderCards() {
  const byRisk = { high: 0, medium: 0, low: 0 };
  state.filtered.forEach(e => byRisk[computeRisk(e)]++);
  const defs = [
    { cls: 'total',  label: 'Total Surfaces', val: state.filtered.length, sub: `of ${state.entries.length} scanned` },
    { cls: 'high',   label: 'High Risk',      val: byRisk.high,           sub: 'Requires attention' },
    { cls: 'medium', label: 'Medium Risk',    val: byRisk.medium,         sub: 'Monitor closely'    },
    { cls: 'low',    label: 'Low Risk',       val: byRisk.low,            sub: 'Compliant'          },
  ];
  document.getElementById('statsCards').innerHTML = defs.map(d => `
    <div class="stat-card ${d.cls}">
      <div class="stat-label">${d.label}</div>
      <div class="stat-value">${d.val}</div>
      <div class="stat-sub">${d.sub}</div>
    </div>
  `).join('');
}

/* ══════════════════════════════════════════
   Render — Donut Chart
══════════════════════════════════════════ */
function renderDonut() {
  const total  = state.filtered.length || 1;
  const byRisk = { high: 0, medium: 0, low: 0 };
  state.filtered.forEach(e => byRisk[computeRisk(e)]++);
  const circ = 2 * Math.PI * 50;

  let offset = 0;
  const segments = [
    { key: 'high',   color: 'var(--high)',   label: 'High'   },
    { key: 'medium', color: 'var(--medium)', label: 'Medium' },
    { key: 'low',    color: 'var(--low)',    label: 'Low'    },
  ];
  segments.forEach(seg => {
    const len = circ * (byRisk[seg.key] / total);
    const el  = document.getElementById('donut-' + seg.key);
    el.setAttribute('stroke-dasharray',  `${len} ${circ - len}`);
    el.setAttribute('stroke-dashoffset', -offset);
    offset += len;
  });

  document.getElementById('donutTotal').textContent = state.filtered.length;
  document.getElementById('donutLegend').innerHTML  = segments.map(seg => `
    <div class="dl-item">
      <div class="dl-dot" style="background:${seg.color}"></div>
      <div class="dl-name">${seg.label}</div>
      <div class="dl-val">${byRisk[seg.key]}</div>
    </div>
  `).join('');
}

/* ══════════════════════════════════════════
   Render — Risk Breakdown Bars
══════════════════════════════════════════ */
function renderRiskBars() {
  const total  = Math.max(state.filtered.length, 1);
  const byRisk = { high: 0, medium: 0, low: 0 };
  state.filtered.forEach(e => byRisk[computeRisk(e)]++);

  const items = [
    { label: 'High',   key: 'high',   color: 'var(--high)'   },
    { label: 'Medium', key: 'medium', color: 'var(--medium)' },
    { label: 'Low',    key: 'low',    color: 'var(--low)'    },
  ];
  document.getElementById('riskBars').innerHTML = items.map(it => {
    const pct = Math.round(byRisk[it.key] / total * 100);
    return `
      <div class="rb-row">
        <div class="rb-header">
          <span class="rb-label">${it.label}</span>
          <span class="rb-count" style="color:${it.color}">${byRisk[it.key]} — ${pct}%</span>
        </div>
        <div class="rb-track">
          <div class="rb-fill" style="width:${pct}%; background:${it.color}"></div>
        </div>
      </div>`;
  }).join('');
}

/* ══════════════════════════════════════════
   Render — Source Breakdown
══════════════════════════════════════════ */
function renderSourceBars() {
  const counts = {};
  state.filtered.forEach(e => {
    const s = e.source || 'unknown';
    counts[s] = (counts[s] || 0) + 1;
  });
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const max    = sorted[0]?.[1] || 1;

  document.getElementById('sourceBars').innerHTML = sorted.length
    ? sorted.map(([src, cnt]) => `
        <div class="sb-item">
          <div class="sb-label" title="${src}">${src}</div>
          <div class="sb-track"><div class="sb-fill" style="width:${Math.round(cnt / max * 100)}%"></div></div>
          <div class="sb-count">${cnt}</div>
        </div>
      `).join('')
    : '<div style="color:var(--muted);font-size:.8rem">No data</div>';
}

/* ══════════════════════════════════════════
   Render — Top Publishers
══════════════════════════════════════════ */
function renderPublishers() {
  const counts = {};
  state.filtered.forEach(e => {
    const p = getPublisher(e);
    if (p) counts[p] = (counts[p] || 0) + 1;
  });
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 7);

  document.getElementById('pubList').innerHTML = sorted.length
    ? sorted.map(([pub, cnt], i) => `
        <div class="pub-item">
          <div class="pub-rank">${String(i + 1).padStart(2, '0')}</div>
          <div class="pub-name" title="${pub}">${pub}</div>
          <div class="pub-badge">${cnt}</div>
        </div>
      `).join('')
    : '<div style="color:var(--muted);font-size:.8rem">No publisher data available</div>';
}

/* ══════════════════════════════════════════
   Render — Inventory Table
══════════════════════════════════════════ */
function renderTable() {
  const tbody = document.getElementById('entriesBody');
  const empty = document.getElementById('emptyState');

  if (!state.filtered.length) {
    tbody.innerHTML = '';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';

  tbody.innerHTML = state.filtered.map(entry => {
    const risk      = computeRisk(entry);
    const path      = entry.metadata?.path || '-';
    const publisher = getPublisher(entry) || '—';
    const explanation = entry.explanation || '—';
    const uninstCmd = entry.metadata?.uninstallCmd || '';

    const btnHtml = uninstCmd
      ? `<button class="uninstall-btn" onclick="openModal(this)"
             data-name="${escHtml(entry.name)}"
             data-cmd="${escHtml(uninstCmd)}">
           <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
             <polyline points="3 6 5 6 21 6"/>
             <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6"/>
           </svg>
           Uninstall
         </button>`
      : `<span style="color:var(--muted);font-size:.72rem">—</span>`;

    return `
      <tr>
        <td><div class="td-name" title="${escHtml(entry.name)}">${escHtml(entry.name)}</div></td>
        <td><span class="badge badge-type">${escHtml(entry.type   || '—')}</span></td>
        <td><span class="badge badge-source">${escHtml(entry.source || '—')}</span></td>
        <td><span class="badge badge-scope">${escHtml(entry.scope  || '—')}</span></td>
        <td><div class="td-mono" title="${escHtml(publisher)}">${escHtml(publisher)}</div></td>
        <td><div class="td-explanation" title="${escHtml(explanation)}">${escHtml(explanation)}</div></td>
        <td><span class="risk-pill risk-${risk}">${risk}</span></td>
        <td><div class="td-path" title="${escHtml(path)}">${escHtml(path)}</div></td>
        <td>${btnHtml}</td>
      </tr>`;
  }).join('');
}

/* ══════════════════════════════════════════
   Status bar + tab counter
══════════════════════════════════════════ */
function updateStatus() {
  document.getElementById('statusText').textContent =
    `${state.entries.length} entries loaded · ${state.filtered.length} shown`;
  document.getElementById('tabCount').textContent = state.filtered.length;
}

/* ══════════════════════════════════════════
   Render all panels
══════════════════════════════════════════ */
function renderAll() {
  renderCards();
  renderDonut();
  renderRiskBars();
  renderSourceBars();
  renderPublishers();
  renderTable();
  updateStatus();
}

/* ══════════════════════════════════════════
   Data loading
══════════════════════════════════════════ */
function setData(json) {
  state.entries = Array.isArray(json.entries) ? json.entries : [];
  qbRules = [];
  renderRules();
  applyFilters();
}

document.getElementById('jsonFile').addEventListener('change', async (ev) => {
  const file = ev.target.files?.[0];
  if (!file) return;
  try {
    setData(JSON.parse(await file.text()));
  } catch {
    alert('Invalid JSON file.');
  }
});

/* ── Tab switching ── */
document.querySelectorAll('.nav-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('view-' + tab.dataset.view).classList.add('active');
  });
});

/* ══════════════════════════════════════════
   Uninstall modal
══════════════════════════════════════════ */
let pendingUninstall = null;

function openModal(btn) {
  pendingUninstall = { name: btn.dataset.name, cmd: btn.dataset.cmd };
  document.getElementById('modalPkgName').textContent = pendingUninstall.name;
  document.getElementById('modalOverlay').classList.add('open');
}

document.getElementById('modalCancel').addEventListener('click', () => {
  document.getElementById('modalOverlay').classList.remove('open');
  pendingUninstall = null;
});

document.getElementById('modalOverlay').addEventListener('click', (e) => {
  if (e.target === document.getElementById('modalOverlay')) {
    document.getElementById('modalOverlay').classList.remove('open');
    pendingUninstall = null;
  }
});

document.getElementById('modalConfirm').addEventListener('click', () => {
  if (pendingUninstall) {
    /*
     * TODO: Replace the alert below with a real agent API call, e.g.:
     *
     * await fetch('http://localhost:PORT/api/uninstall', {
     *   method: 'POST',
     *   headers: { 'Content-Type': 'application/json' },
     *   body: JSON.stringify(pendingUninstall)
     * });
     */
    console.log('[Uninstall requested]', pendingUninstall);
    alert(`Uninstall command sent to agent for: ${pendingUninstall.name}\n\nCmd: ${pendingUninstall.cmd}`);
  }
  document.getElementById('modalOverlay').classList.remove('open');
  pendingUninstall = null;
});

/* ── Init ── */
renderRules();
setData(fallbackData);