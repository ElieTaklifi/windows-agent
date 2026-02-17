/* ═══════════════════════════════════════════════
   Execution Surface Security Dashboard — app.js
   ═══════════════════════════════════════════════ */

const state = { entries: [], filtered: [] };

/* ── Fallback demo data (used when no JSON is loaded) ── */
const fallbackData = {
  entries: [
    {
      name: "Contoso Agent", type: "Win32", source: "registry",
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
      scope: "per-machine", userSID: "N/A",
      metadata: {
        path: "C:/Program Files/WindowsApps/Tailspin.App",
        publisher: "Tailspin Toys",
        displayVersion: "1.0.0"
      }
    },
    {
      name: "OneDrive", type: "Service", source: "persistence",
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
      scope: "per-machine", userSID: "N/A",
      metadata: {
        path: "",
        publisher: "Microsoft Corporation",
        displayVersion: "14.36.32532.0"
      }
    },
  ]
};

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

/* ══════════════════════════════════════════
   Filters
══════════════════════════════════════════ */

function populateFilter(select, values) {
  const current = select.value;
  select.innerHTML = select.options[0].outerHTML;
  [...new Set(values.filter(Boolean))].sort().forEach(v => {
    const opt = document.createElement('option');
    opt.value = v; opt.textContent = v;
    select.appendChild(opt);
  });
  if ([...select.options].some(o => o.value === current)) select.value = current;
}

function applyFilters() {
  const q   = document.getElementById('searchInput').value.trim().toLowerCase();
  const typ = document.getElementById('typeFilter').value;
  const src = document.getElementById('sourceFilter').value;
  const sco = document.getElementById('scopeFilter').value;
  const pub = document.getElementById('publisherFilter').value;
  const rsk = document.getElementById('riskFilter').value;

  state.filtered = state.entries.filter(entry => {
    const risk = computeRisk(entry);
    const blob = JSON.stringify(entry).toLowerCase();
    if (q   && !blob.includes(q))                    return false;
    if (typ !== 'all' && entry.type !== typ)          return false;
    if (src !== 'all' && entry.source !== src)        return false;
    if (sco !== 'all' && entry.scope !== sco)         return false;
    if (pub !== 'all' && getPublisher(entry) !== pub) return false;
    if (rsk !== 'all' && risk !== rsk)                return false;
    return true;
  });
  renderAll();
}

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
  const circ = 2 * Math.PI * 50; // circumference for r=50

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
  const publishers = state.entries.map(e => getPublisher(e)).filter(Boolean);
  populateFilter(document.getElementById('typeFilter'),      state.entries.map(e => e.type));
  populateFilter(document.getElementById('sourceFilter'),    state.entries.map(e => e.source));
  populateFilter(document.getElementById('scopeFilter'),     state.entries.map(e => e.scope));
  populateFilter(document.getElementById('publisherFilter'), publishers);
  applyFilters();
}

/* ── File picker ── */
document.getElementById('jsonFile').addEventListener('change', async (ev) => {
  const file = ev.target.files?.[0];
  if (!file) return;
  try {
    setData(JSON.parse(await file.text()));
  } catch {
    alert('Invalid JSON file.');
  }
});

/* ── Filter listeners ── */
['searchInput', 'typeFilter', 'sourceFilter', 'scopeFilter', 'publisherFilter', 'riskFilter']
  .forEach(id => document.getElementById(id).addEventListener('input', applyFilters));

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

/* ── Init with demo data ── */
setData(fallbackData);
