/* ═══════════════════════════════════════════════════════════════
   Threat Hunter — Execution Surface Dashboard  ·  app.js
   ═══════════════════════════════════════════════════════════════ */

'use strict';

// ── Global state ──────────────────────────────────────────────
const state = { entries: [], filtered: {} };

// ── Demo / fallback data ───────────────────────────────────────
const fallbackData = { entries: [
  { name:"Contoso Agent", type:"Win32", scope:"per-machine", source:"registry",
    severity:"medium", severityReasons:"No publisher recorded; No install date",
    explanation:"Found in uninstall registry keys.",
    userSID:"N/A",
    metadata:{ path:"C:/Program Files/Contoso/agent.exe", publisher:"", displayVersion:"3.2.1",
               installDate:"", uninstallCmd:"MsiExec.exe /X{CONTOSO-GUID}",
               registryPath:"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ContosoAgent",
               context:"machine", severity:"medium",
               severityReasons:"No publisher recorded; No install date" }},
  { name:"OneDrive", type:"Service", scope:"per-machine", source:"persistence",
    severity:"medium", severityReasons:"HKLM Run key — executes for all users",
    explanation:"Found in persistence surface (run_key).",
    userSID:"N/A",
    metadata:{ path:"C:/Users/user/AppData/Local/Microsoft/OneDrive/OneDrive.exe",
               publisher:"Microsoft Corporation", mechanism:"run_key",
               displayVersion:"23.201.1002.0005",
               registryPath:"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
               context:"machine", rawValue:"C:/Users/user/AppData/Local/Microsoft/OneDrive/OneDrive.exe",
               severity:"medium", severityReasons:"HKLM Run key — executes for all users" }},
  { name:"explorer.exe", type:"Service", scope:"per-machine", source:"persistence",
    severity:"medium", severityReasons:"Winlogon value present but points to standard Windows binary",
    explanation:"Found in persistence surface (winlogon_value).",
    userSID:"N/A",
    metadata:{ path:"C:/Windows/explorer.exe", publisher:"Microsoft Corporation",
               mechanism:"winlogon_value", valueName:"Shell",
               registryPath:"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
               context:"machine", rawValue:"explorer.exe",
               severity:"medium", severityReasons:"Winlogon value present but points to standard Windows binary" }},
  { name:"MaliciousAgent", type:"Service", scope:"per-machine", source:"persistence",
    severity:"critical", severityReasons:"Persistence target in TEMP/AppData Temp — strong malware indicator",
    explanation:"Found in persistence surface (run_key).",
    userSID:"N/A",
    metadata:{ path:"C:/Users/user/AppData/Local/Temp/svchost32.exe",
               mechanism:"run_key", context:"machine",
               registryPath:"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
               rawValue:"C:/Users/user/AppData/Local/Temp/svchost32.exe",
               severity:"critical",
               severityReasons:"HKLM Run key — executes for all users; Persistence target in TEMP/AppData Temp" }},
  { name:"Windows Defender", type:"Service", scope:"per-machine", source:"service",
    severity:"low", severityReasons:"Demand-start service with standard configuration",
    explanation:"Windows service registered in SCM.",
    userSID:"N/A",
    metadata:{ serviceName:"WinDefend", serviceType:"OwnProcess", startType:"Auto",
               objectName:"LocalSystem", resolvedPath:"C:/Program Files/Windows Defender/MsMpEng.exe",
               fileExists:"true", fileModifiedTime:"2024-01-15T08:00:00Z",
               fileSizeBytes:"1234567", failureActions:"restart", failureCommand:"",
               requiredPrivs:"SeDebugPrivilege", registryPath:"SYSTEM\\CurrentControlSet\\Services\\WinDefend",
               severity:"low", severityReasons:"Auto-start service — persistent background execution" }},
  { name:"SuspiciousDriver", type:"Driver", scope:"per-machine", source:"service",
    severity:"critical", severityReasons:"Registered binary missing from disk",
    explanation:"Kernel driver registered in SCM.",
    userSID:"N/A",
    metadata:{ serviceName:"sysmon32", serviceType:"KernelDriver", startType:"Boot",
               objectName:"", resolvedPath:"C:/Windows/Temp/sysmon32.sys",
               fileExists:"false", fileModifiedTime:"", fileSizeBytes:"",
               failureActions:"reboot", failureCommand:"",
               requiredPrivs:"", registryPath:"SYSTEM\\CurrentControlSet\\Services\\sysmon32",
               severity:"critical",
               severityReasons:"Registered binary missing from disk; Kernel driver — ring-0 execution" }},
  { name:"7-Zip 22.01", type:"Win32", scope:"per-machine", source:"registry",
    severity:"low", severityReasons:"Standard installer registration with publisher, version, and date",
    explanation:"Found in uninstall registry keys.",
    userSID:"N/A",
    metadata:{ path:"C:/Program Files/7-Zip", publisher:"Igor Pavlov",
               displayVersion:"22.01", installDate:"20230101",
               uninstallCmd:"MsiExec.exe /I{23170F69}",
               registryPath:"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\7-Zip",
               context:"machine", severity:"low",
               severityReasons:"Standard installer registration with publisher, version, and date" }},
  { name:"chrome.exe", type:"Portable", scope:"per-machine", source:"filesystem",
    severity:"low", severityReasons:"Executable in Program Files — standard install location",
    explanation:"Found by executable file scan.",
    userSID:"N/A",
    metadata:{ path:"C:/Program Files/Google/Chrome/Application/chrome.exe",
               extension:".exe", severity:"low",
               severityReasons:"Executable in Program Files — standard install location" }},
  { name:"payload.exe", type:"Portable", scope:"per-machine", source:"filesystem",
    severity:"critical", severityReasons:"Executable in TEMP — classic dropper/stager location",
    explanation:"Found by executable file scan.",
    userSID:"N/A",
    metadata:{ path:"C:/Users/user/AppData/Local/Temp/payload.exe",
               extension:".exe", severity:"critical",
               severityReasons:"Executable in TEMP — classic dropper/stager location" }},
]};

// ════════════════════════════════════════════════════════════════
//  Utility
// ════════════════════════════════════════════════════════════════

function escHtml(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;')
                        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function gm(entry, key) {
  return (entry.metadata && entry.metadata[key]) ? entry.metadata[key] : '';
}

function severityRank(s) {
  return { critical:3, high:2, medium:1, low:0 }[s] ?? -1;
}

// ── Severity pill HTML ────────────────────────────────────────
function sevPill(sev) {
  const s = (sev || 'low').toLowerCase();
  return `<span class="sev-pill sev-${s}"><span class="sev-dot"></span>${s.toUpperCase()}</span>`;
}

// ── Severity reasons tooltip cell ────────────────────────────
function reasonCell(entry) {
  const reasons = entry.severityReasons || gm(entry,'severityReasons') || '—';
  const sev = (entry.severity || 'low').toLowerCase();
  return `<div class="td-reasons risk-text-${sev}" title="${escHtml(reasons)}">${escHtml(reasons.split(';')[0].trim())}</div>`;
}

// ── Bool badge ────────────────────────────────────────────────
function boolBadge(val) {
  if (val === 'true')  return `<span class="badge badge-bool-ok">✓ exists</span>`;
  if (val === 'false') return `<span class="badge badge-bool-err">✗ missing</span>`;
  return `<span style="color:var(--muted);font-size:.72rem">—</span>`;
}

// ════════════════════════════════════════════════════════════════
//  Query Builder engine
// ════════════════════════════════════════════════════════════════

// Field definitions are per-tab so each scanner gets only its relevant fields
const QB_FIELDS = {
  inventory: [
    { key:'name',       label:'Name',       get: e=>e.name||'',               type:'text' },
    { key:'source',     label:'Source',     get: e=>e.source||'',             type:'enum', options:null },
    { key:'type',       label:'Type',       get: e=>e.type||'',               type:'enum', options:null },
    { key:'scope',      label:'Scope',      get: e=>e.scope||'',              type:'enum', options:['per-machine','per-user'] },
    { key:'severity',   label:'Severity',   get: e=>e.severity||'',           type:'enum', options:['critical','high','medium','low'] },
    { key:'publisher',  label:'Publisher',  get: e=>gm(e,'publisher'),        type:'text' },
    { key:'path',       label:'Path',       get: e=>gm(e,'path'),             type:'text' },
    { key:'mechanism',  label:'Mechanism',  get: e=>gm(e,'mechanism'),        type:'text' },
  ],
  registry: [
    { key:'name',       label:'Name',       get: e=>e.name||'',               type:'text' },
    { key:'source',     label:'Source',     get: e=>e.source||'',             type:'enum', options:['registry','registry-msi','os_catalog'] },
    { key:'severity',   label:'Severity',   get: e=>e.severity||'',           type:'enum', options:['critical','high','medium','low'] },
    { key:'publisher',  label:'Publisher',  get: e=>gm(e,'publisher'),        type:'text' },
    { key:'version',    label:'Version',    get: e=>gm(e,'displayVersion'),   type:'text' },
    { key:'installDate',label:'Install Date',get:e=>gm(e,'installDate'),      type:'text' },
    { key:'scope',      label:'Scope',      get: e=>e.scope||'',              type:'enum', options:['per-machine','per-user'] },
    { key:'path',       label:'Install Path',get:e=>gm(e,'path'),             type:'text' },
    { key:'regKey',     label:'Registry Key',get:e=>gm(e,'registryPath'),     type:'text' },
  ],
  autoruns: [
    { key:'name',       label:'Name',       get: e=>e.name||'',               type:'text' },
    { key:'severity',   label:'Severity',   get: e=>e.severity||'',           type:'enum', options:['critical','high','medium','low'] },
    { key:'mechanism',  label:'Mechanism',  get: e=>gm(e,'mechanism'),        type:'enum', options:['run_key','run_once_key','winlogon_value','startup_folder'] },
    { key:'scope',      label:'Scope',      get: e=>e.scope||'',              type:'enum', options:['per-machine','per-user'] },
    { key:'context',    label:'Context',    get: e=>gm(e,'context'),          type:'text' },
    { key:'rawValue',   label:'Target Cmd', get: e=>gm(e,'rawValue'),         type:'text' },
    { key:'regKey',     label:'Registry Key',get:e=>gm(e,'registryPath'),     type:'text' },
  ],
  services: [
    { key:'name',       label:'Name',       get: e=>e.name||'',               type:'text' },
    { key:'severity',   label:'Severity',   get: e=>e.severity||'',           type:'enum', options:['critical','high','medium','low'] },
    { key:'svcType',    label:'Type',       get: e=>gm(e,'serviceType'),      type:'enum', options:['KernelDriver','FilesystemDriver','OwnProcess','SharedProcess'] },
    { key:'startType',  label:'Start',      get: e=>gm(e,'startType'),        type:'enum', options:['Boot','System','Auto','Demand','Disabled'] },
    { key:'account',    label:'Account',    get: e=>gm(e,'objectName'),       type:'text' },
    { key:'path',       label:'Binary Path',get: e=>gm(e,'resolvedPath'),     type:'text' },
    { key:'fileExists', label:'File Exists',get: e=>gm(e,'fileExists'),       type:'enum', options:['true','false'] },
    { key:'failure',    label:'Failure',    get: e=>gm(e,'failureActions'),   type:'enum', options:['restart','reboot','run_program','none'] },
  ],
  filesystem: [
    { key:'name',       label:'Name',       get: e=>e.name||'',               type:'text' },
    { key:'severity',   label:'Severity',   get: e=>e.severity||'',           type:'enum', options:['critical','high','medium','low'] },
    { key:'path',       label:'Full Path',  get: e=>gm(e,'path'),             type:'text' },
    { key:'ext',        label:'Extension',  get: e=>gm(e,'extension'),        type:'text' },
  ],
};

const OPS_TEXT = [
  {key:'contains',    label:'contains'},
  {key:'not_contains',label:'does not contain'},
  {key:'is',          label:'is'},
  {key:'is_not',      label:'is not'},
  {key:'starts_with', label:'starts with'},
  {key:'ends_with',   label:'ends with'},
  {key:'is_empty',    label:'is empty'},
  {key:'is_not_empty',label:'is not empty'},
];
const OPS_ENUM = [{key:'is',label:'is'},{key:'is_not',label:'is not'}];
const ALL_OPS = [...OPS_TEXT, ...OPS_ENUM];

// Per-tab QB state
const qbState = {};
['inventory','registry','autoruns','services','filesystem'].forEach(tab => {
  qbState[tab] = { rules:[], logic:'and', seq:0 };
});

function fieldDef(tab, key) {
  return QB_FIELDS[tab].find(f=>f.key===key) || QB_FIELDS[tab][0];
}

function enumOptions(tab, fieldKey, entries) {
  const fd = fieldDef(tab, fieldKey);
  if (fd.options) return fd.options;
  return [...new Set(entries.map(e=>fd.get(e)).filter(Boolean))].sort();
}

function evalRule(entry, rule, tab) {
  const fd = fieldDef(tab, rule.field);
  const a = (fd.get(entry)||'').toLowerCase();
  const b = (rule.value||'').toLowerCase();
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

function applyQbFilter(tab, entries) {
  const {rules, logic} = qbState[tab];
  const active = rules.filter(r =>
    ['is_empty','is_not_empty'].includes(r.op) || (r.value||'').trim() !== ''
  );
  if (!active.length) return [...entries];
  if (logic === 'and') return entries.filter(e => active.every(r=>evalRule(e,r,tab)));
  return entries.filter(e => active.some(r=>evalRule(e,r,tab)));
}

// ── Render a query builder UI ─────────────────────────────────
function renderQb(tab) {
  const {rules, logic, seq} = qbState[tab];
  const container = document.getElementById('qbRules-'+tab);
  const entries   = tabEntries(tab);

  if (!rules.length) {
    container.innerHTML = `<div class="qb-empty-hint">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>
      No filters active — all entries shown. Click <strong>&nbsp;Add rule&nbsp;</strong> to filter.
    </div>`;
    return;
  }

  container.innerHTML = rules.map((rule, idx) => {
    const fd      = fieldDef(tab, rule.field);
    const ops     = fd.type === 'enum' ? OPS_ENUM : OPS_TEXT;
    const noValue = ['is_empty','is_not_empty'].includes(rule.op);

    const fieldOpts = QB_FIELDS[tab].map(f=>
      `<option value="${f.key}" ${f.key===rule.field?'selected':''}>${f.label}</option>`
    ).join('');
    const opOpts = ops.map(op=>
      `<option value="${op.key}" ${op.key===rule.op?'selected':''}>${op.label}</option>`
    ).join('');

    let valueWidget = '';
    if (!noValue) {
      if (fd.type === 'enum') {
        const opts = enumOptions(tab, rule.field, entries).map(v=>
          `<option value="${v}" ${v===rule.value?'selected':''}>${v}</option>`
        ).join('');
        valueWidget = `<select class="qb-select value-enum" data-id="${rule.id}" data-role="value"><option value="">— select —</option>${opts}</select>`;
      } else {
        valueWidget = `<input class="qb-input value" type="text" placeholder="value…" value="${escHtml(rule.value)}" data-id="${rule.id}" data-role="value" />`;
      }
    }

    const connector = idx > 0
      ? `<span class="qb-connector">${logic.toUpperCase()}</span>`
      : `<span style="width:36px;flex-shrink:0"></span>`;

    return `<div class="qb-rule" data-rule-id="${rule.id}">
      ${connector}
      <select class="qb-select field"    data-id="${rule.id}" data-role="field" data-tab="${tab}">${fieldOpts}</select>
      <select class="qb-select operator" data-id="${rule.id}" data-role="op"    data-tab="${tab}">${opOpts}</select>
      ${valueWidget}
      <button class="qb-rule-remove" data-id="${rule.id}" data-tab="${tab}" title="Remove">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>`;
  }).join('');

  container.querySelectorAll('[data-role]').forEach(el => {
    el.addEventListener(el.tagName==='INPUT'?'input':'change', handleQbChange);
  });
  container.querySelectorAll('.qb-rule-remove').forEach(btn => {
    btn.addEventListener('click', () => removeQbRule(btn.dataset.tab, btn.dataset.id));
  });
}

function handleQbChange(ev) {
  const id   = ev.target.dataset.id;
  const role = ev.target.dataset.role;
  const tab  = ev.target.dataset.tab || ev.target.closest('[data-tab]')?.dataset.tab;
  if (!tab) return;
  const rule = qbState[tab].rules.find(r=>String(r.id)===id);
  if (!rule) return;

  if (role === 'field') {
    rule.field = ev.target.value;
    const fd = fieldDef(tab, rule.field);
    rule.op = fd.type==='enum' ? 'is' : 'contains';
    rule.value = '';
    renderQb(tab);
  } else if (role === 'op') {
    rule.op = ev.target.value;
    renderQb(tab);
  } else {
    rule.value = ev.target.value;
  }
  renderTabAndChips(tab);
}

function addQbRule(tab) {
  const id = ++qbState[tab].seq;
  qbState[tab].rules.push({id, field: QB_FIELDS[tab][0].key, op:'contains', value:''});
  renderQb(tab);
  const inputs = document.querySelectorAll(`#qbRules-${tab} .qb-input.value`);
  if (inputs.length) inputs[inputs.length-1].focus();
}

function removeQbRule(tab, id) {
  qbState[tab].rules = qbState[tab].rules.filter(r=>String(r.id)!==id);
  renderQb(tab);
  renderTabAndChips(tab);
}

function clearQbRules(tab) {
  qbState[tab].rules = [];
  renderQb(tab);
  renderTabAndChips(tab);
}

function renderChips(tab, filteredCount) {
  const container = document.getElementById('qbChips-'+tab);
  const active = qbState[tab].rules.filter(r=>
    ['is_empty','is_not_empty'].includes(r.op) || (r.value||'').trim()!==''
  );
  if (!active.length) { container.innerHTML=''; return; }

  const chips = active.map(r=>{
    const fd = fieldDef(tab, r.field);
    const opLabel = ALL_OPS.find(o=>o.key===r.op)?.label || r.op;
    const valPart = ['is_empty','is_not_empty'].includes(r.op) ? ''
      : `<span class="qb-chip-val">${escHtml(r.value)}</span>`;
    return `<span class="qb-chip">
      <span class="qb-chip-field">${fd.label}</span>
      <span class="qb-chip-op">${opLabel}</span>${valPart}
      <button class="qb-chip-remove" data-id="${r.id}" data-tab="${tab}" title="Remove">×</button>
    </span>`;
  }).join('');

  const badge = `<span class="qb-result-badge"><strong>${filteredCount}</strong> / ${tabEntries(tab).length} entries</span>`;
  container.innerHTML = chips + badge;
  container.querySelectorAll('.qb-chip-remove').forEach(btn=>{
    btn.addEventListener('click', ()=>removeQbRule(btn.dataset.tab, btn.dataset.id));
  });
}

// ════════════════════════════════════════════════════════════════
//  Source routing — which tab owns which sources
// ════════════════════════════════════════════════════════════════

function tabEntries(tab) {
  const all = state.entries;
  switch (tab) {
    case 'registry':   return all.filter(e=>['registry','registry-msi','os_catalog'].includes(e.source));
    case 'autoruns':   return all.filter(e=>e.source==='persistence');
    case 'services':   return all.filter(e=>e.source==='service');
    case 'filesystem': return all.filter(e=>e.source==='filesystem');
    default:           return all;
  }
}

// ════════════════════════════════════════════════════════════════
//  Render helpers
// ════════════════════════════════════════════════════════════════

function renderTabAndChips(tab) {
  const entries  = tabEntries(tab);
  const filtered = applyQbFilter(tab, entries);
  state.filtered[tab] = filtered;

  switch (tab) {
    case 'inventory':  renderInventoryTable(filtered);  break;
    case 'registry':   renderRegistryTable(filtered);   break;
    case 'autoruns':   renderAutorunsTable(filtered);   break;
    case 'services':   renderServicesTable(filtered);   break;
    case 'filesystem': renderFilesystemTable(filtered); break;
  }

  renderChips(tab, filtered.length);
  updateTabCounts();
}

function renderAllTabs() {
  ['inventory','registry','autoruns','services','filesystem'].forEach(tab=>{
    renderQb(tab);
    renderTabAndChips(tab);
  });
  renderDashboard();
}

// ── Inventory table ───────────────────────────────────────────
function renderInventoryTable(entries) {
  const tbody = document.getElementById('entriesBody');
  const empty = document.getElementById('emptyState');
  if (!entries.length) { tbody.innerHTML=''; empty.style.display='block'; return; }
  empty.style.display='none';

  tbody.innerHTML = entries.map(e => {
    const publisher = gm(e,'publisher') || '—';
    const version   = gm(e,'displayVersion') || gm(e,'version') || '—';
    const path      = gm(e,'path') || e.path || '—';
    return `<tr>
      <td>${sevPill(e.severity)}</td>
      <td><div class="td-name" title="${escHtml(e.name)}">${escHtml(e.name)}</div></td>
      <td><span class="badge badge-type">${escHtml(e.type||'—')}</span></td>
      <td><span class="badge badge-source">${escHtml(e.source||'—')}</span></td>
      <td><span class="badge badge-scope">${escHtml(e.scope||'—')}</span></td>
      <td><div class="td-mono" title="${escHtml(publisher)}">${escHtml(publisher)}</div></td>
      <td><div class="td-mono">${escHtml(version)}</div></td>
      <td><div class="td-path" title="${escHtml(path)}">${escHtml(path)}</div></td>
      <td>${reasonCell(e)}</td>
      <td><div class="td-explain">${escHtml(e.explanation||'—')}</div></td>
    </tr>`;
  }).join('');
}

// ── Registry table ────────────────────────────────────────────
function renderRegistryTable(entries) {
  const tbody = document.getElementById('registryBody');
  const empty = document.getElementById('emptyRegistry');
  if (!entries.length) { tbody.innerHTML=''; empty.style.display='block'; return; }
  empty.style.display='none';

  tbody.innerHTML = entries.map(e=>{
    const publisher  = gm(e,'publisher') || '—';
    const version    = gm(e,'displayVersion') || '—';
    const installDate= gm(e,'installDate') || '—';
    const path       = gm(e,'path') || '—';
    const regKey     = gm(e,'registryPath') || '—';
    const uninstall  = gm(e,'uninstallCmd') || '—';
    return `<tr>
      <td>${sevPill(e.severity)}</td>
      <td><div class="td-name" title="${escHtml(e.name)}">${escHtml(e.name)}</div></td>
      <td><span class="badge badge-type">${escHtml(e.type||'—')}</span></td>
      <td><span class="badge badge-source">${escHtml(e.source||'—')}</span></td>
      <td><div class="td-mono" title="${escHtml(publisher)}">${escHtml(publisher)}</div></td>
      <td><div class="td-mono">${escHtml(version)}</div></td>
      <td><div class="td-mono">${escHtml(installDate)}</div></td>
      <td><span class="badge badge-scope">${escHtml(e.scope||'—')}</span></td>
      <td><div class="td-path" title="${escHtml(path)}">${escHtml(path)}</div></td>
      <td><div class="td-path" title="${escHtml(regKey)}">${escHtml(regKey)}</div></td>
      <td><div class="td-path" title="${escHtml(uninstall)}">${escHtml(uninstall)}</div></td>
      <td>${reasonCell(e)}</td>
    </tr>`;
  }).join('');
}

// ── Autoruns table ────────────────────────────────────────────
function renderAutorunsTable(entries) {
  const tbody = document.getElementById('autorunsBody');
  const empty = document.getElementById('emptyAutoruns');
  if (!entries.length) { tbody.innerHTML=''; empty.style.display='block'; return; }
  empty.style.display='none';

  tbody.innerHTML = entries.map(e=>{
    const mech      = gm(e,'mechanism') || '—';
    const context   = gm(e,'context') || '—';
    const regKey    = gm(e,'registryPath') || '—';
    const valueName = gm(e,'valueName') || e.name || '—';
    const rawValue  = gm(e,'rawValue') || gm(e,'path') || '—';
    return `<tr>
      <td>${sevPill(e.severity)}</td>
      <td><div class="td-name" title="${escHtml(e.name)}">${escHtml(e.name)}</div></td>
      <td><span class="badge badge-mech">${escHtml(mech)}</span></td>
      <td><span class="badge badge-scope">${escHtml(e.scope||'—')}</span></td>
      <td><div class="td-mono">${escHtml(context)}</div></td>
      <td><div class="td-path" title="${escHtml(regKey)}">${escHtml(regKey)}</div></td>
      <td><div class="td-mono">${escHtml(valueName)}</div></td>
      <td><div class="td-path" title="${escHtml(rawValue)}">${escHtml(rawValue)}</div></td>
      <td>${reasonCell(e)}</td>
      <td><div class="td-explain">${escHtml(e.explanation||'—')}</div></td>
    </tr>`;
  }).join('');
}

// ── Services table ────────────────────────────────────────────
function renderServicesTable(entries) {
  const tbody = document.getElementById('servicesBody');
  const empty = document.getElementById('emptyServices');
  if (!entries.length) { tbody.innerHTML=''; empty.style.display='block'; return; }
  empty.style.display='none';

  tbody.innerHTML = entries.map(e=>{
    const svcType   = gm(e,'serviceType') || e.type || '—';
    const startType = gm(e,'startType') || '—';
    const account   = gm(e,'objectName') || 'LocalSystem';
    const path      = gm(e,'resolvedPath') || gm(e,'imagePath') || gm(e,'path') || '—';
    const fileExists= gm(e,'fileExists');
    const fileMod   = gm(e,'fileModifiedTime') || '—';
    const failure   = gm(e,'failureActions') || '—';
    const privs     = gm(e,'requiredPrivs') || '—';
    return `<tr>
      <td>${sevPill(e.severity)}</td>
      <td><div class="td-name" title="${escHtml(e.name)}">${escHtml(e.name)}</div></td>
      <td><span class="badge badge-type">${escHtml(svcType)}</span></td>
      <td><span class="badge badge-mech">${escHtml(startType)}</span></td>
      <td><div class="td-mono" title="${escHtml(account)}">${escHtml(account)}</div></td>
      <td><div class="td-path" title="${escHtml(path)}">${escHtml(path)}</div></td>
      <td>${boolBadge(fileExists)}</td>
      <td><div class="td-mono" style="font-size:.68rem">${escHtml(fileMod)}</div></td>
      <td><span class="badge ${failure==='run_program'?'badge-bool-err':'badge-scope'}">${escHtml(failure)}</span></td>
      <td><div class="td-path" title="${escHtml(privs)}">${escHtml(privs)}</div></td>
      <td>${reasonCell(e)}</td>
    </tr>`;
  }).join('');
}

// ── Filesystem table ──────────────────────────────────────────
function renderFilesystemTable(entries) {
  const tbody = document.getElementById('filesystemBody');
  const empty = document.getElementById('emptyFilesystem');
  if (!entries.length) { tbody.innerHTML=''; empty.style.display='block'; return; }
  empty.style.display='none';

  tbody.innerHTML = entries.map(e=>{
    const path = gm(e,'path') || e.path || '—';
    const dir  = path.includes('\\') ? path.substring(0,path.lastIndexOf('\\'))
                                     : path.substring(0,path.lastIndexOf('/'));
    const ext  = gm(e,'extension') || '.exe';
    return `<tr>
      <td>${sevPill(e.severity)}</td>
      <td><div class="td-name" title="${escHtml(e.name)}">${escHtml(e.name)}</div></td>
      <td><div class="td-path" title="${escHtml(path)}">${escHtml(path)}</div></td>
      <td><div class="td-path" title="${escHtml(dir)}">${escHtml(dir)}</div></td>
      <td><span class="badge badge-type">${escHtml(ext)}</span></td>
      <td>${reasonCell(e)}</td>
      <td><div class="td-explain">${escHtml(e.explanation||'—')}</div></td>
    </tr>`;
  }).join('');
}

// ════════════════════════════════════════════════════════════════
//  Dashboard render
// ════════════════════════════════════════════════════════════════

function computeSev(entries) {
  const c = {critical:0,high:0,medium:0,low:0};
  entries.forEach(e=>{ c[(e.severity||'low')]++; });
  return c;
}

function renderDashboard() {
  const all = state.entries;
  const sev = computeSev(all);

  // Stat cards
  document.getElementById('statsCards').innerHTML = [
    {cls:'total',   label:'Total Surfaces', val:all.length,       sub:`${sev.critical} critical · ${sev.high} high`},
    {cls:'critical',label:'Critical',        val:sev.critical,     sub:'Immediate action required'},
    {cls:'high',    label:'High',            val:sev.high,         sub:'Review required'},
    {cls:'medium',  label:'Medium',          val:sev.medium,       sub:'Monitor closely'},
    {cls:'low',     label:'Low',             val:sev.low,          sub:'Informational'},
  ].map(d=>`
    <div class="stat-card ${d.cls}">
      <div class="stat-label">${d.label}</div>
      <div class="stat-value">${d.val}</div>
      <div class="stat-sub">${d.sub}</div>
    </div>`).join('');

  // Donut
  const total = all.length || 1;
  const circ = 2*Math.PI*50;
  let offset = 0;
  [{key:'critical',color:'var(--critical)'},{key:'high',color:'var(--high)'},
   {key:'medium',color:'var(--medium)'},{key:'low',color:'var(--low)'}]
  .forEach(seg=>{
    const len = circ*(sev[seg.key]/total);
    const el  = document.getElementById('donut-'+seg.key);
    el.setAttribute('stroke-dasharray',`${len} ${circ-len}`);
    el.setAttribute('stroke-dashoffset',-offset);
    offset += len;
  });
  document.getElementById('donutTotal').textContent = all.length;
  document.getElementById('donutLegend').innerHTML =
    [{key:'critical',label:'Critical'},{key:'high',label:'High'},
     {key:'medium',label:'Medium'},{key:'low',label:'Low'}].map(seg=>`
    <div class="dl-item">
      <div class="dl-dot" style="background:var(--${seg.key})"></div>
      <div class="dl-name">${seg.label}</div>
      <div class="dl-val">${sev[seg.key]}</div>
    </div>`).join('');

  // Severity bars
  document.getElementById('riskBars').innerHTML =
    [{label:'Critical',key:'critical',color:'var(--critical)'},
     {label:'High',key:'high',color:'var(--high)'},
     {label:'Medium',key:'medium',color:'var(--medium)'},
     {label:'Low',key:'low',color:'var(--low)'}].map(it=>{
    const pct = Math.round(sev[it.key]/total*100);
    return `<div class="rb-row">
      <div class="rb-header"><span class="rb-label">${it.label}</span>
      <span class="rb-count" style="color:${it.color}">${sev[it.key]} — ${pct}%</span></div>
      <div class="rb-track"><div class="rb-fill" style="width:${pct}%;background:${it.color}"></div></div>
    </div>`;
  }).join('');

  // Source bars
  const srcCounts = {};
  all.forEach(e=>{ srcCounts[e.source||'unknown']=(srcCounts[e.source||'unknown']||0)+1; });
  const srcSorted = Object.entries(srcCounts).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const srcMax = srcSorted[0]?.[1]||1;
  document.getElementById('sourceBars').innerHTML = srcSorted.map(([src,cnt])=>`
    <div class="sb-item">
      <div class="sb-label" title="${src}">${src}</div>
      <div class="sb-track"><div class="sb-fill" style="width:${Math.round(cnt/srcMax*100)}%"></div></div>
      <div class="sb-count">${cnt}</div>
    </div>`).join('') || '<div style="color:var(--muted);font-size:.8rem">No data</div>';

  // Publisher list
  const pubCounts = {};
  all.forEach(e=>{ const p=gm(e,'publisher'); if(p) pubCounts[p]=(pubCounts[p]||0)+1; });
  const pubSorted = Object.entries(pubCounts).sort((a,b)=>b[1]-a[1]).slice(0,7);
  document.getElementById('pubList').innerHTML = pubSorted.length
    ? pubSorted.map(([pub,cnt],i)=>`
        <div class="pub-item">
          <div class="pub-rank">${String(i+1).padStart(2,'0')}</div>
          <div class="pub-name" title="${pub}">${pub}</div>
          <div class="pub-badge">${cnt}</div>
        </div>`).join('')
    : '<div style="color:var(--muted);font-size:.8rem">No publisher data</div>';

  // Top findings
  const topFindings = [...all]
    .sort((a,b)=>severityRank(b.severity)-severityRank(a.severity))
    .filter(e=>severityRank(e.severity)>=2)
    .slice(0,20);

  document.getElementById('topFindingsBody').innerHTML = topFindings.length
    ? topFindings.map(e=>{
        const mech  = gm(e,'mechanism')||gm(e,'startType')||'—';
        const path  = gm(e,'path')||gm(e,'resolvedPath')||gm(e,'rawValue')||'—';
        return `<tr>
          <td>${sevPill(e.severity)}</td>
          <td><div class="td-name" title="${escHtml(e.name)}">${escHtml(e.name)}</div></td>
          <td><span class="badge badge-source">${escHtml(e.source||'—')}</span></td>
          <td><span class="badge badge-type">${escHtml(e.type||'—')}</span></td>
          <td><span class="badge badge-mech">${escHtml(mech)}</span></td>
          <td><div class="td-path" title="${escHtml(path)}">${escHtml(path)}</div></td>
          <td>${reasonCell(e)}</td>
        </tr>`;
    }).join('')
    : '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:24px">No critical or high severity findings</td></tr>';
}

// ════════════════════════════════════════════════════════════════
//  Tab count updates
// ════════════════════════════════════════════════════════════════

function updateTabCounts() {
  const all = state.entries;
  document.getElementById('tabCount').textContent          = all.length;
  document.getElementById('tabCountRegistry').textContent  = tabEntries('registry').length;
  document.getElementById('tabCountAutoruns').textContent  = tabEntries('autoruns').length;
  document.getElementById('tabCountServices').textContent  = tabEntries('services').length;
  document.getElementById('tabCountFilesystem').textContent= tabEntries('filesystem').length;
  document.getElementById('statusText').textContent =
    `${all.length} entries loaded · ${computeSev(all).critical} critical · ${computeSev(all).high} high`;
}

// ════════════════════════════════════════════════════════════════
//  Data loading
// ════════════════════════════════════════════════════════════════

function setData(json) {
  state.entries = Array.isArray(json.entries) ? json.entries : [];
  Object.keys(qbState).forEach(t=>{ qbState[t].rules=[]; });
  renderAllTabs();
}

document.getElementById('jsonFile').addEventListener('change', async (ev) => {
  const file = ev.target.files?.[0];
  if (!file) return;
  try { setData(JSON.parse(await file.text())); }
  catch { alert('Invalid JSON file.'); }
});

// ════════════════════════════════════════════════════════════════
//  QB toolbar wire-up
// ════════════════════════════════════════════════════════════════

document.querySelectorAll('.qb-logic-toggle').forEach(toggle => {
  toggle.addEventListener('click', ev => {
    const opt = ev.target.closest('.qbl-opt');
    if (!opt) return;
    const tab = toggle.dataset.qb;
    qbState[tab].logic = opt.dataset.logic;
    toggle.querySelectorAll('.qbl-opt').forEach(o=>
      o.classList.toggle('active', o.dataset.logic===qbState[tab].logic)
    );
    document.getElementById('matchLabel-'+tab).textContent =
      qbState[tab].logic==='and' ? 'All conditions must match' : 'Any condition must match';
    renderQb(tab);
    renderTabAndChips(tab);
  });
});

document.querySelectorAll('[data-add]').forEach(btn=>
  btn.addEventListener('click', ()=>addQbRule(btn.dataset.add)));

document.querySelectorAll('[data-clear]').forEach(btn=>
  btn.addEventListener('click', ()=>clearQbRules(btn.dataset.clear)));

// ════════════════════════════════════════════════════════════════
//  Tab switching
// ════════════════════════════════════════════════════════════════

document.querySelectorAll('.nav-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.nav-tab').forEach(t=>t.classList.remove('active'));
    document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('view-'+tab.dataset.view).classList.add('active');
  });
});

// ════════════════════════════════════════════════════════════════
//  Uninstall modal
// ════════════════════════════════════════════════════════════════

let pendingUninstall = null;

function openModal(btn) {
  pendingUninstall = {name:btn.dataset.name, cmd:btn.dataset.cmd};
  document.getElementById('modalPkgName').textContent = pendingUninstall.name;
  document.getElementById('modalOverlay').classList.add('open');
}

document.getElementById('modalCancel').addEventListener('click',()=>{
  document.getElementById('modalOverlay').classList.remove('open');
  pendingUninstall=null;
});
document.getElementById('modalOverlay').addEventListener('click',e=>{
  if (e.target===document.getElementById('modalOverlay')) {
    document.getElementById('modalOverlay').classList.remove('open');
    pendingUninstall=null;
  }
});
document.getElementById('modalConfirm').addEventListener('click',()=>{
  if (pendingUninstall) {
    console.log('[Uninstall requested]', pendingUninstall);
    alert(`Uninstall sent for: ${pendingUninstall.name}\nCmd: ${pendingUninstall.cmd}`);
  }
  document.getElementById('modalOverlay').classList.remove('open');
  pendingUninstall=null;
});

// ── Boot with demo data ───────────────────────────────────────
setData(fallbackData);
