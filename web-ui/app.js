const state = {
  entries: [],
  filtered: [],
};

const fallbackData = {
  entries: [
    { name: "Contoso Agent", type: "Win32", source: "registry", scope: "per-machine", userSID: "N/A", metadata: { path: "C:/Program Files/Contoso/agent.exe", registryPath: "...Uninstall/ContosoAgent" } },
    { name: "Tailspin.App", type: "UWP", source: "os_catalog", scope: "per-machine", userSID: "N/A", metadata: { path: "C:/Program Files/WindowsApps/Tailspin.App" } },
    { name: "OneDrive", type: "Service", source: "persistence", scope: "per-user", userSID: "S-1-5-21...", metadata: { path: "C:/Users/user/AppData/Local/Microsoft/OneDrive/OneDrive.exe", mechanism: "run_key" } }
  ]
};

const fileInput = document.getElementById("jsonFile");
const searchInput = document.getElementById("searchInput");
const typeFilter = document.getElementById("typeFilter");
const sourceFilter = document.getElementById("sourceFilter");
const scopeFilter = document.getElementById("scopeFilter");
const riskFilter = document.getElementById("riskFilter");

const statsCards = document.getElementById("statsCards");
const riskBars = document.getElementById("riskBars");
const entriesBody = document.getElementById("entriesBody");

function computeRisk(entry) {
  const type = (entry.type || "").toLowerCase();
  const source = (entry.source || "").toLowerCase();
  const metadata = entry.metadata || {};
  const path = (metadata.path || "").toLowerCase();

  if (source === "persistence" || metadata.mechanism === "run_key") return "high";
  if (type === "service" || type === "driver") return "high";
  if (source === "filesystem" && path.includes("temp")) return "high";
  if (source === "registry" || type === "win32") return "medium";
  return "low";
}

function safeStr(v) { return (v ?? "").toString(); }

function populateFilter(select, values) {
  const current = select.value;
  select.innerHTML = '<option value="all">All</option>';
  [...new Set(values.filter(Boolean))].sort().forEach(v => {
    const opt = document.createElement("option");
    opt.value = v;
    opt.textContent = v;
    select.appendChild(opt);
  });
  if ([...select.options].some(o => o.value === current)) select.value = current;
}

function applyFilters() {
  const q = searchInput.value.trim().toLowerCase();
  state.filtered = state.entries.filter(entry => {
    const risk = computeRisk(entry);
    const blob = JSON.stringify(entry).toLowerCase();
    if (q && !blob.includes(q)) return false;
    if (typeFilter.value !== "all" && entry.type !== typeFilter.value) return false;
    if (sourceFilter.value !== "all" && entry.source !== sourceFilter.value) return false;
    if (scopeFilter.value !== "all" && entry.scope !== scopeFilter.value) return false;
    if (riskFilter.value !== "all" && risk !== riskFilter.value) return false;
    return true;
  });
  render();
}

function renderCards() {
  const byRisk = { high: 0, medium: 0, low: 0 };
  state.filtered.forEach(e => byRisk[computeRisk(e)]++);

  const cards = [
    ["Total Surfaces", state.filtered.length],
    ["High Risk", byRisk.high],
    ["Medium Risk", byRisk.medium],
    ["Low Risk", byRisk.low],
  ];

  statsCards.innerHTML = cards.map(([label, value]) => `
    <article class="card">
      <div class="label">${label}</div>
      <div class="value">${value}</div>
    </article>
  `).join("");
}

function renderRiskBars() {
  const totals = { high: 0, medium: 0, low: 0 };
  state.filtered.forEach(e => totals[computeRisk(e)]++);
  const total = Math.max(state.filtered.length, 1);

  const items = [
    ["High", totals.high, "var(--high)"],
    ["Medium", totals.medium, "var(--medium)"],
    ["Low", totals.low, "var(--low)"]
  ];

  riskBars.innerHTML = items.map(([label, value, color]) => {
    const pct = Math.round((value / total) * 100);
    return `
      <div class="bar-row">
        <div>${label} <strong>${value}</strong> (${pct}%)</div>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%; background:${color}"></div></div>
      </div>`;
  }).join("");
}

function renderTable() {
  entriesBody.innerHTML = state.filtered.map(entry => {
    const risk = computeRisk(entry);
    const path = safeStr(entry.metadata?.path || "-");
    return `
      <tr>
        <td>${safeStr(entry.name)}</td>
        <td>${safeStr(entry.type)}</td>
        <td>${safeStr(entry.source)}</td>
        <td>${safeStr(entry.scope)}</td>
        <td><span class="risk-pill risk-${risk}">${risk}</span></td>
        <td title="${path}">${path}</td>
      </tr>`;
  }).join("");
}

function render() {
  renderCards();
  renderRiskBars();
  renderTable();
}

function setData(json) {
  state.entries = Array.isArray(json.entries) ? json.entries : [];
  populateFilter(typeFilter, state.entries.map(e => e.type));
  populateFilter(sourceFilter, state.entries.map(e => e.source));
  populateFilter(scopeFilter, state.entries.map(e => e.scope));
  applyFilters();
}

[fileInput, searchInput, typeFilter, sourceFilter, scopeFilter, riskFilter].forEach(el =>
  el.addEventListener("input", applyFilters)
);

fileInput.addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  const text = await file.text();
  try {
    setData(JSON.parse(text));
  } catch {
    alert("Invalid JSON file.");
  }
});

setData(fallbackData);
