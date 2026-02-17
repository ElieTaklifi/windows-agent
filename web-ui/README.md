# Execution Surface Security Dashboard

A standalone, zero-dependency browser UI for visualising software inventory data produced by the Windows endpoint scanner agent.

## File Structure

```
web-ui/
├── index.html   — markup & layout (no inline styles or scripts)
├── styles.css   — all visual styles, CSS variables, animations
├── app.js       — data loading, filtering, rendering logic
└── README.md    — this file
```

## Usage

1. Open `index.html` directly in any modern browser (Chrome, Edge, Firefox).  
   No web server required — all assets are local.
2. Click **Load inventory.json** in the top-right and select an exported inventory file from the agent.
3. The dashboard populates automatically with demo data until a real file is loaded.

## Views

### Dashboard tab
| Panel | Description |
|---|---|
| Stat cards | Total surfaces, high / medium / low risk counts |
| Risk Distribution | Animated SVG donut chart |
| Risk Breakdown | Percentage bars per risk level |
| By Source | Horizontal bars showing entry counts per scanner source |
| Top Publishers | Ranked leaderboard of software publishers |

### Inventory tab
Full filterable, searchable table of every discovered surface.

**Filters available:** Type · Source · Scope · Publisher · Risk level · Free-text search

**Columns:** Name · Type · Source · Scope · Publisher · Risk · Path · Action (Uninstall)

## Uninstall Action

Rows that contain a `metadata.uninstallCmd` value show an **Uninstall** button.  
Clicking it opens a confirmation modal before proceeding.

To wire this up to a real agent endpoint, replace the placeholder in `app.js`:

```js
// Inside the modalConfirm click handler in app.js:
await fetch('http://localhost:PORT/api/uninstall', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(pendingUninstall)   // { name, cmd }
});
```

## inventory.json Format

The dashboard expects a JSON object with an `entries` array.  
Each entry should conform to the following shape:

```jsonc
{
  "entries": [
    {
      "name":    "My App",          // required — display name
      "type":    "Win32",           // Win32 | UWP | Service | Driver | …
      "source":  "registry",        // registry | registry-msi | persistence | os_catalog | filesystem
      "scope":   "per-machine",     // per-machine | per-user
      "userSID": "S-1-5-21-…",     // or "N/A" for machine-wide installs
      "metadata": {
        "path":           "C:/Program Files/MyApp",
        "publisher":      "Acme Corp",
        "displayVersion": "2.1.0",
        "uninstallCmd":   "MsiExec.exe /X{GUID}",  // optional — enables Uninstall button
        "registryPath":   "…\\Uninstall\\MyApp",
        "mechanism":      "run_key"                // present on persistence sources
      }
    }
  ]
}
```

## Risk Scoring

Risk is computed client-side in `app.js → computeRisk()`:

| Condition | Risk |
|---|---|
| `source === "persistence"` or `mechanism === "run_key"` | **High** |
| `type === "Service"` or `type === "Driver"` | **High** |
| `source === "filesystem"` and path contains `temp` | **High** |
| `source === "registry"` or `type === "Win32"` | **Medium** |
| Everything else | **Low** |

Adjust the function in `app.js` to match your organisation's risk policy.

## Design

- **Fonts:** Syne (UI) + JetBrains Mono (data/code)  
- **Theme:** Dark blue-grey with coloured accent system via CSS custom properties  
- All colours are defined as CSS variables in `styles.css → :root` — easy to re-theme.
