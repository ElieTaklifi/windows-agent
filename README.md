# MABAT — Machine Asset Baseline Analysis & Telemetry

MABAT is a lightweight Windows endpoint visibility agent focused on one thing: **building a clear, evidence-based inventory of what is actually present on a machine**.

Instead of trusting only installer databases, MABAT pulls telemetry from multiple system surfaces (registry, startup mechanisms, filesystem footprints, OS catalog views) and exports a normalized JSON inventory that teams can inspect, compare, and feed into other tooling.

---

## What MABAT Does

MABAT discovers software and execution surfaces from real host artifacts and emits a machine-readable inventory (`inventory.json`).

In practice, this helps you:
- Understand what is installed per-machine and per-user.
- Identify software discovered outside classic installer paths.
- Surface common autorun and persistence clues.
- Build a baseline you can diff over time.

## Why MABAT

Most inventory pipelines answer: _“What was officially installed?”_

MABAT is built to answer: _“What is actually there right now?”_

It is designed for security engineers, IT operations, incident responders, and researchers who want:
- Deterministic collection behavior.
- Transparent scanner logic.
- Minimal dependencies.
- Output that is easy to validate and integrate.

## What MABAT Is Not

MABAT is **not**:
- An EDR platform.
- An antivirus engine.
- A runtime monitor.
- A remediation/enforcement agent.

It does not inject, hook, block, or remove software. It is a **visibility-first** collector.

---

## Technical Overview

### Project Structure

```text
mabat-agent/
├── src/
│   ├── main.cpp                    # interactive scan menu + orchestration
│   ├── software_entry.h            # raw/normalized entry data model
│   ├── orchestration/
│   │   ├── scan_menu.*             # interactive CLI menu and user choice handling
│   │   └── scan_plan.h             # OOP scan profiles (single/general/deep)
│   ├── scanners/
│   │   ├── idiscovery_scanner.h    # scanner interface
│   │   ├── scanner_factory.*       # scanner creation + scanner catalog
│   │   ├── registry_scanner.*      # uninstall + MSI/UserData enumeration
│   │   ├── autorun_scanner.*       # Run/RunOnce autorun key discovery
│   │   ├── filesystem_scanner.*    # executable discovery in Program Files
│   │   ├── os_catalog_scanner.*    # AppX/UWP catalog enumeration
│   │   └── persistence_scanner.*   # startup/persistence surface enumeration
│   └── helper/
│       ├── normalizer.*            # deduplication + field normalization
│       └── json_exporter.*         # inventory.json serialization
├── web-ui/                         # optional local dashboard for inventory.json
├── examples/example_output.json
├── CMakeLists.txt
└── README.md
```

### Scanner Responsibilities (Short)

- **RegistryScanner**  
  Enumerates software from uninstall registry roots (machine + per-user + WOW6432Node) and MSI UserData install properties.

- **AutoRunScanner**  
  Enumerates common autorun registry keys (`Run`, `RunOnce`, `RunOnceEx`) for machine and loaded user hives.

- **FilesystemScanner**  
  Walks `C:/Program Files` and `C:/Program Files (x86)` to discover executable artifacts (`.exe`) that may indicate portable/manual deployments.

- **OSCatalogScanner**  
  Enumerates AppX/UWP package entries from the Windows AppxAllUserStore registry catalog.

- **PersistenceScanner**  
  Enumerates selected persistence surfaces (Run keys, Winlogon values, and Startup folder artifacts).

> The runtime now presents an interactive CLI menu with multiple scan profiles (single scanner, general, deep).

### Scan Modes (CLI Menu)

When you start the binary, MABAT now shows an interactive menu so operators can choose collection depth on demand:

1. **Run a specific scanner**: executes exactly one scanner (for targeted investigations).
2. **Run general scan**: balanced coverage for routine inventory runs.
3. **Run very deep scan**: executes all available scanners including persistence-focused collection.
4. **Exit**.

Current profile composition:

- **General scan**: `RegistryScanner`, `AutorunScanner`, `FilesystemScanner`, `OSCatalogScanner`, `ServiceScanner`
- **Very deep scan**: general scan plus `PersistenceScanner`
- **Specific scanner**: one scanner selected from the scanner catalog at runtime

This feature is implemented with an OOP architecture using:
- `ScanPlan` polymorphism for scan profiles.
- `ScanMenu` for command-line interaction.
- `ScannerFactory` for scanner creation and central scanner metadata.

### Output Highlights (New)

Each normalized entry now carries richer security context for triage in downstream tooling and in the web dashboard:

- `severity` (for example: `critical`, `high`, `medium`, `low`)
- `severityReasons` (human-readable reason string)
- `explanation` (source-focused collection explanation)

These fields are generated from scanner metadata and persisted in exported JSON so analysts can quickly prioritize findings.

---

## Build & Run

### Requirements

- Windows 10 or 11
- CMake 3.21+
- Visual Studio 2022 Build Tools (MSVC)
- Windows SDK

### Build

```powershell
cmake -S . -B build
cmake --build build --config Debug
```

### Run

```powershell
.\build\Debug\windows_agent.exe
```

The binary now launches an interactive menu for selecting scan scope (`specific`, `general`, `very deep`). After each run, results are exported to `inventory.json` in the working directory.

### Optional: Open the Dashboard

You can inspect exported results with the local UI:

```powershell
start .\web-ui\index.html
```
or

```powershell
python3 -m http.server 8080
```

Then load `inventory.json` from the page.

The current dashboard includes:
- Multi-tab analyst views (`Dashboard`, `All Entries`, `Registry`, `Autoruns`, `Services`, `Filesystem`)
- Per-tab query builder filters with AND/OR logic
- Severity distribution and top findings widgets

---

## Roadmap

- Stabilize and finalize all scanner implementations behind a configurable pipeline.
- Add robust offline user hive support for non-loaded profiles.
- Expand persistence coverage (services, tasks, WMI, drivers) with stronger context metadata.
- Add richer normalization (publisher canonicalization, version unification, confidence scoring).
- Add optional output modes (stdout, custom path, split by source, diff mode).
- Improve test coverage (unit tests for normalization and scanner fixtures).
- Add optional remote transport for fleet aggregation.

---

## Disclaimer

MABAT is provided for defensive security operations, asset visibility, and research purposes. Use it only in environments where you are authorized to collect endpoint inventory data. The project is visibility-oriented and intentionally avoids active response behavior.

## Author

Created and maintained as a Windows endpoint visibility and internals exploration project.
