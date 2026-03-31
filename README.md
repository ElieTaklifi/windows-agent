# MABAT — Machine Asset Baseline Analysis & Telemetry

## Overview

MABAT now contains two independent capabilities:

1. **Feature 1 (Static Inventory):** existing scanner pipeline that exports `inventory.json` and is already consumed by the Web UI.
2. **Feature 2 (Execution Monitor):** a new, low-intrusive Windows ETW-based execution telemetry collector that exports JSON Lines (`execution_events.jsonl`).

Feature 2 follows the same architectural philosophy as Feature 1 (structured JSON output), but remains intentionally isolated so both pipelines can be validated independently before future unification.

---

## Relationship with Existing Feature

Current state:

- `Feature 1 -> inventory.json -> Web UI`
- `Feature 2 -> execution_events.jsonl (separate file, local)`

Design intent:

- No regression or coupling with feature 1 runtime state.
- Feature 2 is implemented as a dedicated execution-monitor module and invoked via **case 2** / CLI option `2`.
- Future work can merge both into a centralized schema + pipeline when validation is complete.

---

## Features

### Feature 1 (existing)

- Registry, autorun, filesystem, service, and persistence-oriented static discovery.
- Normalization and export to `inventory.json`.

### Feature 2 (new)

- **Process execution tracking** via ETW (`Microsoft-Windows-Kernel-Process`).
- **PowerShell activity tracking** via ETW (`Microsoft-Windows-PowerShell`).
- **WMI activity tracking** via ETW (`Microsoft-Windows-WMI-Activity`).
- **Optional module load telemetry** via ETW (`Microsoft-Windows-Kernel-Image`).
- JSON Lines output with append mode and basic file rotation.
- Producer-consumer queue so ETW callback remains lightweight.

---

## Architecture

Execution monitor module layout:

```text
src/execution_monitor/
  run_execution_monitor.*
  types.h
  /etw
    etw_session_manager.*
    event_parser.*
  /output
    jsonl_writer.*
  /utils
    thread_safe_queue.h
  /collectors
```

Pipeline:

```text
ETW callback -> thread-safe queue -> writer thread -> execution_events.jsonl
```

### ETW usage

- Real-time ETW session managed by `EtwSessionManager`.
- Providers subscribed:
  - `Microsoft-Windows-Kernel-Process`
  - `Microsoft-Windows-PowerShell`
  - `Microsoft-Windows-WMI-Activity`
  - `Microsoft-Windows-Kernel-Image` (enabled in current implementation)

### Event normalization

`EventParser` maps ETW records to a unified `ExecutionEvent` schema with fields such as:

- `timestamp`, `event_type`, `process_name`, `process_path`
- `pid`, `ppid`, `parent_process`
- `command_line`, `user`, `integrity_level`
- `source` and provider-specific extras

### Threading model

- ETW callback only parses and enqueues.
- Dedicated writer thread flushes JSONL to disk.
- Graceful stop via signal handling.

---

## Build Instructions

### Requirements

- Windows 10/11
- CMake 3.21+
- Visual Studio 2022 Build Tools (MSVC)
- Windows SDK

### Build

```powershell
cmake -S . -B build
cmake --build build --config Release
```

---

## Usage

Interactive menu:

```powershell
.\build\Release\windows_agent.exe
```

Direct option execution (recommended for automation):

```powershell
.\build\Release\windows_agent.exe 2
```

Where:

- `1` => Static inventory feature
- `2` => Execution monitor feature
- `3` => Exit

Execution monitor runs continuously until stopped (Ctrl+C).

---

## Output Example

Feature 2 output path:

```text
C:\ProgramData\Agent\execution_events.jsonl
```

Example line:

```json
{
  "timestamp": "2026-03-15T14:03:12Z",
  "event_type": "process_start",
  "process_name": "powershell.exe",
  "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "pid": 1234,
  "ppid": 567,
  "parent_process": "winword.exe",
  "command_line": "powershell -enc ...",
  "user": "DOMAIN\\user",
  "integrity_level": "High",
  "source": "ETW"
}
```

---

## Limitations

- ETW field availability can vary by Windows build/provider configuration.
- `user` / `integrity_level` enrichment is best-effort (depends on process lifetime and permissions).
- Some PowerShell/WMI properties may be empty if provider payload does not include expected names.
- Current implementation writes locally only (no remote transport).

---

## Future Improvements

- Merge feature 1 + feature 2 into a centralized pipeline.
- Adopt a shared schema version for all telemetry types.
- Add centralized buffering/routing abstraction.
- Add SHA256 binary hashing for process images.
- Add configurable filtering to reduce noisy events.
- Add process tree reconstruction and parent cache.
- Add richer rotation/retention policy and compression.

