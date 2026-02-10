# MABAT — Windows Endpoint Visibility Agent

**MABAT (Machine Asset Baseline Analysis & Telemetry)** is a lightweight Windows endpoint inventory agent written in C/C++.
It focuses on **what is actually present on a system**, not just what Windows claims is installed.

MABAT is designed for engineers who want **clear, low-level visibility** into software and persistence mechanisms without relying on heavy frameworks, background services, or opaque tooling.

---

## What MABAT Does

MABAT scans a Windows system and builds a structured inventory of software and execution-related components.

It covers:

* Installed applications (system-wide, 32-bit on 64-bit systems, and per-user)
* Software that runs without an installer (portable or manually deployed tools)
* Microsoft Store applications (UWP / MSIX)
* Drivers and kernel components
* Manually registered services
* Scheduled tasks used for execution or persistence
* MSI packages hidden from Add/Remove Programs

The result is a **JSON inventory file** that can be reviewed locally or used later for reporting, comparison, or aggregation.

---

## Why MABAT

Most inventory tools only see what installers declare.
MABAT looks at **real system artifacts**: registry entries, filesystem locations, and native Windows APIs.

The project is guided by a few simple principles:

* See the system as it is, not as it reports itself
* Make no assumptions when data is missing
* Keep enumeration deterministic and transparent
* Avoid execution, injection, or system changes

MABAT is visibility-only by design.

---

## How It’s Built

MABAT is written in plain C/C++ and targets Windows 10 and 11.
It uses a simple CMake-based build and depends only on the Windows SDK.

Internally, enumeration logic, data modeling, and JSON output are kept separate to make the code easy to understand and extend.

---

## Project Structure

```text
mabat/
├── src/
│   ├── main.cpp
│   ├── inventory.cpp
│   ├── inventory.h
│   ├── json_builder.cpp
│   ├── json_builder.h
│   └── portable_scanner.cpp   (planned)
│
├── CMakeLists.txt
├── README.md
├── .gitignore
└── inventory.json
```

---

## Build and Run

### Requirements

* Windows 10 or 11
* Visual Studio 2022 (MSVC v143)
* Windows SDK
* CMake

### Build

```powershell
cmake -S . -B build
cmake --build build
```

### Run

```powershell
.\build\Debug\mabat-agent.exe
```

After execution, MABAT generates a JSON inventory file in the working directory.

---

## Roadmap

Planned next steps include:

* Filesystem-based detection of portable software
* Microsoft Store (UWP / MSIX) inventory
* Driver and manual service enumeration
* Scheduled task analysis
* Hidden MSI detection
* Optional network reporting

---

## What MABAT Is Not

* Not an EDR
* Not an antivirus
* Not a monitoring or enforcement tool
* Not intrusive

MABAT does not execute discovered binaries, hook APIs, inject code, or modify the system.

---

## Disclaimer

This project is intended for defensive security research, asset management, and learning Windows internals.
It performs no exploitation, enforcement, or active response.

---

## Author

Built by myself as a Windows internals and endpoint visibility research project.
