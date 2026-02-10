# Windows Endpoint Inventory Agent (C/C++)

## Overview

This project is a **low-level Windows endpoint inventory agent** written in **C/C++**, designed to enumerate **all software execution and persistence mechanisms** on a Windows system — not only what is *installed*, but also what is *present*, *hidden*, or *persisted*.

The goal is to build an **agent-grade inventory engine** similar in philosophy to EDR / asset-management agents, but:

* Fully transparent
* Locally executable
* Registry- and filesystem-driven
* No external dependencies
* Designed for future network reporting

This project deliberately avoids high-level frameworks and focuses on **Windows internals**.

---

## What This Project Does (Global Vision)

The agent builds a **complete software inventory** across multiple domains:

### 1. Installed Applications (Declared)

* Machine-wide software (HKLM)
* 32-bit software on 64-bit systems (WOW6432Node)
* Per-user installed software (HKU for all users)

### 2. Portable / Standalone Software (Observed)

* Tools unpacked manually
* No installer, no registry, no uninstall entry
* Examples:

  * NirSoft utilities
  * Admin / red-team tools
  * ZIP-deployed developer tools

### 3. Microsoft Store (UWP / MSIX) Applications

* Store-managed packages
* Per-user scoped
* Installed under WindowsApps

### 4. Drivers and Kernel Components

* Kernel-mode and filesystem drivers
* Boot / system-start components

### 5. Manually Installed Services

* Services registered directly via `sc.exe` or APIs
* Often backed by custom executables

### 6. Scheduled-Task–Based Persistence

* Tasks executing binaries or scripts
* Often used for stealthy persistence

### 7. Hidden MSI Packages (ARP Suppressed)

* MSI packages installed with `ARPSYSTEMCOMPONENT=1`
* Present in MSI database but hidden from Add/Remove Programs

All collected data is serialized into **JSON**, intended for:

* Local inspection
* Future web UI
* Future network transport (API / agent-server model)

---

## Current Project Status

### ✅ Implemented

* CMake-based build system
* Registry-based enumeration of installed software:

  * HKLM
  * WOW6432Node
  * HKU (all users)
* Clean JSON output via a dedicated JSON builder module

### 🟡 In Design / Next

* Portable filesystem-based software detection
* Microsoft Store (UWP / MSIX) enumeration
* Driver and service inventory

### ⏳ Planned (Later Steps)

* Scheduled task parsing
* Hidden MSI inventory
* Runtime correlation (processes, execution evidence)
* Optional network reporting

---

## Project Structure

```text
windows-agent/
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
└── inventory.json   (runtime output)
```

---

## Design Principles

* **No assumptions**: absence of data is valid data
* **Best-effort visibility**: do not guess unless explicitly designed to
* **Separation of concerns**:

  * Enumeration logic
  * Data model
  * Serialization
* **Safe by default**: no execution, no injection, no hooking

---

## Build Requirements

* Windows 10 / 11
* Visual Studio 2022 (MSVC v143)
* Windows SDK
* CMake

Build commands:

```powershell
cmake -S . -B build
cmake --build build
```

Run:

```powershell
.\build\Debug\windows_agent.exe
```

---

## Roadmap (High Level)

1. Portable filesystem scanning
2. UWP / MSIX inventory
3. Drivers and kernel components
4. Manual services
5. Scheduled task persistence
6. Hidden MSI detection
7. Runtime correlation (processes)
8. Network reporting layer

---

## Disclaimer

This project is for **educational, defensive, and asset-management purposes**.
It does **not exploit**, **inject**, or **modify** system state.

---

## Author

Developed as a low-level Windows internals learning and research project.
