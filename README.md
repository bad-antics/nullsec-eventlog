# NullSec EventLog

**Windows Event Log Analyzer** built with **C++20** - Forensic analysis and threat detection from Windows event logs.

[![Language](https://img.shields.io/badge/C++-00599C?style=flat-square&logo=cplusplus&logoColor=white)](https://isocpp.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-blue?style=flat-square)]()
[![NullSec](https://img.shields.io/badge/NullSec-Tool-red?style=flat-square)](https://bad-antics.github.io)

## Overview

NullSec EventLog is a Windows event log analyzer written in modern C++20, designed for forensic investigation and threat detection. Features MITRE ATT&CK mapping, Sysmon support, and rule-based detection.

## Features

- **Multi-Source Analysis** - Security, Sysmon, PowerShell, Defender
- **MITRE ATT&CK Mapping** - Detection rules mapped to techniques
- **Critical Event Detection** - Log clearing, credential theft, injection
- **Sysmon Integration** - Full Sysmon event ID coverage
- **PowerShell Logging** - Script block and module analysis
- **Modern C++20** - Ranges, concepts, designated initializers

## Detected Techniques

| Technique | Event Source | Event ID | MITRE |
|-----------|-------------|----------|-------|
| Brute Force | Security | 4625 | T1110 |
| Log Clearing | Security | 1102 | T1070.001 |
| Account Creation | Security | 4720 | T1136 |
| Remote Thread | Sysmon | 8 | T1055 |
| LSASS Access | Sysmon | 10 | T1003.001 |
| PowerShell IEX | PowerShell | 4104 | T1059.001 |
| Scheduled Task | Security | 4698 | T1053.005 |
| Service Install | Security | 4697 | T1543.003 |

## Installation

```bash
# Requires C++20 compiler (GCC 12+, Clang 15+, MSVC 2022)

# Clone and build
git clone https://github.com/bad-antics/nullsec-eventlog
cd nullsec-eventlog

# Linux/macOS
g++ -std=c++20 -O3 eventlog.cpp -o eventlog

# Windows (MSVC)
cl /std:c++20 /O2 eventlog.cpp
```

## Usage

### Basic Usage

```bash
# Run demo mode
./eventlog

# Analyze EVTX file
./eventlog Security.evtx

# Live event log analysis
./eventlog -l -s Sysmon

# JSON output
./eventlog -j Application.evtx
```

### Options

```
-h, --help      Show help message
-l, --live      Analyze live event logs
-f, --file      Analyze EVTX file
-j, --json      Output results as JSON
-s, --source    Filter by source (Security, Sysmon, etc.)
```

### Examples

```bash
# Export and analyze Security log
wevtutil epl Security Security.evtx
./eventlog Security.evtx

# Sysmon analysis
./eventlog -s Sysmon Sysmon.evtx

# PowerShell script block analysis
./eventlog -s PowerShell PowerShell-Operational.evtx
```

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│                    Analysis Pipeline                       │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  EVTX Input                                               │
│       │                                                   │
│       ▼                                                   │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              Event Parser                            │ │
│  │   • Security     • Application                      │ │
│  │   • Sysmon       • PowerShell                       │ │
│  └──────────────────────┬──────────────────────────────┘ │
│                         │                                 │
│                         ▼                                 │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              Rule Engine                             │ │
│  ├─────────────────────────────────────────────────────┤ │
│  │  ┌───────────────┐  ┌───────────────┐              │ │
│  │  │  Credential   │  │   Process     │              │ │
│  │  │    Theft      │  │  Injection    │              │ │
│  │  └───────────────┘  └───────────────┘              │ │
│  │  ┌───────────────┐  ┌───────────────┐              │ │
│  │  │  Persistence  │  │   Defense     │              │ │
│  │  │   Mechs       │  │   Evasion     │              │ │
│  │  └───────────────┘  └───────────────┘              │ │
│  └──────────────────────┬──────────────────────────────┘ │
│                         │                                 │
│                         ▼                                 │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              MITRE Mapper                            │ │
│  │   T1055, T1003, T1059, T1070, etc.                  │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

## Critical Event IDs

### Security Log

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4672 | Special privileges assigned |
| 4720 | Account created |
| 4728 | Member added to security group |
| 4688 | Process created |
| 4698 | Scheduled task created |
| 4697 | Service installed |
| 1102 | Audit log cleared |

### Sysmon

| Event ID | Description |
|----------|-------------|
| 1 | Process Create |
| 3 | Network Connection |
| 6 | Driver Load |
| 7 | Image Load |
| 8 | CreateRemoteThread |
| 10 | Process Access |
| 11 | File Create |
| 12-14 | Registry Events |
| 17-18 | Pipe Events |
| 22 | DNS Query |

### PowerShell

| Event ID | Description |
|----------|-------------|
| 4103 | Module Logging |
| 4104 | Script Block Logging |

## Output Example

```
Processing Events:

  [Security] Event 1102: Security log was cleared...
  [Security] Event 4625: Failed logon attempt...
  [Sysmon] Event 8: Remote thread created...
  [Sysmon] Event 10: Process memory accessed...
  [PowerShell] Event 4104: IEX (New-Object Net.WebClient)...

Security Findings:

  [CRITICAL] Log Clearing (T1070.001)
    Event ID: 1102 (Security)
    User: SYSTEM
    Security event log was cleared
    Recommendation: Investigate the activity

  [CRITICAL] LSASS Access (T1003.001)
    Event ID: 10 (Sysmon)
    User: attacker
    Process accessed LSASS memory
    Message: Process memory accessed...
    Recommendation: Investigate the activity

═══════════════════════════════════════════

  Statistics:
    Analyzed:   7 events
    Findings:   7
    Critical:   3
    High:       2
    Medium:     2
```

## Why C++20?

- **Ranges** - Expressive algorithm composition
- **Designated Initializers** - Clear struct initialization
- **Constexpr** - Compile-time computation
- **std::span** - Safe array views
- **Performance** - Native speed for large log files

## MITRE ATT&CK Coverage

- **Credential Access** - T1003, T1558
- **Persistence** - T1053, T1136, T1543
- **Defense Evasion** - T1070, T1562
- **Execution** - T1059, T1569
- **Process Injection** - T1055

## Resources

- [C++ Reference](https://en.cppreference.com/)
- [Windows Security Auditing](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/)
- [Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK](https://attack.mitre.org/)

## NullSec Toolkit

Part of the **NullSec** security toolkit collection:
- 🌐 [Portal](https://bad-antics.github.io)
- 💬 [Discord](https://discord.gg/killers)
- 📦 [GitHub](https://github.com/bad-antics)

## License

MIT License - See [LICENSE](LICENSE) for details.

---

**NullSec** - *Windows event log forensics and threat detection*
