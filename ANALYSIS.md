# Windows Event Log Analysis Guide

## Overview
Techniques for parsing and analyzing Windows event logs.

## Key Event Logs

### Security Log
- Event 4624: Successful logon
- Event 4625: Failed logon
- Event 4648: Explicit credentials
- Event 4672: Special privileges

### System Log
- Event 7045: Service installed
- Event 7036: Service state change
- Event 1074: Shutdown initiated
- Event 6005/6006: System start/stop

### Application Log
- Event 1000: Application crash
- Event 1002: Hang detected
- Application-specific events

## PowerShell Logs

### Script Block Logging
- Event 4104: Script block
- Deobfuscation attempts
- Command reconstruction

### Module Logging
- Event 4103: Module load
- Pipeline execution
- Cmdlet invocation

## Analysis Techniques

### Timeline Analysis
- Event correlation
- Activity patterns
- Gap detection
- Session reconstruction

### Indicator Detection
- Lateral movement
- Credential access
- Persistence mechanisms
- Defense evasion

## Parsing Methods
- EVTX structure
- XML extraction
- Binary carving
- Deleted log recovery

## Legal Notice
For authorized forensic analysis.
