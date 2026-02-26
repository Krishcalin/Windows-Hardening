# Windows-Hardening

CIS Benchmark-based security hardening for Windows 11 Enterprise, deployable via Active Directory Group Policy.

## Overview

`CIS_Win11_Hardening.ps1` is a self-contained PowerShell script that applies **170+ security settings** based on the **CIS Microsoft Windows 11 Enterprise Benchmark v4.0.0**. It supports both Level 1 (general-purpose) and Level 2 (high-security) profiles and is designed for deployment as an AD GPO Computer Startup Script.

## Features

- **CIS Benchmark v4.0.0** compliance across 10 hardening categories
- **Level 1 / Level 2** profile support via `-Profile` parameter
- **Idempotent** — safe to run multiple times; skips already-compliant settings
- **Full backup** of current security state before any modifications
- **WhatIf mode** for dry-run analysis without changing the system
- **Detailed logging** with timestamped entries and before/after values
- **GPO-ready** — single file, no external dependencies

## Settings Coverage

| CIS Section | Category | Settings | Method |
|-------------|----------|----------|--------|
| 1.1, 1.2 | Account Policies (Password + Lockout) | 9 | `secedit` |
| 2.3 | Security Options (UAC, NTLM, SMB, LSA) | ~55 | Registry |
| 5 | System Services | 24 L1 + 13 L2 | `Set-Service` |
| 9 | Windows Defender Firewall (3 profiles) | 30 | Registry + `netsh` |
| 17 | Advanced Audit Policy | 29 | `auditpol` |
| 18 | Administrative Templates (Computer) | ~80 | Registry |
| 19 | Administrative Templates (User) | ~10 | Registry (Default User hive) |
| — | TLS/Cryptography | 24 | Registry |
| — | Network Protocols (LLMNR, NetBIOS, mDNS) | 8 | Registry |
| — | Windows Defender ASR Rules | 13 + 7 | `Set-MpPreference` + Registry |

## Requirements

- **Windows 11** (build 22000 or later)
- **PowerShell 5.1+**
- **Administrator privileges** (enforced via `#Requires -RunAsAdministrator`)
- Domain-joined for GPO deployment (standalone usage also supported)

## Usage

### Local Execution

```powershell
# Level 1 hardening (recommended for most environments)
.\CIS_Win11_Hardening.ps1 -Profile L1

# Level 2 hardening (high-security; may disable RDP, Bluetooth, printing)
.\CIS_Win11_Hardening.ps1 -Profile L2

# Dry-run — see what would change without modifying the system
.\CIS_Win11_Hardening.ps1 -Profile L1 -WhatIf

# Backup only — export current settings for review
.\CIS_Win11_Hardening.ps1 -BackupOnly

# Custom log directory
.\CIS_Win11_Hardening.ps1 -Profile L1 -LogPath "C:\SecOps\Logs"
```

### GPO Deployment via Active Directory

1. **Copy** `CIS_Win11_Hardening.ps1` to:
   ```
   \\domain\SYSVOL\domain\scripts\CIS_Win11_Hardening.ps1
   ```

2. **Create a new GPO** in Group Policy Management Console (GPMC):
   - Name: `CIS Win11 Hardening`

3. **Configure the startup script**:
   - Navigate to: `Computer Configuration` > `Policies` > `Windows Settings` > `Scripts (Startup/Shutdown)` > `Startup`
   - Click `Add` > browse to: `\\domain\SYSVOL\domain\scripts\CIS_Win11_Hardening.ps1`
   - Script Parameters: `-Profile L1`

4. **Link the GPO** to the target OU containing Windows 11 workstations

5. **(Optional) Add WMI filter** to target only Windows 11:
   ```
   SELECT * FROM Win32_OperatingSystem WHERE BuildNumber >= 22000
   ```

6. **Staged rollout**:
   - Test in an isolated lab/VM first
   - Deploy to a pilot OU with a small number of systems
   - Monitor for 1-2 weeks for compatibility issues
   - Expand to production

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Profile` | `L1` / `L2` | `L1` | CIS profile level |
| `-LogPath` | String | `$env:SystemRoot\Logs\CIS_Hardening` | Log and backup directory |
| `-BackupOnly` | Switch | — | Export current state without changes |
| `-WhatIf` | Switch | — | Dry-run mode |

## Output

- **Log file**: `<LogPath>\CIS_Hardening_<timestamp>.log`
- **Transcript**: `<LogPath>\Transcript_<timestamp>.log`
- **Backup directory**: `<LogPath>\Backup_<timestamp>\`
  - `secedit_backup.inf` — security policy export
  - `auditpol_backup.csv` — audit policy export
  - `firewall_backup.wfw` — firewall rules export
  - Registry hive exports (`.reg` files)

## Level 1 vs Level 2

| Aspect | Level 1 | Level 2 |
|--------|---------|---------|
| Target | All organizations | High-security environments |
| Impact | Minimal business disruption | May break RDP, Bluetooth, printing |
| Services disabled | 24 | 37 (adds Bluetooth, RDP, Print Spooler, WinRM, SMB Server) |
| Windows Spotlight | Not modified | Disabled |

## Disclaimer

- **Always test in a non-production environment first**
- Level 2 settings can break Remote Desktop, Bluetooth peripherals, printing, and file sharing
- Domain GPOs take precedence over local settings; review for conflicts
- A **reboot is required** after applying hardening settings
- Review the log file for any errors or warnings before deploying at scale
- This script does not cover User Rights Assignment (requires `secedit` templates or GPO import)
