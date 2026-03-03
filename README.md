# Windows-Hardening

CIS Benchmark-based security hardening and compliance scanning for Windows environments. Includes an **active hardening script** for Windows 11 Enterprise and **read-only compliance scanners** for Windows Server 2016, 2019, and 2022.

## Tools at a Glance

| Script | Type | Target OS | CIS Benchmark | Controls / Settings |
|--------|------|-----------|---------------|---------------------|
| `CIS_Win11_Hardening.ps1` | Hardening (applies changes) | Windows 11 Enterprise | v4.0.0 | 170+ settings |
| `CIS_WinServer2016_Scanner.ps1` | Scanner (read-only) | Windows Server 2016 | v3.0.0 | 318 controls |
| `CIS_WinServer2019_Scanner.ps1` | Scanner (read-only) | Windows Server 2019 | v3.0.1 | 360 controls |
| `CIS_WinServer2022_Scanner.ps1` | Scanner (read-only) | Windows Server 2022 | v3.0.0 | 392 controls |

---

## CIS Windows 11 Hardening

`CIS_Win11_Hardening.ps1` is a self-contained PowerShell script that **applies 170+ security settings** based on the CIS Microsoft Windows 11 Enterprise Benchmark v4.0.0. It supports both Level 1 (general-purpose) and Level 2 (high-security) profiles and is designed for deployment as an AD GPO Computer Startup Script.

### Features

- **CIS Benchmark v4.0.0** compliance across 10 hardening categories
- **Level 1 / Level 2** profile support via `-Profile` parameter
- **Idempotent** — safe to run multiple times; skips already-compliant settings
- **Full backup** of current security state before any modifications
- **WhatIf mode** for dry-run analysis without changing the system
- **Detailed logging** with timestamped entries and before/after values
- **GPO-ready** — single file, no external dependencies

### Settings Coverage

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

### Usage

#### Local Execution

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

#### GPO Deployment via Active Directory

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

### Hardening Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Profile` | `L1` / `L2` | `L1` | CIS profile level |
| `-LogPath` | String | `$env:SystemRoot\Logs\CIS_Hardening` | Log and backup directory |
| `-BackupOnly` | Switch | — | Export current state without changes |
| `-WhatIf` | Switch | — | Dry-run mode |

### Hardening Output

- **Log file**: `<LogPath>\CIS_Hardening_<timestamp>.log`
- **Transcript**: `<LogPath>\Transcript_<timestamp>.log`
- **Backup directory**: `<LogPath>\Backup_<timestamp>\`
  - `secedit_backup.inf` — security policy export
  - `auditpol_backup.csv` — audit policy export
  - `firewall_backup.wfw` — firewall rules export
  - Registry hive exports (`.reg` files)

### Level 1 vs Level 2

| Aspect | Level 1 | Level 2 |
|--------|---------|---------|
| Target | All organizations | High-security environments |
| Impact | Minimal business disruption | May break RDP, Bluetooth, printing |
| Services disabled | 24 | 37 (adds Bluetooth, RDP, Print Spooler, WinRM, SMB Server) |
| Windows Spotlight | Not modified | Disabled |

---

## CIS Windows Server Compliance Scanners

Three read-only compliance scanners that **audit the security configuration** of Windows Server 2016, 2019, and 2022 against CIS Benchmarks. These scripts **never modify the system** — they only read current settings and report PASS/FAIL/WARN per control.

### Scanner Comparison

| Aspect | Server 2016 | Server 2019 | Server 2022 |
|--------|-------------|-------------|-------------|
| Script | `CIS_WinServer2016_Scanner.ps1` | `CIS_WinServer2019_Scanner.ps1` | `CIS_WinServer2022_Scanner.ps1` |
| CIS Benchmark | v3.0.0 | v3.0.1 | v3.0.0 |
| OS Build | 14393 | 17763 | 20348 |
| Total Controls | 318 | 360 | 392 |
| Lines of Code | ~1,347 | ~1,398 | ~1,444 |

### Scanner Features

- **Read-only** — never modifies system state; safe to run on production servers
- **Data-driven architecture** — controls defined as structured arrays, evaluated by a generic engine
- **Profile support**: L1_MS, L2_MS (includes L1), L1_DC, L2_DC (includes L1), BL (BitLocker), NG (Next Generation), All
- **Auto-detection** of server role (Domain Controller / Member Server / Standalone) via `Win32_ComputerSystem.DomainRole`
- **Six check types**: Registry, Secedit, UserRight, Auditpol, Service, Firewall
- **User Rights Assignment** with SID-to-friendly-name translation (32+ well-known SIDs)
- **Three output formats**: Colored console, JSON export, interactive HTML report (dark theme with filtering)
- **Compliance score** with percentage calculation and color-coded summary
- **Exit code**: `1` if CRITICAL or HIGH failures, `0` otherwise (CI/CD friendly)

### Categories Covered

| CIS Section | Category | Check Method |
|-------------|----------|-------------|
| 1.1, 1.2 | Account Policies (Password, Lockout) | Secedit |
| 2.2 | User Rights Assignment | Secedit + SID translation |
| 2.3 | Security Options (UAC, NTLM, SMB, LSA) | Registry |
| 5 | System Services | Service status |
| 9 | Windows Firewall (Domain, Private, Public) | Firewall / Registry |
| 17 | Advanced Audit Policy | Auditpol |
| 18 | Administrative Templates (Computer) | Registry |
| 19 | Administrative Templates (User) | Registry |
| BL | BitLocker Drive Encryption | Registry |
| NG | Next Generation Security (VBS, Credential Guard, HVCI) | Registry |

### Server 2022 Highlights

The Server 2022 scanner includes **32 new controls** and **6 modified controls** over the Server 2019 baseline:

- **Post-PrintNightmare hardening** — 5 new printer RPC controls, Print Spooler elevated to L1 + CRITICAL
- **SMB hardening** — mandatory signing (CRITICAL), SMBv1 disabled, authentication rate limiter, AES-256-GCM encryption
- **Windows Defender** — Tamper Protection, Controlled Folder Access, ASR ransomware + WMI persistence rules, packed exe scanning
- **TLS deprecation** — TLS 1.0 and TLS 1.1 disabled (client + server)
- **Device Guard** — System Guard Secure Launch, Kernel DMA Protection, HVCI promoted to L1
- **DNS over HTTPS (DoH)** and **Administrator account lockout**

### Scanner Usage

```powershell
# Basic scan — Level 1 Member Server (default)
.\CIS_WinServer2022_Scanner.ps1

# Scan as Level 1 Domain Controller
.\CIS_WinServer2022_Scanner.ps1 -ScanProfile L1_DC

# Full scan with JSON and HTML export
.\CIS_WinServer2022_Scanner.ps1 -ScanProfile All -JsonPath scan.json -HtmlPath report.html

# Only show HIGH and CRITICAL findings
.\CIS_WinServer2022_Scanner.ps1 -ScanProfile L1_MS -MinSeverity HIGH

# Verbose output with detailed per-check info
.\CIS_WinServer2022_Scanner.ps1 -ScanProfile L2_MS -ShowVerbose

# Print version and exit
.\CIS_WinServer2022_Scanner.ps1 -Version
```

Replace `2022` with `2016` or `2019` for the other scanners — all three share the same CLI interface.

### Scanner Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-ScanProfile` | `L1_MS` / `L2_MS` / `L1_DC` / `L2_DC` / `BL` / `NG` / `All` | `L1_MS` | CIS profile to scan against |
| `-LogPath` | String | `$env:SystemRoot\Logs\CIS_WinServer<ver>_Scan` | Log directory |
| `-JsonPath` | String | — | Export results to JSON file |
| `-HtmlPath` | String | — | Export interactive HTML report |
| `-MinSeverity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` | `LOW` | Minimum severity to include |
| `-ShowVerbose` | Switch | — | Show detailed per-check console output |
| `-Version` | Switch | — | Print version and exit |

### Scanner Output

- **Console**: Colored PASS/FAIL/WARN per control, compliance score percentage, category breakdown
- **JSON**: Machine-readable results with all control metadata (CIS ID, status, expected vs actual values, CWE, recommendation)
- **HTML**: Self-contained dark-theme report with:
  - Compliance score card
  - Interactive filtering by status, severity, category, and free-text search
  - Expandable control details with recommendations
  - No external dependencies (all CSS/JS inline)

---

## Requirements

### Windows 11 Hardening Script
- Windows 11 (build 22000 or later)
- PowerShell 5.1+
- **Administrator privileges** (enforced via `#Requires -RunAsAdministrator`)
- Domain-joined for GPO deployment (standalone also supported)

### Server Compliance Scanners
- Windows Server 2016 / 2019 / 2022 (matched to the scanner version)
- PowerShell 5.1+
- **Administrator privileges** (required for secedit, auditpol, and service queries)
- No external modules required — fully self-contained

## Disclaimer

- **Always test in a non-production environment first**
- The **hardening script** (`CIS_Win11_Hardening.ps1`) actively modifies system settings — Level 2 can break Remote Desktop, Bluetooth peripherals, printing, and file sharing
- The **compliance scanners** (`CIS_WinServer*.ps1`) are strictly read-only and safe to run on production servers
- Domain GPOs take precedence over local settings; review for conflicts
- A **reboot may be required** after applying hardening settings
- Review log files for any errors or warnings before deploying at scale
- These scripts do not cover every CIS recommendation — User Rights Assignment checks use SID translation from `secedit` exports rather than GPO templates
