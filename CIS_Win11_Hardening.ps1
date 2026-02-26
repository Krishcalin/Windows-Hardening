#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CIS Microsoft Windows 11 Enterprise Benchmark v4.0.0 Hardening Script

.DESCRIPTION
    Applies security hardening settings based on the CIS Microsoft Windows 11
    Enterprise Benchmark v4.0.0. Supports Level 1 (general) and Level 2
    (high-security) profiles. Designed for deployment via Active Directory
    Group Policy as a Computer Startup Script.

    GPO DEPLOYMENT:
      1. Copy to \\domain\SYSVOL\domain\scripts\CIS_Win11_Hardening.ps1
      2. Create GPO -> Computer Configuration -> Policies -> Windows Settings
         -> Scripts (Startup/Shutdown) -> Startup -> Add this script
      3. Parameters: -Profile L1   (or -Profile L2)
      4. Link GPO to target OU; optionally add WMI filter:
         SELECT * FROM Win32_OperatingSystem WHERE BuildNumber >= 22000

.PARAMETER Profile
    CIS profile level. L1 = broadly compatible. L2 = high-security (may
    break RDP, Bluetooth, printing). Default: L1

.PARAMETER LogPath
    Directory for log files and backups. Default: $env:SystemRoot\Logs\CIS_Hardening

.PARAMETER BackupOnly
    Export current settings without applying changes.

.PARAMETER WhatIf
    Dry-run mode. Logs proposed changes without modifying the system.

.EXAMPLE
    .\CIS_Win11_Hardening.ps1 -Profile L1
    .\CIS_Win11_Hardening.ps1 -Profile L2 -WhatIf
    .\CIS_Win11_Hardening.ps1 -BackupOnly

.NOTES
    Version : 1.0.0
    Based on: CIS Microsoft Windows 11 Enterprise Benchmark v4.0.0
    Requires: Windows 11 (build 22000+), PowerShell 5.1+, Administrator
    Author  : Security Hardening Project
#>

param(
    [ValidateSet("L1", "L2")]
    [string]$Profile = "L1",

    [string]$LogPath = "$env:SystemRoot\Logs\CIS_Hardening",

    [switch]$BackupOnly,

    [switch]$WhatIf
)

# ============================================================
# SCRIPT CONSTANTS
# ============================================================
$Script:VERSION   = "1.0.0"
$Script:TIMESTAMP = Get-Date -Format "yyyyMMdd_HHmmss"
$Script:LogFile   = Join-Path $LogPath "CIS_Hardening_$Script:TIMESTAMP.log"
$Script:BackupDir = Join-Path $LogPath "Backup_$Script:TIMESTAMP"
$Script:WhatIfPreference = $WhatIf.IsPresent

# Counters
$Script:Applied  = 0
$Script:Skipped  = 0
$Script:Warnings = 0
$Script:Errors   = 0

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "CHANGE", "SKIP", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"

    switch ($Level) {
        "ERROR"  { Write-Host $entry -ForegroundColor Red;    $Script:Errors++   }
        "WARN"   { Write-Host $entry -ForegroundColor Yellow; $Script:Warnings++ }
        "CHANGE" { Write-Host $entry -ForegroundColor Green;  $Script:Applied++  }
        "SKIP"   { Write-Host $entry -ForegroundColor DarkGray; $Script:Skipped++ }
        default  { Write-Host $entry -ForegroundColor Cyan }
    }

    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    Add-Content -Path $Script:LogFile -Value $entry -ErrorAction SilentlyContinue
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = "DWord",
        [string]$CIS = ""
    )
    $label = if ($CIS) { "[$CIS] " } else { "" }

    try {
        if (-not (Test-Path $Path)) {
            if (-not $Script:WhatIfPreference) {
                New-Item -Path $Path -Force | Out-Null
            }
            Write-Log "${label}Created registry key: $Path" "INFO"
        }

        $current = $null
        try { $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch {}

        if ($current -eq $Value) {
            Write-Log "${label}$Path\$Name = $Value (already set)" "SKIP"
            return
        }

        if ($Script:WhatIfPreference) {
            Write-Log "${label}WOULD SET $Path\$Name = $Value (current: $current)" "INFO"
            return
        }

        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Log "${label}$Path\$Name : $current -> $Value" "CHANGE"
    }
    catch {
        Write-Log "${label}FAILED to set $Path\$Name : $_" "ERROR"
    }
}

function Set-AuditSubcategory {
    param(
        [string]$Subcategory,
        [bool]$Success = $false,
        [bool]$Failure = $false,
        [string]$CIS = ""
    )
    $label = if ($CIS) { "[$CIS] " } else { "" }
    $successFlag = if ($Success) { "/success:enable" } else { "/success:disable" }
    $failureFlag = if ($Failure) { "/failure:enable" } else { "/failure:disable" }

    if ($Script:WhatIfPreference) {
        Write-Log "${label}WOULD SET audit: $Subcategory Success=$Success Failure=$Failure" "INFO"
        return
    }

    try {
        $result = & auditpol /set /subcategory:"$Subcategory" $successFlag $failureFlag 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "${label}Audit policy: $Subcategory -> Success=$Success Failure=$Failure" "CHANGE"
        } else {
            Write-Log "${label}auditpol failed for $Subcategory : $result" "ERROR"
        }
    }
    catch {
        Write-Log "${label}auditpol exception for $Subcategory : $_" "ERROR"
    }
}

function Test-Prerequisites {
    Write-Log "=== Pre-flight Checks ===" "INFO"

    # Check OS build
    $build = [System.Environment]::OSVersion.Version.Build
    if ($build -lt 22000) {
        Write-Log "WARNING: OS build $build < 22000. This script targets Windows 11." "WARN"
    } else {
        Write-Log "OS build $build (Windows 11) confirmed." "INFO"
    }

    # Check PowerShell version
    $psVer = $PSVersionTable.PSVersion
    Write-Log "PowerShell version: $psVer" "INFO"

    # Check domain membership
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs.PartOfDomain) {
        Write-Log "Machine is domain-joined ($($cs.Domain)). Domain GPOs may override local settings." "WARN"
    } else {
        Write-Log "Machine is standalone/workgroup." "INFO"
    }

    Write-Log "Profile: $Profile | WhatIf: $($Script:WhatIfPreference) | BackupOnly: $($BackupOnly.IsPresent)" "INFO"
}

function Backup-CurrentSettings {
    Write-Log "=== Backing Up Current Settings ===" "INFO"

    if (-not (Test-Path $Script:BackupDir)) {
        New-Item -Path $Script:BackupDir -ItemType Directory -Force | Out-Null
    }

    # secedit export
    try {
        $secCfg = Join-Path $Script:BackupDir "secedit_backup.inf"
        & secedit /export /cfg "$secCfg" 2>&1 | Out-Null
        Write-Log "Exported secedit policy to $secCfg" "INFO"
    } catch {
        Write-Log "Failed to export secedit: $_" "WARN"
    }

    # auditpol export
    try {
        $auditCsv = Join-Path $Script:BackupDir "auditpol_backup.csv"
        & auditpol /backup /file:"$auditCsv" 2>&1 | Out-Null
        Write-Log "Exported audit policy to $auditCsv" "INFO"
    } catch {
        Write-Log "Failed to export auditpol: $_" "WARN"
    }

    # Firewall export
    try {
        $fwFile = Join-Path $Script:BackupDir "firewall_backup.wfw"
        & netsh advfirewall export "$fwFile" 2>&1 | Out-Null
        Write-Log "Exported firewall policy to $fwFile" "INFO"
    } catch {
        Write-Log "Failed to export firewall: $_" "WARN"
    }

    # Key registry hives
    $regPaths = @(
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
        "HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog"
    )
    foreach ($rp in $regPaths) {
        $safeName = ($rp -replace '[\\:]', '_')
        $regFile = Join-Path $Script:BackupDir "$safeName.reg"
        try {
            & reg export $rp "$regFile" /y 2>&1 | Out-Null
            Write-Log "Exported $rp" "INFO"
        } catch {
            Write-Log "Failed to export $rp : $_" "WARN"
        }
    }

    Write-Log "Backup complete: $Script:BackupDir" "INFO"
}

# ============================================================
# SECTION 1 — ACCOUNT POLICIES (CIS 1.1 Password, 1.2 Lockout)
# ============================================================

function Set-AccountPolicies {
    Write-Log "=== Section 1: Account Policies ===" "INFO"

    # Export current security policy to a temp INF
    $tempDir  = Join-Path $env:TEMP "CIS_Hardening_$Script:TIMESTAMP"
    $infFile  = Join-Path $tempDir "secpol.inf"
    $sdbFile  = Join-Path $tempDir "secpol.sdb"

    if (-not (Test-Path $tempDir)) {
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
    }

    & secedit /export /cfg "$infFile" 2>&1 | Out-Null
    if (-not (Test-Path $infFile)) {
        Write-Log "Failed to export security policy. Skipping account policies." "ERROR"
        return
    }

    $content = Get-Content $infFile -Raw

    # Helper: set or insert a value in the INF [System Access] section
    function Set-InfValue {
        param([string]$Key, [string]$Val, [string]$CIS)
        $label = if ($CIS) { "[$CIS] " } else { "" }

        if ($Script:WhatIfPreference) {
            Write-Log "${label}WOULD SET $Key = $Val in security policy" "INFO"
            return
        }

        # Match existing key
        $pattern = "(?m)^$Key\s*=\s*.*$"
        if ($content -match $pattern) {
            $oldVal = ($content | Select-String -Pattern $pattern).Matches[0].Value
            if ($oldVal -eq "$Key = $Val") {
                Write-Log "${label}$Key = $Val (already set)" "SKIP"
                return
            }
            $Script:content = $content -replace $pattern, "$Key = $Val"
            $content = $Script:content
            Set-Variable -Name content -Value $Script:content -Scope 1
            Write-Log "${label}$Key -> $Val" "CHANGE"
        } else {
            # Insert under [System Access]
            $content = $content -replace "(\[System Access\])", "`$1`r`n$Key = $Val"
            Set-Variable -Name content -Value $content -Scope 1
            Write-Log "${label}$Key = $Val (inserted)" "CHANGE"
        }
    }

    # CIS 1.1.1 — Enforce password history: 24 or more
    Set-InfValue "PasswordHistorySize" "24" "CIS 1.1.1"

    # CIS 1.1.2 — Maximum password age: 365 or fewer, not 0
    Set-InfValue "MaximumPasswordAge" "365" "CIS 1.1.2"

    # CIS 1.1.3 — Minimum password age: 1 or more
    Set-InfValue "MinimumPasswordAge" "1" "CIS 1.1.3"

    # CIS 1.1.4 — Minimum password length: 14 or more
    Set-InfValue "MinimumPasswordLength" "14" "CIS 1.1.4"

    # CIS 1.1.5 — Password must meet complexity requirements
    Set-InfValue "PasswordComplexity" "1" "CIS 1.1.5"

    # CIS 1.1.6 — Relax minimum password length limits: Enabled
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SAM" `
        -Name "RelaxMinimumPasswordLengthLimits" -Value 1 -CIS "CIS 1.1.6"

    # CIS 1.1.7 — Store passwords using reversible encryption: Disabled
    Set-InfValue "ClearTextPassword" "0" "CIS 1.1.7"

    # CIS 1.2.1 — Account lockout duration: 15 or more minutes
    Set-InfValue "LockoutDuration" "15" "CIS 1.2.1"

    # CIS 1.2.2 — Account lockout threshold: 5 or fewer, not 0
    Set-InfValue "LockoutBadCount" "5" "CIS 1.2.2"

    # CIS 1.2.3 — Reset account lockout counter after: 15 or more minutes
    Set-InfValue "ResetLockoutCount" "15" "CIS 1.2.3"

    # Apply the modified INF
    if (-not $Script:WhatIfPreference) {
        Set-Content -Path $infFile -Value $content -Force
        & secedit /configure /db "$sdbFile" /cfg "$infFile" /areas SECURITYPOLICY 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Account policies applied via secedit." "INFO"
        } else {
            Write-Log "secedit /configure returned exit code $LASTEXITCODE" "ERROR"
        }
    }

    # Cleanup temp
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

# ============================================================
# SECTION 2.3 — LOCAL POLICIES: SECURITY OPTIONS
# ============================================================

function Set-SecurityOptions {
    Write-Log "=== Section 2.3: Security Options ===" "INFO"

    # --- 2.3.1 Accounts ---
    # CIS 2.3.1.1 — Block Microsoft accounts
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "NoConnectedUser" 3 -CIS "CIS 2.3.1.1"

    # CIS 2.3.1.2 — Guest account status: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "EnableGuestAccount" 0 -CIS "CIS 2.3.1.2"

    # CIS 2.3.1.3 — Limit local account use of blank passwords to console only
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "LimitBlankPasswordUse" 1 -CIS "CIS 2.3.1.3"

    # --- 2.3.2 Audit ---
    # CIS 2.3.2.1 — Force audit policy subcategory settings
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "SCENoApplyLegacyAuditPolicy" 1 -CIS "CIS 2.3.2.1"

    # CIS 2.3.2.2 — Shut down system immediately if unable to log security audits
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "CrashOnAuditFail" 0 -CIS "CIS 2.3.2.2"

    # --- 2.3.4 Devices ---
    # CIS 2.3.4.1 — Prevent users from installing printer drivers
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" `
        "AddPrinterDrivers" 1 -CIS "CIS 2.3.4.1"

    # --- 2.3.6 Domain member ---
    # CIS 2.3.6.1 — Digitally encrypt or sign secure channel data (Always)
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
        "RequireSignOrSeal" 1 -CIS "CIS 2.3.6.1"

    # CIS 2.3.6.2 — Digitally encrypt secure channel data (When possible)
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
        "SealSecureChannel" 1 -CIS "CIS 2.3.6.2"

    # CIS 2.3.6.3 — Digitally sign secure channel data (When possible)
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
        "SignSecureChannel" 1 -CIS "CIS 2.3.6.3"

    # CIS 2.3.6.4 — Disable machine account password changes: Disabled
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
        "DisablePasswordChange" 0 -CIS "CIS 2.3.6.4"

    # CIS 2.3.6.5 — Maximum machine account password age: 30 days
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
        "MaximumPasswordAge" 30 -CIS "CIS 2.3.6.5"

    # CIS 2.3.6.6 — Require strong session key
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
        "RequireStrongKey" 1 -CIS "CIS 2.3.6.6"

    # --- 2.3.7 Interactive logon ---
    # CIS 2.3.7.1 — Do not require CTRL+ALT+DEL: Disabled (require it)
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "DisableCAD" 0 -CIS "CIS 2.3.7.1"

    # CIS 2.3.7.2 — Don't display last signed-in
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "DontDisplayLastUserName" 1 -CIS "CIS 2.3.7.2"

    # CIS 2.3.7.3 — Machine inactivity limit: 900 seconds or fewer
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "InactivityTimeoutSecs" 900 -CIS "CIS 2.3.7.3"

    # CIS 2.3.7.4 — Smart card removal behavior: Lock Workstation
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
        "ScRemoveOption" 1 -Type String -CIS "CIS 2.3.7.4"

    # --- 2.3.8 Microsoft network client ---
    # CIS 2.3.8.1 — Digitally sign communications (always)
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
        "RequireSecuritySignature" 1 -CIS "CIS 2.3.8.1"

    # CIS 2.3.8.2 — Digitally sign communications (if server agrees)
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
        "EnableSecuritySignature" 1 -CIS "CIS 2.3.8.2"

    # CIS 2.3.8.3 — Send unencrypted password to third-party SMB servers: Disabled
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
        "EnablePlainTextPassword" 0 -CIS "CIS 2.3.8.3"

    # --- 2.3.9 Microsoft network server ---
    # CIS 2.3.9.1 — Amount of idle time required before suspending session: 15 min
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        "AutoDisconnect" 15 -CIS "CIS 2.3.9.1"

    # CIS 2.3.9.2 — Digitally sign communications (always)
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        "RequireSecuritySignature" 1 -CIS "CIS 2.3.9.2"

    # CIS 2.3.9.3 — Digitally sign communications (if client agrees)
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        "EnableSecuritySignature" 1 -CIS "CIS 2.3.9.3"

    # CIS 2.3.9.4 — Disconnect clients when logon hours expire: Enabled
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        "EnableForcedLogOff" 1 -CIS "CIS 2.3.9.4"

    # CIS 2.3.9.5 — SMB server name hardening level: validation required
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        "SmbServerNameHardeningLevel" 1 -CIS "CIS 2.3.9.5"

    # --- 2.3.10 Network access ---
    # CIS 2.3.10.1 — Allow anonymous SID/Name translation: Disabled (via secedit, skip here)

    # CIS 2.3.10.2 — Do not allow anonymous enumeration of SAM accounts
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "RestrictAnonymousSAM" 1 -CIS "CIS 2.3.10.2"

    # CIS 2.3.10.3 — Do not allow anonymous enumeration of SAM accounts and shares
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "RestrictAnonymous" 1 -CIS "CIS 2.3.10.3"

    # CIS 2.3.10.4 — Do not allow storage of passwords and credentials for network auth
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "DisableDomainCreds" 1 -CIS "CIS 2.3.10.4"

    # CIS 2.3.10.5 — Let Everyone permissions apply to anonymous users: Disabled
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "EveryoneIncludesAnonymous" 0 -CIS "CIS 2.3.10.5"

    # CIS 2.3.10.7 — Named Pipes that can be accessed anonymously: None
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        "NullSessionPipes" "" -Type MultiString -CIS "CIS 2.3.10.7"

    # CIS 2.3.10.9 — Restrict anonymous access to Named Pipes and Shares
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        "RestrictNullSessAccess" 1 -CIS "CIS 2.3.10.9"

    # CIS 2.3.10.10 — Restrict remote calls to SAM (hardened SDDL)
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "RestrictRemoteSAM" "O:BAG:BAD:(A;;RC;;;BA)" -Type String -CIS "CIS 2.3.10.10"

    # CIS 2.3.10.11 — Shares that can be accessed anonymously: None
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        "NullSessionShares" "" -Type MultiString -CIS "CIS 2.3.10.11"

    # CIS 2.3.10.12 — Sharing and security model for local accounts: Classic
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "ForceGuest" 0 -CIS "CIS 2.3.10.12"

    # --- 2.3.11 Network security ---
    # CIS 2.3.11.1 — Allow Local System to use computer identity for NTLM
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "UseMachineId" 1 -CIS "CIS 2.3.11.1"

    # CIS 2.3.11.2 — Allow LocalSystem NULL session fallback: Disabled
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
        "AllowNullSessionFallback" 0 -CIS "CIS 2.3.11.2"

    # CIS 2.3.11.3 — Allow PKU2U authentication requests: Disabled
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u" `
        "AllowOnlineID" 0 -CIS "CIS 2.3.11.3"

    # CIS 2.3.11.4 — Configure encryption types for Kerberos
    # AES128_HMAC_SHA1 + AES256_HMAC_SHA1 + Future = 2147483640
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
        "SupportedEncryptionTypes" 2147483640 -CIS "CIS 2.3.11.4"

    # CIS 2.3.11.5 — Do not store LAN Manager hash value on next password change
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "NoLMHash" 1 -CIS "CIS 2.3.11.5"

    # CIS 2.3.11.6 — LAN Manager authentication level: NTLMv2 only, refuse LM & NTLM
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "LmCompatibilityLevel" 5 -CIS "CIS 2.3.11.6"

    # CIS 2.3.11.7 — LDAP client signing requirements: Negotiate Signing
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "LDAPClientIntegrity" 1 -CIS "CIS 2.3.11.7"

    # CIS 2.3.11.8 — Minimum session security for NTLM SSP clients: NTLMv2 + 128-bit
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
        "NTLMMinClientSec" 537395200 -CIS "CIS 2.3.11.8"

    # CIS 2.3.11.9 — Minimum session security for NTLM SSP servers: NTLMv2 + 128-bit
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
        "NTLMMinServerSec" 537395200 -CIS "CIS 2.3.11.9"

    # --- 2.3.14 Shutdown ---
    # CIS 2.3.14.1 — Allow system to be shut down without having to log on: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "ShutdownWithoutLogon" 0 -CIS "CIS 2.3.14.1"

    # --- 2.3.17 User Account Control ---
    # CIS 2.3.17.1 — UAC: Admin Approval Mode for Built-in Administrator
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "FilterAdministratorToken" 1 -CIS "CIS 2.3.17.1"

    # CIS 2.3.17.2 — UAC: Behavior of elevation prompt for admins
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "ConsentPromptBehaviorAdmin" 2 -CIS "CIS 2.3.17.2"

    # CIS 2.3.17.3 — UAC: Behavior of elevation prompt for standard users: Auto deny
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "ConsentPromptBehaviorUser" 0 -CIS "CIS 2.3.17.3"

    # CIS 2.3.17.4 — UAC: Detect application installations and prompt for elevation
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "EnableInstallerDetection" 1 -CIS "CIS 2.3.17.4"

    # CIS 2.3.17.5 — UAC: Only elevate UIAccess applications installed in secure locations
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "EnableSecureUIAPaths" 1 -CIS "CIS 2.3.17.5"

    # CIS 2.3.17.6 — UAC: Run all administrators in Admin Approval Mode
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "EnableLUA" 1 -CIS "CIS 2.3.17.6"

    # CIS 2.3.17.7 — UAC: Switch to secure desktop when prompting for elevation
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "PromptOnSecureDesktop" 1 -CIS "CIS 2.3.17.7"

    # CIS 2.3.17.8 — UAC: Virtualize file and registry write failures to per-user locations
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "EnableVirtualization" 1 -CIS "CIS 2.3.17.8"

    # --- Additional Security Options ---
    # Disable WDigest credential caching (anti-Mimikatz)
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
        "UseLogonCredential" 0 -CIS "CIS 2.3.11 (WDigest)"

    # Disable AutoAdminLogon
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
        "AutoAdminLogon" 0 -Type String -CIS "CIS 2.3.7 (AutoLogon)"

    # Screen saver grace period: 5 seconds or fewer
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
        "ScreenSaverGracePeriod" 5 -Type String -CIS "CIS 2.3.7 (ScreenSaver)"

    # Credential Guard / LSA protection
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
        "LsaCfgFlags" 1 -CIS "CIS 18.3.6 (Credential Guard)"

    # SMB compression disable (CVE-2020-0796 mitigation)
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        "DisableCompression" 1 -CIS "CIS 2.3.9 (SMB Compression)"
}

# ============================================================
# SECTION 5 — SYSTEM SERVICES
# ============================================================

function Set-ServiceHardening {
    Write-Log "=== Section 5: System Services ===" "INFO"

    # Level 1 services to disable
    $L1Services = @(
        @{ Name = "Browser";        CIS = "CIS 5.1"  }   # Computer Browser
        @{ Name = "IISADMIN";       CIS = "CIS 5.2"  }   # IIS Admin Service
        @{ Name = "irmon";          CIS = "CIS 5.3"  }   # Infrared Monitor
        @{ Name = "SharedAccess";   CIS = "CIS 5.4"  }   # Internet Connection Sharing
        @{ Name = "LxssManager";    CIS = "CIS 5.5"  }   # Linux Subsystem Manager
        @{ Name = "FTPSVC";         CIS = "CIS 5.6"  }   # Microsoft FTP Service
        @{ Name = "sshd";           CIS = "CIS 5.7"  }   # OpenSSH SSH Server
        @{ Name = "RpcLocator";     CIS = "CIS 5.8"  }   # Remote Procedure Call Locator
        @{ Name = "RemoteAccess";   CIS = "CIS 5.9"  }   # Routing and Remote Access
        @{ Name = "simptcp";        CIS = "CIS 5.10" }   # Simple TCP/IP Services
        @{ Name = "SSDPSRV";        CIS = "CIS 5.11" }   # SSDP Discovery
        @{ Name = "upnphost";       CIS = "CIS 5.12" }   # UPnP Device Host
        @{ Name = "WMSvc";          CIS = "CIS 5.13" }   # Web Management Service
        @{ Name = "W3SVC";          CIS = "CIS 5.14" }   # World Wide Web Pub Service
        @{ Name = "XblAuthManager"; CIS = "CIS 5.15" }   # Xbox Accessory Management
        @{ Name = "XblGameSave";    CIS = "CIS 5.16" }   # Xbox Game Monitoring
        @{ Name = "XboxGipSvc";     CIS = "CIS 5.17" }   # Xbox Game Input Protocol
        @{ Name = "XboxNetApiSvc";  CIS = "CIS 5.18" }   # Xbox Live Networking
        @{ Name = "MapsBroker";     CIS = "CIS 5.19" }   # Downloaded Maps Manager
        @{ Name = "lfsvc";          CIS = "CIS 5.20" }   # Geolocation Service
        @{ Name = "MSiSCSI";        CIS = "CIS 5.21" }   # Microsoft iSCSI Initiator
        @{ Name = "RemoteRegistry"; CIS = "CIS 5.22" }   # Remote Registry
        @{ Name = "Spooler";        CIS = "CIS 5.23" }   # Print Spooler (L1 if not needed)
        @{ Name = "WinHttpAutoProxySvc"; CIS = "CIS 5.24" } # WinHTTP Web Proxy Auto-Discovery
    )

    # Level 2 additional services
    $L2Services = @(
        @{ Name = "BTAGService";    CIS = "CIS 5.25 (L2)" } # Bluetooth Audio Gateway
        @{ Name = "bthserv";        CIS = "CIS 5.26 (L2)" } # Bluetooth Support
        @{ Name = "TermService";    CIS = "CIS 5.27 (L2)" } # Remote Desktop Services
        @{ Name = "UmRdpService";   CIS = "CIS 5.28 (L2)" } # Remote Desktop UserMode Port Redirector
        @{ Name = "SessionEnv";     CIS = "CIS 5.29 (L2)" } # Remote Desktop Configuration
        @{ Name = "WinRM";          CIS = "CIS 5.30 (L2)" } # Windows Remote Management
        @{ Name = "LanmanServer";   CIS = "CIS 5.31 (L2)" } # Server (SMB file sharing)
        @{ Name = "WpnService";     CIS = "CIS 5.32 (L2)" } # Windows Push Notifications
        @{ Name = "PushToInstall";  CIS = "CIS 5.33 (L2)" } # Push To Install Service
        @{ Name = "lltdsvc";        CIS = "CIS 5.34 (L2)" } # Link-Layer Topology Discovery Mapper
        @{ Name = "SNMPTRAP";       CIS = "CIS 5.35 (L2)" } # SNMP Trap
        @{ Name = "sacsvr";         CIS = "CIS 5.36 (L2)" } # Special Administration Console Helper
        @{ Name = "WerSvc";         CIS = "CIS 5.37 (L2)" } # Windows Error Reporting
    )

    $allServices = $L1Services
    if ($Profile -eq "L2") {
        $allServices += $L2Services
    }

    foreach ($svc in $allServices) {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-Log "[$($svc.CIS)] Service '$($svc.Name)' not found (not installed)" "SKIP"
            continue
        }

        if ($service.StartType -eq 'Disabled') {
            Write-Log "[$($svc.CIS)] Service '$($svc.Name)' already Disabled" "SKIP"
            continue
        }

        if ($Script:WhatIfPreference) {
            Write-Log "[$($svc.CIS)] WOULD disable service '$($svc.Name)' (current: $($service.StartType))" "INFO"
            continue
        }

        try {
            # Stop the service first if running
            if ($service.Status -eq 'Running') {
                Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
            }
            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
            Write-Log "[$($svc.CIS)] Service '$($svc.Name)': $($service.StartType) -> Disabled" "CHANGE"
        }
        catch {
            Write-Log "[$($svc.CIS)] Failed to disable '$($svc.Name)': $_" "ERROR"
        }
    }
}

# ============================================================
# SECTION 9 — WINDOWS DEFENDER FIREWALL
# ============================================================

function Set-FirewallConfiguration {
    Write-Log "=== Section 9: Windows Defender Firewall ===" "INFO"

    $fwBase = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall"

    # --- 9.1 Domain Profile ---
    $domPath = "$fwBase\DomainProfile"
    $domLog  = "$domPath\Logging"

    # CIS 9.1.1 — Domain: Firewall state: On
    Set-RegistryValue $domPath "EnableFirewall" 1 -CIS "CIS 9.1.1"

    # CIS 9.1.2 — Domain: Inbound connections: Block
    Set-RegistryValue $domPath "DefaultInboundAction" 1 -CIS "CIS 9.1.2"

    # CIS 9.1.3 — Domain: Outbound connections: Allow
    Set-RegistryValue $domPath "DefaultOutboundAction" 0 -CIS "CIS 9.1.3"

    # CIS 9.1.4 — Domain: Display notification: No
    Set-RegistryValue $domPath "DisableNotifications" 1 -CIS "CIS 9.1.4"

    # CIS 9.1.5 — Domain: Log file path
    Set-RegistryValue $domLog "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\domainfw.log" -Type String -CIS "CIS 9.1.5"

    # CIS 9.1.6 — Domain: Log file size: 16384 KB
    Set-RegistryValue $domLog "LogFileSize" 16384 -CIS "CIS 9.1.6"

    # CIS 9.1.7 — Domain: Log dropped packets: Yes
    Set-RegistryValue $domLog "LogDroppedPackets" 1 -CIS "CIS 9.1.7"

    # CIS 9.1.8 — Domain: Log successful connections: Yes
    Set-RegistryValue $domLog "LogSuccessfulConnections" 1 -CIS "CIS 9.1.8"

    # --- 9.2 Private Profile ---
    $privPath = "$fwBase\PrivateProfile"
    $privLog  = "$privPath\Logging"

    # CIS 9.2.1 — Private: Firewall state: On
    Set-RegistryValue $privPath "EnableFirewall" 1 -CIS "CIS 9.2.1"

    # CIS 9.2.2 — Private: Inbound connections: Block
    Set-RegistryValue $privPath "DefaultInboundAction" 1 -CIS "CIS 9.2.2"

    # CIS 9.2.3 — Private: Outbound connections: Allow
    Set-RegistryValue $privPath "DefaultOutboundAction" 0 -CIS "CIS 9.2.3"

    # CIS 9.2.4 — Private: Display notification: No
    Set-RegistryValue $privPath "DisableNotifications" 1 -CIS "CIS 9.2.4"

    # CIS 9.2.5 — Private: Log file path
    Set-RegistryValue $privLog "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\privatefw.log" -Type String -CIS "CIS 9.2.5"

    # CIS 9.2.6 — Private: Log file size: 16384 KB
    Set-RegistryValue $privLog "LogFileSize" 16384 -CIS "CIS 9.2.6"

    # CIS 9.2.7 — Private: Log dropped packets: Yes
    Set-RegistryValue $privLog "LogDroppedPackets" 1 -CIS "CIS 9.2.7"

    # CIS 9.2.8 — Private: Log successful connections: Yes
    Set-RegistryValue $privLog "LogSuccessfulConnections" 1 -CIS "CIS 9.2.8"

    # --- 9.3 Public Profile ---
    $pubPath = "$fwBase\PublicProfile"
    $pubLog  = "$pubPath\Logging"

    # CIS 9.3.1 — Public: Firewall state: On
    Set-RegistryValue $pubPath "EnableFirewall" 1 -CIS "CIS 9.3.1"

    # CIS 9.3.2 — Public: Inbound connections: Block
    Set-RegistryValue $pubPath "DefaultInboundAction" 1 -CIS "CIS 9.3.2"

    # CIS 9.3.3 — Public: Outbound connections: Allow
    Set-RegistryValue $pubPath "DefaultOutboundAction" 0 -CIS "CIS 9.3.3"

    # CIS 9.3.4 — Public: Display notification: No
    Set-RegistryValue $pubPath "DisableNotifications" 1 -CIS "CIS 9.3.4"

    # CIS 9.3.5 — Public: Apply local firewall rules: No
    Set-RegistryValue $pubPath "AllowLocalPolicyMerge" 0 -CIS "CIS 9.3.5"

    # CIS 9.3.6 — Public: Apply local connection security rules: No
    Set-RegistryValue $pubPath "AllowLocalIPsecPolicyMerge" 0 -CIS "CIS 9.3.6"

    # CIS 9.3.7 — Public: Log file path
    Set-RegistryValue $pubLog "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\publicfw.log" -Type String -CIS "CIS 9.3.7"

    # CIS 9.3.8 — Public: Log file size: 16384 KB
    Set-RegistryValue $pubLog "LogFileSize" 16384 -CIS "CIS 9.3.8"

    # CIS 9.3.9 — Public: Log dropped packets: Yes
    Set-RegistryValue $pubLog "LogDroppedPackets" 1 -CIS "CIS 9.3.9"

    # CIS 9.3.10 — Public: Log successful connections: Yes
    Set-RegistryValue $pubLog "LogSuccessfulConnections" 1 -CIS "CIS 9.3.10"

    # Apply firewall settings immediately via netsh
    if (-not $Script:WhatIfPreference) {
        Write-Log "Applying firewall profiles via netsh..." "INFO"
        try {
            & netsh advfirewall set domainprofile state on 2>&1 | Out-Null
            & netsh advfirewall set privateprofile state on 2>&1 | Out-Null
            & netsh advfirewall set publicprofile state on 2>&1 | Out-Null
            & netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound 2>&1 | Out-Null
            Write-Log "Firewall profiles activated via netsh" "INFO"
        } catch {
            Write-Log "netsh firewall activation failed: $_" "WARN"
        }
    }
}

# ============================================================
# SECTION 17 — ADVANCED AUDIT POLICY CONFIGURATION
# ============================================================

function Set-AuditPolicies {
    Write-Log "=== Section 17: Advanced Audit Policy ===" "INFO"

    # Force advanced audit policy to override legacy
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "SCENoApplyLegacyAuditPolicy" 1 -CIS "CIS 17 (prerequisite)"

    # --- 17.1 Account Logon ---
    # CIS 17.1.1 — Credential Validation: Success and Failure
    Set-AuditSubcategory "Credential Validation" -Success $true -Failure $true -CIS "CIS 17.1.1"

    # --- 17.2 Account Management ---
    # CIS 17.2.1 — Application Group Management: Success and Failure
    Set-AuditSubcategory "Application Group Management" -Success $true -Failure $true -CIS "CIS 17.2.1"

    # CIS 17.2.2 — Computer Account Management: Success
    Set-AuditSubcategory "Computer Account Management" -Success $true -Failure $false -CIS "CIS 17.2.2"

    # CIS 17.2.3 — Other Account Management Events: Success and Failure
    Set-AuditSubcategory "Other Account Management Events" -Success $true -Failure $true -CIS "CIS 17.2.3"

    # CIS 17.2.4 — Security Group Management: Success
    Set-AuditSubcategory "Security Group Management" -Success $true -Failure $false -CIS "CIS 17.2.4"

    # CIS 17.2.5 — User Account Management: Success and Failure
    Set-AuditSubcategory "User Account Management" -Success $true -Failure $true -CIS "CIS 17.2.5"

    # --- 17.3 Detailed Tracking ---
    # CIS 17.3.1 — Plug and Play Events: Success
    Set-AuditSubcategory "Plug and Play Events" -Success $true -Failure $false -CIS "CIS 17.3.1"

    # CIS 17.3.2 — Process Creation: Success
    Set-AuditSubcategory "Process Creation" -Success $true -Failure $false -CIS "CIS 17.3.2"

    # --- 17.5 Logon/Logoff ---
    # CIS 17.5.1 — Account Lockout: Failure
    Set-AuditSubcategory "Account Lockout" -Success $false -Failure $true -CIS "CIS 17.5.1"

    # CIS 17.5.2 — Group Membership: Success
    Set-AuditSubcategory "Group Membership" -Success $true -Failure $false -CIS "CIS 17.5.2"

    # CIS 17.5.3 — Logon: Success and Failure
    Set-AuditSubcategory "Logon" -Success $true -Failure $true -CIS "CIS 17.5.3"

    # CIS 17.5.4 — Logoff: Success
    Set-AuditSubcategory "Logoff" -Success $true -Failure $false -CIS "CIS 17.5.4"

    # CIS 17.5.5 — Other Logon/Logoff Events: Success and Failure
    Set-AuditSubcategory "Other Logon/Logoff Events" -Success $true -Failure $true -CIS "CIS 17.5.5"

    # CIS 17.5.6 — Special Logon: Success
    Set-AuditSubcategory "Special Logon" -Success $true -Failure $false -CIS "CIS 17.5.6"

    # --- 17.6 Object Access ---
    # CIS 17.6.1 — Detailed File Share: Failure
    Set-AuditSubcategory "Detailed File Share" -Success $false -Failure $true -CIS "CIS 17.6.1"

    # CIS 17.6.2 — File Share: Success and Failure
    Set-AuditSubcategory "File Share" -Success $true -Failure $true -CIS "CIS 17.6.2"

    # CIS 17.6.3 — Other Object Access Events: Success and Failure
    Set-AuditSubcategory "Other Object Access Events" -Success $true -Failure $true -CIS "CIS 17.6.3"

    # CIS 17.6.4 — Removable Storage: Success and Failure
    Set-AuditSubcategory "Removable Storage" -Success $true -Failure $true -CIS "CIS 17.6.4"

    # --- 17.7 Policy Change ---
    # CIS 17.7.1 — Audit Policy Change: Success
    Set-AuditSubcategory "Audit Policy Change" -Success $true -Failure $false -CIS "CIS 17.7.1"

    # CIS 17.7.2 — Authentication Policy Change: Success
    Set-AuditSubcategory "Authentication Policy Change" -Success $true -Failure $false -CIS "CIS 17.7.2"

    # CIS 17.7.3 — Authorization Policy Change: Success
    Set-AuditSubcategory "Authorization Policy Change" -Success $true -Failure $false -CIS "CIS 17.7.3"

    # CIS 17.7.4 — MPSSVC Rule-Level Policy Change: Success and Failure
    Set-AuditSubcategory "MPSSVC Rule-Level Policy Change" -Success $true -Failure $true -CIS "CIS 17.7.4"

    # --- 17.8 Privilege Use ---
    # CIS 17.8.1 — Sensitive Privilege Use: Success and Failure
    Set-AuditSubcategory "Sensitive Privilege Use" -Success $true -Failure $true -CIS "CIS 17.8.1"

    # --- 17.9 System ---
    # CIS 17.9.1 — IPsec Driver: Success and Failure
    Set-AuditSubcategory "IPsec Driver" -Success $true -Failure $true -CIS "CIS 17.9.1"

    # CIS 17.9.2 — Other System Events: Success and Failure
    Set-AuditSubcategory "Other System Events" -Success $true -Failure $true -CIS "CIS 17.9.2"

    # CIS 17.9.3 — Security State Change: Success
    Set-AuditSubcategory "Security State Change" -Success $true -Failure $false -CIS "CIS 17.9.3"

    # CIS 17.9.4 — Security System Extension: Success
    Set-AuditSubcategory "Security System Extension" -Success $true -Failure $false -CIS "CIS 17.9.4"

    # CIS 17.9.5 — System Integrity: Success and Failure
    Set-AuditSubcategory "System Integrity" -Success $true -Failure $true -CIS "CIS 17.9.5"

    # Enable command-line auditing in process creation events
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        "ProcessCreationIncludeCmdLine_Enabled" 1 -CIS "CIS 18.8.3.1"
}

# ============================================================
# SECTION 18 — ADMINISTRATIVE TEMPLATES (COMPUTER)
# ============================================================

function Set-AdministrativeTemplates {
    Write-Log "=== Section 18: Administrative Templates (Computer) ===" "INFO"

    # --- 18.1 Control Panel / Personalization ---
    # CIS 18.1.1.1 — Prevent enabling lock screen camera
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
        "NoLockScreenCamera" 1 -CIS "CIS 18.1.1.1"

    # CIS 18.1.1.2 — Prevent enabling lock screen slide show
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
        "NoLockScreenSlideshow" 1 -CIS "CIS 18.1.1.2"

    # CIS 18.1.2.2 — Allow users to enable online speech recognition: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" `
        "AllowInputPersonalization" 0 -CIS "CIS 18.1.2.2"

    # --- 18.4 MS Security Guide ---
    # CIS 18.4.1 — Apply UAC restrictions to local accounts on network logons
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "LocalAccountTokenFilterPolicy" 0 -CIS "CIS 18.4.1"

    # CIS 18.4.2 — Configure SMB v1 client driver: Disable
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" `
        "Start" 4 -CIS "CIS 18.4.2"

    # CIS 18.4.3 — Configure SMB v1 server: Disabled
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        "SMB1" 0 -CIS "CIS 18.4.3"

    # CIS 18.4.4 — Enable Structured Exception Handling Overwrite Protection (SEHOP)
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        "DisableExceptionChainValidation" 0 -CIS "CIS 18.4.4"

    # CIS 18.4.5 — NetBT NodeType: P-node (prevent NetBIOS broadcast)
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" `
        "NodeType" 2 -CIS "CIS 18.4.5"

    # CIS 18.4.6 — WDigest Authentication: Disabled
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
        "UseLogonCredential" 0 -CIS "CIS 18.4.6"

    # --- 18.5 MSS (Legacy) ---
    # CIS 18.5.1 — MSS: AutoAdminLogon disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
        "AutoAdminLogon" "0" -Type String -CIS "CIS 18.5.1"

    # CIS 18.5.2 — MSS: DisableIPSourceRouting (IPv6): Highest protection
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
        "DisableIPSourceRouting" 2 -CIS "CIS 18.5.2"

    # CIS 18.5.3 — MSS: DisableIPSourceRouting (IPv4): Highest protection
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        "DisableIPSourceRouting" 2 -CIS "CIS 18.5.3"

    # CIS 18.5.4 — MSS: EnableICMPRedirect: Disabled
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        "EnableICMPRedirect" 0 -CIS "CIS 18.5.4"

    # CIS 18.5.5 — MSS: NoNameReleaseOnDemand: Enabled
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" `
        "NoNameReleaseOnDemand" 1 -CIS "CIS 18.5.5"

    # CIS 18.5.6 — MSS: SafeDllSearchMode: Enabled
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
        "SafeDllSearchMode" 1 -CIS "CIS 18.5.6"

    # CIS 18.5.7 — MSS: ScreenSaverGracePeriod: 5 seconds
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
        "ScreenSaverGracePeriod" "5" -Type String -CIS "CIS 18.5.7"

    # --- 18.6 Network ---
    # CIS 18.6.4.1 — Configure NetBIOS settings: Disabled (P-Node)
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        "EnableNetbios" 0 -CIS "CIS 18.6.4.1"

    # CIS 18.6.4.2 — Turn off multicast name resolution (LLMNR)
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        "EnableMulticast" 0 -CIS "CIS 18.6.4.2"

    # CIS 18.6.8.1 — Enable insecure guest logons: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" `
        "AllowInsecureGuestAuth" 0 -CIS "CIS 18.6.8.1"

    # CIS 18.6.11.2 — Prohibit installation/config of Network Bridge: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" `
        "NC_AllowNetBridge_NLA" 0 -CIS "CIS 18.6.11.2"

    # CIS 18.6.11.3 — Prohibit use of Internet Connection Sharing: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" `
        "NC_ShowSharedAccessUI" 0 -CIS "CIS 18.6.11.3"

    # CIS 18.6.11.4 — Require domain users to elevate when setting network location
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" `
        "NC_StdDomainUserSetLocation" 1 -CIS "CIS 18.6.11.4"

    # CIS 18.6.14.1 — Hardened UNC Paths (NETLOGON)
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
        "\\*\NETLOGON" "RequireMutualAuthentication=1, RequireIntegrity=1" -Type String -CIS "CIS 18.6.14.1"

    # CIS 18.6.14.1 — Hardened UNC Paths (SYSVOL)
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" `
        "\\*\SYSVOL" "RequireMutualAuthentication=1, RequireIntegrity=1" -Type String -CIS "CIS 18.6.14.1"

    # CIS 18.6.21.1 — Minimize the number of simultaneous connections: 3 (prevent WiFi+Eth bridging)
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" `
        "fMinimizeConnections" 3 -CIS "CIS 18.6.21.1"

    # CIS 18.6.21.2 — Prohibit connection to non-domain networks when connected to domain
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" `
        "fBlockNonDomain" 1 -CIS "CIS 18.6.21.2"

    # --- 18.7 Printers ---
    # CIS 18.7.1 — Allow Print Spooler to accept client connections: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
        "RegisterSpoolerRemoteRpcEndPoint" 2 -CIS "CIS 18.7.1"

    # CIS 18.7.2 — Point and Print Restrictions: show warning and elevation prompt
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" `
        "NoWarningNoElevationOnInstall" 0 -CIS "CIS 18.7.2"

    # CIS 18.7.3 — Point and Print: update prompt = Show warning and elevation prompt
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" `
        "UpdatePromptSettings" 0 -CIS "CIS 18.7.3"

    # CIS 18.7.4 — Limits print driver installation to Administrators
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" `
        "RestrictDriverInstallationToAdministrators" 1 -CIS "CIS 18.7.4"

    # --- 18.8 System ---
    # CIS 18.8.3.1 — Include command line in process creation events
    # (Already set in audit section, but also via admin template path)

    # CIS 18.8.4.1 — Remote host allows delegation of non-exportable credentials: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" `
        "AllowProtectedCreds" 1 -CIS "CIS 18.8.4.1"

    # CIS 18.8.5.1 — Turn on virtualization-based security: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
        "EnableVirtualizationBasedSecurity" 1 -CIS "CIS 18.8.5.1"

    # CIS 18.8.5.2 — VBS: Platform security features: Secure Boot and DMA Protection
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
        "RequirePlatformSecurityFeatures" 3 -CIS "CIS 18.8.5.2"

    # CIS 18.8.5.3 — VBS: Credential Guard Configuration: Enabled with UEFI lock
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
        "LsaCfgFlags" 1 -CIS "CIS 18.8.5.3"

    # CIS 18.8.5.4 — VBS: Secure Launch: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
        "HVCIMATRequired" 1 -CIS "CIS 18.8.5.4"

    # CIS 18.8.5.5 — VBS: Kernel-mode Hardware-enforced Stack Protection: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
        "ConfigureKernelShadowStacksLaunch" 1 -CIS "CIS 18.8.5.5"

    # --- 18.8.7 Early Launch Antimalware ---
    # CIS 18.8.14.1 — Boot-Start Driver Initialization Policy: Good, unknown and bad but critical
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" `
        "DriverLoadPolicy" 3 -CIS "CIS 18.8.14.1"

    # --- 18.8.22 Internet Communication ---
    # CIS 18.8.22.1.1 — Turn off downloading print driver packages over HTTP
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
        "DisableWebPnPDownload" 1 -CIS "CIS 18.8.22.1.1"

    # CIS 18.8.22.1.2 — Turn off handwriting personalization data sharing
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" `
        "PreventHandwritingDataSharing" 1 -CIS "CIS 18.8.22.1.2"

    # CIS 18.8.22.1.3 — Turn off handwriting recognition error reporting
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" `
        "PreventHandwritingErrorReports" 1 -CIS "CIS 18.8.22.1.3"

    # CIS 18.8.22.1.4 — Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" `
        "ExitOnMSICW" 1 -CIS "CIS 18.8.22.1.4"

    # CIS 18.8.22.1.5 — Turn off Internet download for Web publishing and online ordering wizards
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        "NoWebServices" 1 -CIS "CIS 18.8.22.1.5"

    # CIS 18.8.22.1.6 — Turn off printing over HTTP
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
        "DisableHTTPPrinting" 1 -CIS "CIS 18.8.22.1.6"

    # CIS 18.8.22.1.7 — Turn off Registration if URL connection is referring to Microsoft.com
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" `
        "NoRegistration" 1 -CIS "CIS 18.8.22.1.7"

    # CIS 18.8.22.1.8 — Turn off Search Companion content file updates
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" `
        "DisableContentFileUpdates" 1 -CIS "CIS 18.8.22.1.8"

    # CIS 18.8.22.1.9 — Turn off the "Order Prints" picture task
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        "NoOnlinePrintsWizard" 1 -CIS "CIS 18.8.22.1.9"

    # CIS 18.8.22.1.10 — Turn off the "Publish to Web" task for files and folders
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        "NoPublishingWizard" 1 -CIS "CIS 18.8.22.1.10"

    # CIS 18.8.22.1.11 — Turn off the Windows Messenger CEIP
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" `
        "CEIP" 2 -CIS "CIS 18.8.22.1.11"

    # CIS 18.8.22.1.12 — Turn off Windows Customer Experience Improvement Program
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" `
        "CEIPEnable" 0 -CIS "CIS 18.8.22.1.12"

    # CIS 18.8.22.1.13 — Turn off Windows Error Reporting
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" `
        "Disabled" 1 -CIS "CIS 18.8.22.1.13"

    # --- 18.8.28 Logon ---
    # CIS 18.8.28.1 — Block user from showing account details on sign-in: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        "BlockUserFromShowingAccountDetailsOnSignin" 1 -CIS "CIS 18.8.28.1"

    # CIS 18.8.28.2 — Do not display network selection UI: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        "DontDisplayNetworkSelectionUI" 1 -CIS "CIS 18.8.28.2"

    # CIS 18.8.28.3 — Do not enumerate connected users on domain-joined computers
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        "DontEnumerateConnectedUsers" 1 -CIS "CIS 18.8.28.3"

    # CIS 18.8.28.4 — Enumerate local users on domain-joined computers: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        "EnumerateLocalUsers" 0 -CIS "CIS 18.8.28.4"

    # CIS 18.8.28.5 — Turn off app notifications on the lock screen: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        "DisableLockScreenAppNotifications" 1 -CIS "CIS 18.8.28.5"

    # CIS 18.8.28.6 — Turn off picture password sign-in: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        "BlockDomainPicturePassword" 1 -CIS "CIS 18.8.28.6"

    # CIS 18.8.28.7 — Turn on convenience PIN sign-in: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        "AllowDomainPINLogon" 0 -CIS "CIS 18.8.28.7"

    # --- 18.8.34 Remote Assistance ---
    # CIS 18.8.36.1 — Configure Offer Remote Assistance: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "fAllowUnsolicited" 0 -CIS "CIS 18.8.36.1"

    # CIS 18.8.36.2 — Configure Solicited Remote Assistance: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "fAllowToGetHelp" 0 -CIS "CIS 18.8.36.2"

    # --- 18.8.37 Remote Procedure Call ---
    # CIS 18.8.37.1 — Enable RPC Endpoint Mapper Client Authentication: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" `
        "EnableAuthEpResolution" 1 -CIS "CIS 18.8.37.1"

    # CIS 18.8.37.2 — Restrict Unauthenticated RPC clients: Authenticated
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" `
        "RestrictRemoteClients" 1 -CIS "CIS 18.8.37.2"

    # --- 18.9.3 Autoplay ---
    # CIS 18.9.3.1 — Disallow Autoplay for non-volume devices: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
        "NoAutoplayfornonVolume" 1 -CIS "CIS 18.9.3.1"

    # CIS 18.9.3.2 — Set default behavior for AutoRun: Do not execute
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        "NoAutorun" 1 -CIS "CIS 18.9.3.2"

    # CIS 18.9.3.3 — Turn off Autoplay: All drives
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        "NoDriveTypeAutoRun" 255 -CIS "CIS 18.9.3.3"

    # --- 18.9.4 BitLocker (if TPM present) ---
    $tpm = $null
    try { $tpm = Get-Tpm -ErrorAction Stop } catch {}
    if ($tpm -and $tpm.TpmPresent) {
        # CIS 18.9.4.1 — Choose how BitLocker-protected fixed drives can be recovered
        Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
            "FDVRecovery" 1 -CIS "CIS 18.9.4.1"

        # CIS 18.9.4.2 — Choose how BitLocker-protected OS drives can be recovered
        Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
            "OSRecovery" 1 -CIS "CIS 18.9.4.2"

        # CIS 18.9.4.3 — Require additional authentication at startup: Enabled
        Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
            "UseAdvancedStartup" 1 -CIS "CIS 18.9.4.3"

        # CIS 18.9.4.4 — Allow enhanced PINs for startup: Enabled
        Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
            "UseEnhancedPin" 1 -CIS "CIS 18.9.4.4"
    } else {
        Write-Log "TPM not detected. Skipping BitLocker policy settings." "WARN"
    }

    # --- 18.9.7 Cloud Content ---
    # CIS 18.9.7.1 — Turn off cloud consumer account state content: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
        "DisableConsumerAccountStateContent" 1 -CIS "CIS 18.9.7.1"

    # CIS 18.9.7.2 — Turn off cloud optimized content: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
        "DisableCloudOptimizedContent" 1 -CIS "CIS 18.9.7.2"

    # CIS 18.9.7.3 — Turn off Microsoft consumer experiences: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
        "DisableWindowsConsumerFeatures" 1 -CIS "CIS 18.9.7.3"

    # --- 18.9.12 Data Collection and Preview Builds ---
    # CIS 18.9.12.1 — Allow Diagnostic Data: Send required diagnostic data (1)
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        "AllowTelemetry" 1 -CIS "CIS 18.9.12.1"

    # CIS 18.9.12.2 — Configure Authenticated Proxy for Diagnostic Data: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        "DisableEnterpriseAuthProxy" 1 -CIS "CIS 18.9.12.2"

    # CIS 18.9.12.3 — Disable OneSettings Downloads: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        "DisableOneSettingsDownloads" 1 -CIS "CIS 18.9.12.3"

    # CIS 18.9.12.4 — Do not show feedback notifications: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        "DoNotShowFeedbackNotifications" 1 -CIS "CIS 18.9.12.4"

    # CIS 18.9.12.5 — Enable OneSettings Auditing: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        "EnableOneSettingsAuditing" 1 -CIS "CIS 18.9.12.5"

    # CIS 18.9.12.6 — Limit Diagnostic Log Collection: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        "LimitDiagnosticLogCollection" 1 -CIS "CIS 18.9.12.6"

    # CIS 18.9.12.7 — Limit Dump Collection: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        "LimitDumpCollection" 1 -CIS "CIS 18.9.12.7"

    # CIS 18.9.12.8 — Toggle user control over Insider builds: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" `
        "AllowBuildPreview" 0 -CIS "CIS 18.9.12.8"

    # --- 18.9.14 Event Log Service ---
    # CIS 18.9.14.1 — Application log max size: 32768 KB
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" `
        "MaxSize" 32768 -CIS "CIS 18.9.14.1"

    # CIS 18.9.14.2 — Security log max size: 196608 KB
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" `
        "MaxSize" 196608 -CIS "CIS 18.9.14.2"

    # CIS 18.9.14.3 — Setup log max size: 32768 KB
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" `
        "MaxSize" 32768 -CIS "CIS 18.9.14.3"

    # CIS 18.9.14.4 — System log max size: 32768 KB
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" `
        "MaxSize" 32768 -CIS "CIS 18.9.14.4"

    # --- 18.9.17 File Explorer ---
    # CIS 18.9.17.1 — Turn off Data Execution Prevention for Explorer: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
        "NoDataExecutionPrevention" 0 -CIS "CIS 18.9.17.1"

    # CIS 18.9.17.2 — Turn off heap termination on corruption: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
        "NoHeapTerminationOnCorruption" 0 -CIS "CIS 18.9.17.2"

    # CIS 18.9.17.3 — Turn off shell protocol protected mode: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        "PreXPSP2ShellProtocolBehavior" 0 -CIS "CIS 18.9.17.3"

    # --- 18.9.27 Microsoft Account ---
    # CIS 18.9.27.1 — Block all consumer Microsoft account user authentication
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" `
        "DisableUserAuth" 1 -CIS "CIS 18.9.27.1"

    # --- 18.9.35 Remote Desktop Services ---
    # CIS 18.9.35.1 — Do not allow COM port redirection
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "fDisableCcm" 1 -CIS "CIS 18.9.35.1"

    # CIS 18.9.35.2 — Do not allow drive redirection
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "fDisableCdm" 1 -CIS "CIS 18.9.35.2"

    # CIS 18.9.35.3 — Do not allow LPT port redirection
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "fDisableLPT" 1 -CIS "CIS 18.9.35.3"

    # CIS 18.9.35.4 — Do not allow supported Plug and Play device redirection
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "fDisablePNPRedir" 1 -CIS "CIS 18.9.35.4"

    # CIS 18.9.35.5 — Always prompt for password upon connection: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "fPromptForPassword" 1 -CIS "CIS 18.9.35.5"

    # CIS 18.9.35.6 — Require secure RPC communication: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "fEncryptRPCTraffic" 1 -CIS "CIS 18.9.35.6"

    # CIS 18.9.35.7 — Require use of specific security layer: SSL
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "SecurityLayer" 2 -CIS "CIS 18.9.35.7"

    # CIS 18.9.35.8 — Require user authentication for remote connections (NLA): Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "UserAuthentication" 1 -CIS "CIS 18.9.35.8"

    # CIS 18.9.35.9 — Set client connection encryption level: High
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "MinEncryptionLevel" 3 -CIS "CIS 18.9.35.9"

    # CIS 18.9.35.10 — Set time limit for disconnected sessions: 1 minute
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "MaxDisconnectionTime" 60000 -CIS "CIS 18.9.35.10"

    # CIS 18.9.35.11 — Do not delete temp folders upon exit: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        "DeleteTempDirsOnExit" 1 -CIS "CIS 18.9.35.11"

    # --- 18.9.37 RSS Feeds ---
    # CIS 18.9.37.1 — Prevent downloading of enclosures: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" `
        "DisableEnclosureDownload" 1 -CIS "CIS 18.9.37.1"

    # --- 18.9.38 Search ---
    # CIS 18.9.38.1 — Allow Cloud Search: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
        "AllowCloudSearch" 0 -CIS "CIS 18.9.38.1"

    # CIS 18.9.38.2 — Allow Cortana: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
        "AllowCortana" 0 -CIS "CIS 18.9.38.2"

    # CIS 18.9.38.3 — Allow Cortana above lock screen: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
        "AllowCortanaAboveLock" 0 -CIS "CIS 18.9.38.3"

    # CIS 18.9.38.4 — Allow indexing of encrypted files: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
        "AllowIndexingEncryptedStoresOrItems" 0 -CIS "CIS 18.9.38.4"

    # CIS 18.9.38.5 — Allow search and Cortana to use location: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
        "AllowSearchToUseLocation" 0 -CIS "CIS 18.9.38.5"

    # --- 18.9.46 Software Protection Platform ---
    # CIS 18.9.46.1 — Turn off KMS Client Online AVS Validation: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" `
        "NoGenTicket" 1 -CIS "CIS 18.9.46.1"

    # --- 18.9.48 Windows Installer ---
    # CIS 18.9.48.1 — Always install with elevated privileges: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
        "AlwaysInstallElevated" 0 -CIS "CIS 18.9.48.1"

    # CIS 18.9.48.2 — Prevent Internet Explorer security prompt for Windows Installer scripts
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
        "SafeForScripting" 0 -CIS "CIS 18.9.48.2"

    # --- 18.9.52 Windows PowerShell ---
    # CIS 18.9.52.1 — Turn on PowerShell Script Block Logging: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        "EnableScriptBlockLogging" 1 -CIS "CIS 18.9.52.1"

    # CIS 18.9.52.2 — Turn on PowerShell Transcription: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        "EnableTranscripting" 1 -CIS "CIS 18.9.52.2"

    # CIS 18.9.52.3 — Disable PowerShell v2
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" `
        "EnableScripts" 1 -CIS "CIS 18.9.52.3"

    # --- 18.9.55 WinRM Client ---
    # CIS 18.9.55.1 — Allow Basic authentication (client): Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
        "AllowBasic" 0 -CIS "CIS 18.9.55.1"

    # CIS 18.9.55.2 — Allow unencrypted traffic (client): Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
        "AllowUnencryptedTraffic" 0 -CIS "CIS 18.9.55.2"

    # CIS 18.9.55.3 — Disallow Digest authentication (client): Enabled (disable digest)
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
        "AllowDigest" 0 -CIS "CIS 18.9.55.3"

    # --- 18.9.56 WinRM Service ---
    # CIS 18.9.56.1 — Allow Basic authentication (service): Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
        "AllowBasic" 0 -CIS "CIS 18.9.56.1"

    # CIS 18.9.56.2 — Allow remote server management through WinRM: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
        "AllowAutoConfig" 0 -CIS "CIS 18.9.56.2"

    # CIS 18.9.56.3 — Allow unencrypted traffic (service): Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
        "AllowUnencryptedTraffic" 0 -CIS "CIS 18.9.56.3"

    # CIS 18.9.56.4 — Disallow WinRM from storing RunAs credentials: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
        "DisableRunAs" 1 -CIS "CIS 18.9.56.4"

    # --- 18.9.57 Windows Remote Shell ---
    # CIS 18.9.57.1 — Allow Remote Shell Access: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" `
        "AllowRemoteShellAccess" 0 -CIS "CIS 18.9.57.1"

    # --- 18.9.59 App Privacy ---
    # CIS 18.9.59.1 — Let Windows apps activate with voice while locked: Force Deny
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" `
        "LetAppsActivateWithVoiceAboveLock" 2 -CIS "CIS 18.9.59.1"

    # --- 18.9.62 Windows Sandbox ---
    # CIS 18.9.62.1 — Allow clipboard sharing with Windows Sandbox: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" `
        "AllowClipboardRedirection" 0 -CIS "CIS 18.9.62.1"

    # CIS 18.9.62.2 — Allow networking in Windows Sandbox: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" `
        "AllowNetworking" 0 -CIS "CIS 18.9.62.2"

    # --- 18.9.66 Windows Update ---
    # CIS 18.9.66.1 — Manage preview builds: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
        "ManagePreviewBuildsPolicyValue" 1 -CIS "CIS 18.9.66.1"

    # CIS 18.9.66.2 — Select when Preview Builds and Feature Updates are received: 180 days deferral
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
        "DeferFeatureUpdatesPeriodInDays" 180 -CIS "CIS 18.9.66.2"

    # CIS 18.9.66.3 — Select when Quality Updates are received: 0 days (apply quickly)
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
        "DeferQualityUpdatesPeriodInDays" 0 -CIS "CIS 18.9.66.3"

    # CIS 18.9.66.4 — Configure Automatic Updates: Auto download and schedule install
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
        "NoAutoUpdate" 0 -CIS "CIS 18.9.66.4"

    # CIS 18.9.66.5 — Configure Automatic Updates: Scheduled install day (0 = Every day)
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
        "ScheduledInstallDay" 0 -CIS "CIS 18.9.66.5"

    # CIS 18.9.66.6 — Remove access to "Pause updates" feature: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
        "SetDisablePauseUXAccess" 1 -CIS "CIS 18.9.66.6"

    # --- 18.10.3 App Package Deployment ---
    # CIS 18.10.3.1 — Allow a Windows app to share application data between users: Disabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" `
        "AllowSharedLocalAppData" 0 -CIS "CIS 18.10.3.1"

    # CIS 18.10.3.2 — Prevent non-admin users from installing packaged Windows apps: Enabled
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" `
        "BlockNonAdminUserInstall" 1 -CIS "CIS 18.10.3.2"

    # --- 18.10.9 Windows Defender SmartScreen ---
    # CIS 18.10.9.1 — Configure Windows Defender SmartScreen: Warn and prevent bypass
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        "EnableSmartScreen" 1 -CIS "CIS 18.10.9.1"

    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
        "ShellSmartScreenLevel" "Block" -Type String -CIS "CIS 18.10.9.1"

    # CIS 18.10.9.2 — Configure Windows Defender SmartScreen for Microsoft Edge
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" `
        "PreventOverride" 1 -CIS "CIS 18.10.9.2"

    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" `
        "EnabledV9" 1 -CIS "CIS 18.10.9.2"
}

# ============================================================
# SECTION 19 — ADMINISTRATIVE TEMPLATES (USER)
# ============================================================

function Set-UserAdministrativeTemplates {
    Write-Log "=== Section 19: Administrative Templates (User) ===" "INFO"

    # In a GPO startup-script context (SYSTEM account), HKCU goes to SYSTEM's hive.
    # Load the Default User hive so new user profiles inherit these settings.
    $defaultHive = "C:\Users\Default\NTUSER.DAT"
    $hiveMounted = $false
    $hivePath    = "HKU:\CIS_DEFAULT"

    if (-not $Script:WhatIfPreference) {
        try {
            if (-not (Get-PSDrive HKU -ErrorAction SilentlyContinue)) {
                New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
            }
            & reg load "HKU\CIS_DEFAULT" "$defaultHive" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $hiveMounted = $true
                Write-Log "Loaded Default User hive for HKCU policy application" "INFO"
            } else {
                Write-Log "Could not load Default User hive (may be in use). Applying to HKCU instead." "WARN"
                $hivePath = "HKCU:"
            }
        } catch {
            Write-Log "Failed to load Default User hive: $_. Applying to HKCU instead." "WARN"
            $hivePath = "HKCU:"
        }
    } else {
        $hivePath = "HKCU:"
    }

    # CIS 19.1.3.1 — Enable screen saver: Enabled
    Set-RegistryValue "$hivePath\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" `
        "ScreenSaveActive" "1" -Type String -CIS "CIS 19.1.3.1"

    # CIS 19.1.3.2 — Screen saver timeout: 900 seconds or less
    Set-RegistryValue "$hivePath\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" `
        "ScreenSaveTimeOut" "900" -Type String -CIS "CIS 19.1.3.2"

    # CIS 19.1.3.3 — Password protect the screen saver: Enabled
    Set-RegistryValue "$hivePath\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" `
        "ScreenSaverIsSecure" "1" -Type String -CIS "CIS 19.1.3.3"

    # CIS 19.5.1.1 — Turn off toast notifications on the lock screen: Enabled
    Set-RegistryValue "$hivePath\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" `
        "NoToastApplicationNotificationOnLockScreen" 1 -CIS "CIS 19.5.1.1"

    # CIS 19.6.6.1.1 — Turn off Help Experience Improvement Program: Enabled
    Set-RegistryValue "$hivePath\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" `
        "NoImplicitFeedback" 1 -CIS "CIS 19.6.6.1.1"

    # CIS 19.7.4.1 — Do not preserve zone information in file attachments: Disabled
    Set-RegistryValue "$hivePath\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" `
        "SaveZoneInformation" 2 -CIS "CIS 19.7.4.1"

    # CIS 19.7.4.2 — Notify antivirus programs when opening attachments: Enabled
    Set-RegistryValue "$hivePath\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" `
        "ScanWithAntiVirus" 3 -CIS "CIS 19.7.4.2"

    # CIS 19.7.8.1 — Configure Windows spotlight on lock screen (L2): Disabled
    if ($Profile -eq "L2") {
        Set-RegistryValue "$hivePath\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
            "ConfigureWindowsSpotlight" 2 -CIS "CIS 19.7.8.1 (L2)"

        Set-RegistryValue "$hivePath\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
            "DisableThirdPartySuggestions" 1 -CIS "CIS 19.7.8.2 (L2)"

        Set-RegistryValue "$hivePath\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
            "DisableWindowsSpotlightFeatures" 1 -CIS "CIS 19.7.8.3 (L2)"
    }

    # Unload the Default User hive
    if ($hiveMounted -and -not $Script:WhatIfPreference) {
        [gc]::Collect()
        Start-Sleep -Seconds 1
        & reg unload "HKU\CIS_DEFAULT" 2>&1 | Out-Null
        Write-Log "Unloaded Default User hive" "INFO"
    }
}

# ============================================================
# TLS / CRYPTOGRAPHY HARDENING
# ============================================================

function Set-TlsCryptography {
    Write-Log "=== TLS/Cryptography Hardening ===" "INFO"

    $protocols = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

    # Disable SSL 2.0
    Set-RegistryValue "$protocols\SSL 2.0\Client" "Enabled" 0 -CIS "TLS: Disable SSL 2.0 Client"
    Set-RegistryValue "$protocols\SSL 2.0\Client" "DisabledByDefault" 1 -CIS "TLS: Disable SSL 2.0 Client"
    Set-RegistryValue "$protocols\SSL 2.0\Server" "Enabled" 0 -CIS "TLS: Disable SSL 2.0 Server"
    Set-RegistryValue "$protocols\SSL 2.0\Server" "DisabledByDefault" 1 -CIS "TLS: Disable SSL 2.0 Server"

    # Disable SSL 3.0
    Set-RegistryValue "$protocols\SSL 3.0\Client" "Enabled" 0 -CIS "TLS: Disable SSL 3.0 Client"
    Set-RegistryValue "$protocols\SSL 3.0\Client" "DisabledByDefault" 1 -CIS "TLS: Disable SSL 3.0 Client"
    Set-RegistryValue "$protocols\SSL 3.0\Server" "Enabled" 0 -CIS "TLS: Disable SSL 3.0 Server"
    Set-RegistryValue "$protocols\SSL 3.0\Server" "DisabledByDefault" 1 -CIS "TLS: Disable SSL 3.0 Server"

    # Disable TLS 1.0
    Set-RegistryValue "$protocols\TLS 1.0\Client" "Enabled" 0 -CIS "TLS: Disable TLS 1.0 Client"
    Set-RegistryValue "$protocols\TLS 1.0\Client" "DisabledByDefault" 1 -CIS "TLS: Disable TLS 1.0 Client"
    Set-RegistryValue "$protocols\TLS 1.0\Server" "Enabled" 0 -CIS "TLS: Disable TLS 1.0 Server"
    Set-RegistryValue "$protocols\TLS 1.0\Server" "DisabledByDefault" 1 -CIS "TLS: Disable TLS 1.0 Server"

    # Disable TLS 1.1
    Set-RegistryValue "$protocols\TLS 1.1\Client" "Enabled" 0 -CIS "TLS: Disable TLS 1.1 Client"
    Set-RegistryValue "$protocols\TLS 1.1\Client" "DisabledByDefault" 1 -CIS "TLS: Disable TLS 1.1 Client"
    Set-RegistryValue "$protocols\TLS 1.1\Server" "Enabled" 0 -CIS "TLS: Disable TLS 1.1 Server"
    Set-RegistryValue "$protocols\TLS 1.1\Server" "DisabledByDefault" 1 -CIS "TLS: Disable TLS 1.1 Server"

    # Enable TLS 1.2
    Set-RegistryValue "$protocols\TLS 1.2\Client" "Enabled" 1 -CIS "TLS: Enable TLS 1.2 Client"
    Set-RegistryValue "$protocols\TLS 1.2\Client" "DisabledByDefault" 0 -CIS "TLS: Enable TLS 1.2 Client"
    Set-RegistryValue "$protocols\TLS 1.2\Server" "Enabled" 1 -CIS "TLS: Enable TLS 1.2 Server"
    Set-RegistryValue "$protocols\TLS 1.2\Server" "DisabledByDefault" 0 -CIS "TLS: Enable TLS 1.2 Server"

    # Enable TLS 1.3
    Set-RegistryValue "$protocols\TLS 1.3\Client" "Enabled" 1 -CIS "TLS: Enable TLS 1.3 Client"
    Set-RegistryValue "$protocols\TLS 1.3\Client" "DisabledByDefault" 0 -CIS "TLS: Enable TLS 1.3 Client"
    Set-RegistryValue "$protocols\TLS 1.3\Server" "Enabled" 1 -CIS "TLS: Enable TLS 1.3 Server"
    Set-RegistryValue "$protocols\TLS 1.3\Server" "DisabledByDefault" 0 -CIS "TLS: Enable TLS 1.3 Server"

    # Disable weak ciphers
    $ciphersBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
    $weakCiphers = @("DES 56/56", "RC2 40/128", "RC2 56/128", "RC2 128/128", "RC4 40/128",
                     "RC4 56/128", "RC4 64/128", "RC4 128/128", "Triple DES 168")
    foreach ($cipher in $weakCiphers) {
        # Ciphers with slashes require reg.exe since PowerShell can't handle them in paths
        if (-not $Script:WhatIfPreference) {
            try {
                & reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher" /v Enabled /t REG_DWORD /d 0 /f 2>&1 | Out-Null
                Write-Log "Disabled cipher: $cipher" "CHANGE"
            } catch {
                Write-Log "Failed to disable cipher $cipher : $_" "ERROR"
            }
        } else {
            Write-Log "WOULD disable cipher: $cipher" "INFO"
        }
    }

    # Disable NULL cipher
    Set-RegistryValue "$ciphersBase\NULL" "Enabled" 0 -CIS "TLS: Disable NULL cipher"
}

# ============================================================
# NETWORK PROTOCOL HARDENING
# ============================================================

function Set-NetworkProtocol {
    Write-Log "=== Network Protocol Hardening ===" "INFO"

    # Disable LLMNR (Link-Local Multicast Name Resolution)
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        "EnableMulticast" 0 -CIS "NET: Disable LLMNR"

    # Disable NetBIOS over TCP/IP via policy
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        "EnableNetbios" 0 -CIS "NET: Disable NetBIOS"

    # Disable mDNS (Multicast DNS)
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" `
        "EnableMDNS" 0 -CIS "NET: Disable mDNS"

    # Disable WPAD (Web Proxy Auto-Discovery)
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" `
        "WpadOverride" 1 -CIS "NET: Disable WPAD"

    # Disable IPv6 source routing completely
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
        "DisableIPSourceRouting" 2 -CIS "NET: Disable IPv6 Source Routing"

    # Disable IPv4 source routing
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        "DisableIPSourceRouting" 2 -CIS "NET: Disable IPv4 Source Routing"

    # Disable ICMP redirects
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        "EnableICMPRedirect" 0 -CIS "NET: Disable ICMP Redirects"

    # Disable IP source routing multicast
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        "PerformRouterDiscovery" 0 -CIS "NET: Disable Router Discovery"
}

# ============================================================
# WINDOWS DEFENDER ASR RULES
# ============================================================

function Set-WindowsDefenderASR {
    Write-Log "=== Windows Defender ASR Rules ===" "INFO"

    # 13 CIS-recommended ASR rules, all set to Block (1)
    $asrRules = @(
        @{ Id = "56a863a9-875e-4185-98a7-b882c64b5ce5"; Desc = "Block abuse of exploited vulnerable signed drivers" }
        @{ Id = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"; Desc = "Block Adobe Reader from creating child processes" }
        @{ Id = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"; Desc = "Block all Office applications from creating child processes" }
        @{ Id = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"; Desc = "Block credential stealing from LSASS" }
        @{ Id = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"; Desc = "Block executable content from email client and webmail" }
        @{ Id = "01443614-cd74-433a-b99e-2ecdc07bfc25"; Desc = "Block executable files unless they meet criteria" }
        @{ Id = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"; Desc = "Block execution of potentially obfuscated scripts" }
        @{ Id = "d3e037e1-3eb8-44c8-a917-57927947596d"; Desc = "Block JavaScript or VBScript from launching downloaded content" }
        @{ Id = "3b576869-a4ec-4529-8536-b80a7769e899"; Desc = "Block Office applications from creating executable content" }
        @{ Id = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"; Desc = "Block Office applications from injecting code into processes" }
        @{ Id = "26190899-1602-49e8-8b27-eb1d0a1ce869"; Desc = "Block Office communication apps from creating child processes" }
        @{ Id = "e6db77e5-3df2-4cf1-b95a-636979351e5b"; Desc = "Block persistence through WMI event subscription" }
        @{ Id = "d1e49aac-8f56-4280-b9ba-993a6d77406c"; Desc = "Block process creations from PSExec and WMI commands" }
    )

    $asrIds     = $asrRules | ForEach-Object { $_.Id }
    $asrActions = @(1) * $asrRules.Count   # 1 = Block for all

    if ($Script:WhatIfPreference) {
        foreach ($rule in $asrRules) {
            Write-Log "WOULD SET ASR rule: $($rule.Desc) -> Block" "INFO"
        }
        return
    }

    try {
        Set-MpPreference -AttackSurfaceReductionRules_Ids $asrIds `
                         -AttackSurfaceReductionRules_Actions $asrActions -ErrorAction Stop
        foreach ($rule in $asrRules) {
            Write-Log "ASR: $($rule.Desc) -> Block" "CHANGE"
        }
    }
    catch {
        Write-Log "Failed to apply ASR rules via Set-MpPreference: $_" "ERROR"
        Write-Log "Applying ASR rules via registry fallback..." "WARN"

        # Fallback: write ASR rules to registry
        $asrRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
        foreach ($rule in $asrRules) {
            Set-RegistryValue $asrRegPath $rule.Id "1" -Type String -CIS "ASR: $($rule.Desc)"
        }
    }

    # Enable ASR rules enforcement
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" `
        "ExploitGuard_ASR_Rules" 1 -CIS "ASR: Enable enforcement"

    # Enable network protection (block mode)
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" `
        "EnableNetworkProtection" 1 -CIS "Defender: Network Protection"

    # Disable local admin merge for Defender exclusions
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
        "DisableLocalAdminMerge" 1 -CIS "Defender: Disable local admin exclusion merge"

    # Enable PUA protection
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
        "PUAProtection" 1 -CIS "Defender: PUA Protection"

    # Enable real-time protection
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
        "DisableRealtimeMonitoring" 0 -CIS "Defender: Real-Time Protection"

    # Enable behavior monitoring
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
        "DisableBehaviorMonitoring" 0 -CIS "Defender: Behavior Monitoring"

    # Scan all downloaded files and attachments
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
        "DisableIOAVProtection" 0 -CIS "Defender: IOAV Protection"

    # Enable cloud-delivered protection
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" `
        "SpynetReporting" 2 -CIS "Defender: Cloud Protection"

    # Enable automatic sample submission
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" `
        "SubmitSamplesConsent" 1 -CIS "Defender: Sample Submission"
}

# ============================================================
# SUMMARY REPORT
# ============================================================

function Show-Summary {
    Write-Log "=== HARDENING COMPLETE ===" "INFO"

    $summary = @"

============================================================
  CIS Windows 11 Enterprise Benchmark v4.0.0 Hardening
  Script Version : $Script:VERSION
  Profile        : $Profile
  Timestamp      : $Script:TIMESTAMP
  WhatIf Mode    : $($Script:WhatIfPreference)
============================================================
  Settings Applied : $Script:Applied
  Settings Skipped : $Script:Skipped (already compliant)
  Warnings         : $Script:Warnings
  Errors           : $Script:Errors
  Backup Location  : $Script:BackupDir
  Log File         : $Script:LogFile
============================================================
"@
    Write-Host $summary -ForegroundColor Cyan
    Add-Content -Path $Script:LogFile -Value $summary -ErrorAction SilentlyContinue

    if ($Script:Errors -gt 0) {
        Write-Host "  WARNING: $Script:Errors error(s) occurred. Review the log file." -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "  POST-HARDENING ACTIONS:" -ForegroundColor Yellow
    Write-Host "  1. Review the log file for any warnings or errors"
    Write-Host "  2. A REBOOT is required for all changes to take effect"
    Write-Host "  3. Domain GPO may override local settings on domain-joined machines"
    Write-Host "  4. Test application compatibility before deploying to production"
    Write-Host "  5. Customize the Legal Notice banner text for your organization"
    Write-Host ""
}

# ============================================================
# MAIN EXECUTION
# ============================================================

# Create log directory
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

# Start transcript
$transcriptFile = Join-Path $LogPath "Transcript_$Script:TIMESTAMP.log"
Start-Transcript -Path $transcriptFile -Append -ErrorAction SilentlyContinue

Write-Log "============================================================" "INFO"
Write-Log "CIS Windows 11 Enterprise Hardening v$Script:VERSION" "INFO"
Write-Log "Profile: $Profile | WhatIf: $($WhatIf.IsPresent) | BackupOnly: $($BackupOnly.IsPresent)" "INFO"
Write-Log "============================================================" "INFO"

# Pre-flight checks
Test-Prerequisites

# Backup current settings (always runs first)
Backup-CurrentSettings

if ($BackupOnly) {
    Write-Log "BackupOnly mode — settings exported to $Script:BackupDir. No changes applied." "INFO"
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 0
}

# Execute hardening sections in CIS order
Set-AccountPolicies              # Section 1: Password + Account Lockout
Set-SecurityOptions              # Section 2.3: Security Options (registry)
Set-ServiceHardening             # Section 5: Disable risky services
Set-FirewallConfiguration        # Section 9: Windows Defender Firewall
Set-AuditPolicies                # Section 17: Advanced Audit Policy
Set-AdministrativeTemplates      # Section 18: Admin Templates (Computer)
Set-UserAdministrativeTemplates  # Section 19: Admin Templates (User)
Set-TlsCryptography              # TLS/SSL protocol hardening
Set-NetworkProtocol              # LLMNR, NetBIOS, mDNS, WPAD, source routing
Set-WindowsDefenderASR           # Defender ASR rules + protection settings

# Refresh Group Policy to apply changes immediately
if (-not $Script:WhatIfPreference) {
    Write-Log "Refreshing Group Policy..." "INFO"
    & gpupdate /force 2>&1 | Out-Null
    Write-Log "Group Policy refresh complete." "INFO"
}

# Print summary report
Show-Summary

Stop-Transcript -ErrorAction SilentlyContinue

# Exit code: 1 if any errors occurred, 0 otherwise
if ($Script:Errors -gt 0) { exit 1 } else { exit 0 }
