<#
.SYNOPSIS
    CIS Microsoft Windows Server 2016 Benchmark v3.0.0 — Compliance Scanner
.DESCRIPTION
    Read-only compliance scanner that checks current Windows Server 2016
    system state against the CIS Benchmark v3.0.0. Reports PASS/FAIL/WARN
    per control with colored console output, optional JSON and HTML reports.
    This script NEVER modifies the system.
.PARAMETER ScanProfile
    CIS profile level to scan against.
    L1_MS  = Level 1 Member Server (default)
    L2_MS  = Level 2 Member Server (includes L1_MS)
    L1_DC  = Level 1 Domain Controller
    L2_DC  = Level 2 Domain Controller (includes L1_DC)
    BL     = BitLocker add-on checks
    NG     = Next Generation Windows Security checks
    All    = Run every control
.PARAMETER LogPath
    Directory for log files. Created if missing.
.PARAMETER JsonPath
    Optional file path to export JSON results.
.PARAMETER HtmlPath
    Optional file path to export an HTML report.
.PARAMETER MinSeverity
    Minimum severity to include in reports (CRITICAL, HIGH, MEDIUM, LOW).
.PARAMETER ShowVerbose
    Show detailed per-check output in the console.
.PARAMETER Version
    Print version string and exit.
.EXAMPLE
    .\CIS_WinServer2016_Scanner.ps1
    .\CIS_WinServer2016_Scanner.ps1 -ScanProfile L1_DC -HtmlPath report.html
    .\CIS_WinServer2016_Scanner.ps1 -ScanProfile All -JsonPath scan.json -MinSeverity HIGH
.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1+, Run as Administrator
    License : MIT
#>

#Requires -Version 5.1

param(
    [ValidateSet("L1_MS","L2_MS","L1_DC","L2_DC","BL","NG","All")]
    [string]$ScanProfile = "L1_MS",

    [string]$LogPath = "$env:SystemRoot\Logs\CIS_WinServer2016_Scan",

    [string]$JsonPath,

    [string]$HtmlPath,

    [ValidateSet("CRITICAL","HIGH","MEDIUM","LOW")]
    [string]$MinSeverity = "LOW",

    [switch]$ShowVerbose,

    [switch]$Version
)

# ============================================================
#  Constants
# ============================================================
$Script:VERSION       = "1.0.0"
$Script:BENCHMARK     = "CIS Microsoft Windows Server 2016 Benchmark v3.0.0"
$Script:TIMESTAMP     = Get-Date -Format "yyyyMMdd_HHmmss"
$Script:LogFile       = Join-Path $LogPath "CIS_Scan_$($Script:TIMESTAMP).log"
$Script:Passed        = 0
$Script:Failed        = 0
$Script:Warnings      = 0
$Script:Errors        = 0
$Script:Skipped       = 0
$Script:Results       = [System.Collections.ArrayList]::new()
$Script:SeceditContent = $null
$Script:ServerRole    = $null
$Script:SelectedProfile = $ScanProfile

$Script:SEVERITY_ORDER = @{ "CRITICAL" = 1; "HIGH" = 2; "MEDIUM" = 3; "LOW" = 4 }
$Script:SEVERITY_COLOR = @{ "CRITICAL" = "Red"; "HIGH" = "DarkYellow"; "MEDIUM" = "Cyan"; "LOW" = "Gray" }
$Script:STATUS_COLOR   = @{ "PASS" = "Green"; "FAIL" = "Red"; "WARN" = "Yellow"; "ERROR" = "DarkGray"; "INFO" = "Cyan" }

# Well-known SID to friendly-name mapping for User Rights checks
$Script:SID_MAP = @{
    "*S-1-0-0"      = "Nobody"
    "*S-1-1-0"      = "Everyone"
    "*S-1-5-6"      = "SERVICE"
    "*S-1-5-9"      = "Enterprise Domain Controllers"
    "*S-1-5-11"     = "Authenticated Users"
    "*S-1-5-13"     = "Terminal Server Users"
    "*S-1-5-19"     = "LOCAL SERVICE"
    "*S-1-5-20"     = "NETWORK SERVICE"
    "*S-1-5-32-544" = "Administrators"
    "*S-1-5-32-545" = "Users"
    "*S-1-5-32-546" = "Guests"
    "*S-1-5-32-547" = "Power Users"
    "*S-1-5-32-548" = "Account Operators"
    "*S-1-5-32-549" = "Server Operators"
    "*S-1-5-32-550" = "Print Operators"
    "*S-1-5-32-551" = "Backup Operators"
    "*S-1-5-32-552" = "Replicators"
    "*S-1-5-32-554" = "Pre-Windows 2000 Compatible Access"
    "*S-1-5-32-555" = "Remote Desktop Users"
    "*S-1-5-32-556" = "Network Configuration Operators"
    "*S-1-5-32-557" = "Incoming Forest Trust Builders"
    "*S-1-5-32-558" = "Performance Monitor Users"
    "*S-1-5-32-559" = "Performance Log Users"
    "*S-1-5-32-562" = "Distributed COM Users"
    "*S-1-5-32-568" = "IIS_IUSRS"
    "*S-1-5-32-569" = "Cryptographic Operators"
    "*S-1-5-32-573" = "Event Log Readers"
    "*S-1-5-32-578" = "Hyper-V Administrators"
    "*S-1-5-90-0"   = "Windows Manager\Window Manager Group"
    "*S-1-5-113"    = "Local account"
    "*S-1-5-114"    = "Local account and member of Administrators group"
}

# ============================================================
#  Helper Functions
# ============================================================

function Write-ScanLog {
    param(
        [string]$Message,
        [ValidateSet("PASS","FAIL","WARN","ERROR","INFO")]
        [string]$Level = "INFO"
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = $Script:STATUS_COLOR[$Level]
    switch ($Level) {
        "PASS"  { $Script:Passed++  }
        "FAIL"  { $Script:Failed++  }
        "WARN"  { $Script:Warnings++ }
        "ERROR" { $Script:Errors++  }
    }
    if ($ShowVerbose -or $Level -in @("ERROR","WARN","INFO")) {
        Write-Host "[$ts] " -NoNewline
        Write-Host "[$Level] " -ForegroundColor $color -NoNewline
        Write-Host $Message
    }
    if ($Script:LogFile) {
        $dir = Split-Path $Script:LogFile -Parent
        if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
        "[$ts] [$Level] $Message" | Out-File -FilePath $Script:LogFile -Append -Encoding UTF8
    }
}

function Get-RegistryValue {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch {
        return $null
    }
}

function Get-SeceditExport {
    $tempDir = Join-Path $env:TEMP "CIS_Scanner_$($Script:TIMESTAMP)"
    if (-not (Test-Path $tempDir)) { New-Item -Path $tempDir -ItemType Directory -Force | Out-Null }
    $infFile = Join-Path $tempDir "secpol.inf"
    try {
        $null = & secedit /export /cfg "$infFile" 2>&1
        if (Test-Path $infFile) {
            $content = Get-Content $infFile -Raw -Encoding Unicode
            return $content
        }
    } catch {
        Write-ScanLog "Failed to export security policy: $_" "ERROR"
    } finally {
        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    return $null
}

function Get-SeceditValue {
    param([string]$Content, [string]$Key)
    if ([string]::IsNullOrEmpty($Content)) { return $null }
    if ($Content -match "(?m)^\s*$([regex]::Escape($Key))\s*=\s*(.+)$") {
        return $Matches[1].Trim()
    }
    return $null
}

function Resolve-SIDsToNames {
    param([string]$SidString)
    if ([string]::IsNullOrEmpty($SidString)) { return @() }
    $sids = $SidString -split "," | ForEach-Object { $_.Trim() }
    $names = foreach ($sid in $sids) {
        if ($Script:SID_MAP.ContainsKey($sid)) {
            $Script:SID_MAP[$sid]
        } else {
            try {
                $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid.TrimStart("*"))
                $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
                $objUser.Value
            } catch {
                $sid
            }
        }
    }
    return ($names | Sort-Object)
}

function Get-AuditpolSetting {
    param([string]$Subcategory)
    try {
        $output = & auditpol /get /subcategory:"$Subcategory" 2>&1
        foreach ($line in $output) {
            $l = $line.ToString().Trim()
            if ($l -match "^\s*.+\s+(Success and Failure|Success|Failure|No Auditing)\s*$") {
                return $Matches[1].Trim()
            }
        }
    } catch {
        return "Error"
    }
    return "No Auditing"
}

function Get-ServiceStartType {
    param([string]$ServiceName)
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) { return "NotInstalled" }
    return $svc.StartType.ToString()
}

function Get-ServerRole {
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    } catch {
        $cs = Get-WmiObject Win32_ComputerSystem
        $os = Get-WmiObject Win32_OperatingSystem
    }
    $isDC = ($cs.DomainRole -ge 4)
    return [PSCustomObject]@{
        IsDomainController = $isDC
        IsMemberServer     = ($cs.PartOfDomain -and -not $isDC)
        IsStandalone       = (-not $cs.PartOfDomain)
        DomainRole         = $cs.DomainRole
        Domain             = $cs.Domain
        OSVersion          = $os.Version
        OSBuild            = $os.BuildNumber
        OSCaption          = $os.Caption
        Hostname           = $env:COMPUTERNAME
    }
}

function Test-Prerequisites {
    Write-ScanLog "============================================================" "INFO"
    Write-ScanLog "  $($Script:BENCHMARK) Scanner" "INFO"
    Write-ScanLog "  Script Version : $($Script:VERSION)" "INFO"
    Write-ScanLog "  Profile        : $($Script:SelectedProfile)" "INFO"
    Write-ScanLog "  Timestamp      : $($Script:TIMESTAMP)" "INFO"
    Write-ScanLog "============================================================" "INFO"

    $Script:ServerRole = Get-ServerRole
    $r = $Script:ServerRole
    Write-ScanLog "Hostname   : $($r.Hostname)" "INFO"
    Write-ScanLog "OS         : $($r.OSCaption) (Build $($r.OSBuild))" "INFO"
    Write-ScanLog "Domain     : $($r.Domain)" "INFO"
    Write-ScanLog "Role       : $(if($r.IsDomainController){'Domain Controller'}elseif($r.IsMemberServer){'Member Server'}else{'Standalone Server'})" "INFO"

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-ScanLog "WARNING: Not running as Administrator. Some checks will fail." "WARN"
    }

    if ($r.OSBuild -ne "14393") {
        Write-ScanLog "WARNING: OS build $($r.OSBuild) detected. This scanner targets Server 2016 build 14393." "WARN"
    }

    # Warn if profile doesn't match role
    if ($Script:SelectedProfile -match "_DC" -and -not $r.IsDomainController) {
        Write-ScanLog "WARNING: DC profile selected but server is not a Domain Controller." "WARN"
    }
    if ($Script:SelectedProfile -match "_MS" -and $r.IsDomainController) {
        Write-ScanLog "WARNING: MS profile selected but server is a Domain Controller." "WARN"
    }
}

function Test-ProfileApplicable {
    param([string]$ControlProfiles)
    if ($Script:SelectedProfile -eq "All") { return $true }
    $applicable = $ControlProfiles -split "," | ForEach-Object { $_.Trim() }
    switch ($Script:SelectedProfile) {
        "L1_MS"  { return ($applicable -contains "L1_MS") }
        "L1_DC"  { return ($applicable -contains "L1_DC") }
        "L2_MS"  { return ($applicable -contains "L1_MS" -or $applicable -contains "L2_MS") }
        "L2_DC"  { return ($applicable -contains "L1_DC" -or $applicable -contains "L2_DC") }
        "BL"     { return ($applicable -contains "BL") }
        "NG"     { return ($applicable -contains "NG") }
    }
    return $false
}

function Compare-Value {
    param($Actual, $Expected, [string]$Operator)
    try {
        switch ($Operator) {
            "EQ"       { return ($Actual -eq $Expected) }
            "NE"       { return ($Actual -ne $Expected) }
            "GE"       { return ([long]$Actual -ge [long]$Expected) }
            "LE"       { return ([long]$Actual -le [long]$Expected) }
            "GT"       { return ([long]$Actual -gt [long]$Expected) }
            "LT"       { return ([long]$Actual -lt [long]$Expected) }
            "RANGE"    {
                # Expected = "min,max"
                $parts = $Expected -split ","
                $v = [long]$Actual
                return ($v -ge [long]$parts[0] -and $v -le [long]$parts[1])
            }
            "MATCH"    { return ($Actual -match $Expected) }
            "NOTMATCH" { return ($Actual -notmatch $Expected) }
            "CONTAINS" { return ($Actual -like "*$Expected*") }
            "IN" {
                $list = if ($Expected -is [array]) { $Expected } else { $Expected -split "," }
                return ($list -contains $Actual)
            }
            "NOTIN" {
                $list = if ($Expected -is [array]) { $Expected } else { $Expected -split "," }
                return ($list -notcontains $Actual)
            }
            "NOTEXIST" { return ($null -eq $Actual) }
            default    { return ($Actual -eq $Expected) }
        }
    } catch {
        return $false
    }
}

function Test-CISControl {
    param([PSCustomObject]$Control)

    $result = [PSCustomObject]@{
        CIS_ID         = $Control.CIS_ID
        Title          = $Control.Title
        Profile        = $Control.Profile
        Category       = $Control.Category
        Subcategory    = $Control.Subcategory
        Severity       = $Control.Severity
        Status         = "ERROR"
        Expected       = $Control.Expected
        Actual         = ""
        Recommendation = $Control.Recommendation
        CWE            = $Control.CWE
        CheckType      = $Control.CheckType
        Timestamp      = (Get-Date -Format "o")
    }

    try {
        switch ($Control.CheckType) {
            "Registry" {
                $result.Actual = Get-RegistryValue -Path $Control.CheckKey -Name $Control.CheckValue
            }
            "Secedit" {
                $raw = Get-SeceditValue -Content $Script:SeceditContent -Key $Control.CheckKey
                if ($null -ne $raw) {
                    $result.Actual = $raw.Trim('"').Trim()
                }
            }
            "UserRight" {
                $raw = Get-SeceditValue -Content $Script:SeceditContent -Key $Control.CheckKey
                if ($null -ne $raw -and $raw.Trim() -ne "") {
                    $names = Resolve-SIDsToNames $raw
                    $result.Actual = ($names -join ", ")
                } else {
                    $result.Actual = "(empty - No One)"
                }
            }
            "Auditpol" {
                $result.Actual = Get-AuditpolSetting -Subcategory $Control.CheckKey
            }
            "Service" {
                $result.Actual = Get-ServiceStartType -ServiceName $Control.CheckKey
            }
            "Firewall" {
                $parts = $Control.CheckKey -split "\|"
                $regBase = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$($parts[0])"
                $val = Get-RegistryValue -Path $regBase -Name $parts[1]
                if ($null -eq $val) {
                    $regBase2 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$($parts[0])\Logging"
                    $val = Get-RegistryValue -Path $regBase2 -Name $parts[1]
                }
                if ($null -eq $val) {
                    try {
                        $pName = $parts[0] -replace "Profile$", ""
                        $fp = Get-NetFirewallProfile -Name $pName -ErrorAction Stop
                        $val = $fp.($parts[1])
                    } catch {}
                }
                $result.Actual = $val
            }
        }

        if ($null -eq $result.Actual -and $Control.Operator -eq "NOTEXIST") {
            $result.Status = "PASS"
        }
        elseif ($null -eq $result.Actual) {
            $result.Status = "WARN"
            $result.Actual = "(not configured)"
        }
        else {
            $result.Status = if (Compare-Value $result.Actual $Control.Expected $Control.Operator) { "PASS" } else { "FAIL" }
        }
    }
    catch {
        $result.Status = "ERROR"
        $result.Actual = "Error: $_"
    }

    return $result
}

function Test-UserRightControl {
    param([PSCustomObject]$Control)

    $result = [PSCustomObject]@{
        CIS_ID         = $Control.CIS_ID
        Title          = $Control.Title
        Profile        = $Control.Profile
        Category       = $Control.Category
        Subcategory    = $Control.Subcategory
        Severity       = $Control.Severity
        Status         = "ERROR"
        Expected       = $Control.Expected
        Actual         = ""
        Recommendation = $Control.Recommendation
        CWE            = $Control.CWE
        CheckType      = "UserRight"
        Timestamp      = (Get-Date -Format "o")
    }

    try {
        $raw = Get-SeceditValue -Content $Script:SeceditContent -Key $Control.CheckKey
        if ($null -ne $raw -and $raw.Trim() -ne "") {
            $names = Resolve-SIDsToNames $raw
            $result.Actual = ($names -join ", ")
        } else {
            $result.Actual = "No One"
        }

        $expectedList = if ($Control.Expected -eq "No One") { @() } else { ($Control.Expected -split ",\s*") | Sort-Object }
        $actualList   = if ($result.Actual -eq "No One") { @() } else { ($result.Actual -split ",\s*") | Sort-Object }

        switch ($Control.Operator) {
            "EXACT" {
                $result.Status = if (($expectedList -join ",") -eq ($actualList -join ",")) { "PASS" } else { "FAIL" }
            }
            "SUBSET" {
                $extra = $actualList | Where-Object { $_ -notin $expectedList }
                $result.Status = if ($extra.Count -eq 0) { "PASS" } else { "FAIL" }
            }
            "EMPTY" {
                $result.Status = if ($actualList.Count -eq 0) { "PASS" } else { "FAIL" }
            }
            default {
                $result.Status = if (($expectedList -join ",") -eq ($actualList -join ",")) { "PASS" } else { "FAIL" }
            }
        }
    } catch {
        $result.Status = "ERROR"
        $result.Actual = "Error: $_"
    }
    return $result
}

function Add-ScanResult {
    param([PSCustomObject]$Result)
    $null = $Script:Results.Add($Result)
    $sev  = "[$($Result.Severity)]"
    $stat = $Result.Status
    $msg  = "$($Result.CIS_ID) $sev $($Result.Title) = $stat (Actual: $($Result.Actual))"
    if ($stat -eq "ERROR") { Write-ScanLog $msg "ERROR"; return }
    if ($stat -eq "WARN")  { Write-ScanLog $msg "WARN";  return }
    if ($stat -eq "FAIL")  { Write-ScanLog $msg "FAIL";  return }
    Write-ScanLog $msg "PASS"
}

function Invoke-Controls {
    param([array]$Controls)
    foreach ($ctrl in $Controls) {
        if (-not (Test-ProfileApplicable $ctrl.Profile)) {
            $Script:Skipped++
            continue
        }
        if ($ctrl.CheckType -eq "UserRight") {
            $r = Test-UserRightControl -Control $ctrl
        } else {
            $r = Test-CISControl -Control $ctrl
        }
        Add-ScanResult $r
    }
}

# ============================================================
#  Section 1 : Account Policies
# ============================================================
function Test-AccountPolicies {
    Write-ScanLog "--- Section 1: Account Policies ---" "INFO"

    $controls = @(
        [PSCustomObject]@{ CIS_ID="1.1.1"; Title="Ensure 'Enforce password history' is set to '24 or more password(s)'"; Profile="L1_MS,L1_DC"; Category="Account Policies"; Subcategory="Password Policy"; Severity="HIGH"; CheckType="Secedit"; CheckKey="PasswordHistorySize"; CheckValue=$null; Operator="GE"; Expected=24; Recommendation="Set 'Enforce password history' to 24 or more."; CWE="CWE-262" },
        [PSCustomObject]@{ CIS_ID="1.1.2"; Title="Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'"; Profile="L1_MS,L1_DC"; Category="Account Policies"; Subcategory="Password Policy"; Severity="HIGH"; CheckType="Secedit"; CheckKey="MaximumPasswordAge"; CheckValue=$null; Operator="RANGE"; Expected="1,365"; Recommendation="Set 'Maximum password age' to 365 or fewer, but not 0."; CWE="CWE-262" },
        [PSCustomObject]@{ CIS_ID="1.1.3"; Title="Ensure 'Minimum password age' is set to '1 or more day(s)'"; Profile="L1_MS,L1_DC"; Category="Account Policies"; Subcategory="Password Policy"; Severity="MEDIUM"; CheckType="Secedit"; CheckKey="MinimumPasswordAge"; CheckValue=$null; Operator="GE"; Expected=1; Recommendation="Set 'Minimum password age' to 1 or more day(s)."; CWE="CWE-262" },
        [PSCustomObject]@{ CIS_ID="1.1.4"; Title="Ensure 'Minimum password length' is set to '14 or more character(s)'"; Profile="L1_MS,L1_DC"; Category="Account Policies"; Subcategory="Password Policy"; Severity="CRITICAL"; CheckType="Secedit"; CheckKey="MinimumPasswordLength"; CheckValue=$null; Operator="GE"; Expected=14; Recommendation="Set 'Minimum password length' to 14 or more characters."; CWE="CWE-521" },
        [PSCustomObject]@{ CIS_ID="1.1.5"; Title="Ensure 'Password must meet complexity requirements' is set to 'Enabled'"; Profile="L1_MS,L1_DC"; Category="Account Policies"; Subcategory="Password Policy"; Severity="HIGH"; CheckType="Secedit"; CheckKey="PasswordComplexity"; CheckValue=$null; Operator="EQ"; Expected=1; Recommendation="Enable 'Password must meet complexity requirements'."; CWE="CWE-521" },
        [PSCustomObject]@{ CIS_ID="1.1.6"; Title="Ensure 'Store passwords using reversible encryption' is set to 'Disabled'"; Profile="L1_MS,L1_DC"; Category="Account Policies"; Subcategory="Password Policy"; Severity="CRITICAL"; CheckType="Secedit"; CheckKey="ClearTextPassword"; CheckValue=$null; Operator="EQ"; Expected=0; Recommendation="Disable 'Store passwords using reversible encryption'."; CWE="CWE-257" },
        [PSCustomObject]@{ CIS_ID="1.2.1"; Title="Ensure 'Account lockout duration' is set to '15 or more minute(s)'"; Profile="L1_MS,L1_DC"; Category="Account Policies"; Subcategory="Account Lockout Policy"; Severity="HIGH"; CheckType="Secedit"; CheckKey="LockoutDuration"; CheckValue=$null; Operator="GE"; Expected=15; Recommendation="Set 'Account lockout duration' to 15 or more minutes."; CWE="CWE-307" },
        [PSCustomObject]@{ CIS_ID="1.2.2"; Title="Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'"; Profile="L1_MS,L1_DC"; Category="Account Policies"; Subcategory="Account Lockout Policy"; Severity="HIGH"; CheckType="Secedit"; CheckKey="LockoutBadCount"; CheckValue=$null; Operator="RANGE"; Expected="1,5"; Recommendation="Set 'Account lockout threshold' to 1-5 attempts."; CWE="CWE-307" },
        [PSCustomObject]@{ CIS_ID="1.2.3"; Title="Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'"; Profile="L1_MS,L1_DC"; Category="Account Policies"; Subcategory="Account Lockout Policy"; Severity="MEDIUM"; CheckType="Secedit"; CheckKey="ResetLockoutCount"; CheckValue=$null; Operator="GE"; Expected=15; Recommendation="Set 'Reset account lockout counter after' to 15 or more minutes."; CWE="CWE-307" }
    )

    Invoke-Controls $controls
}   # End Test-AccountPolicies

# ============================================================
#  Section 2.2 : User Rights Assignment
# ============================================================
function Test-UserRightsAssignment {
    Write-ScanLog "--- Section 2.2: User Rights Assignment ---" "INFO"

    $controls = @(
        [PSCustomObject]@{ CIS_ID="2.2.1"; Title="Access Credential Manager as a trusted caller is set to 'No One'"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeTrustedCredManAccessPrivilege"; CheckValue=$null; Operator="EMPTY"; Expected="No One"; Recommendation="Remove all principals from 'Access Credential Manager as a trusted caller'."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.2"; Title="Access this computer from the network"; Profile="L1_MS"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeNetworkLogonRight"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators, Authenticated Users"; Recommendation="Limit to Administrators, Authenticated Users."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="2.2.2"; Title="Access this computer from the network (DC)"; Profile="L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeNetworkLogonRight"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators, Authenticated Users, Enterprise Domain Controllers"; Recommendation="Limit to Administrators, Authenticated Users, Enterprise Domain Controllers."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="2.2.3"; Title="Act as part of the operating system is set to 'No One'"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="CRITICAL"; CheckType="UserRight"; CheckKey="SeTcbPrivilege"; CheckValue=$null; Operator="EMPTY"; Expected="No One"; Recommendation="Remove all principals from 'Act as part of the operating system'."; CWE="CWE-250" },
        [PSCustomObject]@{ CIS_ID="2.2.4"; Title="Add workstations to domain is set to 'Administrators' (DC only)"; Profile="L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeMachineAccountPrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators"; Recommendation="Limit to Administrators only."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.5"; Title="Adjust memory quotas for a process"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="MEDIUM"; CheckType="UserRight"; CheckKey="SeIncreaseQuotaPrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators, LOCAL SERVICE, NETWORK SERVICE"; Recommendation="Limit to Administrators, LOCAL SERVICE, NETWORK SERVICE."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.6"; Title="Allow log on locally"; Profile="L1_MS"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeInteractiveLogonRight"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators"; Recommendation="Limit to Administrators."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="2.2.6"; Title="Allow log on locally (DC)"; Profile="L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeInteractiveLogonRight"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators, Enterprise Domain Controllers"; Recommendation="Limit to Administrators, Enterprise Domain Controllers."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="2.2.7"; Title="Allow log on through Remote Desktop Services"; Profile="L1_MS"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeRemoteInteractiveLogonRight"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators, Remote Desktop Users"; Recommendation="Limit to Administrators, Remote Desktop Users."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="2.2.7"; Title="Allow log on through Remote Desktop Services (DC)"; Profile="L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeRemoteInteractiveLogonRight"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators"; Recommendation="Limit to Administrators."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="2.2.8"; Title="Back up files and directories"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="MEDIUM"; CheckType="UserRight"; CheckKey="SeBackupPrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators"; Recommendation="Limit to Administrators."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.9"; Title="Change the system time"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="MEDIUM"; CheckType="UserRight"; CheckKey="SeSystemtimePrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators, LOCAL SERVICE"; Recommendation="Limit to Administrators, LOCAL SERVICE."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.10"; Title="Change the time zone"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="LOW"; CheckType="UserRight"; CheckKey="SeTimeZonePrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators, LOCAL SERVICE"; Recommendation="Limit to Administrators, LOCAL SERVICE."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.11"; Title="Create a pagefile"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="MEDIUM"; CheckType="UserRight"; CheckKey="SeCreatePagefilePrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators"; Recommendation="Limit to Administrators."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.12"; Title="Create a token object is set to 'No One'"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeCreateTokenPrivilege"; CheckValue=$null; Operator="EMPTY"; Expected="No One"; Recommendation="Remove all principals from 'Create a token object'."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.13"; Title="Create global objects"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="MEDIUM"; CheckType="UserRight"; CheckKey="SeCreateGlobalPrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE"; Recommendation="Limit to Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.14"; Title="Create permanent shared objects is set to 'No One'"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="MEDIUM"; CheckType="UserRight"; CheckKey="SeCreatePermanentPrivilege"; CheckValue=$null; Operator="EMPTY"; Expected="No One"; Recommendation="Remove all principals from 'Create permanent shared objects'."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.15"; Title="Create symbolic links"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="LOW"; CheckType="UserRight"; CheckKey="SeCreateSymbolicLinkPrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators"; Recommendation="Limit to Administrators (add Hyper-V Administrators if applicable)."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.16"; Title="Debug programs is set to 'Administrators'"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="CRITICAL"; CheckType="UserRight"; CheckKey="SeDebugPrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators"; Recommendation="Limit to Administrators only."; CWE="CWE-250" },
        [PSCustomObject]@{ CIS_ID="2.2.17"; Title="Deny access to this computer from the network"; Profile="L1_MS"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeDenyNetworkLogonRight"; CheckValue=$null; Operator="SUBSET"; Expected="Guests, Local account and member of Administrators group"; Recommendation="Include Guests and Local account and member of Administrators group."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="2.2.17"; Title="Deny access to this computer from the network (DC)"; Profile="L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeDenyNetworkLogonRight"; CheckValue=$null; Operator="SUBSET"; Expected="Guests"; Recommendation="Include Guests."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="2.2.18"; Title="Deny log on as a batch job to include 'Guests'"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="MEDIUM"; CheckType="UserRight"; CheckKey="SeDenyBatchLogonRight"; CheckValue=$null; Operator="SUBSET"; Expected="Guests"; Recommendation="Include Guests."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="2.2.19"; Title="Deny log on as a service to include 'Guests'"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="MEDIUM"; CheckType="UserRight"; CheckKey="SeDenyServiceLogonRight"; CheckValue=$null; Operator="SUBSET"; Expected="Guests"; Recommendation="Include Guests."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="2.2.20"; Title="Deny log on locally to include 'Guests'"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeDenyInteractiveLogonRight"; CheckValue=$null; Operator="SUBSET"; Expected="Guests"; Recommendation="Include Guests."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="2.2.21"; Title="Deny log on through Remote Desktop Services"; Profile="L1_MS"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeDenyRemoteInteractiveLogonRight"; CheckValue=$null; Operator="SUBSET"; Expected="Guests, Local account"; Recommendation="Include Guests and Local account."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="2.2.21"; Title="Deny log on through Remote Desktop Services (DC)"; Profile="L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeDenyRemoteInteractiveLogonRight"; CheckValue=$null; Operator="SUBSET"; Expected="Guests"; Recommendation="Include Guests."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="2.2.22"; Title="Enable computer and user accounts to be trusted for delegation"; Profile="L1_MS"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeEnableDelegationPrivilege"; CheckValue=$null; Operator="EMPTY"; Expected="No One"; Recommendation="Set to No One on Member Servers."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.22"; Title="Enable computer and user accounts to be trusted for delegation (DC)"; Profile="L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeEnableDelegationPrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators"; Recommendation="Limit to Administrators on DCs."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.23"; Title="Force shutdown from a remote system"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="MEDIUM"; CheckType="UserRight"; CheckKey="SeRemoteShutdownPrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators"; Recommendation="Limit to Administrators."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.24"; Title="Generate security audits"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="MEDIUM"; CheckType="UserRight"; CheckKey="SeAuditPrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="LOCAL SERVICE, NETWORK SERVICE"; Recommendation="Limit to LOCAL SERVICE, NETWORK SERVICE."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.25"; Title="Impersonate a client after authentication"; Profile="L1_MS"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeImpersonatePrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE"; Recommendation="Limit to Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.26"; Title="Increase scheduling priority"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="LOW"; CheckType="UserRight"; CheckKey="SeIncreaseBasePriorityPrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators, Windows Manager\Window Manager Group"; Recommendation="Limit to Administrators, Window Manager Group."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.27"; Title="Load and unload device drivers"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeLoadDriverPrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators"; Recommendation="Limit to Administrators."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.28"; Title="Lock pages in memory is set to 'No One'"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="LOW"; CheckType="UserRight"; CheckKey="SeLockMemoryPrivilege"; CheckValue=$null; Operator="EMPTY"; Expected="No One"; Recommendation="Remove all principals from 'Lock pages in memory'."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.30"; Title="Manage auditing and security log"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeSecurityPrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators"; Recommendation="Limit to Administrators."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.31"; Title="Modify an object label is set to 'No One'"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="LOW"; CheckType="UserRight"; CheckKey="SeRelabelPrivilege"; CheckValue=$null; Operator="EMPTY"; Expected="No One"; Recommendation="Remove all principals from 'Modify an object label'."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.32"; Title="Modify firmware environment values"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="MEDIUM"; CheckType="UserRight"; CheckKey="SeSystemEnvironmentPrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators"; Recommendation="Limit to Administrators."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.33"; Title="Perform volume maintenance tasks"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="MEDIUM"; CheckType="UserRight"; CheckKey="SeManageVolumePrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators"; Recommendation="Limit to Administrators."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.34"; Title="Profile single process"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="LOW"; CheckType="UserRight"; CheckKey="SeProfileSingleProcessPrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators"; Recommendation="Limit to Administrators."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.35"; Title="Profile system performance"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="LOW"; CheckType="UserRight"; CheckKey="SeSystemProfilePrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators, NT SERVICE\WdiServiceHost"; Recommendation="Limit to Administrators, NT SERVICE\WdiServiceHost."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.36"; Title="Replace a process level token"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeAssignPrimaryTokenPrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="LOCAL SERVICE, NETWORK SERVICE"; Recommendation="Limit to LOCAL SERVICE, NETWORK SERVICE."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.37"; Title="Restore files and directories"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="MEDIUM"; CheckType="UserRight"; CheckKey="SeRestorePrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators"; Recommendation="Limit to Administrators."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.38"; Title="Shut down the system"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="LOW"; CheckType="UserRight"; CheckKey="SeShutdownPrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators"; Recommendation="Limit to Administrators."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.39"; Title="Synchronize directory service data is set to 'No One' (DC only)"; Profile="L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeSyncAgentPrivilege"; CheckValue=$null; Operator="EMPTY"; Expected="No One"; Recommendation="Remove all principals from 'Synchronize directory service data'."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.2.40"; Title="Take ownership of files or other objects"; Profile="L1_MS,L1_DC"; Category="Local Policies"; Subcategory="User Rights Assignment"; Severity="HIGH"; CheckType="UserRight"; CheckKey="SeTakeOwnershipPrivilege"; CheckValue=$null; Operator="SUBSET"; Expected="Administrators"; Recommendation="Limit to Administrators."; CWE="CWE-269" }
    )

    Invoke-Controls $controls
}   # End Test-UserRightsAssignment

# ============================================================
#  Section 2.3 : Security Options
# ============================================================
function Test-SecurityOptions {
    Write-ScanLog "--- Section 2.3: Security Options ---" "INFO"

    $controls = @(
        # 2.3.1 Accounts
        [PSCustomObject]@{ CIS_ID="2.3.1.1"; Title="Accounts: Block Microsoft accounts"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Accounts"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; CheckValue="NoConnectedUser"; Operator="EQ"; Expected=3; Recommendation="Set to 'Users can't add or log on with Microsoft accounts' (3)."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="2.3.1.2"; Title="Accounts: Guest account status is Disabled"; Profile="L1_MS"; Category="Security Options"; Subcategory="Accounts"; Severity="HIGH"; CheckType="Secedit"; CheckKey="EnableGuestAccount"; CheckValue=$null; Operator="EQ"; Expected=0; Recommendation="Disable the Guest account."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="2.3.1.3"; Title="Accounts: Limit local account use of blank passwords to console logon only"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Accounts"; Severity="CRITICAL"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; CheckValue="LimitBlankPasswordUse"; Operator="EQ"; Expected=1; Recommendation="Enable blank password console-only restriction."; CWE="CWE-521" },
        # 2.3.2 Audit
        [PSCustomObject]@{ CIS_ID="2.3.2.1"; Title="Audit: Force audit policy subcategory settings to override"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Audit"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; CheckValue="SCENoApplyLegacyAuditPolicy"; Operator="EQ"; Expected=1; Recommendation="Enable audit policy subcategory override."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="2.3.2.2"; Title="Audit: Shut down system immediately if unable to log security audits is Disabled"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Audit"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; CheckValue="CrashOnAuditFail"; Operator="EQ"; Expected=0; Recommendation="Disable crash on audit fail."; CWE="CWE-778" },
        # 2.3.4 Devices
        [PSCustomObject]@{ CIS_ID="2.3.4.1"; Title="Devices: Prevent users from installing printer drivers"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Devices"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"; CheckValue="AddPrinterDrivers"; Operator="EQ"; Expected=1; Recommendation="Enable printer driver installation restriction."; CWE="CWE-269" },
        # 2.3.6 Domain Member
        [PSCustomObject]@{ CIS_ID="2.3.6.1"; Title="Domain member: Digitally encrypt or sign secure channel data (always)"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Domain Member"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; CheckValue="RequireSignOrSeal"; Operator="EQ"; Expected=1; Recommendation="Enable secure channel encryption/signing."; CWE="CWE-311" },
        [PSCustomObject]@{ CIS_ID="2.3.6.2"; Title="Domain member: Digitally encrypt secure channel data (when possible)"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Domain Member"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; CheckValue="SealSecureChannel"; Operator="EQ"; Expected=1; Recommendation="Enable secure channel encryption."; CWE="CWE-311" },
        [PSCustomObject]@{ CIS_ID="2.3.6.3"; Title="Domain member: Digitally sign secure channel data (when possible)"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Domain Member"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; CheckValue="SignSecureChannel"; Operator="EQ"; Expected=1; Recommendation="Enable secure channel signing."; CWE="CWE-311" },
        [PSCustomObject]@{ CIS_ID="2.3.6.4"; Title="Domain member: Disable machine account password changes is Disabled"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Domain Member"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; CheckValue="DisablePasswordChange"; Operator="EQ"; Expected=0; Recommendation="Do not disable machine account password changes."; CWE="CWE-262" },
        [PSCustomObject]@{ CIS_ID="2.3.6.5"; Title="Domain member: Maximum machine account password age is 30 or fewer days, not 0"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Domain Member"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; CheckValue="MaximumPasswordAge"; Operator="RANGE"; Expected="1,30"; Recommendation="Set machine account password age to 1-30 days."; CWE="CWE-262" },
        [PSCustomObject]@{ CIS_ID="2.3.6.6"; Title="Domain member: Require strong session key"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Domain Member"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; CheckValue="RequireStrongKey"; Operator="EQ"; Expected=1; Recommendation="Enable strong session key requirement."; CWE="CWE-326" },
        # 2.3.7 Interactive Logon
        [PSCustomObject]@{ CIS_ID="2.3.7.1"; Title="Interactive logon: Do not require CTRL+ALT+DEL is Disabled"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Interactive Logon"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; CheckValue="DisableCAD"; Operator="EQ"; Expected=0; Recommendation="Require CTRL+ALT+DEL for logon."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="2.3.7.2"; Title="Interactive logon: Don't display last signed-in"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Interactive Logon"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; CheckValue="DontDisplayLastUserName"; Operator="EQ"; Expected=1; Recommendation="Hide last signed-in username."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="2.3.7.3"; Title="Interactive logon: Machine inactivity limit is 900 or fewer seconds, not 0"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Interactive Logon"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; CheckValue="InactivityTimeoutSecs"; Operator="RANGE"; Expected="1,900"; Recommendation="Set inactivity limit to 1-900 seconds."; CWE="CWE-613" },
        [PSCustomObject]@{ CIS_ID="2.3.7.4"; Title="Interactive logon: Message text for users attempting to log on is configured"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Interactive Logon"; Severity="LOW"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; CheckValue="LegalNoticeText"; Operator="NE"; Expected=""; Recommendation="Configure a logon banner text."; CWE="CWE-1188" },
        [PSCustomObject]@{ CIS_ID="2.3.7.5"; Title="Interactive logon: Message title for users attempting to log on is configured"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Interactive Logon"; Severity="LOW"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; CheckValue="LegalNoticeCaption"; Operator="NE"; Expected=""; Recommendation="Configure a logon banner title."; CWE="CWE-1188" },
        [PSCustomObject]@{ CIS_ID="2.3.7.6"; Title="Interactive logon: Number of previous logons to cache is 4 or fewer"; Profile="L2_MS,L2_DC"; Category="Security Options"; Subcategory="Interactive Logon"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; CheckValue="CachedLogonsCount"; Operator="LE"; Expected=4; Recommendation="Set cached logons to 4 or fewer."; CWE="CWE-522" },
        [PSCustomObject]@{ CIS_ID="2.3.7.7"; Title="Interactive logon: Prompt user to change password before expiration (5-14 days)"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Interactive Logon"; Severity="LOW"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; CheckValue="PasswordExpiryWarning"; Operator="RANGE"; Expected="5,14"; Recommendation="Set password expiry warning to 5-14 days."; CWE="CWE-262" },
        [PSCustomObject]@{ CIS_ID="2.3.7.8"; Title="Interactive logon: Smart card removal behavior is Lock Workstation or higher"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Interactive Logon"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; CheckValue="ScRemoveOption"; Operator="IN"; Expected="1,2,3"; Recommendation="Set smart card removal to Lock Workstation (1) or Force Logoff (2)."; CWE="CWE-613" },
        # 2.3.8 Microsoft Network Client
        [PSCustomObject]@{ CIS_ID="2.3.8.1"; Title="MS network client: Digitally sign communications (always)"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="MS Network Client"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; CheckValue="RequireSecuritySignature"; Operator="EQ"; Expected=1; Recommendation="Enable mandatory SMB client signing."; CWE="CWE-311" },
        [PSCustomObject]@{ CIS_ID="2.3.8.2"; Title="MS network client: Digitally sign communications (if server agrees)"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="MS Network Client"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; CheckValue="EnableSecuritySignature"; Operator="EQ"; Expected=1; Recommendation="Enable opportunistic SMB client signing."; CWE="CWE-311" },
        [PSCustomObject]@{ CIS_ID="2.3.8.3"; Title="MS network client: Send unencrypted password to third-party SMB servers is Disabled"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="MS Network Client"; Severity="CRITICAL"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; CheckValue="EnablePlainTextPassword"; Operator="EQ"; Expected=0; Recommendation="Disable unencrypted password to third-party SMB."; CWE="CWE-319" },
        # 2.3.9 Microsoft Network Server
        [PSCustomObject]@{ CIS_ID="2.3.9.1"; Title="MS network server: Idle time before suspending session is 15 or fewer min"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="MS Network Server"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; CheckValue="AutoDisconnect"; Operator="LE"; Expected=15; Recommendation="Set idle timeout to 15 min or fewer."; CWE="CWE-613" },
        [PSCustomObject]@{ CIS_ID="2.3.9.2"; Title="MS network server: Digitally sign communications (always)"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="MS Network Server"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; CheckValue="RequireSecuritySignature"; Operator="EQ"; Expected=1; Recommendation="Enable mandatory SMB server signing."; CWE="CWE-311" },
        [PSCustomObject]@{ CIS_ID="2.3.9.3"; Title="MS network server: Digitally sign communications (if client agrees)"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="MS Network Server"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; CheckValue="EnableSecuritySignature"; Operator="EQ"; Expected=1; Recommendation="Enable opportunistic SMB server signing."; CWE="CWE-311" },
        [PSCustomObject]@{ CIS_ID="2.3.9.4"; Title="MS network server: Disconnect clients when logon hours expire"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="MS Network Server"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; CheckValue="EnableForcedLogOff"; Operator="EQ"; Expected=1; Recommendation="Enable forced disconnect on logon hours expiry."; CWE="CWE-613" },
        [PSCustomObject]@{ CIS_ID="2.3.9.5"; Title="MS network server: Server SPN target name validation level is 1 or higher"; Profile="L1_MS"; Category="Security Options"; Subcategory="MS Network Server"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; CheckValue="SmbServerNameHardeningLevel"; Operator="GE"; Expected=1; Recommendation="Set SPN validation to 'Accept if provided' (1) or higher."; CWE="CWE-290" },
        # 2.3.10 Network Access
        [PSCustomObject]@{ CIS_ID="2.3.10.1"; Title="Network access: Allow anonymous SID/Name translation is Disabled"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Network Access"; Severity="HIGH"; CheckType="Secedit"; CheckKey="LSAAnonymousNameLookup"; CheckValue=$null; Operator="EQ"; Expected=0; Recommendation="Disable anonymous SID/Name translation."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="2.3.10.2"; Title="Network access: Do not allow anonymous enumeration of SAM accounts"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Network Access"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; CheckValue="RestrictAnonymousSAM"; Operator="EQ"; Expected=1; Recommendation="Restrict anonymous SAM enumeration."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="2.3.10.3"; Title="Network access: Do not allow anonymous enumeration of SAM accounts and shares"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Network Access"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; CheckValue="RestrictAnonymous"; Operator="EQ"; Expected=1; Recommendation="Restrict anonymous SAM and share enumeration."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="2.3.10.5"; Title="Network access: Let Everyone permissions apply to anonymous users is Disabled"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Network Access"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; CheckValue="EveryoneIncludesAnonymous"; Operator="EQ"; Expected=0; Recommendation="Exclude anonymous from Everyone group."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="2.3.10.9"; Title="Network access: Restrict anonymous access to Named Pipes and Shares"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Network Access"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; CheckValue="RestrictNullSessAccess"; Operator="EQ"; Expected=1; Recommendation="Restrict anonymous Named Pipe/Share access."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="2.3.10.11"; Title="Network access: Sharing and security model for local accounts is Classic"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Network Access"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; CheckValue="ForceGuest"; Operator="EQ"; Expected=0; Recommendation="Set sharing model to Classic (0)."; CWE="CWE-284" },
        # 2.3.11 Network Security
        [PSCustomObject]@{ CIS_ID="2.3.11.1"; Title="Network security: Allow Local System to use computer identity for NTLM"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Network Security"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; CheckValue="UseMachineId"; Operator="EQ"; Expected=1; Recommendation="Enable computer identity for NTLM."; CWE="CWE-287" },
        [PSCustomObject]@{ CIS_ID="2.3.11.2"; Title="Network security: Allow LocalSystem NULL session fallback is Disabled"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Network Security"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; CheckValue="AllowNullSessionFallback"; Operator="EQ"; Expected=0; Recommendation="Disable NULL session fallback."; CWE="CWE-287" },
        [PSCustomObject]@{ CIS_ID="2.3.11.3"; Title="Network security: Allow PKU2U authentication requests is Disabled"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Network Security"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"; CheckValue="AllowOnlineID"; Operator="EQ"; Expected=0; Recommendation="Disable PKU2U authentication."; CWE="CWE-287" },
        [PSCustomObject]@{ CIS_ID="2.3.11.4"; Title="Network security: Configure encryption types allowed for Kerberos"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Network Security"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"; CheckValue="SupportedEncryptionTypes"; Operator="EQ"; Expected=2147483640; Recommendation="Set Kerberos to AES128+AES256+Future (2147483640)."; CWE="CWE-326" },
        [PSCustomObject]@{ CIS_ID="2.3.11.5"; Title="Network security: Do not store LAN Manager hash value on next password change"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Network Security"; Severity="CRITICAL"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; CheckValue="NoLMHash"; Operator="EQ"; Expected=1; Recommendation="Prevent LM hash storage."; CWE="CWE-328" },
        [PSCustomObject]@{ CIS_ID="2.3.11.7"; Title="Network security: LAN Manager authentication level is 'NTLMv2 only, refuse LM and NTLM'"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Network Security"; Severity="CRITICAL"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; CheckValue="LmCompatibilityLevel"; Operator="EQ"; Expected=5; Recommendation="Set LM auth level to 5 (NTLMv2 only)."; CWE="CWE-287" },
        [PSCustomObject]@{ CIS_ID="2.3.11.8"; Title="Network security: LDAP client signing requirements is Negotiate signing or higher"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Network Security"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"; CheckValue="LDAPClientIntegrity"; Operator="GE"; Expected=1; Recommendation="Set LDAP client signing to 1+ (Negotiate/Require)."; CWE="CWE-311" },
        [PSCustomObject]@{ CIS_ID="2.3.11.9"; Title="Network security: Minimum session security for NTLM SSP clients"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Network Security"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; CheckValue="NtlmMinClientSec"; Operator="EQ"; Expected=537395200; Recommendation="Set NTLMv2+128-bit (537395200)."; CWE="CWE-326" },
        [PSCustomObject]@{ CIS_ID="2.3.11.10"; Title="Network security: Minimum session security for NTLM SSP servers"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Network Security"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; CheckValue="NtlmMinServerSec"; Operator="EQ"; Expected=537395200; Recommendation="Set NTLMv2+128-bit (537395200)."; CWE="CWE-326" },
        # 2.3.13 Shutdown
        [PSCustomObject]@{ CIS_ID="2.3.13.1"; Title="Shutdown: Allow system to be shut down without having to log on is Disabled"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="Shutdown"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; CheckValue="ShutdownWithoutLogon"; Operator="EQ"; Expected=0; Recommendation="Require logon before shutdown."; CWE="CWE-284" },
        # 2.3.15 System Objects
        [PSCustomObject]@{ CIS_ID="2.3.15.1"; Title="System objects: Require case insensitivity for non-Windows subsystems"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="System Objects"; Severity="LOW"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"; CheckValue="ObCaseInsensitive"; Operator="EQ"; Expected=1; Recommendation="Enable case insensitivity."; CWE="CWE-178" },
        [PSCustomObject]@{ CIS_ID="2.3.15.2"; Title="System objects: Strengthen default permissions of internal system objects"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="System Objects"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"; CheckValue="ProtectionMode"; Operator="EQ"; Expected=1; Recommendation="Strengthen default object permissions."; CWE="CWE-732" },
        # 2.3.17 UAC
        [PSCustomObject]@{ CIS_ID="2.3.17.1"; Title="UAC: Admin Approval Mode for Built-in Administrator"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="UAC"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; CheckValue="FilterAdministratorToken"; Operator="EQ"; Expected=1; Recommendation="Enable Admin Approval Mode for built-in admin."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.3.17.2"; Title="UAC: Behavior of elevation prompt for admins is Prompt for consent on secure desktop"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="UAC"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; CheckValue="ConsentPromptBehaviorAdmin"; Operator="EQ"; Expected=2; Recommendation="Set admin elevation to secure desktop consent (2)."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.3.17.3"; Title="UAC: Behavior of elevation prompt for standard users is Automatically deny"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="UAC"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; CheckValue="ConsentPromptBehaviorUser"; Operator="EQ"; Expected=0; Recommendation="Auto-deny standard user elevation (0)."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.3.17.4"; Title="UAC: Detect application installations and prompt for elevation"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="UAC"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; CheckValue="EnableInstallerDetection"; Operator="EQ"; Expected=1; Recommendation="Enable installer detection."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.3.17.5"; Title="UAC: Only elevate UIAccess apps installed in secure locations"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="UAC"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; CheckValue="EnableSecureUIAPaths"; Operator="EQ"; Expected=1; Recommendation="Require secure location for UIAccess elevation."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.3.17.6"; Title="UAC: Run all administrators in Admin Approval Mode"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="UAC"; Severity="CRITICAL"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; CheckValue="EnableLUA"; Operator="EQ"; Expected=1; Recommendation="Enable Admin Approval Mode (UAC)."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.3.17.7"; Title="UAC: Switch to secure desktop when prompting for elevation"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="UAC"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; CheckValue="PromptOnSecureDesktop"; Operator="EQ"; Expected=1; Recommendation="Enable secure desktop for elevation."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="2.3.17.8"; Title="UAC: Virtualize file and registry write failures to per-user locations"; Profile="L1_MS,L1_DC"; Category="Security Options"; Subcategory="UAC"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; CheckValue="EnableVirtualization"; Operator="EQ"; Expected=1; Recommendation="Enable write failure virtualization."; CWE="CWE-269" }
    )

    Invoke-Controls $controls
}   # End Test-SecurityOptions

# ============================================================
#  Section 5 : System Services
# ============================================================
function Test-SystemServices {
    Write-ScanLog "--- Section 5: System Services ---" "INFO"

    $controls = @(
        [PSCustomObject]@{ CIS_ID="5.1"; Title="Computer Browser (Browser) is Disabled or Not Installed"; Profile="L1_MS,L1_DC"; Category="System Services"; Subcategory="Services"; Severity="MEDIUM"; CheckType="Service"; CheckKey="Browser"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable or remove Computer Browser service."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.2"; Title="IIS Admin Service (IISADMIN) is Disabled or Not Installed"; Profile="L1_MS,L1_DC"; Category="System Services"; Subcategory="Services"; Severity="HIGH"; CheckType="Service"; CheckKey="IISADMIN"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable or remove IIS Admin Service."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.3"; Title="Infrared monitor service (irmon) is Disabled or Not Installed"; Profile="L1_MS,L1_DC"; Category="System Services"; Subcategory="Services"; Severity="LOW"; CheckType="Service"; CheckKey="irmon"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable or remove Infrared monitor service."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.4"; Title="Internet Connection Sharing (SharedAccess) is Disabled"; Profile="L1_MS,L1_DC"; Category="System Services"; Subcategory="Services"; Severity="HIGH"; CheckType="Service"; CheckKey="SharedAccess"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Internet Connection Sharing."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.5"; Title="LxssManager (WSL) is Disabled or Not Installed"; Profile="L1_MS,L1_DC"; Category="System Services"; Subcategory="Services"; Severity="MEDIUM"; CheckType="Service"; CheckKey="LxssManager"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Windows Subsystem for Linux."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.6"; Title="Microsoft FTP Service (FTPSVC) is Disabled or Not Installed"; Profile="L1_MS,L1_DC"; Category="System Services"; Subcategory="Services"; Severity="HIGH"; CheckType="Service"; CheckKey="FTPSVC"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable or remove FTP Service."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.7"; Title="OpenSSH SSH Server (sshd) is Disabled or Not Installed"; Profile="L1_MS,L1_DC"; Category="System Services"; Subcategory="Services"; Severity="MEDIUM"; CheckType="Service"; CheckKey="sshd"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable or remove OpenSSH Server if not needed."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.8"; Title="Peer Name Resolution Protocol (PNRPsvc) is Disabled or Not Installed"; Profile="L2_MS,L2_DC"; Category="System Services"; Subcategory="Services"; Severity="LOW"; CheckType="Service"; CheckKey="PNRPsvc"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Peer Name Resolution Protocol."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.9"; Title="Peer Networking Grouping (p2psvc) is Disabled or Not Installed"; Profile="L2_MS,L2_DC"; Category="System Services"; Subcategory="Services"; Severity="LOW"; CheckType="Service"; CheckKey="p2psvc"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Peer Networking Grouping."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.10"; Title="Peer Networking Identity Manager (p2pimsvc) is Disabled or Not Installed"; Profile="L2_MS,L2_DC"; Category="System Services"; Subcategory="Services"; Severity="LOW"; CheckType="Service"; CheckKey="p2pimsvc"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Peer Networking Identity Manager."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.11"; Title="PNRP Machine Name Publication (PNRPAutoReg) is Disabled or Not Installed"; Profile="L2_MS,L2_DC"; Category="System Services"; Subcategory="Services"; Severity="LOW"; CheckType="Service"; CheckKey="PNRPAutoReg"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable PNRP Machine Name Publication."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.12"; Title="Print Spooler (Spooler) is Disabled (DC)"; Profile="L2_DC"; Category="System Services"; Subcategory="Services"; Severity="HIGH"; CheckType="Service"; CheckKey="Spooler"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Print Spooler on Domain Controllers."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.13"; Title="Remote Access Auto Connection Manager (RasAuto) is Disabled or Not Installed"; Profile="L2_MS,L2_DC"; Category="System Services"; Subcategory="Services"; Severity="LOW"; CheckType="Service"; CheckKey="RasAuto"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Remote Access Auto Connection Manager."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.14"; Title="Remote Desktop Configuration (SessionEnv) is Disabled or Not Installed"; Profile="L2_MS,L2_DC"; Category="System Services"; Subcategory="Services"; Severity="MEDIUM"; CheckType="Service"; CheckKey="SessionEnv"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Remote Desktop Configuration."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.15"; Title="Remote Desktop Services (TermService) is Disabled or Not Installed"; Profile="L2_MS,L2_DC"; Category="System Services"; Subcategory="Services"; Severity="MEDIUM"; CheckType="Service"; CheckKey="TermService"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Remote Desktop Services if not needed."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.16"; Title="Remote Desktop Services UserMode Port Redirector (UmRdpService) is Disabled or Not Installed"; Profile="L2_MS,L2_DC"; Category="System Services"; Subcategory="Services"; Severity="LOW"; CheckType="Service"; CheckKey="UmRdpService"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable RDS UserMode Port Redirector."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.17"; Title="Remote Procedure Call Locator (RpcLocator) is Disabled"; Profile="L2_MS,L2_DC"; Category="System Services"; Subcategory="Services"; Severity="LOW"; CheckType="Service"; CheckKey="RpcLocator"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable RPC Locator."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.18"; Title="Remote Registry (RemoteRegistry) is Disabled"; Profile="L2_MS,L2_DC"; Category="System Services"; Subcategory="Services"; Severity="MEDIUM"; CheckType="Service"; CheckKey="RemoteRegistry"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Remote Registry."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.19"; Title="Routing and Remote Access (RemoteAccess) is Disabled"; Profile="L1_MS,L1_DC"; Category="System Services"; Subcategory="Services"; Severity="HIGH"; CheckType="Service"; CheckKey="RemoteAccess"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Routing and Remote Access."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.20"; Title="Server (LanmanServer) is Disabled or Not Installed"; Profile="L2_MS"; Category="System Services"; Subcategory="Services"; Severity="MEDIUM"; CheckType="Service"; CheckKey="LanmanServer"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Server service if file sharing not needed."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.21"; Title="Simple TCP/IP Services (simptcp) is Disabled or Not Installed"; Profile="L1_MS,L1_DC"; Category="System Services"; Subcategory="Services"; Severity="MEDIUM"; CheckType="Service"; CheckKey="simptcp"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Simple TCP/IP Services."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.22"; Title="SNMP Service (SNMP) is Disabled or Not Installed"; Profile="L2_MS,L2_DC"; Category="System Services"; Subcategory="Services"; Severity="MEDIUM"; CheckType="Service"; CheckKey="SNMP"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable SNMP Service."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.23"; Title="SSDP Discovery (SSDPSRV) is Disabled"; Profile="L1_MS,L1_DC"; Category="System Services"; Subcategory="Services"; Severity="MEDIUM"; CheckType="Service"; CheckKey="SSDPSRV"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable SSDP Discovery."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.24"; Title="UPnP Device Host (upnphost) is Disabled"; Profile="L1_MS,L1_DC"; Category="System Services"; Subcategory="Services"; Severity="MEDIUM"; CheckType="Service"; CheckKey="upnphost"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable UPnP Device Host."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.25"; Title="Web Management Service (WMSvc) is Disabled or Not Installed"; Profile="L1_MS,L1_DC"; Category="System Services"; Subcategory="Services"; Severity="HIGH"; CheckType="Service"; CheckKey="WMSvc"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Web Management Service."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.26"; Title="Windows Error Reporting Service (WerSvc) is Disabled"; Profile="L2_MS,L2_DC"; Category="System Services"; Subcategory="Services"; Severity="LOW"; CheckType="Service"; CheckKey="WerSvc"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Windows Error Reporting."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="5.27"; Title="Windows Event Collector (Wecsvc) is Disabled or Not Installed"; Profile="L2_MS,L2_DC"; Category="System Services"; Subcategory="Services"; Severity="LOW"; CheckType="Service"; CheckKey="Wecsvc"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Windows Event Collector if not needed."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.28"; Title="Windows Push Notifications System (WpnService) is Disabled"; Profile="L2_MS,L2_DC"; Category="System Services"; Subcategory="Services"; Severity="LOW"; CheckType="Service"; CheckKey="WpnService"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Windows Push Notifications."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.29"; Title="Windows Remote Management (WinRM) is Disabled"; Profile="L2_MS,L2_DC"; Category="System Services"; Subcategory="Services"; Severity="MEDIUM"; CheckType="Service"; CheckKey="WinRM"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable WinRM if not needed."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.30"; Title="World Wide Web Publishing Service (W3SVC) is Disabled or Not Installed"; Profile="L1_MS,L1_DC"; Category="System Services"; Subcategory="Services"; Severity="HIGH"; CheckType="Service"; CheckKey="W3SVC"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable W3SVC unless IIS is required."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.31"; Title="Xbox Accessory Management Service (XboxGipSvc) is Disabled or Not Installed"; Profile="L1_MS,L1_DC"; Category="System Services"; Subcategory="Services"; Severity="LOW"; CheckType="Service"; CheckKey="XboxGipSvc"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Xbox Accessory Management."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.32"; Title="Xbox Live Auth Manager (XblAuthManager) is Disabled or Not Installed"; Profile="L1_MS,L1_DC"; Category="System Services"; Subcategory="Services"; Severity="LOW"; CheckType="Service"; CheckKey="XblAuthManager"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Xbox Live Auth Manager."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.33"; Title="Xbox Live Game Save (XblGameSave) is Disabled or Not Installed"; Profile="L1_MS,L1_DC"; Category="System Services"; Subcategory="Services"; Severity="LOW"; CheckType="Service"; CheckKey="XblGameSave"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Xbox Live Game Save."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.34"; Title="Xbox Live Networking Service (XboxNetApiSvc) is Disabled or Not Installed"; Profile="L1_MS,L1_DC"; Category="System Services"; Subcategory="Services"; Severity="LOW"; CheckType="Service"; CheckKey="XboxNetApiSvc"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Xbox Live Networking."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.35"; Title="Microsoft iSCSI Initiator Service (MSiSCSI) is Disabled"; Profile="L2_MS,L2_DC"; Category="System Services"; Subcategory="Services"; Severity="MEDIUM"; CheckType="Service"; CheckKey="MSiSCSI"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable iSCSI Initiator if not needed."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="5.36"; Title="Windows Search (WSearch) is Disabled"; Profile="L2_MS,L2_DC"; Category="System Services"; Subcategory="Services"; Severity="LOW"; CheckType="Service"; CheckKey="WSearch"; CheckValue=$null; Operator="IN"; Expected="Disabled,NotInstalled"; Recommendation="Disable Windows Search if not needed."; CWE="CWE-284" }
    )

    Invoke-Controls $controls
}   # End Test-SystemServices

# ============================================================
#  Section 9 : Windows Firewall with Advanced Security
# ============================================================
function Test-FirewallConfiguration {
    Write-ScanLog "--- Section 9: Windows Firewall ---" "INFO"

    $controls = @(
        # 9.1 Domain Profile
        [PSCustomObject]@{ CIS_ID="9.1.1"; Title="Windows Firewall: Domain: Firewall state is On"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Domain Profile"; Severity="HIGH"; CheckType="Firewall"; CheckKey="DomainProfile|EnableFirewall"; CheckValue=$null; Operator="EQ"; Expected=1; Recommendation="Enable Windows Firewall for Domain profile."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="9.1.2"; Title="Windows Firewall: Domain: Inbound connections is Block"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Domain Profile"; Severity="HIGH"; CheckType="Firewall"; CheckKey="DomainProfile|DefaultInboundAction"; CheckValue=$null; Operator="EQ"; Expected=1; Recommendation="Set Domain profile inbound to Block (1)."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="9.1.3"; Title="Windows Firewall: Domain: Outbound connections is Allow"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Domain Profile"; Severity="MEDIUM"; CheckType="Firewall"; CheckKey="DomainProfile|DefaultOutboundAction"; CheckValue=$null; Operator="EQ"; Expected=0; Recommendation="Set Domain profile outbound to Allow (0)."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="9.1.4"; Title="Windows Firewall: Domain: Display notification is No"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Domain Profile"; Severity="LOW"; CheckType="Firewall"; CheckKey="DomainProfile|DisableNotifications"; CheckValue=$null; Operator="EQ"; Expected=1; Recommendation="Disable firewall notifications for Domain profile."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="9.1.5"; Title="Windows Firewall: Domain: Log file size is 16384 KB or greater"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Domain Profile"; Severity="MEDIUM"; CheckType="Firewall"; CheckKey="DomainProfile|LogFileSize"; CheckValue=$null; Operator="GE"; Expected=16384; Recommendation="Set Domain log file size to 16384 KB+."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="9.1.6"; Title="Windows Firewall: Domain: Log dropped packets is Yes"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Domain Profile"; Severity="MEDIUM"; CheckType="Firewall"; CheckKey="DomainProfile|LogDroppedPackets"; CheckValue=$null; Operator="EQ"; Expected=1; Recommendation="Enable logging of dropped packets for Domain."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="9.1.7"; Title="Windows Firewall: Domain: Log successful connections is Yes"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Domain Profile"; Severity="MEDIUM"; CheckType="Firewall"; CheckKey="DomainProfile|LogSuccessfulConnections"; CheckValue=$null; Operator="EQ"; Expected=1; Recommendation="Enable logging of successful connections for Domain."; CWE="CWE-778" },
        # 9.2 Private Profile
        [PSCustomObject]@{ CIS_ID="9.2.1"; Title="Windows Firewall: Private: Firewall state is On"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Private Profile"; Severity="HIGH"; CheckType="Firewall"; CheckKey="PrivateProfile|EnableFirewall"; CheckValue=$null; Operator="EQ"; Expected=1; Recommendation="Enable Windows Firewall for Private profile."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="9.2.2"; Title="Windows Firewall: Private: Inbound connections is Block"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Private Profile"; Severity="HIGH"; CheckType="Firewall"; CheckKey="PrivateProfile|DefaultInboundAction"; CheckValue=$null; Operator="EQ"; Expected=1; Recommendation="Set Private profile inbound to Block (1)."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="9.2.3"; Title="Windows Firewall: Private: Outbound connections is Allow"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Private Profile"; Severity="MEDIUM"; CheckType="Firewall"; CheckKey="PrivateProfile|DefaultOutboundAction"; CheckValue=$null; Operator="EQ"; Expected=0; Recommendation="Set Private profile outbound to Allow (0)."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="9.2.4"; Title="Windows Firewall: Private: Display notification is No"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Private Profile"; Severity="LOW"; CheckType="Firewall"; CheckKey="PrivateProfile|DisableNotifications"; CheckValue=$null; Operator="EQ"; Expected=1; Recommendation="Disable firewall notifications for Private profile."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="9.2.5"; Title="Windows Firewall: Private: Log file size is 16384 KB or greater"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Private Profile"; Severity="MEDIUM"; CheckType="Firewall"; CheckKey="PrivateProfile|LogFileSize"; CheckValue=$null; Operator="GE"; Expected=16384; Recommendation="Set Private log file size to 16384 KB+."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="9.2.6"; Title="Windows Firewall: Private: Log dropped packets is Yes"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Private Profile"; Severity="MEDIUM"; CheckType="Firewall"; CheckKey="PrivateProfile|LogDroppedPackets"; CheckValue=$null; Operator="EQ"; Expected=1; Recommendation="Enable logging of dropped packets for Private."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="9.2.7"; Title="Windows Firewall: Private: Log successful connections is Yes"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Private Profile"; Severity="MEDIUM"; CheckType="Firewall"; CheckKey="PrivateProfile|LogSuccessfulConnections"; CheckValue=$null; Operator="EQ"; Expected=1; Recommendation="Enable logging of successful connections for Private."; CWE="CWE-778" },
        # 9.3 Public Profile
        [PSCustomObject]@{ CIS_ID="9.3.1"; Title="Windows Firewall: Public: Firewall state is On"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Public Profile"; Severity="HIGH"; CheckType="Firewall"; CheckKey="PublicProfile|EnableFirewall"; CheckValue=$null; Operator="EQ"; Expected=1; Recommendation="Enable Windows Firewall for Public profile."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="9.3.2"; Title="Windows Firewall: Public: Inbound connections is Block"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Public Profile"; Severity="HIGH"; CheckType="Firewall"; CheckKey="PublicProfile|DefaultInboundAction"; CheckValue=$null; Operator="EQ"; Expected=1; Recommendation="Set Public profile inbound to Block (1)."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="9.3.3"; Title="Windows Firewall: Public: Outbound connections is Allow"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Public Profile"; Severity="MEDIUM"; CheckType="Firewall"; CheckKey="PublicProfile|DefaultOutboundAction"; CheckValue=$null; Operator="EQ"; Expected=0; Recommendation="Set Public profile outbound to Allow (0)."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="9.3.4"; Title="Windows Firewall: Public: Display notification is No"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Public Profile"; Severity="LOW"; CheckType="Firewall"; CheckKey="PublicProfile|DisableNotifications"; CheckValue=$null; Operator="EQ"; Expected=1; Recommendation="Disable firewall notifications for Public profile."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="9.3.5"; Title="Windows Firewall: Public: Apply local firewall rules is No"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Public Profile"; Severity="MEDIUM"; CheckType="Firewall"; CheckKey="PublicProfile|AllowLocalPolicyMerge"; CheckValue=$null; Operator="EQ"; Expected=0; Recommendation="Disable local firewall rule merge for Public."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="9.3.6"; Title="Windows Firewall: Public: Apply local connection security rules is No"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Public Profile"; Severity="MEDIUM"; CheckType="Firewall"; CheckKey="PublicProfile|AllowLocalIPsecPolicyMerge"; CheckValue=$null; Operator="EQ"; Expected=0; Recommendation="Disable local IPsec rule merge for Public."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="9.3.7"; Title="Windows Firewall: Public: Log file size is 16384 KB or greater"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Public Profile"; Severity="MEDIUM"; CheckType="Firewall"; CheckKey="PublicProfile|LogFileSize"; CheckValue=$null; Operator="GE"; Expected=16384; Recommendation="Set Public log file size to 16384 KB+."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="9.3.8"; Title="Windows Firewall: Public: Log dropped packets is Yes"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Public Profile"; Severity="MEDIUM"; CheckType="Firewall"; CheckKey="PublicProfile|LogDroppedPackets"; CheckValue=$null; Operator="EQ"; Expected=1; Recommendation="Enable logging of dropped packets for Public."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="9.3.9"; Title="Windows Firewall: Public: Log successful connections is Yes"; Profile="L1_MS,L1_DC"; Category="Windows Firewall"; Subcategory="Public Profile"; Severity="MEDIUM"; CheckType="Firewall"; CheckKey="PublicProfile|LogSuccessfulConnections"; CheckValue=$null; Operator="EQ"; Expected=1; Recommendation="Enable logging of successful connections for Public."; CWE="CWE-778" }
    )

    Invoke-Controls $controls
}   # End Test-FirewallConfiguration

# ============================================================
#  Section 17 : Advanced Audit Policy Configuration
# ============================================================
function Test-AuditPolicies {
    Write-ScanLog "--- Section 17: Advanced Audit Policy ---" "INFO"

    $controls = @(
        # 17.1 Account Logon
        [PSCustomObject]@{ CIS_ID="17.1.1"; Title="Audit Credential Validation is set to Success and Failure"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Account Logon"; Severity="HIGH"; CheckType="Auditpol"; CheckKey="Credential Validation"; CheckValue=$null; Operator="EQ"; Expected="Success and Failure"; Recommendation="Set Credential Validation audit to Success and Failure."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.1.2"; Title="Audit Kerberos Authentication Service is set to Success and Failure (DC)"; Profile="L1_DC"; Category="Audit Policy"; Subcategory="Account Logon"; Severity="HIGH"; CheckType="Auditpol"; CheckKey="Kerberos Authentication Service"; CheckValue=$null; Operator="EQ"; Expected="Success and Failure"; Recommendation="Set Kerberos Authentication audit to Success and Failure."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.1.3"; Title="Audit Kerberos Service Ticket Operations is set to Success and Failure (DC)"; Profile="L1_DC"; Category="Audit Policy"; Subcategory="Account Logon"; Severity="HIGH"; CheckType="Auditpol"; CheckKey="Kerberos Service Ticket Operations"; CheckValue=$null; Operator="EQ"; Expected="Success and Failure"; Recommendation="Set Kerberos Service Ticket Operations audit to Success and Failure."; CWE="CWE-778" },
        # 17.2 Account Management
        [PSCustomObject]@{ CIS_ID="17.2.1"; Title="Audit Application Group Management is set to Success and Failure"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Account Management"; Severity="MEDIUM"; CheckType="Auditpol"; CheckKey="Application Group Management"; CheckValue=$null; Operator="EQ"; Expected="Success and Failure"; Recommendation="Set Application Group Management audit to Success and Failure."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.2.2"; Title="Audit Computer Account Management is set to include Success (DC)"; Profile="L1_DC"; Category="Audit Policy"; Subcategory="Account Management"; Severity="HIGH"; CheckType="Auditpol"; CheckKey="Computer Account Management"; CheckValue=$null; Operator="MATCH"; Expected="Success"; Recommendation="Include Success in Computer Account Management audit."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.2.3"; Title="Audit Distribution Group Management is set to include Success (DC)"; Profile="L1_DC"; Category="Audit Policy"; Subcategory="Account Management"; Severity="MEDIUM"; CheckType="Auditpol"; CheckKey="Distribution Group Management"; CheckValue=$null; Operator="MATCH"; Expected="Success"; Recommendation="Include Success in Distribution Group Management audit."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.2.4"; Title="Audit Other Account Management Events is set to include Success"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Account Management"; Severity="MEDIUM"; CheckType="Auditpol"; CheckKey="Other Account Management Events"; CheckValue=$null; Operator="MATCH"; Expected="Success"; Recommendation="Include Success in Other Account Management Events audit."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.2.5"; Title="Audit Security Group Management is set to include Success"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Account Management"; Severity="HIGH"; CheckType="Auditpol"; CheckKey="Security Group Management"; CheckValue=$null; Operator="MATCH"; Expected="Success"; Recommendation="Include Success in Security Group Management audit."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.2.6"; Title="Audit User Account Management is set to Success and Failure"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Account Management"; Severity="HIGH"; CheckType="Auditpol"; CheckKey="User Account Management"; CheckValue=$null; Operator="EQ"; Expected="Success and Failure"; Recommendation="Set User Account Management audit to Success and Failure."; CWE="CWE-778" },
        # 17.3 Detailed Tracking
        [PSCustomObject]@{ CIS_ID="17.3.1"; Title="Audit PNP Activity is set to include Success"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Detailed Tracking"; Severity="MEDIUM"; CheckType="Auditpol"; CheckKey="Plug and Play Events"; CheckValue=$null; Operator="MATCH"; Expected="Success"; Recommendation="Include Success in PNP Activity audit."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.3.2"; Title="Audit Process Creation is set to include Success"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Detailed Tracking"; Severity="HIGH"; CheckType="Auditpol"; CheckKey="Process Creation"; CheckValue=$null; Operator="MATCH"; Expected="Success"; Recommendation="Include Success in Process Creation audit."; CWE="CWE-778" },
        # 17.4 DS Access (DC only)
        [PSCustomObject]@{ CIS_ID="17.4.1"; Title="Audit Directory Service Access is set to include Failure (DC)"; Profile="L1_DC"; Category="Audit Policy"; Subcategory="DS Access"; Severity="HIGH"; CheckType="Auditpol"; CheckKey="Directory Service Access"; CheckValue=$null; Operator="MATCH"; Expected="Failure"; Recommendation="Include Failure in Directory Service Access audit."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.4.2"; Title="Audit Directory Service Changes is set to include Success (DC)"; Profile="L1_DC"; Category="Audit Policy"; Subcategory="DS Access"; Severity="HIGH"; CheckType="Auditpol"; CheckKey="Directory Service Changes"; CheckValue=$null; Operator="MATCH"; Expected="Success"; Recommendation="Include Success in Directory Service Changes audit."; CWE="CWE-778" },
        # 17.5 Logon/Logoff
        [PSCustomObject]@{ CIS_ID="17.5.1"; Title="Audit Account Lockout is set to include Failure"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Logon/Logoff"; Severity="HIGH"; CheckType="Auditpol"; CheckKey="Account Lockout"; CheckValue=$null; Operator="MATCH"; Expected="Failure"; Recommendation="Include Failure in Account Lockout audit."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.5.2"; Title="Audit Group Membership is set to include Success"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Logon/Logoff"; Severity="MEDIUM"; CheckType="Auditpol"; CheckKey="Group Membership"; CheckValue=$null; Operator="MATCH"; Expected="Success"; Recommendation="Include Success in Group Membership audit."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.5.3"; Title="Audit Logoff is set to include Success"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Logon/Logoff"; Severity="MEDIUM"; CheckType="Auditpol"; CheckKey="Logoff"; CheckValue=$null; Operator="MATCH"; Expected="Success"; Recommendation="Include Success in Logoff audit."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.5.4"; Title="Audit Logon is set to Success and Failure"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Logon/Logoff"; Severity="HIGH"; CheckType="Auditpol"; CheckKey="Logon"; CheckValue=$null; Operator="EQ"; Expected="Success and Failure"; Recommendation="Set Logon audit to Success and Failure."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.5.5"; Title="Audit Other Logon/Logoff Events is set to Success and Failure"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Logon/Logoff"; Severity="MEDIUM"; CheckType="Auditpol"; CheckKey="Other Logon/Logoff Events"; CheckValue=$null; Operator="EQ"; Expected="Success and Failure"; Recommendation="Set Other Logon/Logoff Events audit to Success and Failure."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.5.6"; Title="Audit Special Logon is set to include Success"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Logon/Logoff"; Severity="HIGH"; CheckType="Auditpol"; CheckKey="Special Logon"; CheckValue=$null; Operator="MATCH"; Expected="Success"; Recommendation="Include Success in Special Logon audit."; CWE="CWE-778" },
        # 17.6 Object Access
        [PSCustomObject]@{ CIS_ID="17.6.1"; Title="Audit Detailed File Share is set to include Failure"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Object Access"; Severity="MEDIUM"; CheckType="Auditpol"; CheckKey="Detailed File Share"; CheckValue=$null; Operator="MATCH"; Expected="Failure"; Recommendation="Include Failure in Detailed File Share audit."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.6.2"; Title="Audit File Share is set to Success and Failure"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Object Access"; Severity="MEDIUM"; CheckType="Auditpol"; CheckKey="File Share"; CheckValue=$null; Operator="EQ"; Expected="Success and Failure"; Recommendation="Set File Share audit to Success and Failure."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.6.3"; Title="Audit Other Object Access Events is set to Success and Failure"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Object Access"; Severity="MEDIUM"; CheckType="Auditpol"; CheckKey="Other Object Access Events"; CheckValue=$null; Operator="EQ"; Expected="Success and Failure"; Recommendation="Set Other Object Access Events audit to Success and Failure."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.6.4"; Title="Audit Removable Storage is set to Success and Failure"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Object Access"; Severity="MEDIUM"; CheckType="Auditpol"; CheckKey="Removable Storage"; CheckValue=$null; Operator="EQ"; Expected="Success and Failure"; Recommendation="Set Removable Storage audit to Success and Failure."; CWE="CWE-778" },
        # 17.7 Policy Change
        [PSCustomObject]@{ CIS_ID="17.7.1"; Title="Audit Audit Policy Change is set to include Success"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Policy Change"; Severity="HIGH"; CheckType="Auditpol"; CheckKey="Audit Policy Change"; CheckValue=$null; Operator="MATCH"; Expected="Success"; Recommendation="Include Success in Audit Policy Change audit."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.7.2"; Title="Audit Authentication Policy Change is set to include Success"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Policy Change"; Severity="MEDIUM"; CheckType="Auditpol"; CheckKey="Authentication Policy Change"; CheckValue=$null; Operator="MATCH"; Expected="Success"; Recommendation="Include Success in Authentication Policy Change audit."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.7.3"; Title="Audit Authorization Policy Change is set to include Success"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Policy Change"; Severity="MEDIUM"; CheckType="Auditpol"; CheckKey="Authorization Policy Change"; CheckValue=$null; Operator="MATCH"; Expected="Success"; Recommendation="Include Success in Authorization Policy Change audit."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.7.4"; Title="Audit MPSSVC Rule-Level Policy Change is set to Success and Failure"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Policy Change"; Severity="MEDIUM"; CheckType="Auditpol"; CheckKey="MPSSVC Rule-Level Policy Change"; CheckValue=$null; Operator="EQ"; Expected="Success and Failure"; Recommendation="Set MPSSVC Rule-Level audit to Success and Failure."; CWE="CWE-778" },
        # 17.8 Privilege Use
        [PSCustomObject]@{ CIS_ID="17.8.1"; Title="Audit Sensitive Privilege Use is set to Success and Failure"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="Privilege Use"; Severity="HIGH"; CheckType="Auditpol"; CheckKey="Sensitive Privilege Use"; CheckValue=$null; Operator="EQ"; Expected="Success and Failure"; Recommendation="Set Sensitive Privilege Use audit to Success and Failure."; CWE="CWE-778" },
        # 17.9 System
        [PSCustomObject]@{ CIS_ID="17.9.1"; Title="Audit IPsec Driver is set to Success and Failure"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="System"; Severity="MEDIUM"; CheckType="Auditpol"; CheckKey="IPsec Driver"; CheckValue=$null; Operator="EQ"; Expected="Success and Failure"; Recommendation="Set IPsec Driver audit to Success and Failure."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.9.2"; Title="Audit Other System Events is set to Success and Failure"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="System"; Severity="MEDIUM"; CheckType="Auditpol"; CheckKey="Other System Events"; CheckValue=$null; Operator="EQ"; Expected="Success and Failure"; Recommendation="Set Other System Events audit to Success and Failure."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.9.3"; Title="Audit Security State Change is set to include Success"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="System"; Severity="HIGH"; CheckType="Auditpol"; CheckKey="Security State Change"; CheckValue=$null; Operator="MATCH"; Expected="Success"; Recommendation="Include Success in Security State Change audit."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.9.4"; Title="Audit Security System Extension is set to include Success"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="System"; Severity="HIGH"; CheckType="Auditpol"; CheckKey="Security System Extension"; CheckValue=$null; Operator="MATCH"; Expected="Success"; Recommendation="Include Success in Security System Extension audit."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="17.9.5"; Title="Audit System Integrity is set to Success and Failure"; Profile="L1_MS,L1_DC"; Category="Audit Policy"; Subcategory="System"; Severity="HIGH"; CheckType="Auditpol"; CheckKey="System Integrity"; CheckValue=$null; Operator="EQ"; Expected="Success and Failure"; Recommendation="Set System Integrity audit to Success and Failure."; CWE="CWE-778" }
    )

    Invoke-Controls $controls
}   # End Test-AuditPolicies

# ============================================================
#  Section 18 : Administrative Templates (Computer)
# ============================================================
function Test-AdminTemplatesComputer {
    Write-ScanLog "--- Section 18: Administrative Templates (Computer) ---" "INFO"

    $controls = @(
        # 18.1 Control Panel / Personalization
        [PSCustomObject]@{ CIS_ID="18.1.1.1"; Title="Prevent enabling lock screen camera"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Personalization"; Severity="LOW"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; CheckValue="NoLockScreenCamera"; Operator="EQ"; Expected=1; Recommendation="Disable lock screen camera."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="18.1.1.2"; Title="Prevent enabling lock screen slide show"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Personalization"; Severity="LOW"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; CheckValue="NoLockScreenSlideshow"; Operator="EQ"; Expected=1; Recommendation="Disable lock screen slide show."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="18.1.2.2"; Title="Allow users to enable online speech recognition services is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Personalization"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; CheckValue="AllowInputPersonalization"; Operator="EQ"; Expected=0; Recommendation="Disable online speech recognition services."; CWE="CWE-200" },
        # 18.2 LAPS
        [PSCustomObject]@{ CIS_ID="18.2.1"; Title="LAPS AdmPwd GPO Extension / CSE is installed"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="LAPS"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}"; CheckValue="DllName"; Operator="NE"; Expected=""; Recommendation="Install LAPS GPO client-side extension."; CWE="CWE-522" },
        [PSCustomObject]@{ CIS_ID="18.2.2"; Title="Do not allow password expiration time longer than required by policy"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="LAPS"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"; CheckValue="PwdExpirationProtectionEnabled"; Operator="EQ"; Expected=1; Recommendation="Enable LAPS password expiration protection."; CWE="CWE-262" },
        [PSCustomObject]@{ CIS_ID="18.2.3"; Title="Enable local admin password management (LAPS)"; Profile="L1_MS"; Category="Admin Templates"; Subcategory="LAPS"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"; CheckValue="AdmPwdEnabled"; Operator="EQ"; Expected=1; Recommendation="Enable LAPS for local admin password management."; CWE="CWE-522" },
        # 18.3 MS Security Guide
        [PSCustomObject]@{ CIS_ID="18.3.1"; Title="Apply UAC restrictions to local accounts on network logons"; Profile="L1_MS"; Category="Admin Templates"; Subcategory="MS Security Guide"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; CheckValue="LocalAccountTokenFilterPolicy"; Operator="EQ"; Expected=0; Recommendation="Apply UAC restrictions to local accounts on network logons (0)."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="18.3.2"; Title="Configure SMB v1 client driver is Enabled: Disable driver"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="MS Security Guide"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"; CheckValue="Start"; Operator="EQ"; Expected=4; Recommendation="Set SMBv1 client driver to Disabled (4)."; CWE="CWE-327" },
        [PSCustomObject]@{ CIS_ID="18.3.3"; Title="Configure SMB v1 server is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="MS Security Guide"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; CheckValue="SMB1"; Operator="EQ"; Expected=0; Recommendation="Disable SMBv1 server."; CWE="CWE-327" },
        [PSCustomObject]@{ CIS_ID="18.3.4"; Title="Enable Structured Exception Handling Overwrite Protection (SEHOP)"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="MS Security Guide"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; CheckValue="DisableExceptionChainValidation"; Operator="EQ"; Expected=0; Recommendation="Enable SEHOP (set DisableExceptionChainValidation to 0)."; CWE="CWE-120" },
        [PSCustomObject]@{ CIS_ID="18.3.6"; Title="WDigest Authentication is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="MS Security Guide"; Severity="CRITICAL"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; CheckValue="UseLogonCredential"; Operator="EQ"; Expected=0; Recommendation="Disable WDigest to prevent cleartext credential storage."; CWE="CWE-522" },
        # 18.4 MSS (Legacy)
        [PSCustomObject]@{ CIS_ID="18.4.1"; Title="MSS: (AutoAdminLogon) Enable Automatic Logon is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="MSS Legacy"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; CheckValue="AutoAdminLogon"; Operator="EQ"; Expected="0"; Recommendation="Disable automatic admin logon."; CWE="CWE-287" },
        [PSCustomObject]@{ CIS_ID="18.4.2"; Title="MSS: (DisableIPSourceRouting IPv6) is Highest protection"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="MSS Legacy"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; CheckValue="DisableIPSourceRouting"; Operator="EQ"; Expected=2; Recommendation="Set IPv6 IP source routing to Highest protection (2)."; CWE="CWE-441" },
        [PSCustomObject]@{ CIS_ID="18.4.3"; Title="MSS: (DisableIPSourceRouting) is Highest protection"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="MSS Legacy"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; CheckValue="DisableIPSourceRouting"; Operator="EQ"; Expected=2; Recommendation="Set IP source routing to Highest protection (2)."; CWE="CWE-441" },
        [PSCustomObject]@{ CIS_ID="18.4.4"; Title="MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF routes is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="MSS Legacy"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; CheckValue="EnableICMPRedirect"; Operator="EQ"; Expected=0; Recommendation="Disable ICMP redirects overriding OSPF routes."; CWE="CWE-441" },
        [PSCustomObject]@{ CIS_ID="18.4.6"; Title="MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="MSS Legacy"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; CheckValue="NoNameReleaseOnDemand"; Operator="EQ"; Expected=1; Recommendation="Ignore NetBIOS name release requests."; CWE="CWE-441" },
        [PSCustomObject]@{ CIS_ID="18.4.8"; Title="MSS: (SafeDllSearchMode) is Enabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="MSS Legacy"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"; CheckValue="SafeDllSearchMode"; Operator="EQ"; Expected=1; Recommendation="Enable Safe DLL Search Mode."; CWE="CWE-427" },
        [PSCustomObject]@{ CIS_ID="18.4.9"; Title="MSS: (ScreenSaverGracePeriod) is set to 5 or fewer seconds"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="MSS Legacy"; Severity="LOW"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; CheckValue="ScreenSaverGracePeriod"; Operator="LE"; Expected=5; Recommendation="Set screen saver grace period to 5 or fewer seconds."; CWE="CWE-613" },
        # 18.5 Network
        [PSCustomObject]@{ CIS_ID="18.5.4.1"; Title="Turn off multicast name resolution (LLMNR) is Enabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Network"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; CheckValue="EnableMulticast"; Operator="EQ"; Expected=0; Recommendation="Disable LLMNR multicast name resolution."; CWE="CWE-441" },
        [PSCustomObject]@{ CIS_ID="18.5.8.1"; Title="Enable insecure guest logons is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Network"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"; CheckValue="AllowInsecureGuestAuth"; Operator="EQ"; Expected=0; Recommendation="Disable insecure guest logons."; CWE="CWE-287" },
        [PSCustomObject]@{ CIS_ID="18.5.11.2"; Title="Prohibit installation and configuration of Network Bridge"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Network"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"; CheckValue="NC_AllowNetBridge_NLA"; Operator="EQ"; Expected=0; Recommendation="Prohibit Network Bridge."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="18.5.11.3"; Title="Prohibit use of Internet Connection Sharing on DNS domain network"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Network"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"; CheckValue="NC_ShowSharedAccessUI"; Operator="EQ"; Expected=0; Recommendation="Prohibit Internet Connection Sharing."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="18.5.11.4"; Title="Require domain users to elevate when setting a network's location"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Network"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"; CheckValue="NC_StdDomainUserSetLocation"; Operator="EQ"; Expected=1; Recommendation="Require elevation for network location changes."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="18.5.14.1"; Title="Hardened UNC Paths for NETLOGON is Enabled (RequireMutualAuthentication=1, RequireIntegrity=1)"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Network"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"; CheckValue="\\*\NETLOGON"; Operator="MATCH"; Expected="RequireMutualAuthentication=1.*RequireIntegrity=1"; Recommendation="Enable hardened UNC paths for NETLOGON share."; CWE="CWE-311" },
        [PSCustomObject]@{ CIS_ID="18.5.14.2"; Title="Hardened UNC Paths for SYSVOL is Enabled (RequireMutualAuthentication=1, RequireIntegrity=1)"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Network"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"; CheckValue="\\*\SYSVOL"; Operator="MATCH"; Expected="RequireMutualAuthentication=1.*RequireIntegrity=1"; Recommendation="Enable hardened UNC paths for SYSVOL share."; CWE="CWE-311" },
        [PSCustomObject]@{ CIS_ID="18.5.21.1"; Title="Minimize the number of simultaneous connections to the Internet or a Windows Domain"; Profile="L1_MS"; Category="Admin Templates"; Subcategory="Network"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"; CheckValue="fMinimizeConnections"; Operator="EQ"; Expected=1; Recommendation="Minimize simultaneous connections."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="18.5.21.2"; Title="Prohibit connection to non-domain networks when connected to domain authenticated network"; Profile="L2_MS"; Category="Admin Templates"; Subcategory="Network"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"; CheckValue="fBlockNonDomain"; Operator="EQ"; Expected=1; Recommendation="Prohibit non-domain network connections when domain connected."; CWE="CWE-284" },
        # 18.6 Printers
        [PSCustomObject]@{ CIS_ID="18.6.1"; Title="Point and Print Restrictions: When installing drivers for a new connection (Show warning and elevation prompt)"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Printers"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"; CheckValue="NoWarningNoElevationOnInstall"; Operator="EQ"; Expected=0; Recommendation="Require warning and elevation for Point and Print driver installs."; CWE="CWE-269" },
        [PSCustomObject]@{ CIS_ID="18.6.2"; Title="Point and Print Restrictions: When updating drivers for an existing connection (Show warning and elevation prompt)"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Printers"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"; CheckValue="UpdatePromptSettings"; Operator="EQ"; Expected=0; Recommendation="Require warning and elevation for Point and Print driver updates."; CWE="CWE-269" },
        # 18.8 System
        [PSCustomObject]@{ CIS_ID="18.8.3.1"; Title="Include command line in process creation events"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Audit Process Creation"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; CheckValue="ProcessCreationIncludeCmdLine_Enabled"; Operator="EQ"; Expected=1; Recommendation="Include command line in process creation audit events."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="18.8.4.1"; Title="Remote host allows delegation of non-exportable credentials"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Credentials Delegation"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"; CheckValue="AllowProtectedCreds"; Operator="EQ"; Expected=1; Recommendation="Allow delegation of non-exportable credentials only."; CWE="CWE-522" },
        [PSCustomObject]@{ CIS_ID="18.8.5.1"; Title="Turn On Virtualization Based Security"; Profile="NG"; Category="Admin Templates"; Subcategory="Device Guard"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; CheckValue="EnableVirtualizationBasedSecurity"; Operator="EQ"; Expected=1; Recommendation="Enable Virtualization Based Security."; CWE="CWE-693" },
        [PSCustomObject]@{ CIS_ID="18.8.5.2"; Title="VBS: Require Platform Security Features (Secure Boot and DMA Protection)"; Profile="NG"; Category="Admin Templates"; Subcategory="Device Guard"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; CheckValue="RequirePlatformSecurityFeatures"; Operator="EQ"; Expected=3; Recommendation="Set platform security to Secure Boot + DMA Protection (3)."; CWE="CWE-693" },
        [PSCustomObject]@{ CIS_ID="18.8.5.3"; Title="VBS: Credential Guard Configuration (Enabled with UEFI lock)"; Profile="NG"; Category="Admin Templates"; Subcategory="Device Guard"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; CheckValue="LsaCfgFlags"; Operator="EQ"; Expected=1; Recommendation="Enable Credential Guard with UEFI lock (1)."; CWE="CWE-522" },
        [PSCustomObject]@{ CIS_ID="18.8.7.1.1"; Title="Prevent device metadata retrieval from the Internet"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Device Installation"; Severity="LOW"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata"; CheckValue="PreventDeviceMetadataFromNetwork"; Operator="EQ"; Expected=1; Recommendation="Prevent device metadata from Internet."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="18.8.14.1"; Title="Boot-Start Driver Initialization Policy is Enabled: Good, unknown and bad but critical"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Early Launch AM"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"; CheckValue="DriverLoadPolicy"; Operator="EQ"; Expected=3; Recommendation="Set Early Launch AM driver policy to 'Good, unknown, and bad but critical' (3)."; CWE="CWE-829" },
        # 18.8.21 Internet Communication settings
        [PSCustomObject]@{ CIS_ID="18.8.22.1.1"; Title="Turn off downloading of print drivers over HTTP"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Internet Communication"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; CheckValue="DisableWebPnPDownload"; Operator="EQ"; Expected=1; Recommendation="Disable downloading of print drivers over HTTP."; CWE="CWE-494" },
        [PSCustomObject]@{ CIS_ID="18.8.22.1.5"; Title="Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Internet Communication"; Severity="LOW"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard"; CheckValue="ExitOnMSICW"; Operator="EQ"; Expected=1; Recommendation="Turn off Internet Connection Wizard."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="18.8.22.1.6"; Title="Turn off Internet download for Web publishing and online ordering wizards"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Internet Communication"; Severity="LOW"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; CheckValue="NoWebServices"; Operator="EQ"; Expected=1; Recommendation="Disable Internet download for web publishing wizards."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="18.8.22.1.7"; Title="Turn off printing over HTTP"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Internet Communication"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"; CheckValue="DisableHTTPPrinting"; Operator="EQ"; Expected=1; Recommendation="Disable printing over HTTP."; CWE="CWE-319" },
        # 18.8.27 Logon
        [PSCustomObject]@{ CIS_ID="18.8.28.1"; Title="Block user from showing account details on sign-in"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Logon"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; CheckValue="BlockUserFromShowingAccountDetailsOnSignin"; Operator="EQ"; Expected=1; Recommendation="Block user from showing account details on sign-in."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="18.8.28.2"; Title="Do not display network selection UI"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Logon"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; CheckValue="DontDisplayNetworkSelectionUI"; Operator="EQ"; Expected=1; Recommendation="Do not display network selection UI."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="18.8.28.3"; Title="Do not enumerate connected users on domain-joined computers"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Logon"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; CheckValue="DontEnumerateConnectedUsers"; Operator="EQ"; Expected=1; Recommendation="Do not enumerate connected users on domain-joined PCs."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="18.8.28.4"; Title="Enumerate local users on domain-joined computers is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Logon"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; CheckValue="EnumerateLocalUsers"; Operator="EQ"; Expected=0; Recommendation="Disable local user enumeration on domain-joined PCs."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="18.8.28.5"; Title="Turn off app notifications on the lock screen"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Logon"; Severity="LOW"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; CheckValue="DisableLockScreenAppNotifications"; Operator="EQ"; Expected=1; Recommendation="Disable app notifications on lock screen."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="18.8.28.6"; Title="Turn off picture password sign-in"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Logon"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; CheckValue="BlockDomainPicturePassword"; Operator="EQ"; Expected=1; Recommendation="Disable picture password sign-in."; CWE="CWE-287" },
        [PSCustomObject]@{ CIS_ID="18.8.28.7"; Title="Turn on convenience PIN sign-in is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Logon"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; CheckValue="AllowDomainPINLogon"; Operator="EQ"; Expected=0; Recommendation="Disable convenience PIN sign-in."; CWE="CWE-287" },
        # 18.8.34 Remote Assistance
        [PSCustomObject]@{ CIS_ID="18.8.36.1"; Title="Configure Offer Remote Assistance is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Remote Assistance"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; CheckValue="fAllowUnsolicited"; Operator="EQ"; Expected=0; Recommendation="Disable unsolicited Remote Assistance offers."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="18.8.36.2"; Title="Configure Solicited Remote Assistance is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Remote Assistance"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; CheckValue="fAllowToGetHelp"; Operator="EQ"; Expected=0; Recommendation="Disable Solicited Remote Assistance."; CWE="CWE-284" },
        # 18.8.37 RPC
        [PSCustomObject]@{ CIS_ID="18.8.37.1"; Title="Enable RPC Endpoint Mapper Client Authentication"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="RPC"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"; CheckValue="EnableAuthEpResolution"; Operator="EQ"; Expected=1; Recommendation="Enable RPC Endpoint Mapper client authentication."; CWE="CWE-287" },
        [PSCustomObject]@{ CIS_ID="18.8.37.2"; Title="Restrict Unauthenticated RPC clients to Authenticated"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="RPC"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"; CheckValue="RestrictRemoteClients"; Operator="EQ"; Expected=1; Recommendation="Restrict unauthenticated RPC clients (1)."; CWE="CWE-287" },
        # 18.9 Windows Components
        # 18.9.4 AutoPlay
        [PSCustomObject]@{ CIS_ID="18.9.8.1"; Title="Disallow Autoplay for non-volume devices"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="AutoPlay"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; CheckValue="NoAutoplayfornonVolume"; Operator="EQ"; Expected=1; Recommendation="Disallow Autoplay for non-volume devices."; CWE="CWE-829" },
        [PSCustomObject]@{ CIS_ID="18.9.8.2"; Title="Set the default behavior for AutoRun to Do not execute"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="AutoPlay"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; CheckValue="NoAutorun"; Operator="EQ"; Expected=1; Recommendation="Set AutoRun default to 'Do not execute'."; CWE="CWE-829" },
        [PSCustomObject]@{ CIS_ID="18.9.8.3"; Title="Turn off Autoplay for all drives (255)"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="AutoPlay"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; CheckValue="NoDriveTypeAutoRun"; Operator="EQ"; Expected=255; Recommendation="Disable Autoplay on all drives (255)."; CWE="CWE-829" },
        # 18.9.15 Data Collection and Preview Builds
        [PSCustomObject]@{ CIS_ID="18.9.16.1"; Title="Allow Telemetry is set to 0 (Security) or 1 (Basic)"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Data Collection"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; CheckValue="AllowTelemetry"; Operator="LE"; Expected=1; Recommendation="Set telemetry to Security (0) or Basic (1)."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="18.9.16.2"; Title="Disable pre-release features or settings is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Data Collection"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"; CheckValue="AllowBuildPreview"; Operator="EQ"; Expected=0; Recommendation="Disable pre-release features and insider builds."; CWE="CWE-829" },
        [PSCustomObject]@{ CIS_ID="18.9.16.3"; Title="Do not show feedback notifications"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Data Collection"; Severity="LOW"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; CheckValue="DoNotShowFeedbackNotifications"; Operator="EQ"; Expected=1; Recommendation="Disable feedback notifications."; CWE="CWE-200" },
        # 18.9.17 Event Log Service
        [PSCustomObject]@{ CIS_ID="18.9.27.1.1"; Title="Application: Maximum log file size is 32768 KB or greater"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Event Log"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"; CheckValue="MaxSize"; Operator="GE"; Expected=32768; Recommendation="Set Application log max size to 32768 KB+."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="18.9.27.2.1"; Title="Security: Maximum log file size is 196608 KB or greater"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Event Log"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"; CheckValue="MaxSize"; Operator="GE"; Expected=196608; Recommendation="Set Security log max size to 196608 KB+."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="18.9.27.3.1"; Title="Setup: Maximum log file size is 32768 KB or greater"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Event Log"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"; CheckValue="MaxSize"; Operator="GE"; Expected=32768; Recommendation="Set Setup log max size to 32768 KB+."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="18.9.27.4.1"; Title="System: Maximum log file size is 32768 KB or greater"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Event Log"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"; CheckValue="MaxSize"; Operator="GE"; Expected=32768; Recommendation="Set System log max size to 32768 KB+."; CWE="CWE-778" },
        # 18.9.30 File Explorer
        [PSCustomObject]@{ CIS_ID="18.9.31.2"; Title="Turn off Data Execution Prevention for Explorer"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="File Explorer"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; CheckValue="NoDataExecutionPrevention"; Operator="EQ"; Expected=0; Recommendation="Keep DEP enabled for Explorer (set to 0)."; CWE="CWE-120" },
        [PSCustomObject]@{ CIS_ID="18.9.31.3"; Title="Turn off heap termination on corruption"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="File Explorer"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; CheckValue="NoHeapTerminationOnCorruption"; Operator="EQ"; Expected=0; Recommendation="Keep heap termination on corruption (set to 0)."; CWE="CWE-120" },
        [PSCustomObject]@{ CIS_ID="18.9.31.4"; Title="Turn off shell protocol protected mode"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="File Explorer"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; CheckValue="PreXPSP2ShellProtocolBehavior"; Operator="EQ"; Expected=0; Recommendation="Keep shell protocol protected mode (set to 0)."; CWE="CWE-693" },
        # 18.9.44 Microsoft account
        [PSCustomObject]@{ CIS_ID="18.9.45.1"; Title="Block all consumer Microsoft account user authentication"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Microsoft Account"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"; CheckValue="DisableUserAuth"; Operator="EQ"; Expected=1; Recommendation="Block consumer Microsoft account authentication."; CWE="CWE-284" },
        # 18.9.59 Remote Desktop Services
        [PSCustomObject]@{ CIS_ID="18.9.59.2.2"; Title="Do not allow COM port redirection"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="RDS"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; CheckValue="fDisableCcm"; Operator="EQ"; Expected=1; Recommendation="Disable COM port redirection in RDS."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="18.9.59.2.3"; Title="Do not allow drive redirection"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="RDS"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; CheckValue="fDisableCdm"; Operator="EQ"; Expected=1; Recommendation="Disable drive redirection in RDS."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="18.9.59.2.4"; Title="Do not allow LPT port redirection"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="RDS"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; CheckValue="fDisableLPT"; Operator="EQ"; Expected=1; Recommendation="Disable LPT port redirection in RDS."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="18.9.59.2.5"; Title="Do not allow supported Plug and Play device redirection"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="RDS"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; CheckValue="fDisablePNPRedir"; Operator="EQ"; Expected=1; Recommendation="Disable PnP device redirection in RDS."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="18.9.59.3.3.1"; Title="Set client connection encryption level to High"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="RDS"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; CheckValue="MinEncryptionLevel"; Operator="EQ"; Expected=3; Recommendation="Set RDS encryption level to High (3)."; CWE="CWE-311" },
        [PSCustomObject]@{ CIS_ID="18.9.59.3.3.2"; Title="Always prompt for password upon connection"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="RDS"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; CheckValue="fPromptForPassword"; Operator="EQ"; Expected=1; Recommendation="Always prompt for password in RDS connections."; CWE="CWE-287" },
        [PSCustomObject]@{ CIS_ID="18.9.59.3.3.3"; Title="Require secure RPC communication"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="RDS"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; CheckValue="fEncryptRPCTraffic"; Operator="EQ"; Expected=1; Recommendation="Require secure RPC communication for RDS."; CWE="CWE-311" },
        [PSCustomObject]@{ CIS_ID="18.9.59.3.3.4"; Title="Require use of specific security layer for remote (RDP) connections is SSL"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="RDS"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; CheckValue="SecurityLayer"; Operator="EQ"; Expected=2; Recommendation="Set RDS security layer to SSL (2)."; CWE="CWE-319" },
        [PSCustomObject]@{ CIS_ID="18.9.59.3.3.5"; Title="Require user authentication for remote connections by using NLA"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="RDS"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; CheckValue="UserAuthentication"; Operator="EQ"; Expected=1; Recommendation="Enable Network Level Authentication for RDS."; CWE="CWE-287" },
        [PSCustomObject]@{ CIS_ID="18.9.59.3.9.1"; Title="Set time limit for active but idle RDS sessions to 15 minutes or less"; Profile="L2_MS,L2_DC"; Category="Admin Templates"; Subcategory="RDS"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; CheckValue="MaxIdleTime"; Operator="RANGE"; Expected="1,900000"; Recommendation="Set RDS idle session limit (max 900000ms = 15min)."; CWE="CWE-613" },
        [PSCustomObject]@{ CIS_ID="18.9.59.3.9.2"; Title="Set time limit for disconnected sessions to 1 minute"; Profile="L2_MS,L2_DC"; Category="Admin Templates"; Subcategory="RDS"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; CheckValue="MaxDisconnectionTime"; Operator="LE"; Expected=60000; Recommendation="Set RDS disconnected session limit to 60000ms (1min)."; CWE="CWE-613" },
        [PSCustomObject]@{ CIS_ID="18.9.59.3.10.1"; Title="Delete temp folders upon exit"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="RDS"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; CheckValue="DeleteTempDirsOnExit"; Operator="EQ"; Expected=1; Recommendation="Delete temporary folders when RDS session ends."; CWE="CWE-459" },
        [PSCustomObject]@{ CIS_ID="18.9.59.3.10.2"; Title="Do not use temporary folders per session"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="RDS"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; CheckValue="PerSessionTempDir"; Operator="EQ"; Expected=1; Recommendation="Use per-session temporary folders for RDS."; CWE="CWE-459" },
        # 18.9.60 RSS Feeds
        [PSCustomObject]@{ CIS_ID="18.9.61.1"; Title="Prevent downloading of enclosures"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="RSS Feeds"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"; CheckValue="DisableEnclosureDownload"; Operator="EQ"; Expected=1; Recommendation="Prevent downloading of RSS enclosures."; CWE="CWE-494" },
        # 18.9.62 Search
        [PSCustomObject]@{ CIS_ID="18.9.67.2"; Title="Allow Cortana is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Search"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; CheckValue="AllowCortana"; Operator="EQ"; Expected=0; Recommendation="Disable Cortana."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="18.9.67.3"; Title="Allow Cortana above lock screen is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Search"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; CheckValue="AllowCortanaAboveLock"; Operator="EQ"; Expected=0; Recommendation="Disable Cortana above lock screen."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="18.9.67.4"; Title="Allow indexing of encrypted files is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Search"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; CheckValue="AllowIndexingEncryptedStoresOrItems"; Operator="EQ"; Expected=0; Recommendation="Disable indexing of encrypted files."; CWE="CWE-312" },
        [PSCustomObject]@{ CIS_ID="18.9.67.5"; Title="Allow search and Cortana to use location is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Search"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; CheckValue="AllowSearchToUseLocation"; Operator="EQ"; Expected=0; Recommendation="Disable location for Search and Cortana."; CWE="CWE-200" },
        # 18.9.72 Windows Installer
        [PSCustomObject]@{ CIS_ID="18.9.86.1"; Title="Always install with elevated privileges is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Windows Installer"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; CheckValue="AlwaysInstallElevated"; Operator="EQ"; Expected=0; Recommendation="Disable 'Always install with elevated privileges'."; CWE="CWE-269" },
        # 18.9.84 PowerShell
        [PSCustomObject]@{ CIS_ID="18.9.100.1"; Title="Turn on PowerShell Script Block Logging"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="PowerShell"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; CheckValue="EnableScriptBlockLogging"; Operator="EQ"; Expected=1; Recommendation="Enable PowerShell script block logging."; CWE="CWE-778" },
        [PSCustomObject]@{ CIS_ID="18.9.100.2"; Title="Turn on PowerShell Transcription"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="PowerShell"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; CheckValue="EnableTranscripting"; Operator="EQ"; Expected=1; Recommendation="Enable PowerShell transcription logging."; CWE="CWE-778" },
        # 18.9.98 WinRM Client
        [PSCustomObject]@{ CIS_ID="18.9.102.1.1"; Title="Allow Basic authentication (WinRM Client) is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="WinRM Client"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; CheckValue="AllowBasic"; Operator="EQ"; Expected=0; Recommendation="Disable WinRM client basic authentication."; CWE="CWE-319" },
        [PSCustomObject]@{ CIS_ID="18.9.102.1.2"; Title="Allow unencrypted traffic (WinRM Client) is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="WinRM Client"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; CheckValue="AllowUnencryptedTraffic"; Operator="EQ"; Expected=0; Recommendation="Disable unencrypted WinRM client traffic."; CWE="CWE-319" },
        [PSCustomObject]@{ CIS_ID="18.9.102.1.3"; Title="Disallow Digest authentication (WinRM Client)"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="WinRM Client"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"; CheckValue="AllowDigest"; Operator="EQ"; Expected=0; Recommendation="Disable WinRM client digest authentication."; CWE="CWE-287" },
        # 18.9.98 WinRM Service
        [PSCustomObject]@{ CIS_ID="18.9.102.2.1"; Title="Allow Basic authentication (WinRM Service) is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="WinRM Service"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; CheckValue="AllowBasic"; Operator="EQ"; Expected=0; Recommendation="Disable WinRM service basic authentication."; CWE="CWE-319" },
        [PSCustomObject]@{ CIS_ID="18.9.102.2.2"; Title="Allow remote server management through WinRM is Disabled"; Profile="L2_MS,L2_DC"; Category="Admin Templates"; Subcategory="WinRM Service"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; CheckValue="AllowAutoConfig"; Operator="EQ"; Expected=0; Recommendation="Disable WinRM service auto-config."; CWE="CWE-284" },
        [PSCustomObject]@{ CIS_ID="18.9.102.2.3"; Title="Allow unencrypted traffic (WinRM Service) is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="WinRM Service"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; CheckValue="AllowUnencryptedTraffic"; Operator="EQ"; Expected=0; Recommendation="Disable unencrypted WinRM service traffic."; CWE="CWE-319" },
        [PSCustomObject]@{ CIS_ID="18.9.102.2.4"; Title="Disallow WinRM from storing RunAs credentials"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="WinRM Service"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"; CheckValue="DisableRunAs"; Operator="EQ"; Expected=1; Recommendation="Disallow WinRM from storing RunAs credentials."; CWE="CWE-522" },
        # 18.9.99 Remote Shell
        [PSCustomObject]@{ CIS_ID="18.9.102.3.1"; Title="Allow Remote Shell Access is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Remote Shell"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS"; CheckValue="AllowRemoteShellAccess"; Operator="EQ"; Expected=0; Recommendation="Disable Remote Shell access."; CWE="CWE-284" },
        # 18.9.105 Windows Update
        [PSCustomObject]@{ CIS_ID="18.9.108.1.1"; Title="Manage preview builds is Disabled"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Windows Update"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; CheckValue="ManagePreviewBuildsPolicyValue"; Operator="EQ"; Expected=1; Recommendation="Disable preview builds management (1 = Disable)."; CWE="CWE-829" },
        [PSCustomObject]@{ CIS_ID="18.9.108.2.1"; Title="Configure Automatic Updates"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Windows Update"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; CheckValue="NoAutoUpdate"; Operator="EQ"; Expected=0; Recommendation="Enable Automatic Updates (0 = enabled)."; CWE="CWE-1188" },
        [PSCustomObject]@{ CIS_ID="18.9.108.2.2"; Title="Configure Automatic Updates: Scheduled install day"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Windows Update"; Severity="LOW"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; CheckValue="ScheduledInstallDay"; Operator="EQ"; Expected=0; Recommendation="Set auto-update install day to 0 (Every day)."; CWE="CWE-1188" },
        [PSCustomObject]@{ CIS_ID="18.9.108.4.1"; Title="Remove access to Pause updates feature"; Profile="L1_MS,L1_DC"; Category="Admin Templates"; Subcategory="Windows Update"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; CheckValue="SetDisablePauseUXAccess"; Operator="EQ"; Expected=1; Recommendation="Remove user access to Pause updates."; CWE="CWE-1188" }
    )

    Invoke-Controls $controls
}   # End Test-AdminTemplatesComputer

# ============================================================
#  Section 19 : Administrative Templates (User)
# ============================================================
function Test-AdminTemplatesUser {
    Write-ScanLog "--- Section 19: Administrative Templates (User) ---" "INFO"

    $controls = @(
        [PSCustomObject]@{ CIS_ID="19.1.3.1"; Title="Enable screen saver"; Profile="L1_MS,L1_DC"; Category="Admin Templates (User)"; Subcategory="Personalization"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"; CheckValue="ScreenSaveActive"; Operator="EQ"; Expected="1"; Recommendation="Enable screen saver via Group Policy."; CWE="CWE-613" },
        [PSCustomObject]@{ CIS_ID="19.1.3.2"; Title="Screen saver timeout is set to 900 seconds or fewer, but not 0"; Profile="L1_MS,L1_DC"; Category="Admin Templates (User)"; Subcategory="Personalization"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"; CheckValue="ScreenSaveTimeOut"; Operator="RANGE"; Expected="1,900"; Recommendation="Set screen saver timeout to 1-900 seconds."; CWE="CWE-613" },
        [PSCustomObject]@{ CIS_ID="19.1.3.3"; Title="Password protect the screen saver"; Profile="L1_MS,L1_DC"; Category="Admin Templates (User)"; Subcategory="Personalization"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"; CheckValue="ScreenSaverIsSecure"; Operator="EQ"; Expected="1"; Recommendation="Enable password protection for screen saver."; CWE="CWE-613" },
        [PSCustomObject]@{ CIS_ID="19.5.1.1"; Title="Turn off toast notifications on the lock screen"; Profile="L1_MS,L1_DC"; Category="Admin Templates (User)"; Subcategory="Notifications"; Severity="LOW"; CheckType="Registry"; CheckKey="HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"; CheckValue="NoToastApplicationNotificationOnLockScreen"; Operator="EQ"; Expected=1; Recommendation="Disable toast notifications on lock screen."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="19.7.4.1"; Title="Do not preserve zone information in file attachments"; Profile="L1_MS,L1_DC"; Category="Admin Templates (User)"; Subcategory="Attachment Manager"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"; CheckValue="SaveZoneInformation"; Operator="EQ"; Expected=2; Recommendation="Preserve zone information in file attachments (2)."; CWE="CWE-829" },
        [PSCustomObject]@{ CIS_ID="19.7.4.2"; Title="Notify antivirus programs when opening attachments"; Profile="L1_MS,L1_DC"; Category="Admin Templates (User)"; Subcategory="Attachment Manager"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"; CheckValue="ScanWithAntiVirus"; Operator="EQ"; Expected=3; Recommendation="Notify antivirus when opening attachments (3)."; CWE="CWE-829" },
        [PSCustomObject]@{ CIS_ID="19.7.8.1"; Title="Configure Windows spotlight on lock screen is Disabled"; Profile="L2_MS,L2_DC"; Category="Admin Templates (User)"; Subcategory="Cloud Content"; Severity="LOW"; CheckType="Registry"; CheckKey="HKCU:\Software\Policies\Microsoft\Windows\CloudContent"; CheckValue="ConfigureWindowsSpotlight"; Operator="EQ"; Expected=2; Recommendation="Disable Windows spotlight (2)."; CWE="CWE-200" },
        [PSCustomObject]@{ CIS_ID="19.7.8.2"; Title="Do not suggest third-party content in Windows spotlight"; Profile="L2_MS,L2_DC"; Category="Admin Templates (User)"; Subcategory="Cloud Content"; Severity="LOW"; CheckType="Registry"; CheckKey="HKCU:\Software\Policies\Microsoft\Windows\CloudContent"; CheckValue="DisableThirdPartySuggestions"; Operator="EQ"; Expected=1; Recommendation="Disable third-party spotlight suggestions."; CWE="CWE-200" }
    )

    Invoke-Controls $controls
}   # End Test-AdminTemplatesUser

# ============================================================
#  BitLocker (BL) Profile Controls
# ============================================================
function Test-BitLockerControls {
    Write-ScanLog "--- BitLocker Profile Controls ---" "INFO"

    $controls = @(
        [PSCustomObject]@{ CIS_ID="18.9.11.1.1"; Title="BitLocker: Allow access to BitLocker-protected fixed data drives from earlier versions of Windows"; Profile="BL"; Category="BitLocker"; Subcategory="Fixed Drives"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\FVE"; CheckValue="FDVDiscoveryVolumeType"; Operator="NE"; Expected=""; Recommendation="Configure BitLocker fixed drive discovery."; CWE="CWE-311" },
        [PSCustomObject]@{ CIS_ID="18.9.11.1.2"; Title="BitLocker: Choose how BitLocker-protected fixed drives can be recovered"; Profile="BL"; Category="BitLocker"; Subcategory="Fixed Drives"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\FVE"; CheckValue="FDVRecovery"; Operator="EQ"; Expected=1; Recommendation="Configure BitLocker fixed drive recovery."; CWE="CWE-311" },
        [PSCustomObject]@{ CIS_ID="18.9.11.2.1"; Title="BitLocker: Require additional authentication at startup"; Profile="BL"; Category="BitLocker"; Subcategory="OS Drive"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\FVE"; CheckValue="UseAdvancedStartup"; Operator="EQ"; Expected=1; Recommendation="Require additional authentication at startup for OS drive."; CWE="CWE-311" },
        [PSCustomObject]@{ CIS_ID="18.9.11.2.2"; Title="BitLocker: Allow enhanced PINs for startup"; Profile="BL"; Category="BitLocker"; Subcategory="OS Drive"; Severity="MEDIUM"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\FVE"; CheckValue="UseEnhancedPin"; Operator="EQ"; Expected=1; Recommendation="Allow enhanced PINs for BitLocker startup."; CWE="CWE-521" },
        [PSCustomObject]@{ CIS_ID="18.9.11.2.3"; Title="BitLocker: Choose how BitLocker-protected OS drives can be recovered"; Profile="BL"; Category="BitLocker"; Subcategory="OS Drive"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\FVE"; CheckValue="OSRecovery"; Operator="EQ"; Expected=1; Recommendation="Configure BitLocker OS drive recovery."; CWE="CWE-311" },
        [PSCustomObject]@{ CIS_ID="18.9.11.3.1"; Title="BitLocker: Configure encryption method (AES 256-bit)"; Profile="BL"; Category="BitLocker"; Subcategory="Encryption"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\FVE"; CheckValue="EncryptionMethod"; Operator="GE"; Expected=4; Recommendation="Set BitLocker encryption to AES 256-bit (4) or higher."; CWE="CWE-326" }
    )

    Invoke-Controls $controls
}   # End Test-BitLockerControls

# ============================================================
#  Next Generation (NG) Profile Controls
# ============================================================
function Test-NextGenControls {
    Write-ScanLog "--- Next Generation (NG) Profile Controls ---" "INFO"

    $controls = @(
        [PSCustomObject]@{ CIS_ID="NG.1"; Title="Virtualization Based Security is Enabled"; Profile="NG"; Category="Next Generation"; Subcategory="Device Guard"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; CheckValue="EnableVirtualizationBasedSecurity"; Operator="EQ"; Expected=1; Recommendation="Enable Virtualization Based Security."; CWE="CWE-693" },
        [PSCustomObject]@{ CIS_ID="NG.2"; Title="VBS: Platform Security Features is Secure Boot and DMA Protection (3)"; Profile="NG"; Category="Next Generation"; Subcategory="Device Guard"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; CheckValue="RequirePlatformSecurityFeatures"; Operator="EQ"; Expected=3; Recommendation="Set platform security to Secure Boot + DMA (3)."; CWE="CWE-693" },
        [PSCustomObject]@{ CIS_ID="NG.3"; Title="Credential Guard is Enabled with UEFI lock"; Profile="NG"; Category="Next Generation"; Subcategory="Device Guard"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; CheckValue="LsaCfgFlags"; Operator="EQ"; Expected=1; Recommendation="Enable Credential Guard with UEFI lock (1)."; CWE="CWE-522" },
        [PSCustomObject]@{ CIS_ID="NG.4"; Title="LSA Protection is Enabled"; Profile="NG"; Category="Next Generation"; Subcategory="LSA"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; CheckValue="RunAsPPL"; Operator="EQ"; Expected=1; Recommendation="Enable LSA Protection (RunAsPPL)."; CWE="CWE-522" },
        [PSCustomObject]@{ CIS_ID="NG.5"; Title="Windows Defender Credential Guard is running"; Profile="NG"; Category="Next Generation"; Subcategory="Device Guard"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; CheckValue="EnableVirtualizationBasedSecurity"; Operator="EQ"; Expected=1; Recommendation="Verify Credential Guard is active at system level."; CWE="CWE-522" },
        [PSCustomObject]@{ CIS_ID="NG.6"; Title="Secure Boot is Enabled"; Profile="NG"; Category="Next Generation"; Subcategory="Firmware"; Severity="HIGH"; CheckType="Registry"; CheckKey="HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"; CheckValue="UEFISecureBootEnabled"; Operator="EQ"; Expected=1; Recommendation="Verify Secure Boot is enabled in firmware."; CWE="CWE-693" }
    )

    Invoke-Controls $controls
}   # End Test-NextGenControls

# ============================================================
#  Report Functions
# ============================================================

function Show-ConsoleReport {
    param([array]$FilteredResults)

    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "  CIS Windows Server 2016 Benchmark v3.0.0 Compliance Report" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan

    $r = $Script:ServerRole
    Write-Host "  Hostname   : $($r.Hostname)"
    Write-Host "  OS         : $($r.OSCaption)"
    Write-Host "  Role       : $(if($r.IsDomainController){'Domain Controller'}elseif($r.IsMemberServer){'Member Server'}else{'Standalone'})"
    Write-Host "  Profile    : $($Script:SelectedProfile)"
    Write-Host "  Scan Time  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host "-" * 80

    $total     = ($FilteredResults | Where-Object { $_.Status -in @("PASS","FAIL") }).Count
    $passCount = ($FilteredResults | Where-Object { $_.Status -eq "PASS" }).Count
    $failCount = ($FilteredResults | Where-Object { $_.Status -eq "FAIL" }).Count
    $warnCount = ($FilteredResults | Where-Object { $_.Status -eq "WARN" }).Count
    $errCount  = ($FilteredResults | Where-Object { $_.Status -eq "ERROR" }).Count
    $pct       = if ($total -gt 0) { [math]::Round(($passCount / $total) * 100, 1) } else { 0 }

    $pctColor = if ($pct -ge 90) { "Green" } elseif ($pct -ge 70) { "Yellow" } else { "Red" }
    Write-Host ""
    Write-Host "  Compliance Score: " -NoNewline
    Write-Host "$pct%" -ForegroundColor $pctColor -NoNewline
    Write-Host "  ($passCount / $total controls passed)"
    Write-Host ""
    Write-Host "  PASS : $passCount" -ForegroundColor Green -NoNewline
    Write-Host "   FAIL : $failCount" -ForegroundColor Red -NoNewline
    Write-Host "   WARN : $warnCount" -ForegroundColor Yellow -NoNewline
    Write-Host "   ERROR: $errCount" -ForegroundColor DarkGray
    Write-Host ""

    # Summary by category
    $categories = $FilteredResults | Group-Object Category
    foreach ($cat in ($categories | Sort-Object Name)) {
        $cPass = ($cat.Group | Where-Object Status -eq "PASS").Count
        $cFail = ($cat.Group | Where-Object Status -eq "FAIL").Count
        $cTotal = $cPass + $cFail
        $cPct  = if ($cTotal -gt 0) { [math]::Round(($cPass / $cTotal) * 100, 0) } else { 0 }
        $cColor = if ($cPct -ge 90) { "Green" } elseif ($cPct -ge 70) { "Yellow" } else { "Red" }
        Write-Host ("  {0,-30} {1,3}% ({2}/{3})" -f $cat.Name, $cPct, $cPass, $cTotal) -ForegroundColor $cColor
    }

    Write-Host ""
    Write-Host "-" * 80

    # Failed checks detail
    $failures = $FilteredResults | Where-Object { $_.Status -eq "FAIL" } | Sort-Object @{e={$Script:SEVERITY_ORDER[$_.Severity]}}, CIS_ID
    if ($failures.Count -gt 0) {
        Write-Host "  FAILED CONTROLS ($($failures.Count)):" -ForegroundColor Red
        Write-Host ""
        foreach ($f in $failures) {
            $sevColor = $Script:SEVERITY_COLOR[$f.Severity]
            Write-Host "  [FAIL] " -ForegroundColor Red -NoNewline
            Write-Host "[$($f.Severity)] " -ForegroundColor $sevColor -NoNewline
            Write-Host "$($f.CIS_ID) - $($f.Title)"
            Write-Host "         Expected: $($f.Expected)  |  Actual: $($f.Actual)" -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "  Log File: $($Script:LogFile)" -ForegroundColor DarkGray
    Write-Host "=" * 80 -ForegroundColor Cyan
}

function Export-JsonReport {
    param([string]$Path, [array]$FilteredResults)

    $r = $Script:ServerRole
    $total     = ($FilteredResults | Where-Object { $_.Status -in @("PASS","FAIL") }).Count
    $passCount = ($FilteredResults | Where-Object { $_.Status -eq "PASS" }).Count
    $failCount = ($FilteredResults | Where-Object { $_.Status -eq "FAIL" }).Count
    $warnCount = ($FilteredResults | Where-Object { $_.Status -eq "WARN" }).Count
    $errCount  = ($FilteredResults | Where-Object { $_.Status -eq "ERROR" }).Count
    $pct       = if ($total -gt 0) { [math]::Round(($passCount / $total) * 100, 1) } else { 0 }

    $sevBreakdown = @{}
    foreach ($sev in @("CRITICAL","HIGH","MEDIUM","LOW")) {
        $sevBreakdown[$sev] = @{
            passed = ($FilteredResults | Where-Object { $_.Severity -eq $sev -and $_.Status -eq "PASS" }).Count
            failed = ($FilteredResults | Where-Object { $_.Severity -eq $sev -and $_.Status -eq "FAIL" }).Count
        }
    }

    $report = [ordered]@{
        scanner            = "CIS_WinServer2016_Scanner"
        version            = $Script:VERSION
        benchmark          = $Script:BENCHMARK
        generated          = (Get-Date -Format "o")
        target             = [ordered]@{
            hostname = $r.Hostname
            os       = $r.OSCaption
            os_build = $r.OSBuild
            role     = if($r.IsDomainController){"Domain Controller"}elseif($r.IsMemberServer){"Member Server"}else{"Standalone"}
            domain   = $r.Domain
        }
        profile_scanned    = $Script:SelectedProfile
        summary            = [ordered]@{
            total_controls     = $FilteredResults.Count
            passed             = $passCount
            failed             = $failCount
            warnings           = $warnCount
            errors             = $errCount
            compliance_percent = $pct
            by_severity        = $sevBreakdown
        }
        results = @($FilteredResults | ForEach-Object {
            [ordered]@{
                cis_id         = $_.CIS_ID
                title          = $_.Title
                profile        = $_.Profile
                category       = $_.Category
                subcategory    = $_.Subcategory
                severity       = $_.Severity
                status         = $_.Status
                expected       = "$($_.Expected)"
                actual         = "$($_.Actual)"
                recommendation = $_.Recommendation
                cwe            = $_.CWE
                check_type     = $_.CheckType
            }
        })
    }

    $report | ConvertTo-Json -Depth 5 | Out-File -FilePath $Path -Encoding UTF8
    Write-ScanLog "JSON report saved to: $Path" "INFO"
}

function Export-HtmlReport {
    param([string]$Path, [array]$FilteredResults)

    $r = $Script:ServerRole
    $total     = ($FilteredResults | Where-Object { $_.Status -in @("PASS","FAIL") }).Count
    $passCount = ($FilteredResults | Where-Object { $_.Status -eq "PASS" }).Count
    $failCount = ($FilteredResults | Where-Object { $_.Status -eq "FAIL" }).Count
    $warnCount = ($FilteredResults | Where-Object { $_.Status -eq "WARN" }).Count
    $errCount  = ($FilteredResults | Where-Object { $_.Status -eq "ERROR" }).Count
    $pct       = if ($total -gt 0) { [math]::Round(($passCount / $total) * 100, 1) } else { 0 }
    $pctClass  = if ($pct -ge 90) { "score-good" } elseif ($pct -ge 70) { "score-warn" } else { "score-bad" }
    $roleText  = if($r.IsDomainController){"Domain Controller"}elseif($r.IsMemberServer){"Member Server"}else{"Standalone Server"}
    $scanDate  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Build table rows
    $rows = [System.Text.StringBuilder]::new()
    foreach ($res in $FilteredResults) {
        $statusClass = switch($res.Status) { "PASS"{"pass"} "FAIL"{"fail"} "WARN"{"warn"} default{"error"} }
        $sevClass    = switch($res.Severity) { "CRITICAL"{"critical"} "HIGH"{"high"} "MEDIUM"{"medium"} default{"low"} }
        $escapedTitle = [System.Web.HttpUtility]::HtmlEncode($res.Title)
        $escapedRec   = [System.Web.HttpUtility]::HtmlEncode($res.Recommendation)
        $escapedAct   = [System.Web.HttpUtility]::HtmlEncode("$($res.Actual)")
        $escapedExp   = [System.Web.HttpUtility]::HtmlEncode("$($res.Expected)")
        $null = $rows.AppendLine("<tr class=`"row-$statusClass`" data-status=`"$($res.Status)`" data-severity=`"$($res.Severity)`" data-category=`"$($res.Category)`">")
        $null = $rows.AppendLine("  <td><span class=`"badge badge-$statusClass`">$($res.Status)</span></td>")
        $null = $rows.AppendLine("  <td class=`"cis-id`">$($res.CIS_ID)</td>")
        $null = $rows.AppendLine("  <td>$escapedTitle</td>")
        $null = $rows.AppendLine("  <td><span class=`"sev sev-$sevClass`">$($res.Severity)</span></td>")
        $null = $rows.AppendLine("  <td class=`"mono`">$escapedExp</td>")
        $null = $rows.AppendLine("  <td class=`"mono`">$escapedAct</td>")
        $null = $rows.AppendLine("  <td>$($res.Category)</td>")
        $null = $rows.AppendLine("  <td class=`"rec`">$escapedRec</td>")
        $null = $rows.AppendLine("</tr>")
    }

    # Build category options
    $catOptions = ($FilteredResults | Select-Object -ExpandProperty Category -Unique | Sort-Object | ForEach-Object { "<option value=`"$_`">$_</option>" }) -join "`n            "

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CIS Windows Server 2016 Compliance Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0f1117;color:#e0e0e0;font-size:14px}
.header{background:linear-gradient(135deg,#0078d4 0%,#1a1b2e 100%);padding:32px 40px;color:#fff}
.header h1{font-size:24px;font-weight:600;margin-bottom:4px}
.header .sub{opacity:.85;font-size:13px}
.meta{display:flex;gap:40px;margin-top:16px;flex-wrap:wrap}
.meta div{font-size:13px}.meta .label{opacity:.7}
.container{max-width:1600px;margin:0 auto;padding:24px}
.score-row{display:flex;gap:20px;margin-bottom:24px;flex-wrap:wrap}
.score-card{background:#1a1b2e;border-radius:12px;padding:24px 32px;text-align:center;min-width:180px;flex:1}
.score-card .num{font-size:48px;font-weight:700;line-height:1.1}
.score-card .lbl{font-size:12px;opacity:.7;margin-top:4px;text-transform:uppercase}
.score-good .num{color:#27ae60}.score-warn .num{color:#e67e22}.score-bad .num{color:#c0392b}
.chip{display:inline-block;padding:6px 16px;border-radius:20px;font-size:13px;font-weight:600;margin:0 4px}
.chip-pass{background:#27ae60;color:#fff}.chip-fail{background:#c0392b;color:#fff}
.chip-warn{background:#e67e22;color:#fff}.chip-error{background:#6c757d;color:#fff}
.filters{background:#1a1b2e;border-radius:8px;padding:16px 20px;margin-bottom:20px;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.filters select,.filters input{background:#252736;color:#e0e0e0;border:1px solid #3a3d52;border-radius:6px;padding:8px 12px;font-size:13px}
.filters label{font-size:12px;opacity:.7;text-transform:uppercase;margin-right:4px}
#resultCount{margin-left:auto;font-size:13px;opacity:.7}
table{width:100%;border-collapse:collapse;background:#1a1b2e;border-radius:8px;overflow:hidden}
th{background:#252736;padding:12px 14px;text-align:left;font-size:12px;text-transform:uppercase;opacity:.8;cursor:pointer;user-select:none;position:sticky;top:0}
td{padding:10px 14px;border-bottom:1px solid #252736;font-size:13px;vertical-align:top}
tr:hover{background:#252736}
.badge{display:inline-block;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase}
.badge-pass{background:#27ae60;color:#fff}.badge-fail{background:#c0392b;color:#fff}
.badge-warn{background:#e67e22;color:#fff}.badge-error{background:#6c757d;color:#fff}
.sev{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:600}
.sev-critical{background:#c0392b;color:#fff}.sev-high{background:#e67e22;color:#fff}
.sev-medium{background:#2980b9;color:#fff}.sev-low{background:#27ae60;color:#fff}
.cis-id{font-family:'Cascadia Code',Consolas,monospace;font-size:12px;white-space:nowrap}
.mono{font-family:'Cascadia Code',Consolas,monospace;font-size:12px;word-break:break-all;max-width:180px}
.rec{max-width:280px;font-size:12px;opacity:.8}
.hidden{display:none}
.footer{text-align:center;padding:24px;opacity:.5;font-size:12px}
</style>
</head>
<body>
<div class="header">
  <h1>CIS Microsoft Windows Server 2016 Benchmark v3.0.0</h1>
  <div class="sub">Compliance Scan Report &mdash; Generated by CIS_WinServer2016_Scanner v$($Script:VERSION)</div>
  <div class="meta">
    <div><span class="label">Hostname:</span> $($r.Hostname)</div>
    <div><span class="label">OS:</span> $($r.OSCaption)</div>
    <div><span class="label">Role:</span> $roleText</div>
    <div><span class="label">Profile:</span> $($Script:SelectedProfile)</div>
    <div><span class="label">Scanned:</span> $scanDate</div>
  </div>
</div>
<div class="container">
  <div class="score-row">
    <div class="score-card $pctClass"><div class="num">$pct%</div><div class="lbl">Compliance</div></div>
    <div class="score-card"><div class="num" style="color:#27ae60">$passCount</div><div class="lbl">Passed</div></div>
    <div class="score-card"><div class="num" style="color:#c0392b">$failCount</div><div class="lbl">Failed</div></div>
    <div class="score-card"><div class="num" style="color:#e67e22">$warnCount</div><div class="lbl">Warnings</div></div>
    <div class="score-card"><div class="num" style="color:#6c757d">$errCount</div><div class="lbl">Errors</div></div>
  </div>
  <div class="filters">
    <label>Status</label>
    <select id="fStatus"><option value="">All</option><option value="FAIL">FAIL</option><option value="PASS">PASS</option><option value="WARN">WARN</option><option value="ERROR">ERROR</option></select>
    <label>Severity</label>
    <select id="fSeverity"><option value="">All</option><option value="CRITICAL">CRITICAL</option><option value="HIGH">HIGH</option><option value="MEDIUM">MEDIUM</option><option value="LOW">LOW</option></select>
    <label>Category</label>
    <select id="fCategory"><option value="">All</option>$catOptions</select>
    <label>Search</label>
    <input type="text" id="fSearch" placeholder="CIS ID or keyword...">
    <span id="resultCount"></span>
  </div>
  <table id="resultsTable">
    <thead><tr><th>Status</th><th>CIS ID</th><th>Title</th><th>Severity</th><th>Expected</th><th>Actual</th><th>Category</th><th>Recommendation</th></tr></thead>
    <tbody>
$($rows.ToString())
    </tbody>
  </table>
  <div class="footer">CIS_WinServer2016_Scanner v$($Script:VERSION) &mdash; $($Script:BENCHMARK)</div>
</div>
<script>
(function(){
  var fs=document.getElementById('fStatus'),fv=document.getElementById('fSeverity'),
      fc=document.getElementById('fCategory'),fi=document.getElementById('fSearch'),
      rc=document.getElementById('resultCount'),
      rows=document.querySelectorAll('#resultsTable tbody tr');
  function filter(){
    var s=fs.value,v=fv.value,c=fc.value,q=fi.value.toLowerCase(),shown=0;
    rows.forEach(function(r){
      var ok=true;
      if(s&&r.dataset.status!==s)ok=false;
      if(v&&r.dataset.severity!==v)ok=false;
      if(c&&r.dataset.category!==c)ok=false;
      if(q&&r.textContent.toLowerCase().indexOf(q)<0)ok=false;
      r.classList.toggle('hidden',!ok);
      if(ok)shown++;
    });
    rc.textContent=shown+' of '+rows.length+' controls shown';
  }
  fs.onchange=fv.onchange=fc.onchange=fi.oninput=filter;
  filter();
})();
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $Path -Encoding UTF8
    Write-ScanLog "HTML report saved to: $Path" "INFO"
}

# ============================================================
#  Main Execution
# ============================================================

# Handle -Version flag
if ($Version) {
    Write-Host "CIS_WinServer2016_Scanner v$($Script:VERSION) ($($Script:BENCHMARK))"
    exit 0
}

# Ensure log directory exists
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

# Start transcript
$transcriptPath = Join-Path $LogPath "Transcript_$($Script:TIMESTAMP).log"
Start-Transcript -Path $transcriptPath -Force | Out-Null

# Prerequisites and role detection
Test-Prerequisites

# Export secedit once for all Secedit/UserRight checks
Write-ScanLog "Exporting security policy (secedit)..." "INFO"
$Script:SeceditContent = Get-SeceditExport
if ([string]::IsNullOrEmpty($Script:SeceditContent)) {
    Write-ScanLog "WARNING: Could not export security policy. Secedit-based checks will report WARN." "WARN"
}

# Execute all check sections in CIS order
Test-AccountPolicies
Test-UserRightsAssignment
Test-SecurityOptions
Test-SystemServices
Test-FirewallConfiguration
Test-AuditPolicies
Test-AdminTemplatesComputer
Test-AdminTemplatesUser
Test-BitLockerControls
Test-NextGenControls

# Filter results by minimum severity
$minSevOrder = $Script:SEVERITY_ORDER[$MinSeverity]
$filtered = $Script:Results | Where-Object {
    $Script:SEVERITY_ORDER[$_.Severity] -le $minSevOrder
}

# Console report
Show-ConsoleReport $filtered

# JSON report
if ($JsonPath) {
    Export-JsonReport -Path $JsonPath -FilteredResults $filtered
}

# HTML report
if ($HtmlPath) {
    # Load System.Web for HtmlEncode
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    Export-HtmlReport -Path $HtmlPath -FilteredResults $filtered
}

# Summary line
$totalChecked = ($filtered | Where-Object { $_.Status -in @("PASS","FAIL") }).Count
$passedCount  = ($filtered | Where-Object { $_.Status -eq "PASS" }).Count
$compPct      = if ($totalChecked -gt 0) { [math]::Round(($passedCount / $totalChecked) * 100, 1) } else { 0 }
Write-ScanLog "Scan complete. Compliance: $compPct% ($passedCount/$totalChecked). Skipped: $($Script:Skipped). Log: $($Script:LogFile)" "INFO"

Stop-Transcript | Out-Null

# Exit code: 1 if any CRITICAL or HIGH failures
$criticalFails = $filtered | Where-Object { $_.Status -eq "FAIL" -and $_.Severity -in @("CRITICAL","HIGH") }
if ($criticalFails.Count -gt 0) {
    exit 1
} else {
    exit 0
}
