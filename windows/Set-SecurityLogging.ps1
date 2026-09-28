#Requires -Version 2.0
<#
.SYNOPSIS
    Detects the host role, checks and enables security/telemetry event logs,
    Advanced Audit Policy, PowerShell logging, NTLM auditing and Sysmon.

.DESCRIPTION
    Pipeline: detect host -> read current state -> apply only what is missing
    -> re-read and verify -> write a report (console + JSON + Application log).

    Compatible with Windows PowerShell 2.0 (Windows Server 2008 / 2008 R2)
    up to Windows 11 / Server 2025. Every value is "raise only": log sizes and
    audit settings that are already stricter/larger on the host are kept.

    Sysmon sources (one of three installation modes):
      1. Online      - no -SourcePath: Sysmon.zip from download.sysinternals.com,
                       config from SwiftOnSecurity (pinned commit), SHA256-checked.
      2. Offline     - -SourcePath <folder|UNC> with a package made by -BuildPackage.
      3. GPO         - New-SecLoggingGpo.ps1 stages the package into NETLOGON and
                       runs this script as a computer startup script (mode 2).

.PARAMETER AuditOnly
    Only report current state and what would change. Nothing is modified.

.PARAMETER SourcePath
    Folder or UNC path of an offline package (built with -BuildPackage).

.PARAMETER Online
    With -SourcePath: fall back to downloading files missing in the package.

.PARAMETER Role
    Override detected role: Workstation, Server, DomainController.

.PARAMETER SkipSysmon
    Do not install/configure Sysmon.

.PARAMETER UpgradeSysmon
    Upgrade an installed Sysmon older than the package version (uninstall + install).

.PARAMETER AllowUnpinnedSysmon
    Accept Sysmon.zip without a pinned SHA256 (only a valid Microsoft Authenticode
    signature is required). Use only when you cannot pin the hash.

.PARAMETER AllowLegacySysmon
    Allow Sysmon installation on Windows 7 / Server 2008 / 2008 R2 (NT 6.0/6.1).
    Requires legacy\Sysmon.zip (Sysmon 10.42) in the package. Test on one host first.

.PARAMETER DisablePowerShellV2
    Remove the PowerShell 2.0 engine optional feature (Windows 8 / 2012 and newer).

.PARAMETER TranscriptionPath
    Enable PowerShell transcription into this folder (local path gets a write-only ACL).

.PARAMETER ConfigureWazuh
    Add missing eventchannel <localfile> entries to the local Wazuh agent ossec.conf.

.PARAMETER SkipAuditPolicy
    Do not touch Advanced Audit Policy.

.PARAMETER ReportPath
    JSON report path. Default: %ProgramData%\SecLogging\report-<timestamp>.json

.PARAMETER Quiet
    Print only the summary (for GPO startup runs).

.PARAMETER BuildPackage
    Build an offline package into this folder (needs internet): downloads Sysmon and
    configs, verifies signatures/hashes, copies this script, writes sources.ini.

.PARAMETER LegacySysmonZip
    With -BuildPackage: path to a Sysmon 10.42 Sysmon.zip for legacy hosts.

.PARAMETER AcceptNewSysmon
    With -BuildPackage: accept a Sysmon.zip whose hash differs from the pinned one
    (new Microsoft release). The signature is still verified.

.PARAMETER ExportSettings
    Return the settings hashtable (used by New-SecLoggingGpo.ps1).

.EXAMPLE
    .\Set-SecurityLogging.ps1 -AuditOnly
.EXAMPLE
    .\Set-SecurityLogging.ps1 -SourcePath \\corp.local\NETLOGON\SecLogging
.EXAMPLE
    .\Set-SecurityLogging.ps1 -BuildPackage D:\SecLogging
#>
[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [string]$SourcePath,
    [switch]$Online,
    [ValidateSet('Auto', 'Workstation', 'Server', 'DomainController')]
    [string]$Role = 'Auto',
    [switch]$SkipSysmon,
    [switch]$UpgradeSysmon,
    [switch]$AllowUnpinnedSysmon,
    [switch]$AllowLegacySysmon,
    [switch]$DisablePowerShellV2,
    [string]$TranscriptionPath,
    [switch]$ConfigureWazuh,
    [switch]$SkipAuditPolicy,
    [string]$ReportPath,
    [switch]$Quiet,
    [string]$BuildPackage,
    [string]$LegacySysmonZip,
    [switch]$AcceptNewSysmon,
    [switch]$ExportSettings
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0.0'
$ScriptPath = $MyInvocation.MyCommand.Path
$ScriptDir = Split-Path -Parent $ScriptPath
$StateRegPath = 'SOFTWARE\SecLogging'
$WorkDir = Join-Path $env:ProgramData 'SecLogging'

# Pinned sources. sources.ini next to the script (written by -BuildPackage) overrides these.
# SysmonZipSha256 changes with every Sysmon release: fill it via -BuildPackage.
$DefaultPins = @{
    SysmonZipUrl          = 'https://download.sysinternals.com/files/Sysmon.zip'
    SysmonZipSha256       = ''
    SysmonVersion         = ''
    ConfigUrl             = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/1836897f12fbd6a0a473665ef6abc34a6b497e31/sysmonconfig-export.xml'
    ConfigSha256          = '055febc600e6d7448cdf3812307275912927a62b1f94d0d933b64b294bc87162'
    LegacySysmonZipSha256 = ''
    LegacySysmonVersion   = ''
    LegacyConfigUrl       = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/c00581f8a75671bdb1d79d6193f429ee28dc6adc/sysmonconfig-export.xml'
    LegacyConfigSha256    = 'bf7800825bd025d77fc0af6985f6a08fb201048a772f3085564351b5a0b66e3f'
}

#region ---------------------------------------------------------------- settings

function New-OD { New-Object System.Collections.Specialized.OrderedDictionary }

function Get-SecLoggingSettings {
    # Log sizes in MB per profile and log class. Classic logs top out around 4 GB.
    $sizes = @{
        DomainController = @{ Security = 3072; Sysmon = 1536; PowerShell = 1024; System = 384; Application = 256; DirSvc = 512; Other = 192 }
        Server           = @{ Security = 1536; Sysmon = 1024; PowerShell = 768;  System = 256; Application = 256; DirSvc = 256; Other = 192 }
        Workstation      = @{ Security = 768;  Sysmon = 512;  PowerShell = 384;  System = 192; Application = 192; DirSvc = 128; Other = 96 }
        Minimal          = @{ Security = 256;  Sysmon = 256;  PowerShell = 128;  System = 64;  Application = 64;  DirSvc = 128; Other = 32 }
    }

    # N = channel, C = size class, DC = only on domain controllers, NoWazuh = keep local only
    $channels = @(
        @{ N = 'Security'; C = 'Security' }
        @{ N = 'System'; C = 'System' }
        @{ N = 'Application'; C = 'Application' }
        @{ N = 'Windows PowerShell'; C = 'PowerShell' }
        @{ N = 'Microsoft-Windows-PowerShell/Operational'; C = 'PowerShell' }
        @{ N = 'PowerShellCore/Operational'; C = 'PowerShell' }
        @{ N = 'Microsoft-Windows-Sysmon/Operational'; C = 'Sysmon' }
        @{ N = 'Microsoft-Windows-Windows Defender/Operational'; C = 'Other' }
        @{ N = 'Microsoft-Windows-TaskScheduler/Operational'; C = 'Other' }
        @{ N = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; C = 'Other' }
        @{ N = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; C = 'Other' }
        @{ N = 'Microsoft-Windows-TerminalServices-RDPClient/Operational'; C = 'Other' }
        @{ N = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; C = 'Other' }
        @{ N = 'Microsoft-Windows-WMI-Activity/Operational'; C = 'Other' }
        @{ N = 'Microsoft-Windows-Bits-Client/Operational'; C = 'Other' }
        @{ N = 'Microsoft-Windows-CodeIntegrity/Operational'; C = 'Other' }
        @{ N = 'Microsoft-Windows-AppLocker/EXE and DLL'; C = 'Other' }
        @{ N = 'Microsoft-Windows-AppLocker/MSI and Script'; C = 'Other' }
        @{ N = 'Microsoft-Windows-AppLocker/Packaged app-Deployment'; C = 'Other' }
        @{ N = 'Microsoft-Windows-AppLocker/Packaged app-Execution'; C = 'Other' }
        @{ N = 'Microsoft-Windows-NTLM/Operational'; C = 'Other' }
        @{ N = 'Microsoft-Windows-DNS-Client/Operational'; C = 'Other'; NoWazuh = $true }
        @{ N = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; C = 'Other' }
        @{ N = 'Microsoft-Windows-PrintService/Operational'; C = 'Other' }
        @{ N = 'Microsoft-Windows-WinRM/Operational'; C = 'Other' }
        @{ N = 'Microsoft-Windows-SMBServer/Security'; C = 'Other' }
        @{ N = 'Microsoft-Windows-SMBClient/Security'; C = 'Other' }
        @{ N = 'OpenSSH/Operational'; C = 'Other' }
        @{ N = 'Microsoft-Windows-DriverFrameworks-UserMode/Operational'; C = 'Other' }
        @{ N = 'Microsoft-Windows-Security-Mitigations/KernelMode'; C = 'Other' }
        @{ N = 'Microsoft-Windows-Security-Mitigations/UserMode'; C = 'Other' }
        @{ N = 'Microsoft-Windows-LSA/Operational'; C = 'Other' }
        @{ N = 'Directory Service'; C = 'DirSvc'; DC = $true }
        @{ N = 'DNS Server'; C = 'Other'; DC = $true }
        @{ N = 'Microsoft-Windows-DNSServer/Audit'; C = 'Other'; DC = $true }
        @{ N = 'DFS Replication'; C = 'Other'; DC = $true }
    )

    # Advanced Audit Policy by subcategory GUID (locale independent).
    # Values: 0 = not managed, 1 = Success, 2 = Failure, 3 = Success and Failure.
    # W = workstation, S = member server, D = domain controller.
    $audit = @()
    # Name|GUID suffix|Workstation|Server|DC
    $auditTable = @(
        # --- Account Logon
        'Credential Validation|923F|3|3|3'
        'Kerberos Authentication Service|9242|0|0|3'
        'Kerberos Service Ticket Operations|9240|0|0|3'
        # --- Account Management
        'User Account Management|9235|3|3|3'
        'Computer Account Management|9236|1|1|3'
        'Security Group Management|9237|1|1|3'
        'Distribution Group Management|9238|0|0|1'
        'Other Account Management Events|923A|1|1|3'
        # --- Detailed Tracking
        'Process Creation|922B|1|1|1'
        'DPAPI Activity|922D|3|3|3'
        'Plug and Play Events|9248|1|1|1'
        # --- DS Access (DC only)
        'Directory Service Access|923B|0|0|3'
        'Directory Service Changes|923C|0|0|1'
        # --- Logon/Logoff
        'Logon|9215|3|3|3'
        'Logoff|9216|1|1|1'
        'Account Lockout|9217|3|3|3'
        'Special Logon|921B|1|1|1'
        'Other Logon/Logoff Events|921C|3|3|3'
        'Group Membership|9249|1|1|1'
        # --- Object Access (targeted, low noise)
        'File Share|9224|3|1|3'
        'Detailed File Share|9244|2|2|2'
        'Removable Storage|9245|3|3|3'
        'Other Object Access Events|9227|3|3|3'
        # --- Policy Change
        'Audit Policy Change|922F|3|3|3'
        'Authentication Policy Change|9230|1|1|1'
        'Authorization Policy Change|9231|1|1|1'
        'MPSSVC Rule-Level Policy Change|9232|3|3|3'
        # --- Privilege Use
        'Sensitive Privilege Use|9228|3|3|3'
        # --- System
        'Security State Change|9210|1|1|1'
        'Security System Extension|9211|1|1|1'
        'System Integrity|9212|3|3|3'
        'IPsec Driver|9213|3|3|3'
        'Other System Events|9214|3|3|3'
    )
    foreach ($row in $auditTable) {
        $a = $row.Split('|')
        $audit += @{ Name = $a[0]; Guid = ('0CCE{0}-69AE-11D9-BED3-505054503030' -f $a[1]); Workstation = [int]$a[2]; Server = [int]$a[3]; DomainController = [int]$a[4] }
    }

    # Registry settings. Mode Min = raise a DWORD to at least Value; Exact = set as is.
    $pol = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    $core = 'SOFTWARE\Policies\Microsoft\PowerShellCore'
    $registry = @(
        @{ Path = 'SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'SCENoApplyLegacyAuditPolicy'; Type = 'DWord'; Value = 1; Mode = 'Min'; DC = $false; Why = 'Force advanced audit subcategories' }
        @{ Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Type = 'DWord'; Value = 1; Mode = 'Min'; DC = $false; Why = 'Command line in 4688' }
        @{ Path = "$pol\ScriptBlockLogging"; Name = 'EnableScriptBlockLogging'; Type = 'DWord'; Value = 1; Mode = 'Min'; DC = $false; Why = 'PowerShell 4104' }
        @{ Path = "$pol\ModuleLogging"; Name = 'EnableModuleLogging'; Type = 'DWord'; Value = 1; Mode = 'Min'; DC = $false; Why = 'PowerShell 4103' }
        @{ Path = "$pol\ModuleLogging\ModuleNames"; Name = '*'; Type = 'String'; Value = '*'; Mode = 'Exact'; DC = $false; Why = 'Module logging for all modules' }
        @{ Path = "$core\ScriptBlockLogging"; Name = 'EnableScriptBlockLogging'; Type = 'DWord'; Value = 1; Mode = 'Min'; DC = $false; Why = 'PowerShell 7 4104' }
        @{ Path = "$core\ModuleLogging"; Name = 'EnableModuleLogging'; Type = 'DWord'; Value = 1; Mode = 'Min'; DC = $false; Why = 'PowerShell 7 4103' }
        @{ Path = "$core\ModuleLogging\ModuleNames"; Name = '*'; Type = 'String'; Value = '*'; Mode = 'Exact'; DC = $false; Why = 'PowerShell 7 module logging' }
        @{ Path = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'AuditReceivingNTLMTraffic'; Type = 'DWord'; Value = 2; Mode = 'Min'; DC = $false; Why = 'Audit incoming NTLM (8001-8003)' }
        @{ Path = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'RestrictSendingNTLMTraffic'; Type = 'DWord'; Value = 1; Mode = 'Min'; DC = $false; Why = 'Audit outgoing NTLM (8001)' }
        @{ Path = 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'AuditNTLMInDomain'; Type = 'DWord'; Value = 7; Mode = 'Min'; DC = $true; Why = 'Audit NTLM in domain (8004)' }
        @{ Path = 'SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'; Name = '16 LDAP Interface Events'; Type = 'DWord'; Value = 2; Mode = 'Min'; DC = $true; Why = 'LDAP unsigned/simple bind (2889)' }
    )

    @{ Sizes = $sizes; Channels = $channels; AuditPolicy = $audit; Registry = $registry; Pins = $DefaultPins; ScriptVersion = $ScriptVersion }
}

#endregion
#region ---------------------------------------------------------------- report

$Script:Report = @()
$Script:Counts = @{ OK = 0; Changed = 0; WouldChange = 0; Warning = 0; Error = 0; Skipped = 0 }

function Add-Result {
    param([string]$Area, [string]$Item, [string]$Status, [string]$Message, $Before, $After)
    $r = New-OD
    $r.Area = $Area; $r.Item = $Item; $r.Status = $Status; $r.Message = $Message
    $r.Before = $Before; $r.After = $After
    $Script:Report += $r
    $Script:Counts[$Status]++
    if (-not $Quiet -or $Status -eq 'Error') {
        $color = @{ OK = 'Green'; Changed = 'Cyan'; WouldChange = 'Yellow'; Warning = 'Yellow'; Error = 'Red'; Skipped = 'DarkGray' }[$Status]
        $line = '[{0,-11}] {1,-12} {2}' -f $Status, $Area, $Item
        if ($Message) { $line += " - $Message" }
        Write-Host $line -ForegroundColor $color
    }
}

function ConvertTo-JsonString {
    param($Value, [int]$Depth = 0)
    $pad = '  ' * $Depth
    $pad1 = '  ' * ($Depth + 1)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [decimal]) {
        return ([string]$Value).Replace(',', '.')
    }
    if ($Value -is [string] -or $Value -is [char] -or $Value -is [guid] -or $Value -is [version] -or $Value -is [datetime] -or $Value -is [enum]) {
        if ($Value -is [datetime]) { $s = $Value.ToString('o') } else { $s = [string]$Value }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('"')
        foreach ($ch in $s.ToCharArray()) {
            switch ($ch) {
                '"' { [void]$sb.Append('\"') }
                '\' { [void]$sb.Append('\\') }
                "`n" { [void]$sb.Append('\n') }
                "`r" { [void]$sb.Append('\r') }
                "`t" { [void]$sb.Append('\t') }
                default {
                    if ([int]$ch -lt 32) { [void]$sb.Append(('\u{0:x4}' -f [int]$ch)) } else { [void]$sb.Append($ch) }
                }
            }
        }
        [void]$sb.Append('"')
        return $sb.ToString()
    }
    if ($Value -is [System.Collections.IDictionary]) {
        if ($Value.Count -eq 0) { return '{}' }
        $parts = @()
        foreach ($k in $Value.Keys) { $parts += ('{0}{1}: {2}' -f $pad1, (ConvertTo-JsonString ([string]$k)), (ConvertTo-JsonString $Value[$k] ($Depth + 1))) }
        return "{`n" + ($parts -join ",`n") + "`n$pad}"
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = @()
        foreach ($i in $Value) { $parts += ($pad1 + (ConvertTo-JsonString $i ($Depth + 1))) }
        if ($parts.Count -eq 0) { return '[]' }
        return "[`n" + ($parts -join ",`n") + "`n$pad]"
    }
    return (ConvertTo-JsonString ([string]$Value) $Depth)
}

#endregion
#region ---------------------------------------------------------------- helpers

function Test-IsAdmin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-FileSha256 {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead($Path)
    try { $hash = $sha.ComputeHash($fs) } finally { $fs.Close(); $sha.Clear() }
    -join ($hash | ForEach-Object { $_.ToString('x2') })
}

function Get-VersionFromString {
    param([string]$Text)
    if ($Text -match '(\d+(\.\d+){1,3})') { return [version]$Matches[1] }
    $null
}

function Read-IniFile {
    param([string]$Path)
    $h = @{}
    if (-not (Test-Path -LiteralPath $Path)) { return $h }
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        if ($line -match '^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$') { $h[$Matches[1]] = $Matches[2] }
    }
    $h
}

function Get-Pins {
    $pins = @{}
    foreach ($k in $DefaultPins.Keys) { $pins[$k] = $DefaultPins[$k] }
    $candidates = @((Join-Path $ScriptDir 'sources.ini'))
    if ($SourcePath) { $candidates += (Join-Path $SourcePath 'sources.ini') }
    foreach ($ini in $candidates) {
        $h = Read-IniFile $ini
        foreach ($k in $h.Keys) { if ($h[$k]) { $pins[$k] = $h[$k] } }
    }
    $pins
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Path)
    if (-not $key) { return $null }
    try { return $key.GetValue($Name, $null) } finally { $key.Close() }
}

function Set-RegValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type)
    $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($Path)
    try {
        if ($Type -eq 'DWord') { $key.SetValue($Name, [int]$Value, [Microsoft.Win32.RegistryValueKind]::DWord) }
        else { $key.SetValue($Name, [string]$Value, [Microsoft.Win32.RegistryValueKind]::String) }
    }
    finally { $key.Close() }
}

function Invoke-Native {
    # Runs an external program, returns @{ Code; Output }
    param([string]$FilePath, [string[]]$Arguments)
    # stderr of native tools must not become a terminating error under ErrorActionPreference=Stop
    $ErrorActionPreference = 'Continue'
    $out = & $FilePath @Arguments 2>&1 | ForEach-Object { [string]$_ }
    @{ Code = $LASTEXITCODE; Output = (($out | Where-Object { $_ -ne '' }) -join "`n") }
}

function Save-Download {
    param([string]$Url, [string]$Destination)
    try {
        # TLS 1.2 (3072) is not in the enum on .NET 3.5, hence the numeric value.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
    }
    catch { Write-Verbose 'TLS 1.2 is not available in this .NET version' }
    $wc = New-Object System.Net.WebClient
    $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
    $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    $dir = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $wc.DownloadFile($Url, $Destination)
}

function Expand-ZipFile {
    param([string]$ZipPath, [string]$Destination)
    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Recurse -Force }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $Destination)
    }
    catch {
        # .NET < 4.5 (Server 2008 / 2008 R2): Shell zip folder
        $shell = New-Object -ComObject Shell.Application
        $zip = $shell.NameSpace($ZipPath)
        if (-not $zip) { throw "Cannot open zip $ZipPath (no .NET 4.5 and no Shell zip support)" }
        $shell.NameSpace($Destination).CopyHere($zip.Items(), 0x14)
    }
}

function Test-MicrosoftSignature {
    param([string]$Path)
    $sig = Get-AuthenticodeSignature -FilePath $Path
    $subject = ''
    if ($sig.SignerCertificate) { $subject = $sig.SignerCertificate.Subject }
    @{ Valid = ([string]$sig.Status -eq 'Valid' -and $subject -match 'O=Microsoft Corporation'); Status = [string]$sig.Status; Subject = $subject }
}

#endregion
#region ---------------------------------------------------------------- detection

function Get-HostInfo {
    $os = Get-WmiObject Win32_OperatingSystem
    $cs = Get-WmiObject Win32_ComputerSystem
    $info = New-OD
    $info.ComputerName = $env:COMPUTERNAME
    $info.OSCaption = [string]$os.Caption
    $info.OSVersion = [string]$os.Version
    $info.OSBuild = [string]$os.BuildNumber
    $info.ProductType = [int]$os.ProductType
    $info.DetectedRole = @{ 1 = 'Workstation'; 2 = 'DomainController'; 3 = 'Server' }[[int]$os.ProductType]
    $info.PartOfDomain = [bool]$cs.PartOfDomain
    $info.Domain = [string]$cs.Domain
    $info.OSLanguage = [int]$os.OSLanguage
    $info.UICulture = [string](Get-UICulture).Name
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
    $info.Architecture = $arch
    $info.PSVersion = [string]$PSVersionTable.PSVersion
    $v = [version]$os.Version
    $info.IsLegacyOS = ($v -lt [version]'6.2')
    $disk = Get-WmiObject Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $env:SystemDrive)
    $info.SystemDriveFreeMB = [long]($disk.FreeSpace / 1MB)
    $info.SystemDriveSizeMB = [long]($disk.Size / 1MB)
    $info
}

#endregion
#region ---------------------------------------------------------------- event log channels

[void][Reflection.Assembly]::LoadWithPartialName('System.Core')

function Get-ChannelState {
    param([string]$Name)
    $st = New-OD
    $st.Name = $Name
    try {
        $cfg = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($Name)
        $st.Exists = $true
        $st.Enabled = [bool]$cfg.IsEnabled
        $st.MaxBytes = [long]$cfg.MaximumSizeInBytes
        $st.Mode = [string]$cfg.LogMode
        $cfg.Dispose()
    }
    catch { $st.Exists = $false }
    $st
}

function Get-ChannelPolicy {
    # GPO "Event Log Service" admin template only covers the four classic logs.
    param([string]$Name)
    if (@('Application', 'Security', 'System', 'Setup') -notcontains $Name) { return $null }
    $path = "SOFTWARE\Policies\Microsoft\Windows\EventLog\$Name"
    $max = Get-RegValue $path 'MaxSize'
    $ret = Get-RegValue $path 'Retention'
    $ab = Get-RegValue $path 'AutoBackupLogFiles'
    if ($null -eq $max -and $null -eq $ret -and $null -eq $ab) { return $null }
    $p = @{ MaxBytes = $null; Retention = $ret; AutoBackup = $ab }
    if ($null -ne $max) { $p.MaxBytes = [long]$max * 1KB }
    $p
}

function Get-SizePlan {
    # Returns profile name whose growth fits in 50% of free space, stepping down if needed.
    param([string]$RoleName, $States, $Settings, [long]$FreeMB)
    $chain = @{ DomainController = @('DomainController', 'Server', 'Workstation', 'Minimal'); Server = @('Server', 'Workstation', 'Minimal'); Workstation = @('Workstation', 'Minimal') }[$RoleName]
    foreach ($p in $chain) {
        $growth = 0L
        foreach ($s in $States) {
            if (-not $s.State.Exists) { continue }
            $want = [long]$Settings.Sizes[$p][$s.Class] * 1MB
            if ($want -gt $s.State.MaxBytes) { $growth += ($want - $s.State.MaxBytes) }
        }
        if (($growth / 1MB) -le ($FreeMB * 0.5)) { return @{ Profile = $p; GrowthMB = [long]($growth / 1MB) } }
    }
    @{ Profile = $null; GrowthMB = $null }
}

function Invoke-Channels {
    param($Settings, [string]$RoleName, $HostInfo)
    $states = @()
    foreach ($c in $Settings.Channels) {
        if ($c.DC -and $RoleName -ne 'DomainController') { continue }
        $states += @{ Name = $c.N; Class = $c.C; State = (Get-ChannelState $c.N) }
    }
    $plan = Get-SizePlan $RoleName $states $Settings $HostInfo.SystemDriveFreeMB
    if (-not $plan.Profile) {
        Add-Result 'EventLog' 'Size profile' 'Warning' ("Not enough free space on {0} ({1} MB free): sizes are not increased, only enable/retention." -f $env:SystemDrive, $HostInfo.SystemDriveFreeMB)
    }
    elseif ($plan.Profile -ne $RoleName) {
        Add-Result 'EventLog' 'Size profile' 'Warning' ("Profile '{0}' does not fit free space, using '{1}' (+{2} MB)" -f $RoleName, $plan.Profile, $plan.GrowthMB)
    }
    else {
        Add-Result 'EventLog' 'Size profile' 'OK' ("{0} (+{1} MB growth, {2} MB free)" -f $plan.Profile, $plan.GrowthMB, $HostInfo.SystemDriveFreeMB)
    }

    foreach ($s in $states) {
        $name = $s.Name; $st = $s.State
        if (-not $st.Exists) { Add-Result 'EventLog' $name 'Skipped' 'Channel not present on this host'; continue }

        $wantBytes = $st.MaxBytes
        if ($plan.Profile) { $wantBytes = [long]$Settings.Sizes[$plan.Profile][$s.Class] * 1MB }
        $policy = Get-ChannelPolicy $name
        $notes = @()
        if ($policy) {
            if ($null -ne $policy.MaxBytes -and $policy.MaxBytes -lt $wantBytes) {
                $notes += ('GPO limits size to {0} MB (want {1} MB) - change the GPO' -f [long]($policy.MaxBytes / 1MB), [long]($wantBytes / 1MB))
                $wantBytes = $st.MaxBytes
            }
            if ($null -ne $policy.Retention -and [string]$policy.Retention -ne '0') { $notes += "GPO Retention='$($policy.Retention)' (not overwrite-as-needed)" }
            if ($null -ne $policy.AutoBackup -and [string]$policy.AutoBackup -ne '0') { $notes += 'GPO AutoBackupLogFiles is on' }
        }

        $needEnable = -not $st.Enabled
        $needSize = $wantBytes -gt $st.MaxBytes
        $needMode = $st.Mode -ne 'Circular'
        $before = '{0}; {1} MB; {2}' -f $(if ($st.Enabled) { 'enabled' } else { 'disabled' }), [long]($st.MaxBytes / 1MB), $st.Mode

        if (-not ($needEnable -or $needSize -or $needMode)) {
            if ($notes.Count) { Add-Result 'EventLog' $name 'Warning' ($notes -join '; ') $before $before }
            else { Add-Result 'EventLog' $name 'OK' $before $before $before }
            continue
        }
        $target = '{0}; {1} MB; Circular' -f 'enabled', [long]([math]::Max($wantBytes, $st.MaxBytes) / 1MB)
        if ($AuditOnly) { Add-Result 'EventLog' $name 'WouldChange' ((@("-> $target") + $notes) -join '; ') $before $target; continue }

        $wargs = @('sl', $name)
        if ($needEnable) { $wargs += '/e:true' }
        if ($needMode) { $wargs += '/rt:false'; $wargs += '/ab:false' }
        if ($needSize) { $wargs += ('/ms:{0}' -f $wantBytes) }
        $r = Invoke-Native 'wevtutil.exe' $wargs
        $after = Get-ChannelState $name
        $afterText = '{0}; {1} MB; {2}' -f $(if ($after.Enabled) { 'enabled' } else { 'disabled' }), [long]($after.MaxBytes / 1MB), $after.Mode
        $ok = $after.Enabled -and $after.Mode -eq 'Circular' -and $after.MaxBytes -ge $wantBytes
        if ($r.Code -eq 0 -and $ok) {
            $status = 'Changed'; if ($notes.Count) { $status = 'Warning' }
            Add-Result 'EventLog' $name $status ((@("$before -> $afterText") + $notes) -join '; ') $before $afterText
        }
        else {
            Add-Result 'EventLog' $name 'Error' ("wevtutil exit {0}: {1}; now: {2}" -f $r.Code, $r.Output, $afterText) $before $afterText
        }
    }
}

#endregion
#region ---------------------------------------------------------------- audit policy

function ConvertFrom-AuditCsv {
    # Parses auditpol /backup or GPO audit.csv; returns @{ GUID(upper) = SettingValue }
    param([string[]]$Lines)
    $map = @{}
    foreach ($l in $Lines) {
        if ($l -match '\{([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}' -and $l -match ',\s*(\d+)\s*$') {
            $guid = ([regex]::Match($l, '\{([0-9A-Fa-f-]{36})\}')).Groups[1].Value.ToUpper()
            $map[$guid] = [int]([regex]::Match($l, ',\s*(\d+)\s*$')).Groups[1].Value
        }
    }
    $map
}

function Get-AuditPolicyMap {
    $tmp = Join-Path $env:TEMP ('auditpol-{0}.csv' -f [guid]::NewGuid())
    $r = Invoke-Native 'auditpol.exe' @('/backup', "/file:$tmp")
    if ($r.Code -ne 0) { throw "auditpol /backup failed: $($r.Output)" }
    try { return (ConvertFrom-AuditCsv (Get-Content -LiteralPath $tmp)) }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}

function Format-AuditValue {
    param([int]$V)
    @('No Auditing', 'Success', 'Failure', 'Success and Failure')[$V]
}

function Invoke-AuditPolicy {
    param($Settings, [string]$RoleName)
    $current = Get-AuditPolicyMap
    $gpoFile = Join-Path $env:SystemRoot 'security\audit\audit.csv'
    $gpo = @{}
    if (Test-Path -LiteralPath $gpoFile) { $gpo = ConvertFrom-AuditCsv (Get-Content -LiteralPath $gpoFile) }
    if ($gpo.Count) { Add-Result 'AuditPolicy' 'GPO' 'OK' ("Advanced audit policy is delivered by GPO ({0} subcategories); local changes may be overwritten at GPO refresh" -f $gpo.Count) }

    foreach ($a in $Settings.AuditPolicy) {
        $want = [int]$a[$RoleName]
        if ($want -eq 0) { continue }
        $guid = $a.Guid.ToUpper()
        $cur = 0; if ($current.ContainsKey($guid)) { $cur = $current[$guid] }
        $target = $cur -bor $want
        $item = $a.Name
        $gpoNote = ''
        if ($gpo.ContainsKey($guid) -and (($gpo[$guid] -bor $want) -ne $gpo[$guid])) {
            $gpoNote = ('GPO sets {0}, want at least {1} - update the GPO' -f (Format-AuditValue $gpo[$guid]), (Format-AuditValue $want))
        }
        if ($target -eq $cur) {
            if ($gpoNote) { Add-Result 'AuditPolicy' $item 'Warning' $gpoNote (Format-AuditValue $cur) (Format-AuditValue $cur) }
            else { Add-Result 'AuditPolicy' $item 'OK' (Format-AuditValue $cur) (Format-AuditValue $cur) (Format-AuditValue $cur) }
            continue
        }
        if ($AuditOnly) { Add-Result 'AuditPolicy' $item 'WouldChange' ('{0} -> {1} {2}' -f (Format-AuditValue $cur), (Format-AuditValue $target), $gpoNote) (Format-AuditValue $cur) (Format-AuditValue $target); continue }
        $wargs = @('/set', "/subcategory:{$guid}")
        if ($target -band 1) { $wargs += '/success:enable' }
        if ($target -band 2) { $wargs += '/failure:enable' }
        $r = Invoke-Native 'auditpol.exe' $wargs
        if ($r.Code -ne 0) { Add-Result 'AuditPolicy' $item 'Error' ("auditpol exit {0}: {1}" -f $r.Code, $r.Output) (Format-AuditValue $cur) $null }
        else { $a.Pending = $target }
    }

    if ($AuditOnly) { return }
    $after = Get-AuditPolicyMap
    foreach ($a in $Settings.AuditPolicy) {
        if (-not $a.ContainsKey('Pending')) { continue }
        $guid = $a.Guid.ToUpper()
        $now = 0; if ($after.ContainsKey($guid)) { $now = $after[$guid] }
        $was = 0; if ($current.ContainsKey($guid)) { $was = $current[$guid] }
        if (($now -band $a.Pending) -eq $a.Pending) {
            $status = 'Changed'; $msg = '{0} -> {1}' -f (Format-AuditValue $was), (Format-AuditValue $now)
            if ($gpo.ContainsKey($guid) -and (($gpo[$guid] -bor $a.Pending) -ne $gpo[$guid])) { $status = 'Warning'; $msg += '; GPO will overwrite it - update the GPO' }
            Add-Result 'AuditPolicy' $a.Name $status $msg (Format-AuditValue $was) (Format-AuditValue $now)
        }
        else { Add-Result 'AuditPolicy' $a.Name 'Error' ('not applied, now {0}' -f (Format-AuditValue $now)) (Format-AuditValue $was) (Format-AuditValue $now) }
    }
}

#endregion
#region ---------------------------------------------------------------- registry

function Invoke-RegistrySettings {
    param($Settings, [string]$RoleName)
    $items = @()
    foreach ($r in $Settings.Registry) { if (-not $r.DC -or $RoleName -eq 'DomainController') { $items += $r } }
    if ($TranscriptionPath) {
        $t = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        $items += @{ Path = $t; Name = 'EnableTranscripting'; Type = 'DWord'; Value = 1; Mode = 'Min'; Why = 'PowerShell transcription' }
        $items += @{ Path = $t; Name = 'EnableInvocationHeader'; Type = 'DWord'; Value = 1; Mode = 'Min'; Why = 'Transcription timestamps' }
        $items += @{ Path = $t; Name = 'OutputDirectory'; Type = 'String'; Value = $TranscriptionPath; Mode = 'Exact'; Why = 'Transcription folder' }
    }
    foreach ($r in $items) {
        $item = '{0}\{1}' -f $r.Path, $r.Name
        $cur = Get-RegValue $r.Path $r.Name
        if ($r.Mode -eq 'Min') { $ok = ($null -ne $cur -and ($cur -is [int]) -and [int]$cur -ge [int]$r.Value) }
        else { $ok = ($null -ne $cur -and [string]$cur -eq [string]$r.Value) }
        if ($ok) { Add-Result 'Registry' $item 'OK' $r.Why $cur $cur; continue }
        if ($AuditOnly) { Add-Result 'Registry' $item 'WouldChange' ('{0}: {1} -> {2}' -f $r.Why, $cur, $r.Value) $cur $r.Value; continue }
        try {
            Set-RegValue $r.Path $r.Name $r.Value $r.Type
            $now = Get-RegValue $r.Path $r.Name
            Add-Result 'Registry' $item 'Changed' ('{0}: {1} -> {2}' -f $r.Why, $cur, $now) $cur $now
        }
        catch { Add-Result 'Registry' $item 'Error' $_.Exception.Message $cur $null }
    }
    if ($TranscriptionPath) { Initialize-TranscriptionFolder $TranscriptionPath }
}

function Initialize-TranscriptionFolder {
    param([string]$Path)
    if ($Path -like '\\*') {
        Add-Result 'PowerShell' 'Transcription share' 'Warning' 'UNC path: set the share ACL yourself (Authenticated Users: write-only, Admins: full)'
        return
    }
    if (Test-Path -LiteralPath $Path) { Add-Result 'PowerShell' 'Transcription folder' 'OK' $Path; return }
    if ($AuditOnly) { Add-Result 'PowerShell' 'Transcription folder' 'WouldChange' "create $Path with write-only ACL"; return }
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    # SYSTEM + Administrators: full; Authenticated Users: write only (cannot read others' transcripts)
    $r = Invoke-Native 'icacls.exe' @($Path, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-11:(OI)(CI)(W)')
    if ($r.Code -eq 0) { Add-Result 'PowerShell' 'Transcription folder' 'Changed' "$Path created, write-only ACL" }
    else { Add-Result 'PowerShell' 'Transcription folder' 'Error' $r.Output }
}

#endregion
#region ---------------------------------------------------------------- PowerShell v2

function Invoke-PowerShellV2Check {
    param($HostInfo)
    if ($HostInfo.IsLegacyOS) { Add-Result 'PowerShell' 'PowerShell 2.0 engine' 'Skipped' 'Legacy OS: v2 is the native engine, cannot be removed'; return }
    if (-not (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)) { Add-Result 'PowerShell' 'PowerShell 2.0 engine' 'Skipped' 'DISM cmdlets not available'; return }
    try { $features = @(Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like 'MicrosoftWindowsPowerShellV2*' }) }
    catch { Add-Result 'PowerShell' 'PowerShell 2.0 engine' 'Error' $_.Exception.Message; return }
    if ($features.Count -eq 0) { Add-Result 'PowerShell' 'PowerShell 2.0 engine' 'OK' 'Not present on this OS'; return }
    foreach ($f in $features) {
        $state = [string]$f.State
        if ($state -notlike 'Enabled*') { Add-Result 'PowerShell' $f.FeatureName 'OK' "State: $state"; continue }
        if (-not $DisablePowerShellV2) { Add-Result 'PowerShell' $f.FeatureName 'Warning' 'PowerShell 2.0 is enabled (downgrade attack bypasses logging). Use -DisablePowerShellV2'; continue }
        if ($AuditOnly) { Add-Result 'PowerShell' $f.FeatureName 'WouldChange' 'disable'; continue }
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName $f.FeatureName -NoRestart -WarningAction SilentlyContinue | Out-Null
            Add-Result 'PowerShell' $f.FeatureName 'Changed' 'Disabled'
        }
        catch { Add-Result 'PowerShell' $f.FeatureName 'Error' $_.Exception.Message }
    }
}

#endregion
#region ---------------------------------------------------------------- Sysmon

function Get-SysmonState {
    $s = New-OD
    $s.Installed = $false
    foreach ($n in @('Sysmon64', 'Sysmon', 'Sysmon64a')) {
        $svc = Get-WmiObject Win32_Service -Filter "Name='$n'"
        if ($svc) {
            $s.Installed = $true
            $s.ServiceName = $n
            $s.State = [string]$svc.State
            if ([string]$svc.PathName -match '^"?([^"]+?\.exe)') { $s.Path = $Matches[1] }
            if ($s.Path -and (Test-Path -LiteralPath $s.Path)) { $s.Version = [string](Get-VersionFromString (Get-Item -LiteralPath $s.Path).VersionInfo.FileVersion) }
            break
        }
    }
    $s.ChannelExists = (Get-ChannelState 'Microsoft-Windows-Sysmon/Operational').Exists
    $s.AppliedConfigSha256 = Get-RegValue $StateRegPath 'SysmonConfigSha256'
    $s
}

function Get-SysmonExeName {
    param([string]$Arch)
    switch ($Arch) { 'AMD64' { 'Sysmon64.exe' } 'ARM64' { 'Sysmon64a.exe' } default { 'Sysmon.exe' } }
}

function Resolve-SourceFile {
    # Finds a package file in -SourcePath or downloads it (online mode); verifies SHA256 pin.
    param([string]$RelPath, [string]$Url, [string]$Pin, [string]$Label, [switch]$AllowUnpinned)
    $file = $null
    if ($SourcePath) {
        $candidate = Join-Path $SourcePath $RelPath
        if (Test-Path -LiteralPath $candidate) { $file = $candidate }
        elseif (-not $Online) { throw "$Label not found in package: $candidate" }
    }
    if (-not $file) {
        if (-not $Url) { throw "$Label is not in the package and cannot be downloaded" }
        $file = Join-Path $WorkDir ('cache\' + $RelPath)
        Save-Download $Url $file
    }
    $hash = Get-FileSha256 $file
    if ($Pin) {
        if ($hash -ne $Pin.ToLower()) { throw "$Label SHA256 mismatch: got $hash, pinned $Pin ($file). New release or tampering - rebuild the package with -BuildPackage." }
    }
    elseif (-not $AllowUnpinned) {
        throw "$Label has no pinned SHA256 (got $hash). Build a package with -BuildPackage or use -AllowUnpinnedSysmon."
    }
    @{ Path = $file; Sha256 = $hash }
}

function Invoke-Sysmon {
    param($HostInfo)
    $state = Get-SysmonState
    $desc = 'not installed'
    if ($state.Installed) { $desc = '{0} v{1} ({2})' -f $state.ServiceName, $state.Version, $state.State }
    if ($SkipSysmon) { Add-Result 'Sysmon' 'Sysmon' 'Skipped' "-SkipSysmon; current: $desc"; return }
    if (-not $state.Installed -and $state.ChannelExists) {
        Add-Result 'Sysmon' 'Sysmon' 'Warning' 'Sysmon channel exists but no Sysmon/Sysmon64 service: installed under a custom name? Not touching it.'
        return
    }

    $pins = Get-Pins
    $legacy = $HostInfo.IsLegacyOS
    if ($legacy) {
        if (-not $AllowLegacySysmon) {
            Add-Result 'Sysmon' 'Sysmon' $(if ($state.Installed) { 'OK' } else { 'Warning' }) "Legacy OS ($($HostInfo.OSCaption)): modern Sysmon may hang/BSOD. Current: $desc. Use -AllowLegacySysmon with legacy\Sysmon.zip (10.42)."
            return
        }
        if ([version]$HostInfo.OSVersion -ge [version]'6.1') {
            Add-Result 'Sysmon' 'SHA-2 support' 'Warning' 'Server 2008 R2 / Win7: Sysmon driver needs SHA-2 code signing support (KB4474419 + KB4490628). Verify before install.'
        }
        $zipRel = 'legacy\Sysmon.zip'; $cfgRel = 'legacy\sysmonconfig-export.xml'
        $zipPin = $pins.LegacySysmonZipSha256; $cfgPin = $pins.LegacyConfigSha256; $cfgUrl = $pins.LegacyConfigUrl; $zipUrl = $null
    }
    else {
        $zipRel = 'Sysmon.zip'; $cfgRel = 'sysmonconfig-export.xml'
        $zipPin = $pins.SysmonZipSha256; $cfgPin = $pins.ConfigSha256; $cfgUrl = $pins.ConfigUrl; $zipUrl = $pins.SysmonZipUrl
    }

    try {
        $cfg = Resolve-SourceFile $cfgRel $cfgUrl $cfgPin 'Sysmon config'
        Add-Result 'Sysmon' 'Config source' 'OK' ('{0} sha256={1}' -f $cfg.Path, $cfg.Sha256)
    }
    catch { Add-Result 'Sysmon' 'Config source' 'Error' $_.Exception.Message; return }

    $configOk = $state.Installed -and $state.AppliedConfigSha256 -eq $cfg.Sha256
    $needInstall = -not $state.Installed
    $zip = $null; $pkgExe = $null; $pkgVersion = $null
    $mightUpgrade = $state.Installed -and ($UpgradeSysmon -or $AuditOnly)
    if ($needInstall -or $mightUpgrade) {
        try {
            $zip = Resolve-SourceFile $zipRel $zipUrl $zipPin 'Sysmon.zip' -AllowUnpinned:$AllowUnpinnedSysmon
            $extract = Join-Path $WorkDir 'sysmon-extract'
            Expand-ZipFile $zip.Path $extract
            $pkgExe = Join-Path $extract (Get-SysmonExeName $HostInfo.Architecture)
            if (-not (Test-Path -LiteralPath $pkgExe)) { throw "$(Split-Path -Leaf $pkgExe) not found in Sysmon.zip" }
            $sig = Test-MicrosoftSignature $pkgExe
            if (-not $sig.Valid) { throw "Authenticode check failed: $($sig.Status) $($sig.Subject)" }
            $pkgVersion = Get-VersionFromString (Get-Item -LiteralPath $pkgExe).VersionInfo.FileVersion
            Add-Result 'Sysmon' 'Package' 'OK' ('v{0}, sha256={1}, signed by Microsoft' -f $pkgVersion, $zip.Sha256)
        }
        catch {
            Add-Result 'Sysmon' 'Package' $(if ($needInstall) { 'Error' } else { 'Warning' }) $_.Exception.Message
            if ($needInstall) { return }
        }
    }

    $installedVersion = Get-VersionFromString $state.Version
    $outdated = $state.Installed -and $pkgVersion -and $installedVersion -and ($installedVersion -lt $pkgVersion)

    if ($AuditOnly) {
        if ($needInstall) { Add-Result 'Sysmon' 'Sysmon' 'WouldChange' "install v$pkgVersion" }
        elseif ($outdated) { Add-Result 'Sysmon' 'Sysmon' 'WouldChange' "$desc -> v$pkgVersion (needs -UpgradeSysmon)" }
        else { Add-Result 'Sysmon' 'Sysmon' 'OK' $desc }
        if (-not $needInstall -and -not $configOk) { Add-Result 'Sysmon' 'Config' 'WouldChange' "apply $($cfg.Sha256)" }
        elseif ($configOk) { Add-Result 'Sysmon' 'Config' 'OK' $cfg.Sha256 }
        return
    }

    if ($outdated -and $UpgradeSysmon) {
        $r = Invoke-Native $state.Path @('-u', 'force')
        if ($r.Code -ne 0) { Add-Result 'Sysmon' 'Uninstall old' 'Error' $r.Output; return }
        Add-Result 'Sysmon' 'Uninstall old' 'Changed' "removed $desc"
        $needInstall = $true
    }
    elseif ($outdated) { Add-Result 'Sysmon' 'Version' 'Warning' "$desc is older than package v$pkgVersion (use -UpgradeSysmon)" }

    if ($needInstall) {
        $r = Invoke-Native $pkgExe @('-accepteula', '-i', $cfg.Path)
        $after = Get-SysmonState
        if ($r.Code -eq 0 -and $after.Installed -and $after.State -eq 'Running') {
            Set-RegValue $StateRegPath 'SysmonConfigSha256' $cfg.Sha256 'String'
            Add-Result 'Sysmon' 'Sysmon' 'Changed' ('installed {0} v{1}, config {2}' -f $after.ServiceName, $after.Version, $cfg.Sha256)
        }
        else { Add-Result 'Sysmon' 'Sysmon' 'Error' ("install exit {0}: {1}" -f $r.Code, $r.Output) }
        return
    }

    if ($configOk) { Add-Result 'Sysmon' 'Sysmon' 'OK' "$desc, config $($cfg.Sha256)"; return }
    $r = Invoke-Native $state.Path @('-c', $cfg.Path)
    if ($r.Code -eq 0) {
        Set-RegValue $StateRegPath 'SysmonConfigSha256' $cfg.Sha256 'String'
        Add-Result 'Sysmon' 'Config' 'Changed' ('applied {0}' -f $cfg.Sha256) $state.AppliedConfigSha256 $cfg.Sha256
    }
    else { Add-Result 'Sysmon' 'Config' 'Error' ("sysmon -c exit {0}: {1}" -f $r.Code, $r.Output) }
}

#endregion
#region ---------------------------------------------------------------- Wazuh

function Get-WazuhLocations {
    param([string[]]$Files)
    $loc = @()
    foreach ($f in $Files) {
        if (-not (Test-Path -LiteralPath $f)) { continue }
        $text = [System.IO.File]::ReadAllText($f)
        # ignore our own previous block? no - it counts as configured
        foreach ($m in [regex]::Matches($text, '<location>\s*([^<]+?)\s*</location>')) { $loc += $m.Groups[1].Value.ToLower() }
    }
    $loc
}

function New-WazuhBlock {
    param([string[]]$Channels)
    $lines = @('<!-- SecLogging BEGIN (managed by Set-SecurityLogging.ps1) -->', '<ossec_config>')
    foreach ($c in $Channels) {
        $lines += '  <localfile>'
        $lines += "    <location>$c</location>"
        $lines += '    <log_format>eventchannel</log_format>'
        $lines += '  </localfile>'
    }
    $lines += '</ossec_config>'
    $lines += '<!-- SecLogging END -->'
    $lines -join "`r`n"
}

function Invoke-Wazuh {
    param($Settings, [string]$RoleName)
    $svc = $null
    foreach ($n in @('WazuhSvc', 'OssecSvc')) { $svc = Get-WmiObject Win32_Service -Filter "Name='$n'"; if ($svc) { break } }
    if (-not $svc) { Add-Result 'Wazuh' 'Agent' 'Warning' 'Wazuh agent is not installed - logs stay local only'; return }
    $exe = $null
    if ([string]$svc.PathName -match '^"?([^"]+?\.exe)') { $exe = $Matches[1] }
    $dir = Split-Path -Parent $exe
    $conf = Join-Path $dir 'ossec.conf'
    $shared = Join-Path $dir 'shared\agent.conf'
    $ver = ''
    foreach ($vf in @('VERSION', 'VERSION.json')) { $p = Join-Path $dir $vf; if (Test-Path -LiteralPath $p) { $ver = ((Get-Content -LiteralPath $p) -join ' ').Trim(); break } }
    Add-Result 'Wazuh' 'Agent' 'OK' ('{0} ({1}) {2}' -f $svc.Name, $svc.State, $ver)

    $present = Get-WazuhLocations @($conf, $shared)
    $missing = @()
    foreach ($c in $Settings.Channels) {
        if ($c.NoWazuh) { continue }
        if ($c.DC -and $RoleName -ne 'DomainController') { continue }
        if (-not (Get-ChannelState $c.N).Exists) { continue }
        if ($present -notcontains $c.N.ToLower()) { $missing += $c.N }
    }
    if ($missing.Count -eq 0) { Add-Result 'Wazuh' 'eventchannel' 'OK' 'All local security channels are collected'; return }
    if (-not $ConfigureWazuh) {
        Add-Result 'Wazuh' 'eventchannel' 'Warning' ('Not collected: {0}. Use the manager agent.conf group (wazuh\shared) or -ConfigureWazuh' -f ($missing -join ', '))
        return
    }
    if ($AuditOnly) { Add-Result 'Wazuh' 'eventchannel' 'WouldChange' ('add {0}' -f ($missing -join ', ')); return }
    try {
        $text = [System.IO.File]::ReadAllText($conf)
        $old = @()
        $m = [regex]::Match($text, '(?s)<!-- SecLogging BEGIN.*?<!-- SecLogging END -->')
        if ($m.Success) {
            foreach ($x in [regex]::Matches($m.Value, '<location>\s*([^<]+?)\s*</location>')) { $old += $x.Groups[1].Value }
            $text = $text.Remove($m.Index, $m.Length).TrimEnd()
        }
        $all = @($old + $missing | Select-Object -Unique)
        Copy-Item -LiteralPath $conf -Destination ($conf + '.seclogging.bak') -Force
        $text = $text.TrimEnd() + "`r`n`r`n" + (New-WazuhBlock $all) + "`r`n"
        [System.IO.File]::WriteAllText($conf, $text, (New-Object System.Text.UTF8Encoding($false)))
        Restart-Service -Name $svc.Name -Force
        Add-Result 'Wazuh' 'eventchannel' 'Changed' ('added {0}; agent restarted (backup: ossec.conf.seclogging.bak)' -f ($missing -join ', '))
    }
    catch { Add-Result 'Wazuh' 'eventchannel' 'Error' $_.Exception.Message }
}

#endregion
#region ---------------------------------------------------------------- package builder

function Invoke-BuildPackage {
    param([string]$OutDir)
    $pins = Get-Pins
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $OutDir 'legacy') -Force | Out-Null

    Write-Host "Downloading $($pins.SysmonZipUrl)"
    $zip = Join-Path $OutDir 'Sysmon.zip'
    Save-Download $pins.SysmonZipUrl $zip
    $zipHash = Get-FileSha256 $zip
    $ex = Join-Path $env:TEMP ('sysmon-' + [guid]::NewGuid())
    Expand-ZipFile $zip $ex
    $version = $null
    foreach ($exe in @('Sysmon.exe', 'Sysmon64.exe', 'Sysmon64a.exe')) {
        $p = Join-Path $ex $exe
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $sig = Test-MicrosoftSignature $p
        if (-not $sig.Valid) { throw "$exe signature invalid: $($sig.Status) $($sig.Subject)" }
        $version = Get-VersionFromString (Get-Item -LiteralPath $p).VersionInfo.FileVersion
        Write-Host "  $exe v$version signed by Microsoft: OK"
    }
    Remove-Item -LiteralPath $ex -Recurse -Force
    if ($pins.SysmonZipSha256 -and $pins.SysmonZipSha256 -ne $zipHash) {
        if (-not $AcceptNewSysmon) { throw "Sysmon.zip hash $zipHash differs from pinned $($pins.SysmonZipSha256). New release? Re-run with -AcceptNewSysmon." }
        Write-Warning "Accepting new Sysmon.zip $zipHash (was $($pins.SysmonZipSha256))"
    }

    foreach ($c in @(@{ Url = $pins.ConfigUrl; Pin = $pins.ConfigSha256; Rel = 'sysmonconfig-export.xml' }, @{ Url = $pins.LegacyConfigUrl; Pin = $pins.LegacyConfigSha256; Rel = 'legacy\sysmonconfig-export.xml' })) {
        $dst = Join-Path $OutDir $c.Rel
        Write-Host "Downloading $($c.Url)"
        Save-Download $c.Url $dst
        $h = Get-FileSha256 $dst
        if ($h -ne $c.Pin) { throw "$($c.Rel) hash $h does not match pin $($c.Pin)" }
        Write-Host "  $($c.Rel) sha256 OK"
    }

    $legacyHash = $pins.LegacySysmonZipSha256; $legacyVer = $pins.LegacySysmonVersion
    if ($LegacySysmonZip) {
        $dst = Join-Path $OutDir 'legacy\Sysmon.zip'
        Copy-Item -LiteralPath $LegacySysmonZip -Destination $dst -Force
        $ex = Join-Path $env:TEMP ('sysmon-' + [guid]::NewGuid())
        Expand-ZipFile $dst $ex
        foreach ($exe in @('Sysmon.exe', 'Sysmon64.exe')) {
            $p = Join-Path $ex $exe
            if (-not (Test-Path -LiteralPath $p)) { continue }
            $sig = Test-MicrosoftSignature $p
            if (-not $sig.Valid) { throw "legacy $exe signature invalid: $($sig.Status)" }
            $legacyVer = [string](Get-VersionFromString (Get-Item -LiteralPath $p).VersionInfo.FileVersion)
        }
        Remove-Item -LiteralPath $ex -Recurse -Force
        $legacyHash = Get-FileSha256 $dst
        Write-Host "  legacy Sysmon v$legacyVer sha256 $legacyHash"
    }

    Copy-Item -LiteralPath $ScriptPath -Destination (Join-Path $OutDir 'Set-SecurityLogging.ps1') -Force
    $ini = @(
        "; Generated by Set-SecurityLogging.ps1 -BuildPackage on $(Get-Date -Format s)"
        "SysmonZipUrl=$($pins.SysmonZipUrl)"
        "SysmonZipSha256=$zipHash"
        "SysmonVersion=$version"
        "ConfigUrl=$($pins.ConfigUrl)"
        "ConfigSha256=$($pins.ConfigSha256)"
        "LegacySysmonZipSha256=$legacyHash"
        "LegacySysmonVersion=$legacyVer"
        "LegacyConfigUrl=$($pins.LegacyConfigUrl)"
        "LegacyConfigSha256=$($pins.LegacyConfigSha256)"
    )
    [System.IO.File]::WriteAllLines((Join-Path $OutDir 'sources.ini'), $ini)
    Write-Host ''
    Write-Host "Package ready: $OutDir" -ForegroundColor Green
    Write-Host 'Commit sources.ini to the repository (windows\sources.ini) so online installs are pinned too.'
}

#endregion
#region ---------------------------------------------------------------- main

if ($ExportSettings) { return (Get-SecLoggingSettings) }

# 32-bit PowerShell on 64-bit Windows would hit registry/file redirection: relaunch 64-bit.
if ($env:PROCESSOR_ARCHITEW6432 -and -not $env:SECLOGGING_RELAUNCHED) {
    $ps = Join-Path $env:SystemRoot 'sysnative\WindowsPowerShell\v1.0\powershell.exe'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath)
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v.IsPresent) { $argList += "-$k" } }
        else { $argList += "-$k"; $argList += [string]$v }
    }
    $env:SECLOGGING_RELAUNCHED = '1'
    & $ps @argList
    exit $LASTEXITCODE
}

if ($BuildPackage) {
    try { Invoke-BuildPackage $BuildPackage; exit 0 }
    catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 2 }
}

if (-not (Test-IsAdmin)) { Write-Error 'Run as Administrator (elevated).'; exit 3 }

$mutex = New-Object System.Threading.Mutex($false, 'Global\SecLoggingRun')
if (-not $mutex.WaitOne(0)) { Write-Host 'Another Set-SecurityLogging run is in progress, exiting.'; exit 0 }

try {
    if (-not (Test-Path -LiteralPath $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }
    $started = Get-Date
    $settings = Get-SecLoggingSettings
    $hostInfo = Get-HostInfo
    $roleName = $hostInfo.DetectedRole
    if ($Role -ne 'Auto') { $roleName = $Role }

    if (-not $Quiet) {
        Write-Host ''
        Write-Host ('Set-SecurityLogging {0}  mode: {1}' -f $ScriptVersion, $(if ($AuditOnly) { 'AUDIT ONLY' } else { 'APPLY' })) -ForegroundColor White
        Write-Host ('{0}: {1} ({2}), role {3}, domain {4}, {5}, PS {6}, free {7} MB' -f $hostInfo.ComputerName, $hostInfo.OSCaption, $hostInfo.OSVersion, $roleName, $(if ($hostInfo.PartOfDomain) { $hostInfo.Domain } else { '-' }), $hostInfo.Architecture, $hostInfo.PSVersion, $hostInfo.SystemDriveFreeMB)
        if ($SourcePath) { Write-Host "Source: package $SourcePath" } else { Write-Host 'Source: online (pinned URLs)' }
        Write-Host ''
    }
    Add-Result 'Host' 'Role' 'OK' ('{0} (detected {1}, legacy OS: {2})' -f $roleName, $hostInfo.DetectedRole, $hostInfo.IsLegacyOS)

    # Sysmon first: its channel must exist before sizing.
    foreach ($step in @(
            @{ Name = 'Sysmon'; Block = { Invoke-Sysmon $hostInfo } }
            @{ Name = 'Registry'; Block = { Invoke-RegistrySettings $settings $roleName } }
            @{ Name = 'AuditPolicy'; Block = { if ($SkipAuditPolicy) { Add-Result 'AuditPolicy' 'AuditPolicy' 'Skipped' '-SkipAuditPolicy' } else { Invoke-AuditPolicy $settings $roleName } } }
            @{ Name = 'PowerShell'; Block = { Invoke-PowerShellV2Check $hostInfo } }
            @{ Name = 'EventLog'; Block = { Invoke-Channels $settings $roleName $hostInfo } }
            @{ Name = 'Wazuh'; Block = { Invoke-Wazuh $settings $roleName } }
        )) {
        try { & $step.Block }
        catch { Add-Result $step.Name 'Step failed' 'Error' $_.Exception.Message }
    }

    if (-not $AuditOnly) {
        Set-RegValue $StateRegPath 'LastRun' (Get-Date -Format s) 'String'
        Set-RegValue $StateRegPath 'ScriptVersion' $ScriptVersion 'String'
    }

    $summary = 'OK={0} Changed={1} WouldChange={2} Warning={3} Error={4} Skipped={5}' -f $Script:Counts.OK, $Script:Counts.Changed, $Script:Counts.WouldChange, $Script:Counts.Warning, $Script:Counts.Error, $Script:Counts.Skipped
    $report = New-OD
    $report.Tool = 'Set-SecurityLogging'
    $report.Version = $ScriptVersion
    $report.Mode = $(if ($AuditOnly) { 'AuditOnly' } else { 'Apply' })
    $report.Started = $started
    $report.Finished = Get-Date
    $report.Host = $hostInfo
    $report.Role = $roleName
    $report.Source = $(if ($SourcePath) { $SourcePath } else { 'online' })
    $report.Summary = $Script:Counts
    $report.Results = $Script:Report
    if (-not $ReportPath) { $ReportPath = Join-Path $WorkDir ('report-{0:yyyyMMdd-HHmmss}.json' -f $started) }
    $json = ConvertTo-JsonString $report
    [System.IO.File]::WriteAllText($ReportPath, $json, (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $WorkDir 'last-report.json'), $json, (New-Object System.Text.UTF8Encoding($false)))

    if (-not $AuditOnly) {
        # Summary event for the SIEM (Application log, source SecLogging): 1000 ok, 1001 warnings, 1002 errors.
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists('SecLogging')) { New-EventLog -LogName Application -Source SecLogging }
            $id = 1000; $type = 'Information'
            if ($Script:Counts.Warning) { $id = 1001; $type = 'Warning' }
            if ($Script:Counts.Error) { $id = 1002; $type = 'Error' }
            $problems = @($Script:Report | Where-Object { $_.Status -eq 'Error' -or $_.Status -eq 'Warning' } | ForEach-Object { '{0} | {1} | {2} | {3}' -f $_.Status, $_.Area, $_.Item, $_.Message })
            Write-EventLog -LogName Application -Source SecLogging -EventId $id -EntryType $type -Message ("Set-SecurityLogging $ScriptVersion role=$roleName $summary`r`n" + ($problems -join "`r`n"))
        }
        catch { Write-Verbose "Cannot write summary event: $($_.Exception.Message)" }
    }

    Write-Host ''
    Write-Host "Summary: $summary" -ForegroundColor White
    Write-Host "Report:  $ReportPath"
    if ($Script:Counts.Error) { exit 2 }
    exit 0
}
finally {
    $mutex.ReleaseMutex()
    $mutex.Close()
}

#endregion
