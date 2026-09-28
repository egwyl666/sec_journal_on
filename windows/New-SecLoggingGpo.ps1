#Requires -Version 5.1
<#
.SYNOPSIS
    Creates/updates the domain GPOs for security logging (run on a domain controller).

.DESCRIPTION
    Two GPOs are created (Default Domain / Default DC policies are never touched):

      SEC-Logging-Baseline           -> linked to the domain root (or -LinkTargets)
      SEC-Logging-DomainControllers  -> linked to OU=Domain Controllers

    Each GPO carries:
      * Advanced Audit Policy (audit.csv, by subcategory GUID, role-specific set)
      * Registry policy: force subcategories, command line in 4688, PowerShell
        ScriptBlock/Module logging (Windows PowerShell and PowerShell 7), NTLM auditing,
        optional transcription
      * DC GPO only: classic event log sizes/retention, NTLM domain audit,
        LDAP interface diagnostics (2889)
      * Computer startup script: Set-SecurityLogging.ps1 from NETLOGON
        (enables operational channels, role-based sizes, Sysmon from the package)

    The offline package (Set-SecurityLogging.ps1 -BuildPackage) is staged to
    \\<domain>\NETLOGON\SecLogging and verified by SHA256.

    Supports -WhatIf.

.PARAMETER PackagePath
    Folder with the package built by Set-SecurityLogging.ps1 -BuildPackage.
    Default: the folder of this script.

.PARAMETER LinkTargets
    Distinguished names to link the baseline GPO to. Default: domain root.

.PARAMETER SkipSysmon
    Startup script runs with -SkipSysmon (logs/audit only).

.PARAMETER UpgradeSysmon / DisablePowerShellV2 / AllowLegacySysmon
    Passed through to the startup script.

.PARAMETER TranscriptionPath
    UNC path for PowerShell transcription (policy only; set the share ACL yourself).

.PARAMETER SetDomainRootSacl
    Add SACL entries on the domain root so 4662 is logged for DCSync
    (replication extended rights) and for DACL/owner changes.

.EXAMPLE
    .\New-SecLoggingGpo.ps1 -PackagePath D:\SecLogging -WhatIf
.EXAMPLE
    .\New-SecLoggingGpo.ps1 -PackagePath D:\SecLogging -SetDomainRootSacl
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$PackagePath,
    [string]$BaselineGpoName = 'SEC-Logging-Baseline',
    [string]$DcGpoName = 'SEC-Logging-DomainControllers',
    [string[]]$LinkTargets,
    [switch]$SkipSysmon,
    [switch]$UpgradeSysmon,
    [switch]$DisablePowerShellV2,
    [switch]$AllowLegacySysmon,
    [string]$TranscriptionPath,
    [switch]$SetDomainRootSacl
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $PackagePath) { $PackagePath = $here }

# Client-side extension GUID pairs: [CSE}{Tool]
$CseRegistry = '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]'
$CseScripts = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
$CseAudit = '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'

# DCSync = DS-Replication-Get-Changes(-All / -In-Filtered-Set)
$ReplicationRights = @(
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    '89e95b76-444d-4c62-991a-0facbeda640c'
)

function Write-Step { param([string]$Text) Write-Host "==> $Text" -ForegroundColor Cyan }

#region ---------------------------------------------------------------- pure helpers (unit tested)

function Merge-GpoExtensionNames {
    # gPCMachineExtensionNames: "[{cse}{tool}][{cse}{tool}]", sorted by CSE GUID.
    param([string]$Current, [string[]]$Add)
    $set = @{}
    foreach ($m in [regex]::Matches([string]$Current, '\[[^\]]+\]')) { $set[$m.Value.ToUpper()] = $m.Value.ToUpper() }
    foreach ($a in $Add) { $set[$a.ToUpper()] = $a.ToUpper() }
    ($set.Keys | Sort-Object) -join ''
}

function New-AuditCsv {
    param($AuditPolicy, [string]$RoleName)
    $names = @('No Auditing', 'Success', 'Failure', 'Success and Failure')
    $lines = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
    foreach ($a in $AuditPolicy) {
        $v = [int]$a[$RoleName]
        if ($v -eq 0) { continue }
        $lines += (',System,Audit {0},{{{1}}},{2},,{3}' -f $a.Name, $a.Guid.ToLower(), $names[$v], $v)
    }
    $lines
}

function New-ScriptsIni {
    param([string]$CmdLine, [string]$Parameters)
    @('', '[Startup]', "0CmdLine=$CmdLine", "0Parameters=$Parameters")
}

function Get-EventLogPolicyValues {
    # Admin template "Windows Components/Event Log Service": MaxSize in KB, Retention "0" = overwrite.
    param($Sizes, [string]$ProfileName)
    $map = @{ Security = 'Security'; System = 'System'; Application = 'Application' }
    $out = @()
    foreach ($log in $map.Keys) {
        $out += @{ Key = "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\$log"; Name = 'MaxSize'; Type = 'DWord'; Value = [int]($Sizes[$ProfileName][$map[$log]] * 1024) }
        $out += @{ Key = "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\$log"; Name = 'Retention'; Type = 'String'; Value = '0' }
        $out += @{ Key = "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\$log"; Name = 'AutoBackupLogFiles'; Type = 'String'; Value = '0' }
    }
    $out
}

#endregion
#region ---------------------------------------------------------------- AD / SYSVOL helpers

function Update-GpoFiles {
    # Writes audit.csv + scripts.ini into the GPO folder, registers CSEs, bumps the machine version.
    param($Gpo, [string[]]$AuditCsv, [string[]]$ScriptsIni, [string]$DcName, [string]$DomainDns)
    $gpoPath = "\\$DcName\SYSVOL\$DomainDns\Policies\{$($Gpo.Id)}"
    $auditDir = Join-Path $gpoPath 'Machine\Microsoft\Windows NT\Audit'
    $scriptDir = Join-Path $gpoPath 'Machine\Scripts'
    New-Item -ItemType Directory -Path $auditDir -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $scriptDir 'Startup') -Force | Out-Null
    [IO.File]::WriteAllLines((Join-Path $auditDir 'audit.csv'), [string[]]$AuditCsv, (New-Object Text.UTF8Encoding($false)))
    # scripts.ini must be UTF-16 LE
    [IO.File]::WriteAllLines((Join-Path $scriptDir 'scripts.ini'), [string[]]$ScriptsIni, [Text.Encoding]::Unicode)

    $de = [ADSI]"LDAP://$DcName/CN={$($Gpo.Id)},CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)"
    $ext = Merge-GpoExtensionNames ([string]$de.Properties['gPCMachineExtensionNames'].Value) @($CseRegistry, $CseScripts, $CseAudit)
    $version = [int]$de.Properties['versionNumber'].Value + 1   # low word = computer version
    $de.Properties['gPCMachineExtensionNames'].Value = $ext
    $de.Properties['versionNumber'].Value = $version
    $de.CommitChanges()

    $gptIni = Join-Path $gpoPath 'GPT.INI'
    $content = @(Get-Content -LiteralPath $gptIni)
    if ($content -match '^Version=') { $content = $content -replace '^Version=\d+', "Version=$version" }
    else { $content += "Version=$version" }
    Set-Content -LiteralPath $gptIni -Value $content -Encoding ASCII
}

function Set-GpoRegistryList {
    param([string]$GpoName, $Items, [string]$DcName)
    foreach ($i in $Items) {
        $params = @{ Name = $GpoName; Key = $i.Key; ValueName = $i.Name; Type = $i.Type; Value = $i.Value; Server = $DcName }
        Set-GPRegistryValue @params | Out-Null
        Write-Host ("    {0}\{1} = {2}" -f $i.Key, $i.Name, $i.Value)
    }
}

function Get-OrNewGpo {
    param([string]$Name, [string]$Comment, [string]$DcName)
    $g = Get-GPO -Name $Name -Server $DcName -ErrorAction SilentlyContinue
    if ($g) { Write-Host "    exists: $Name {$($g.Id)}"; return $g }
    $g = New-GPO -Name $Name -Comment $Comment -Server $DcName
    Write-Host "    created: $Name {$($g.Id)}"
    $g
}

function Add-GpoLinkOnce {
    param([string]$GpoName, [string]$Target, [string]$DcName)
    $links = (Get-GPInheritance -Target $Target -Server $DcName).GpoLinks | ForEach-Object { $_.DisplayName }
    if ($links -contains $GpoName) { Write-Host "    already linked: $Target"; return }
    New-GPLink -Name $GpoName -Target $Target -LinkEnabled Yes -Server $DcName | Out-Null
    Write-Host "    linked: $Target"
}

function Set-DomainRootSacl {
    param([string]$DomainDn, [string]$DcName)
    $de = New-Object DirectoryServices.DirectoryEntry("LDAP://$DcName/$DomainDn")
    $de.psbase.Options.SecurityMasks = [DirectoryServices.SecurityMasks]::Sacl
    $sd = $de.psbase.ObjectSecurity
    $everyone = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
    $existing = $sd.GetAuditRules($true, $false, [Security.Principal.SecurityIdentifier])
    $want = @()
    foreach ($g in $ReplicationRights) {
        $want += New-Object DirectoryServices.ActiveDirectoryAuditRule($everyone, [DirectoryServices.ActiveDirectoryRights]::ExtendedRight, [Security.AccessControl.AuditFlags]::Success, [guid]$g, [DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    }
    $want += New-Object DirectoryServices.ActiveDirectoryAuditRule($everyone, ([DirectoryServices.ActiveDirectoryRights]::WriteDacl -bor [DirectoryServices.ActiveDirectoryRights]::WriteOwner), [Security.AccessControl.AuditFlags]::Success, [DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    $added = 0
    foreach ($w in $want) {
        $dup = $existing | Where-Object { $_.IdentityReference -eq $w.IdentityReference -and $_.ObjectType -eq $w.ObjectType -and (($_.ActiveDirectoryRights -band $w.ActiveDirectoryRights) -eq $w.ActiveDirectoryRights) -and (($_.AuditFlags -band $w.AuditFlags) -eq $w.AuditFlags) }
        if ($dup) { continue }
        $sd.AddAuditRule($w); $added++
    }
    if ($added -eq 0) { Write-Host '    SACL already present'; return }
    $de.psbase.CommitChanges()
    Write-Host "    added $added audit rule(s) on $DomainDn"
}

#endregion
#region ---------------------------------------------------------------- main

if ($MyInvocation.InvocationName -eq '.') { return }   # dot-sourced for tests: functions only

$os = Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -ne 2) { throw 'Run this script on a domain controller.' }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated (Domain Admin).' }
Import-Module GroupPolicy, ActiveDirectory

$domain = Get-ADDomain
$domainDns = $domain.DNSRoot
$domainDn = $domain.DistinguishedName
$dcName = $env:COMPUTERNAME
if (-not $LinkTargets) { $LinkTargets = @($domainDn) }
$dcOu = $domain.DomainControllersContainer

Write-Step "Domain $domainDns, working against DC $dcName"

# ---- 1. package
Write-Step "Checking package $PackagePath"
$mainScript = Join-Path $PackagePath 'Set-SecurityLogging.ps1'
if (-not (Test-Path -LiteralPath $mainScript)) { $mainScript = Join-Path $here 'Set-SecurityLogging.ps1' }
if (-not (Test-Path -LiteralPath $mainScript)) { throw "Set-SecurityLogging.ps1 not found in $PackagePath" }
$settings = & $mainScript -ExportSettings
$pins = @{}
$iniPath = Join-Path $PackagePath 'sources.ini'
if (Test-Path -LiteralPath $iniPath) {
    foreach ($l in Get-Content -LiteralPath $iniPath) { if ($l -match '^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$') { $pins[$Matches[1]] = $Matches[2] } }
}
$files = @(@{ Rel = 'Set-SecurityLogging.ps1'; Pin = $null; Src = $mainScript })
if (Test-Path -LiteralPath $iniPath) { $files += @{ Rel = 'sources.ini'; Pin = $null; Src = $iniPath } }
foreach ($f in @(
        @{ Rel = 'Sysmon.zip'; Pin = $pins.SysmonZipSha256 }
        @{ Rel = 'sysmonconfig-export.xml'; Pin = $settings.Pins.ConfigSha256 }
        @{ Rel = 'legacy\Sysmon.zip'; Pin = $pins.LegacySysmonZipSha256 }
        @{ Rel = 'legacy\sysmonconfig-export.xml'; Pin = $settings.Pins.LegacyConfigSha256 })) {
    $src = Join-Path $PackagePath $f.Rel
    if (-not (Test-Path -LiteralPath $src)) {
        if (-not $SkipSysmon -and $f.Rel -notlike 'legacy*') { throw "$($f.Rel) missing in package. Build it: Set-SecurityLogging.ps1 -BuildPackage $PackagePath" }
        Write-Host "    skip (absent): $($f.Rel)"; continue
    }
    $h = (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash.ToLower()
    if ($f.Pin -and $h -ne $f.Pin.ToLower()) { throw "$($f.Rel): SHA256 $h does not match pin $($f.Pin)" }
    if (-not $f.Pin) { throw "$($f.Rel): no pinned SHA256 in sources.ini - rebuild the package with -BuildPackage" }
    Write-Host "    OK $($f.Rel) $h"
    $files += @{ Rel = $f.Rel; Pin = $h; Src = $src }
}

$share = "\\$domainDns\NETLOGON\SecLogging"
$localShare = "\\$dcName\NETLOGON\SecLogging"
Write-Step "Staging package to $localShare (replicates to all DCs via SYSVOL)"
if ($PSCmdlet.ShouldProcess($localShare, 'Copy package')) {
    foreach ($f in $files) {
        $dst = Join-Path $localShare $f.Rel
        New-Item -ItemType Directory -Path (Split-Path -Parent $dst) -Force | Out-Null
        Copy-Item -LiteralPath $f.Src -Destination $dst -Force
        if ($f.Pin -and (Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash.ToLower() -ne $f.Pin) { throw "Copy verification failed: $dst" }
    }
    Write-Host '    copied and verified'
}

# ---- 2. startup script command line
$startupArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$share\Set-SecurityLogging.ps1`" -SourcePath `"$share`" -Quiet"
if ($SkipSysmon) { $startupArgs += ' -SkipSysmon' }
if ($UpgradeSysmon) { $startupArgs += ' -UpgradeSysmon' }
if ($DisablePowerShellV2) { $startupArgs += ' -DisablePowerShellV2' }
if ($AllowLegacySysmon) { $startupArgs += ' -AllowLegacySysmon' }
if ($TranscriptionPath) { $startupArgs += " -TranscriptionPath `"$TranscriptionPath`"" }
$scriptsIni = New-ScriptsIni 'powershell.exe' $startupArgs

# ---- 3. registry policy lists
function ConvertTo-GpoRegistry {
    param($Items)
    $out = @()
    foreach ($r in $Items) {
        $t = 'String'; if ($r.Type -eq 'DWord') { $t = 'DWord' }
        $out += @{ Key = "HKLM\$($r.Path)"; Name = $r.Name; Type = $t; Value = $r.Value }
    }
    $out
}
$common = ConvertTo-GpoRegistry @($settings.Registry | Where-Object { -not $_.DC })
$dcOnly = ConvertTo-GpoRegistry @($settings.Registry | Where-Object { $_.DC })
if ($TranscriptionPath) {
    $t = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    $common += @{ Key = $t; Name = 'EnableTranscripting'; Type = 'DWord'; Value = 1 }
    $common += @{ Key = $t; Name = 'EnableInvocationHeader'; Type = 'DWord'; Value = 1 }
    $common += @{ Key = $t; Name = 'OutputDirectory'; Type = 'String'; Value = $TranscriptionPath }
}
$dcRegistry = @($common) + @($dcOnly) + @(Get-EventLogPolicyValues $settings.Sizes 'DomainController')

# ---- 4. GPOs
foreach ($g in @(
        @{ Name = $BaselineGpoName; Role = 'Workstation'; Registry = $common; Links = $LinkTargets; Comment = 'Security logging baseline: audit policy, PowerShell/NTLM logging, Sysmon startup script. Managed by New-SecLoggingGpo.ps1' }
        @{ Name = $DcGpoName; Role = 'DomainController'; Registry = $dcRegistry; Links = @($dcOu); Comment = 'Security logging for domain controllers: DC audit policy, log sizes, NTLM/LDAP auditing. Managed by New-SecLoggingGpo.ps1' })) {
    Write-Step "GPO $($g.Name)"
    if (-not $PSCmdlet.ShouldProcess($g.Name, 'Create/update GPO, registry policy, audit.csv, startup script, links')) { continue }
    $gpo = Get-OrNewGpo $g.Name $g.Comment $dcName
    Set-GpoRegistryList $g.Name $g.Registry $dcName
    # Baseline audit.csv uses the workstation set (member servers get the same; File Share differs only slightly).
    # The DC GPO carries the complete DC set, so the result is correct whether or not audit.csv files merge.
    $csv = New-AuditCsv $settings.AuditPolicy $g.Role
    Update-GpoFiles -Gpo $gpo -AuditCsv $csv -ScriptsIni $scriptsIni -DcName $dcName -DomainDns $domainDns
    Write-Host "    audit.csv: $($csv.Count - 1) subcategories; startup script set"
    foreach ($t in $g.Links) { Add-GpoLinkOnce $g.Name $t $dcName }
}

# ---- 5. SACL for DCSync / ACL abuse
if ($SetDomainRootSacl) {
    Write-Step "SACL on $domainDn (4662 for replication rights, WriteDacl/WriteOwner)"
    if ($PSCmdlet.ShouldProcess($domainDn, 'Add audit rules')) { Set-DomainRootSacl $domainDn $dcName }
}
else {
    Write-Host ''
    Write-Host 'Note: without -SetDomainRootSacl event 4662 for DCSync may not be generated.' -ForegroundColor Yellow
}

Write-Host ''
Write-Host 'Done. Verify on a client / DC:' -ForegroundColor Green
Write-Host '  gpupdate /force'
Write-Host '  gpresult /h C:\gp.html            (both SEC-Logging GPOs applied?)'
Write-Host '  auditpol /get /category:*'
Write-Host '  after reboot: type C:\ProgramData\SecLogging\last-report.json'

#endregion
