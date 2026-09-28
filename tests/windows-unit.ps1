# Unit tests for the pure (OS independent) parts of the Windows scripts.
# Runs on pwsh (Linux/Windows):  pwsh -NoProfile -File tests/windows-unit.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$main = Join-Path $root 'windows/Set-SecurityLogging.ps1'
$gpo = Join-Path $root 'windows/New-SecLoggingGpo.ps1'
if (-not $env:ProgramData) { $env:ProgramData = [IO.Path]::GetTempPath() }

$script:failed = 0; $script:passed = 0
function Assert {
    param([bool]$Condition, [string]$Name)
    if ($Condition) { $script:passed++; Write-Host "  PASS $Name" -ForegroundColor Green }
    else { $script:failed++; Write-Host "  FAIL $Name" -ForegroundColor Red }
}
function Assert-Throws {
    param([scriptblock]$Block, [string]$Pattern, [string]$Name)
    try { & $Block; Assert $false "$Name (no exception)" }
    catch { Assert ($_.Exception.Message -match $Pattern) "$Name [$($_.Exception.Message)]" }
}

# Load function definitions only (no main code) from a script
function Import-ScriptFunctions {
    param([string]$Path)
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        . ([scriptblock]::Create($f.Extent.Text))
        Set-Item -Path "function:global:$($f.Name)" -Value (Get-Item "function:$($f.Name)").ScriptBlock
    }
}
Import-ScriptFunctions $main
Import-ScriptFunctions $gpo

Write-Host 'Settings (via -ExportSettings)'
$s = & $main -ExportSettings
Assert ($s.AuditPolicy.Count -ge 30) 'audit subcategories present'
$guids = @($s.AuditPolicy | ForEach-Object { $_.Guid })
Assert (($guids | Sort-Object -Unique).Count -eq $guids.Count) 'audit GUIDs unique'
Assert (@($guids | Where-Object { $_ -notmatch '^0CCE92[0-9A-F]{2}-69AE-11D9-BED3-505054503030$' }).Count -eq 0) 'audit GUIDs well-formed'
$bad = @($s.AuditPolicy | Where-Object { foreach ($r in 'Workstation', 'Server', 'DomainController') { if ($_[$r] -lt 0 -or $_[$r] -gt 3) { $true } } })
Assert ($bad.Count -eq 0) 'audit values within 0..3'
Assert (@($s.AuditPolicy | Where-Object { $_.Name -like 'Directory Service*' -and $_.Workstation -ne 0 }).Count -eq 0) 'DS Access only on DC'
$names = @($s.Channels | ForEach-Object { $_.N })
Assert (($names | Sort-Object -Unique).Count -eq $names.Count) 'channel names unique'
foreach ($p in 'DomainController', 'Server', 'Workstation', 'Minimal') {
    $classes = @($s.Channels | ForEach-Object { $_.C } | Sort-Object -Unique)
    $missing = @($classes | Where-Object { -not $s.Sizes[$p].ContainsKey($_) })
    Assert ($missing.Count -eq 0) "profile $p has all size classes"
    Assert (@($s.Sizes[$p].Values | Where-Object { $_ -gt 4096 }).Count -eq 0) "profile $p <= 4 GB per log"
}
Assert ($s.Pins.ConfigSha256 -match '^[0-9a-f]{64}$') 'config pin is a sha256'

Write-Host 'auditpol CSV parsing (localized names)'
$csv = @(
    'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
    'DC1,System,Вход в систему,{0CCE9215-69AE-11D9-BED3-505054503030},Успех и сбой,,3'
    'DC1,System,Проверка учетных данных,{0cce923f-69ae-11d9-bed3-505054503030},Успех,,1'
    'DC1,System,Option:CrashOnAuditFail,,Disabled,,0'
)
$m = ConvertFrom-AuditCsv $csv
Assert ($m.Count -eq 2) 'two GUID rows parsed, option row ignored'
Assert ($m['0CCE9215-69AE-11D9-BED3-505054503030'] -eq 3) 'Logon = 3'
Assert ($m['0CCE923F-69AE-11D9-BED3-505054503030'] -eq 1) 'lower-case GUID normalized'

Write-Host 'JSON writer'
$od = New-OD; $od.Text = "a`"b\c`nd"; $od.Num = 5L; $od.Flag = $true; $od.Null = $null; $od.List = @(1, 'x'); $od.Empty = @()
$od.Nested = @{ K = 'v' }
$parsed = (ConvertTo-JsonString $od) | ConvertFrom-Json
Assert ($parsed.Text -eq "a`"b\c`nd") 'string escaping round-trips'
Assert ($parsed.Num -eq 5 -and $parsed.Flag -eq $true -and $null -eq $parsed.Null) 'scalars'
Assert ($parsed.List.Count -eq 2 -and $parsed.Nested.K -eq 'v') 'arrays and nested maps'

Write-Host 'Size planning'
$st = @(
    @{ Class = 'Security'; State = @{ Exists = $true; MaxBytes = 20MB } }
    @{ Class = 'Sysmon'; State = @{ Exists = $false; MaxBytes = 0 } }
    @{ Class = 'System'; State = @{ Exists = $true; MaxBytes = 20MB } }
)
$p = Get-SizePlan 'DomainController' $st $s 100000
Assert ($p.Profile -eq 'DomainController') 'DC profile fits 100 GB free'
$p = Get-SizePlan 'DomainController' $st $s 3000
Assert ($p.Profile -eq 'Workstation') 'steps down to Workstation with 3 GB free'
$p = Get-SizePlan 'Workstation' $st $s 100
Assert ($null -eq $p.Profile) 'no profile when nothing fits'
$st[0].State.MaxBytes = 8GB
$p = Get-SizePlan 'Server' $st $s 1000
Assert ($p.Profile -eq 'Server') 'larger existing size does not count as growth'

Write-Host 'Pinned source resolution'
$pkg = Join-Path ([IO.Path]::GetTempPath()) ('pkg-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $pkg | Out-Null
Set-Content -LiteralPath (Join-Path $pkg 'sysmonconfig-export.xml') -Value '<Sysmon/>' -NoNewline
$h = Get-FileSha256 (Join-Path $pkg 'sysmonconfig-export.xml')
$global:SourcePath = $pkg; $global:Online = $false; $global:WorkDir = $pkg; $global:ScriptDir = $pkg; $global:DefaultPins = $s.Pins
$r = Resolve-SourceFile 'sysmonconfig-export.xml' $null $h 'cfg'
Assert ($r.Sha256 -eq $h) 'matching pin accepted'
Assert-Throws { Resolve-SourceFile 'sysmonconfig-export.xml' $null ('0' * 64) 'cfg' } 'mismatch' 'wrong pin rejected'
Assert-Throws { Resolve-SourceFile 'sysmonconfig-export.xml' $null '' 'cfg' } 'no pinned' 'unpinned rejected by default'
$r = Resolve-SourceFile 'sysmonconfig-export.xml' $null '' 'cfg' -AllowUnpinned
Assert ($r.Sha256 -eq $h) 'unpinned accepted with -AllowUnpinned'
Assert-Throws { Resolve-SourceFile 'Sysmon.zip' $null 'x' 'zip' } 'not found' 'missing file in offline package'
Set-Content -LiteralPath (Join-Path $pkg 'sources.ini') -Value "SysmonZipSha256=abc`nConfigSha256=`n"
$pins = Get-Pins
Assert ($pins.SysmonZipSha256 -eq 'abc') 'sources.ini overrides pins'
Assert ($pins.ConfigSha256 -eq $s.Pins.ConfigSha256) 'empty ini value keeps embedded pin'
Remove-Item -LiteralPath $pkg -Recurse -Force

Write-Host 'Wazuh block'
$block = New-WazuhBlock @('Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-PowerShell/Operational')
$tmp = [IO.Path]::GetTempFileName()
Set-Content -LiteralPath $tmp -Value ("<ossec_config><localfile><location>Security</location></localfile></ossec_config>`r`n" + $block)
$loc = Get-WazuhLocations @($tmp)
Assert ($loc -contains 'security' -and $loc -contains 'microsoft-windows-sysmon/operational') 'locations parsed (case-insensitive)'
Assert (([xml]("<root>$block</root>")).root.ossec_config.localfile.Count -eq 2) 'block is well-formed XML'
Remove-Item $tmp

Write-Host 'GPO helpers'
$ext = Merge-GpoExtensionNames '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]' @(
    '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'
    '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
    '[{35378eac-683f-11d2-a89a-00c04fbbcfa2}{d02b1f72-3407-48ae-ba88-e8213c6761f1}]')
$parts = @([regex]::Matches($ext, '\[[^\]]+\]') | ForEach-Object { $_.Value })
Assert ($parts.Count -eq 4) 'extension names deduplicated'
Assert (($parts -join '') -eq (($parts | Sort-Object) -join '')) 'extension names sorted'
Assert ($parts[0].StartsWith('[{35378EAC') -and $parts[3].StartsWith('[{F3CCC681')) 'existing security CSE kept'
$dcCsv = New-AuditCsv $s.AuditPolicy 'DomainController'
$wsCsv = New-AuditCsv $s.AuditPolicy 'Workstation'
Assert ($dcCsv[0] -like 'Machine Name,*') 'audit.csv header'
Assert (@($dcCsv | Where-Object { $_ -like '*{0cce923b-*' }).Count -eq 1 -and @($wsCsv | Where-Object { $_ -like '*{0cce923b-*' }).Count -eq 0) 'DS Access only in DC audit.csv'
Assert (@($dcCsv | Select-Object -Skip 1 | Where-Object { $_ -notmatch '^,System,Audit .+,\{[0-9a-f-]{36}\},(Success|Failure|Success and Failure),,[123]$' }).Count -eq 0) 'audit.csv rows well-formed'
$back = ConvertFrom-AuditCsv $dcCsv
Assert ($back['0CCE9242-69AE-11D9-BED3-505054503030'] -eq 3) 'audit.csv parses back with the same parser'
$ini = New-ScriptsIni 'powershell.exe' '-File "\\corp\NETLOGON\SecLogging\Set-SecurityLogging.ps1"'
Assert ($ini -contains '[Startup]' -and $ini -contains '0CmdLine=powershell.exe') 'scripts.ini content'
$el = Get-EventLogPolicyValues $s.Sizes 'DomainController'
$sec = $el | Where-Object { $_.Key -like '*\Security' -and $_.Name -eq 'MaxSize' }
Assert ($sec.Value -eq 3072 * 1024) 'DC Security MaxSize in KB'

Write-Host 'Audit policy logic (mocked auditpol)'
$global:Quiet = $true; $global:AuditOnly = $false; $global:SysRoot = [IO.Path]::GetTempPath()
$env:SystemRoot = Join-Path $global:SysRoot ('sr-' + [guid]::NewGuid())
$global:AuditState = @{ '0CCE9215-69AE-11D9-BED3-505054503030' = 1; '0CCE9224-69AE-11D9-BED3-505054503030' = 3 }
$global:Calls = @()
function global:Get-AuditPolicyMap { $h = @{}; foreach ($k in $global:AuditState.Keys) { $h[$k] = $global:AuditState[$k] }; $h }
function global:Invoke-Native {
    param([string]$FilePath, [string[]]$Arguments)
    $global:Calls += ,@($FilePath) + $Arguments
    if ($FilePath -eq 'auditpol.exe' -and $Arguments[0] -eq '/set') {
        $g = ([regex]::Match($Arguments[1], '\{(.+)\}')).Groups[1].Value.ToUpper()
        $v = 0; if ($global:AuditState.ContainsKey($g)) { $v = $global:AuditState[$g] }
        if ($Arguments -contains '/success:enable') { $v = $v -bor 1 }
        if ($Arguments -contains '/failure:enable') { $v = $v -bor 2 }
        $global:AuditState[$g] = $v
    }
    if ($FilePath -eq 'wevtutil.exe') {
        $c = $global:Chan[$Arguments[1]]
        foreach ($a in $Arguments) {
            if ($a -eq '/e:true') { $c.Enabled = $true }
            if ($a -eq '/rt:false') { $c.Mode = 'Circular' }
            if ($a -like '/ms:*') { $c.MaxBytes = [long]$a.Substring(4) }
        }
    }
    @{ Code = 0; Output = '' }
}
$Script:Report = @(); $Script:Counts = @{ OK = 0; Changed = 0; WouldChange = 0; Warning = 0; Error = 0; Skipped = 0 }
$s2 = & $main -ExportSettings
Invoke-AuditPolicy $s2 'Workstation'
$logon = $global:AuditState['0CCE9215-69AE-11D9-BED3-505054503030']
Assert ($logon -eq 3) 'Logon raised Success -> Success and Failure'
Assert ($global:AuditState['0CCE9224-69AE-11D9-BED3-505054503030'] -eq 3) 'File Share already SF untouched'
Assert (-not $global:AuditState.ContainsKey('0CCE923B-69AE-11D9-BED3-505054503030')) 'DS Access not set on workstation'
Assert ($Script:Counts.Error -eq 0 -and $Script:Counts.Changed -gt 20) "changes verified ($($Script:Counts.Changed) changed)"
$setCalls = @($global:Calls | Where-Object { $_[0] -eq 'auditpol.exe' -and $_[1] -eq '/set' })
Assert (@($setCalls | Where-Object { $_[2] -notmatch '^/subcategory:\{0CCE92[0-9A-F]{2}-69AE-11D9-BED3-505054503030\}$' }).Count -eq 0) 'auditpol called with GUIDs only'
Assert (@($setCalls | Where-Object { $_ -match 'disable' }).Count -eq 0) 'never disables anything'
$global:Calls = @(); $Script:Counts = @{ OK = 0; Changed = 0; WouldChange = 0; Warning = 0; Error = 0; Skipped = 0 }
$s3 = & $main -ExportSettings
Invoke-AuditPolicy $s3 'Workstation'
Assert ($global:Calls.Count -eq 0 -and $Script:Counts.Changed -eq 0) 'second run is a no-op'

Write-Host 'Event log channel logic (mocked wevtutil)'
$global:Chan = @{
    'Security'    = @{ Name = 'Security'; Exists = $true; Enabled = $true; MaxBytes = 20MB; Mode = 'Circular' }
    'System'      = @{ Name = 'System'; Exists = $true; Enabled = $true; MaxBytes = 2GB; Mode = 'AutoBackup' }
    'Microsoft-Windows-DNS-Client/Operational' = @{ Name = 'x'; Exists = $true; Enabled = $false; MaxBytes = 1MB; Mode = 'Circular' }
}
function global:Get-ChannelState { param([string]$Name) if ($global:Chan.ContainsKey($Name)) { $global:Chan[$Name].Clone() } else { @{ Name = $Name; Exists = $false } } }
function global:Get-ChannelPolicy { param([string]$Name) if ($Name -eq 'Security') { @{ MaxBytes = 100MB; Retention = '0'; AutoBackup = $null } } else { $null } }
$Script:Report = @(); $Script:Counts = @{ OK = 0; Changed = 0; WouldChange = 0; Warning = 0; Error = 0; Skipped = 0 }
Invoke-Channels $s2 'Server' @{ SystemDriveFreeMB = 100000 }
$res = @{}; foreach ($r in $Script:Report) { $res[$r.Item] = $r }
Assert ($global:Chan['Security'].MaxBytes -eq 20MB -and $res['Security'].Status -eq 'Warning' -and $res['Security'].Message -match 'GPO limits') 'GPO-limited Security log reported, not changed'
Assert ($global:Chan['System'].MaxBytes -eq 2GB -and $global:Chan['System'].Mode -eq 'Circular') 'larger System log kept, retention fixed'
$dns = $global:Chan['Microsoft-Windows-DNS-Client/Operational']
Assert ($dns.Enabled -and $dns.MaxBytes -eq 192MB) 'disabled channel enabled and sized (Server/Other = 192 MB)'
Assert ($res['Directory Service'] -eq $null) 'DC-only channels skipped on server'
Assert ($res['Microsoft-Windows-Sysmon/Operational'].Status -eq 'Skipped') 'absent channel skipped'
$global:AuditOnly = $true
$before = $global:Chan['Microsoft-Windows-DNS-Client/Operational'].Clone(); $global:Chan['Microsoft-Windows-DNS-Client/Operational'].Enabled = $false
$global:Calls = @(); $Script:Counts = @{ OK = 0; Changed = 0; WouldChange = 0; Warning = 0; Error = 0; Skipped = 0 }
Invoke-Channels $s2 'Server' @{ SystemDriveFreeMB = 100000 }
Assert (@($global:Calls | Where-Object { $_[0] -eq 'wevtutil.exe' }).Count -eq 0 -and $Script:Counts.WouldChange -eq 1) 'AuditOnly makes no calls'
$global:AuditOnly = $false

Write-Host ''
Write-Host "Passed: $script:passed  Failed: $script:failed"
if ($script:failed) { exit 1 }
