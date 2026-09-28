# Юніт-тести для чистих (незалежних від ОС) частин Windows-скриптів.
# Запуск у pwsh (Linux/Windows):  pwsh -NoProfile -File tests/windows-unit.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$main = Join-Path $root 'windows/Set-SecurityLogging.ps1'
$gpo = Join-Path $root 'windows/New-SecLoggingGpo.ps1'
if (-not $env:ProgramData) { $env:ProgramData = [IO.Path]::GetTempPath() }

$script:failed = 0; $script:passed = 0
function Assert {
    param([bool]$Condition, [string]$Name)
    if ($Condition) { $script:passed++; Write-Host "  ОК   $Name" -ForegroundColor Green }
    else { $script:failed++; Write-Host "  ЗБІЙ $Name" -ForegroundColor Red }
}
function Assert-Throws {
    param([scriptblock]$Block, [string]$Pattern, [string]$Name)
    try { & $Block; Assert $false "$Name (виняток не виникло)" }
    catch { Assert ($_.Exception.Message -match $Pattern) "$Name [$($_.Exception.Message)]" }
}

# Завантажує зі скрипта лише визначення функцій (без основного коду)
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

Write-Host 'Налаштування (через -ExportSettings)'
$s = & $main -ExportSettings
Assert ($s.AuditPolicy.Count -ge 30) 'підкатегорії аудиту присутні'
$guids = @($s.AuditPolicy | ForEach-Object { $_.Guid })
Assert (($guids | Sort-Object -Unique).Count -eq $guids.Count) 'GUID аудиту унікальні'
Assert (@($guids | Where-Object { $_ -notmatch '^0CCE92[0-9A-F]{2}-69AE-11D9-BED3-505054503030$' }).Count -eq 0) 'GUID аудиту мають правильний формат'
$bad = @($s.AuditPolicy | Where-Object { foreach ($r in 'Workstation', 'Server', 'DomainController') { if ($_[$r] -lt 0 -or $_[$r] -gt 3) { $true } } })
Assert ($bad.Count -eq 0) 'значення аудиту в межах 0..3'
Assert (@($s.AuditPolicy | Where-Object { $_.Name -like 'Directory Service*' -and $_.Workstation -ne 0 }).Count -eq 0) 'DS Access лише на DC'
$names = @($s.Channels | ForEach-Object { $_.N })
Assert (($names | Sort-Object -Unique).Count -eq $names.Count) 'назви каналів унікальні'
foreach ($p in 'DomainController', 'Server', 'Workstation', 'Minimal') {
    $classes = @($s.Channels | ForEach-Object { $_.C } | Sort-Object -Unique)
    $missing = @($classes | Where-Object { -not $s.Sizes[$p].ContainsKey($_) })
    Assert ($missing.Count -eq 0) "профіль $p має всі класи розмірів"
    Assert (@($s.Sizes[$p].Values | Where-Object { $_ -gt 4096 }).Count -eq 0) "профіль ${p}: <= 4 ГБ на журнал"
}
Assert ($s.Pins.ConfigSha256 -match '^[0-9a-f]{64}$') 'закріплений хеш конфігу - це sha256'

Write-Host 'розбір CSV auditpol (локалізовані назви)'
$csv = @(
    'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
    'DC1,System,Вход в систему,{0CCE9215-69AE-11D9-BED3-505054503030},Успех и сбой,,3'
    'DC1,System,Проверка учетных данных,{0cce923f-69ae-11d9-bed3-505054503030},Успех,,1'
    'DC1,System,Option:CrashOnAuditFail,,Disabled,,0'
)
$m = ConvertFrom-AuditCsv $csv
Assert ($m.Count -eq 2) 'розібрано два рядки з GUID, рядок Option проігноровано'
Assert ($m['0CCE9215-69AE-11D9-BED3-505054503030'] -eq 3) 'Logon = 3'
Assert ($m['0CCE923F-69AE-11D9-BED3-505054503030'] -eq 1) 'GUID у нижньому регістрі нормалізовано'

Write-Host 'Запис JSON'
$od = New-OD; $od.Text = "a`"b\c`nd"; $od.Num = 5L; $od.Flag = $true; $od.Null = $null; $od.List = @(1, 'x'); $od.Empty = @()
$od.Nested = @{ K = 'v' }
$parsed = (ConvertTo-JsonString $od) | ConvertFrom-Json
Assert ($parsed.Text -eq "a`"b\c`nd") 'екранування рядків зберігається після розбору'
Assert ($parsed.Num -eq 5 -and $parsed.Flag -eq $true -and $null -eq $parsed.Null) 'скалярні значення'
Assert ($parsed.List.Count -eq 2 -and $parsed.Nested.K -eq 'v') 'масиви та вкладені словники'

Write-Host 'Планування розмірів'
$st = @(
    @{ Class = 'Security'; State = @{ Exists = $true; MaxBytes = 20MB } }
    @{ Class = 'Sysmon'; State = @{ Exists = $false; MaxBytes = 0 } }
    @{ Class = 'System'; State = @{ Exists = $true; MaxBytes = 20MB } }
)
$p = Get-SizePlan 'DomainController' $st $s 100000
Assert ($p.Profile -eq 'DomainController') 'профіль DC вміщується у 100 ГБ вільного місця'
$p = Get-SizePlan 'DomainController' $st $s 3000
Assert ($p.Profile -eq 'Workstation') 'при 3 ГБ вільного місця знижується до Workstation'
$p = Get-SizePlan 'Workstation' $st $s 100
Assert ($null -eq $p.Profile) 'немає профілю, якщо нічого не вміщується'
$st[0].State.MaxBytes = 8GB
$p = Get-SizePlan 'Server' $st $s 1000
Assert ($p.Profile -eq 'Server') 'більший наявний розмір не рахується як приріст'

Write-Host 'Пошук джерел із закріпленим хешем'
$pkg = Join-Path ([IO.Path]::GetTempPath()) ('pkg-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $pkg | Out-Null
Set-Content -LiteralPath (Join-Path $pkg 'sysmonconfig-export.xml') -Value '<Sysmon/>' -NoNewline
$h = Get-FileSha256 (Join-Path $pkg 'sysmonconfig-export.xml')
$global:SourcePath = $pkg; $global:Online = $false; $global:WorkDir = $pkg; $global:ScriptDir = $pkg; $global:DefaultPins = $s.Pins
$r = Resolve-SourceFile 'sysmonconfig-export.xml' $null $h 'cfg'
Assert ($r.Sha256 -eq $h) 'збіжний хеш прийнято'
Assert-Throws { Resolve-SourceFile 'sysmonconfig-export.xml' $null ('0' * 64) 'cfg' } 'не збігається' 'неправильний хеш відхилено'
Assert-Throws { Resolve-SourceFile 'sysmonconfig-export.xml' $null '' 'cfg' } 'немає закріпленого' 'незакріплений файл відхилено за замовчуванням'
$r = Resolve-SourceFile 'sysmonconfig-export.xml' $null '' 'cfg' -AllowUnpinned
Assert ($r.Sha256 -eq $h) 'незакріплений файл прийнято з -AllowUnpinned'
Assert-Throws { Resolve-SourceFile 'Sysmon.zip' $null 'x' 'zip' } 'не знайдено' 'відсутній файл в офлайн-пакеті'
Set-Content -LiteralPath (Join-Path $pkg 'sources.ini') -Value "SysmonZipSha256=abc`nConfigSha256=`n"
$pins = Get-Pins
Assert ($pins.SysmonZipSha256 -eq 'abc') 'sources.ini перевизначає закріплені значення'
Assert ($pins.ConfigSha256 -eq $s.Pins.ConfigSha256) 'порожнє значення в ini залишає вбудований хеш'
Remove-Item -LiteralPath $pkg -Recurse -Force

Write-Host 'Блок Wazuh'
$block = New-WazuhBlock @('Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-PowerShell/Operational')
$tmp = [IO.Path]::GetTempFileName()
Set-Content -LiteralPath $tmp -Value ("<ossec_config><localfile><location>Security</location></localfile></ossec_config>`r`n" + $block)
$loc = Get-WazuhLocations @($tmp)
Assert ($loc -contains 'security' -and $loc -contains 'microsoft-windows-sysmon/operational') 'розташування розібрано (без урахування регістру)'
Assert (([xml]("<root>$block</root>")).root.ossec_config.localfile.Count -eq 2) 'блок є коректним XML'
Remove-Item $tmp

Write-Host 'Допоміжні функції GPO'
$ext = Merge-GpoExtensionNames '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]' @(
    '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'
    '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
    '[{35378eac-683f-11d2-a89a-00c04fbbcfa2}{d02b1f72-3407-48ae-ba88-e8213c6761f1}]')
$parts = @([regex]::Matches($ext, '\[[^\]]+\]') | ForEach-Object { $_.Value })
Assert ($parts.Count -eq 4) 'дублікати розширень прибрано'
Assert (($parts -join '') -eq (($parts | Sort-Object) -join '')) 'розширення відсортовано'
Assert ($parts[0].StartsWith('[{35378EAC') -and $parts[3].StartsWith('[{F3CCC681')) 'наявний CSE безпеки збережено'
$dcCsv = New-AuditCsv $s.AuditPolicy 'DomainController'
$wsCsv = New-AuditCsv $s.AuditPolicy 'Workstation'
Assert ($dcCsv[0] -like 'Machine Name,*') 'заголовок audit.csv'
Assert (@($dcCsv | Where-Object { $_ -like '*{0cce923b-*' }).Count -eq 1 -and @($wsCsv | Where-Object { $_ -like '*{0cce923b-*' }).Count -eq 0) 'DS Access лише в audit.csv для DC'
Assert (@($dcCsv | Select-Object -Skip 1 | Where-Object { $_ -notmatch '^,System,Audit .+,\{[0-9a-f-]{36}\},(Success|Failure|Success and Failure),,[123]$' }).Count -eq 0) 'рядки audit.csv мають правильний формат'
$back = ConvertFrom-AuditCsv $dcCsv
Assert ($back['0CCE9242-69AE-11D9-BED3-505054503030'] -eq 3) 'audit.csv розбирається тим самим парсером'
$ini = New-ScriptsIni 'powershell.exe' '-File "\\corp\NETLOGON\SecLogging\Set-SecurityLogging.ps1"'
Assert ($ini -contains '[Startup]' -and $ini -contains '0CmdLine=powershell.exe') 'вміст scripts.ini'
$el = Get-EventLogPolicyValues $s.Sizes 'DomainController'
$sec = $el | Where-Object { $_.Key -like '*\Security' -and $_.Name -eq 'MaxSize' }
Assert ($sec.Value -eq 3072 * 1024) 'MaxSize журналу Security для DC у КБ'

Write-Host 'Логіка політики аудиту (auditpol підмінено)'
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
Assert ($logon -eq 3) 'Logon піднято: Успіх -> Успіх і відмова'
Assert ($global:AuditState['0CCE9224-69AE-11D9-BED3-505054503030'] -eq 3) 'File Share, вже SF, не змінено'
Assert (-not $global:AuditState.ContainsKey('0CCE923B-69AE-11D9-BED3-505054503030')) 'DS Access не встановлено на робочій станції'
Assert ($Script:Counts.Error -eq 0 -and $Script:Counts.Changed -gt 20) "зміни перевірено (змінено: $($Script:Counts.Changed))"
$setCalls = @($global:Calls | Where-Object { $_[0] -eq 'auditpol.exe' -and $_[1] -eq '/set' })
Assert (@($setCalls | Where-Object { $_[2] -notmatch '^/subcategory:\{0CCE92[0-9A-F]{2}-69AE-11D9-BED3-505054503030\}$' }).Count -eq 0) 'auditpol викликається лише з GUID'
Assert (@($setCalls | Where-Object { $_ -match 'disable' }).Count -eq 0) 'нічого не вимикає'
$global:Calls = @(); $Script:Counts = @{ OK = 0; Changed = 0; WouldChange = 0; Warning = 0; Error = 0; Skipped = 0 }
$s3 = & $main -ExportSettings
Invoke-AuditPolicy $s3 'Workstation'
Assert ($global:Calls.Count -eq 0 -and $Script:Counts.Changed -eq 0) 'повторний запуск нічого не змінює'

Write-Host 'Логіка каналів журналів (wevtutil підмінено)'
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
Assert ($global:Chan['Security'].MaxBytes -eq 20MB -and $res['Security'].Status -eq 'Warning' -and $res['Security'].Message -match 'GPO обмежує') 'обмежений GPO журнал Security показано у звіті, не змінено'
Assert ($global:Chan['System'].MaxBytes -eq 2GB -and $global:Chan['System'].Mode -eq 'Circular') 'більший журнал System збережено, режим виправлено'
$dns = $global:Chan['Microsoft-Windows-DNS-Client/Operational']
Assert ($dns.Enabled -and $dns.MaxBytes -eq 192MB) 'вимкнений канал увімкнено й задано розмір (Server/Other = 192 МБ)'
Assert ($res['Directory Service'] -eq $null) 'канали лише для DC пропущено на сервері'
Assert ($res['Microsoft-Windows-Sysmon/Operational'].Status -eq 'Skipped') 'відсутній канал пропущено'
$global:AuditOnly = $true
$before = $global:Chan['Microsoft-Windows-DNS-Client/Operational'].Clone(); $global:Chan['Microsoft-Windows-DNS-Client/Operational'].Enabled = $false
$global:Calls = @(); $Script:Counts = @{ OK = 0; Changed = 0; WouldChange = 0; Warning = 0; Error = 0; Skipped = 0 }
Invoke-Channels $s2 'Server' @{ SystemDriveFreeMB = 100000 }
Assert (@($global:Calls | Where-Object { $_[0] -eq 'wevtutil.exe' }).Count -eq 0 -and $Script:Counts.WouldChange -eq 1) 'AuditOnly нічого не викликає'
$global:AuditOnly = $false

Write-Host ''
Write-Host "Пройдено: $script:passed  Не пройдено: $script:failed"
if ($script:failed) { exit 1 }
