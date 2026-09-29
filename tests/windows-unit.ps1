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
$installer = Join-Path $root 'windows/Install-SecLogging.ps1'

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
# як справжній auditpol /backup: усі підкатегорії ОС (0), але без Group Membership - як на Server 2008 R2
$global:AuditState = @{}
foreach ($a in $s.AuditPolicy) { $global:AuditState[$a.Guid.ToUpper()] = 0 }
$global:AuditState['0CCE9215-69AE-11D9-BED3-505054503030'] = 1
$global:AuditState['0CCE9224-69AE-11D9-BED3-505054503030'] = 3
$global:AuditState.Remove('0CCE9249-69AE-11D9-BED3-505054503030')
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
Assert ($global:AuditState['0CCE923B-69AE-11D9-BED3-505054503030'] -eq 0) 'DS Access не встановлено на робочій станції'
Assert (-not $global:AuditState.ContainsKey('0CCE9249-69AE-11D9-BED3-505054503030') -and @($Script:Report | Where-Object { $_.Item -eq 'Group Membership' -and $_.Status -eq 'Skipped' }).Count -eq 1) 'непідтримувана ОС підкатегорія пропущена, auditpol для неї не викликано'
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

Write-Host 'Sysmon для старих ОС з репозиторію (vendor)'
foreach ($lv in '10.42', '10.2') {
    $lk = Get-LegacyKey $lv
    $vz = Join-Path $root "vendor/sysmon/$lv/Sysmon.zip"
    Assert (Test-Path -LiteralPath $vz) "vendor/sysmon/$lv/Sysmon.zip існує"
    Assert ((Get-FileSha256 $vz) -eq $s.Pins["${lk}ZipSha256"]) "${lv}: хеш vendor-архіву збігається із закріпленим"
    Assert ($s.Pins["${lk}ZipUrl"] -like "*/vendor/sysmon/$lv/Sysmon.zip") "${lv}: URL вказує на vendor"
    Assert ($s.Pins["${lk}ConfigSha256"] -match '^[0-9a-f]{64}$') "${lv}: хеш конфігу закріплено"
}
Assert ($s.Pins.Legacy1042ConfigUrl -like '*c00581f8*' -and $s.Pins.Legacy102ConfigUrl -like '*9fb44e98*') 'конфіги: 10.42 -> схема 4.22, 10.2 -> схема 4.00'
Assert ((Get-LegacyKey '10.42') -eq 'Legacy1042' -and (Get-LegacyKey '10.2') -eq 'Legacy102') 'ключі legacy-версій'
$vendorZip = Join-Path $root 'vendor/sysmon/10.42/Sysmon.zip'

Write-Host 'Install-SecLogging: допоміжні функції'
Import-ScriptFunctions $installer
Assert ((Get-ArchiveUrl 'egwyl666' 'sec_journal_on' 'HEAD') -eq 'https://github.com/egwyl666/sec_journal_on/archive/HEAD.zip') 'URL архіву репозиторію'
$a = Add-SwitchArgs @('-SourcePath', 'X') @{ AuditOnly = [switch]$true; SkipSysmon = [switch]$false; TranscriptionPath = ''; LinkTargets = @('OU=A,DC=c,DC=l', 'OU=B,DC=c,DC=l') } @('AuditOnly', 'SkipSysmon', 'TranscriptionPath', 'LinkTargets')
Assert (($a -join ' ') -eq '-SourcePath X -AuditOnly -LinkTargets OU=A,DC=c,DC=l;OU=B,DC=c,DC=l') 'аргументи: лише увімкнені перемикачі, DN через ";"'
$tmpRoot = Join-Path ([IO.Path]::GetTempPath()) ('src-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path (Join-Path $tmpRoot 'sec_journal_on-HEAD/windows') -Force | Out-Null
Set-Content -LiteralPath (Join-Path $tmpRoot 'sec_journal_on-HEAD/windows/Set-SecurityLogging.ps1') -Value '#'
Assert ((Find-SourceRoot $tmpRoot) -eq (Join-Path $tmpRoot 'sec_journal_on-HEAD')) 'корінь розпакованого архіву знайдено'
Remove-Item -LiteralPath $tmpRoot -Recurse -Force
$pkg2 = Join-Path ([IO.Path]::GetTempPath()) ('pkg2-' + [guid]::NewGuid())
foreach ($lv in '10.42', '10.2') { New-Item -ItemType Directory -Path (Join-Path $pkg2 "legacy/$lv") -Force | Out-Null }
Set-Content -LiteralPath (Join-Path $pkg2 'Set-SecurityLogging.ps1') -Value '#'
foreach ($f in 'Sysmon.zip', 'sysmonconfig-export.xml', 'legacy/10.42/sysmonconfig-export.xml', 'legacy/10.2/sysmonconfig-export.xml') { Set-Content -LiteralPath (Join-Path $pkg2 $f) -Value $f -NoNewline }
foreach ($lv in '10.42', '10.2') { Copy-Item -LiteralPath (Join-Path $root "vendor/sysmon/$lv/Sysmon.zip") -Destination (Join-Path $pkg2 "legacy/$lv/Sysmon.zip") }
$ini2 = @(
    "SysmonZipSha256=$(Get-FileSha256 (Join-Path $pkg2 'Sysmon.zip'))"
    "ConfigSha256=$(Get-FileSha256 (Join-Path $pkg2 'sysmonconfig-export.xml'))"
    "Legacy1042ZipSha256=$($s.Pins.Legacy1042ZipSha256)"
    "Legacy1042ConfigSha256=$(Get-FileSha256 (Join-Path $pkg2 'legacy/10.42/sysmonconfig-export.xml'))"
    "Legacy102ZipSha256=$($s.Pins.Legacy102ZipSha256)"
    "Legacy102ConfigSha256=$(Get-FileSha256 (Join-Path $pkg2 'legacy/10.2/sysmonconfig-export.xml'))"
)
Set-Content -LiteralPath (Join-Path $pkg2 'sources.ini') -Value $ini2
$t = Test-Package $pkg2 $true
Assert ($t.Ok) "коректний пакет приймається [$($t.Problems -join '; ')]"
Add-Content -LiteralPath (Join-Path $pkg2 'legacy/10.2/Sysmon.zip') -Value 'x'
$t = Test-Package $pkg2 $true
Assert ((-not $t.Ok) -and ($t.Problems -join ' ') -match '10\.2.Sysmon.zip: SHA256') 'змінений legacy\10.2\Sysmon.zip виявлено'
Remove-Item -LiteralPath (Join-Path $pkg2 'legacy/10.42/Sysmon.zip')
$t = Test-Package $pkg2 $true
Assert (($t.Problems -join ' ') -match 'немає legacy.10\.42.Sysmon.zip') 'відсутній legacy\10.42\Sysmon.zip виявлено'
Remove-Item -LiteralPath $pkg2 -Recurse -Force

Write-Host 'Запуск дочірніх процесів і стендовий скрипт'
Assert ((ConvertTo-ArgumentString @('-File', 'C:\Program Files\x.ps1', '-SharePath', 'C:\SecLab', '-Empty', '')) -eq '-File "C:\Program Files\x.ps1" -SharePath C:\SecLab -Empty ""') 'аргументи з пробілами і порожні - в лапках'
foreach ($lv in '10.42', '10.2') {
    $lk = Get-LegacyKey $lv
    Assert ((Get-FileSha256 (Join-Path $root "vendor/sysmon-config/$lv/sysmonconfig-export.xml")) -eq $s.Pins["${lk}ConfigSha256"]) "${lv}: хеш конфігу у vendor збігається із закріпленим"
}
Import-ScriptFunctions (Join-Path $root 'windows/lab/Test-LegacySysmon.ps1')
$lp = Join-Path ([IO.Path]::GetTempPath()) ('labpkg-' + [guid]::NewGuid())
$null = New-LocalPackage $root $lp
foreach ($lv in '10.42', '10.2') {
    $lk = Get-LegacyKey $lv
    Assert ((Get-FileSha256 (Join-Path $lp "legacy/$lv/Sysmon.zip")) -eq $s.Pins["${lk}ZipSha256"]) "${lv}: локальний пакет - Sysmon.zip з правильним хешем"
    Assert ((Get-FileSha256 (Join-Path $lp "legacy/$lv/sysmonconfig-export.xml")) -eq $s.Pins["${lk}ConfigSha256"]) "${lv}: локальний пакет - конфіг з правильним хешем"
}
Assert (Test-Path -LiteralPath (Join-Path $lp 'Set-SecurityLogging.ps1')) 'локальний пакет містить Set-SecurityLogging.ps1'
Remove-Item -LiteralPath $lp -Recurse -Force
Assert ((Get-KbNumber 'windows6.1-kb4474419-v3-x64_b5614c6cea5cb4e198717789633dca16308ef79c.msu') -eq 'KB4474419') 'номер KB з імені .msu'

Write-Host 'PowerShell 2.0 / Server 2008 R2: запасні шляхи'
$al = New-Object System.Collections.ArrayList
[void]$al.Add('a'); [void]$al.Add($al)
$j = ConvertTo-JsonString $al
Assert ($j -match '"a"') 'колекція, що містить сама себе, не призводить до переповнення стеку'
$deep = @{}; $cur = $deep; for ($i = 0; $i -lt 60; $i++) { $cur.n = @{}; $cur = $cur.n }
Assert ((ConvertTo-JsonString $deep).Length -gt 0) 'глибока вкладеність обмежується'
$mix = New-OD; $mix.I16 = [int16]5; $mix.B = [byte]7; $mix.F = [single]1.5; $mix.P = [psobject]'текст'; $mix.D = [datetime]'2026-01-02T03:04:05'; $mix.E = [ConsoleColor]::Red
$pj = (ConvertTo-JsonString $mix) | ConvertFrom-Json
Assert ($pj.I16 -eq 5 -and $pj.B -eq 7 -and $pj.F -eq 1.5 -and $pj.P -eq 'текст' -and $pj.E -eq 'Red') 'int16/byte/single/PSObject/enum серіалізуються коректно'
$chXml = '<?xml version="1.0" encoding="UTF-8"?><channel name="Security" enabled="true" type="Admin" isolation="Custom"><logging><logFileName>%SystemRoot%\System32\Winevt\Logs\Security.evtx</logFileName><retention>false</retention><autoBackup>true</autoBackup><maxSize>20971520</maxSize></logging><publishing><fileMax>1</fileMax></publishing></channel>'
$cx = ConvertFrom-ChannelXml $chXml
Assert ($cx.Exists -and $cx.Enabled -and $cx.MaxBytes -eq 20971520 -and $cx.Mode -eq 'AutoBackup') 'розбір wevtutil gl /f:xml (без .NET 3.5)'
$cx2 = ConvertFrom-ChannelXml '<channel name="X" enabled="false"><logging><retention>false</retention><autoBackup>false</autoBackup><maxSize>1052672</maxSize></logging></channel>'
Assert ((-not $cx2.Enabled) -and $cx2.Mode -eq 'Circular' -and $cx2.MaxBytes -eq 1052672) 'вимкнений канал, режим Circular'
Import-ScriptFunctions (Join-Path $root 'windows/lab/Test-LegacySysmon.ps1')
$evXml = @(
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f}'/><EventID>1</EventID><TimeCreated SystemTime='2026-09-29T10:00:00.000Z'/></System></Event>"
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-WER-SystemErrorReporting'/><EventID Qualifiers='16384'>1001</EventID><TimeCreated SystemTime='2026-09-29T11:00:00.000Z'/></System></Event>"
)
$ev = @(ConvertFrom-EventXml $evXml)
Assert ($ev.Count -eq 2 -and $ev[0].Id -eq 1 -and $ev[1].Id -eq 1001 -and $ev[1].Provider -like '*SystemErrorReporting' -and $ev[1].Time -like '2026-09-29T11*') 'розбір wevtutil qe /f:xml (EventID з Qualifiers, провайдер, час)'
Assert ((ConvertTo-ConsoleText 'Підсумок: OK, звіт Їжак' -Force) -eq 'Pidsumok: OK, zvit Yizhak') 'транслітерація для консолі без кирилиці'
Assert ((ConvertTo-ConsoleText 'Підсумок') -eq 'Підсумок') 'без потреби текст не змінюється'

Write-Host 'Wazuh agent.conf відповідає списку каналів'
$std = @('Security', 'System', 'Application')
foreach ($g in @(@{ File = 'windows'; Dc = $false }, @{ File = 'windows-dc'; Dc = $true })) {
    $want = @($s.Channels | Where-Object { [bool]$_.DC -eq $g.Dc -and -not $_.NoWazuh -and $std -notcontains $_.N } | ForEach-Object { $_.N })
    $have = @(([xml]('<r>' + (Get-Content -Raw (Join-Path $root "wazuh/shared/$($g.File)/agent.conf") -Encoding UTF8) + '</r>')).r.agent_config.localfile | ForEach-Object { $_.location })
    Assert ((($want -join '|') -eq ($have -join '|'))) "wazuh/shared/$($g.File)/agent.conf: ті самі канали й порядок [$(@(Compare-Object $want $have | ForEach-Object { $_.InputObject }) -join ', ')]"
}
Assert (@($s.AuditPolicy | Where-Object { $_.Guid -like '0CCE9221-*' -and $_.Workstation -eq 0 -and $_.DomainController -eq 3 }).Count -eq 1) 'аудит Certification Services (AD CS) на серверах і DC'

Write-Host 'Start-SecLogging: одна команда для будь-якої машини'
$start = Join-Path $root 'windows/Start-SecLogging.ps1'
$tok = $null; $err = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($start, [ref]$tok, [ref]$err)
Assert ($err.Count -eq 0) 'Start-SecLogging.ps1 без синтаксичних помилок'
$sbText = [System.IO.File]::ReadAllText($start, [System.Text.Encoding]::UTF8).TrimStart([char]0xFEFF)
Assert ($null -ne [scriptblock]::Create($sbText)) 'створюється як scriptblock (як в однорядковій команді)'
Import-ScriptFunctions $start
$p = Get-StartPlan 1 ([version]'10.0.22631') $false $false $false $false '10.42'
Assert ($p.Role -eq 'Workstation' -and -not $p.Gpo -and ($p.Local -join ' ') -eq '-Mode Local -ConfigureWazuh') 'Win10/11: лише локально, Sysmon сучасний'
$p = Get-StartPlan 3 ([version]'6.1.7601') $false $false $false $false '10.42'
Assert ($p.Legacy -and ($p.Local -join ' ') -eq '-Mode Local -AllowLegacySysmon -LegacySysmonVersion 10.42 -ConfigureWazuh' -and -not $p.Gpo) '2008 R2: Sysmon 10.42 для старих ОС'
$p = Get-StartPlan 3 ([version]'6.1.7601') $false $false $false $true '10.42'
Assert (($p.Local -join ' ') -eq '-Mode Local -SkipSysmon -ConfigureWazuh') '2008 R2 з -NoLegacySysmon: без Sysmon'
$p = Get-StartPlan 2 ([version]'10.0.20348') $false $false $false $false '10.2'
Assert ($p.Role -eq 'DomainController' -and ($p.Gpo -join ' ') -eq '-Mode Domain -NoBuild -SetDomainRootSacl -AllowLegacySysmon -LegacySysmonVersion 10.2') 'DC: локально + GPO + SACL для DCSync'
$p = Get-StartPlan 2 ([version]'10.0.20348') $true $false $false $false '10.42'
Assert (($p.Local -contains '-AuditOnly') -and ($p.Gpo -contains '-WhatIfGpo')) 'DC -AuditOnly: нічого не змінює, GPO лише -WhatIf'
Assert ($null -eq (Get-StartPlan 2 ([version]'10.0.20348') $false $false $true $false '10.42').Gpo) 'DC -NoGpo: без GPO'
Assert ((ConvertTo-ArgLine @('-File', 'C:\Program Files\x.ps1', '-Snapshot', 'C:\ProgramData\SecLogging\a.tsv')) -eq '-File "C:\Program Files\x.ps1" -Snapshot C:\ProgramData\SecLogging\a.tsv') 'аргументи дочірнього процесу з пробілами - у лапках'

Write-Host 'Знімки стану "до / після"'
Import-ScriptFunctions $main
$before = @('# SecLogging знімок стану; PC1', "# Область`tЕлемент`tЗначення",
    "AuditPolicy`tLogon`tУспіх", "AuditPolicy`tProcess Creation`tБез аудиту",
    "EventLog`tSecurity`tувімкнено=True; розмір=20 МБ; режим=Circular",
    "Registry`tSOFTWARE\x\EnableScriptBlockLogging`t(не задано)", "Sysmon`tСлужба`tне встановлено", "Wazuh`tsecurity`tзбирається")
$after = @('# SecLogging знімок стану; PC1', "# Область`tЕлемент`tЗначення",
    "AuditPolicy`tLogon`tУспіх і відмова", "AuditPolicy`tProcess Creation`tУспіх",
    "EventLog`tSecurity`tувімкнено=True; розмір=768 МБ; режим=Circular",
    "Registry`tSOFTWARE\x\EnableScriptBlockLogging`t1", "Sysmon`tСлужба`tSysmon64 (Running)", "Sysmon`tВерсія`t15.15",
    "Wazuh`tsecurity`tзбирається", "Wazuh`tmicrosoft-windows-sysmon/operational`tзбирається")
$ch = @(Compare-StateSnapshot $before $after)
$byItem = @{}; foreach ($c in $ch) { $byItem[$c.Item] = $c }
Assert ($ch.Count -eq 7) "знайдено 7 змін, незмінене пропущено ($($ch.Count))"
Assert ($byItem['Logon'].Before -eq 'Успіх' -and $byItem['Logon'].After -eq 'Успіх і відмова') 'аудит: було -> стало'
Assert ($byItem['Security'].After -like '*768 МБ*') 'розмір журналу'
Assert ($byItem['Версія'].Before -eq '(не було)' -and $byItem['microsoft-windows-sysmon/operational'].Before -eq '(не було)') 'нові елементи позначено "(не було)"'
Assert (@($ch | Where-Object { $_.Area -eq 'Wazuh' -and $_.Item -eq 'security' }).Count -eq 0) 'незмінений рядок не потрапляє у звіт'
Assert (@(Compare-StateSnapshot $after $after).Count -eq 0) 'однакові знімки - змін немає'
$tb = [IO.Path]::GetTempFileName(); $ta = [IO.Path]::GetTempFileName(); $to = Join-Path ([IO.Path]::GetTempPath()) ('changes-' + [guid]::NewGuid() + '.txt')
[IO.File]::WriteAllLines($tb, [string[]]$before); [IO.File]::WriteAllLines($ta, [string[]]$after)
$n = Write-StateComparison $tb $ta $to 6>$null
$txt = [IO.File]::ReadAllText($to); $csvText = [IO.File]::ReadAllText([IO.Path]::ChangeExtension($to, '.csv'))
Assert ($n -eq 7 -and $txt -match 'Змін: 7' -and $txt -match 'було:  Успіх' -and $csvText -match '^\W*Область;Елемент;Було;Стало') 'звіт .txt і .csv записано'
Remove-Item $tb, $ta, $to, ([IO.Path]::ChangeExtension($to, '.csv')) -Force

Write-Host ''
Write-Host "Пройдено: $script:passed  Не пройдено: $script:failed"
if ($script:failed) { exit 1 }
