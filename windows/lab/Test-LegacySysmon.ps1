#Requires -Version 2.0
<#
.SYNOPSIS
    Стендова перевірка Sysmon для старих ОС (Windows 7 / Server 2008 / 2008 R2): одна команда у VM.

.DESCRIPTION
    Два способи запуску:
      а) з мережевої шари, підготовленої на хості командою
         Install-SecLogging.ps1 -Mode Share -SharePath <тека> (оновлення й результати - на шарі);
      б) прямо з розпакованого ZIP репозиторію у VM, наприклад
         C:\SecLab\sec_journal_on-<коміт>\windows\lab\Test-LegacySysmon.ps1 - пакет збирається
         локально з vendor\ (без мережі), оновлення беруться з C:\SecLab\updates, результати -
         у C:\SecLab\results (тобто в теці, куди розпаковано ZIP).
    Кроки:

      1. Оновлення: встановлює всі *.msu з <шара>\updates (за іменем файлу, пропускаючи вже
         встановлені). Якщо потрібне перезавантаження - зупиняється й просить перезапустити.
      2. Перевіряє оновлення SHA-2 (KB4474419, KB4490628), без яких драйвер Sysmon не завантажиться.
      3. Set-SecurityLogging.ps1 -AllowLegacySysmon -LegacySysmonVersion <версія> -ReinstallSysmon
         (перехід між 10.42 і 10.2 - автоматично).
      4. Генерує трохи активності, рахує події Sysmon, зберігає конфіг і стан служби.
      5. Складає результати в <шара>\results\<комп'ютер>-sysmon<версія>-<час>\ (або локально).

    -CollectOnly: лише зібрати стан і пошукати BSOD / аварійні перезавантаження
    (події 1001 BugCheck, 41 Kernel-Power, 6008) з моменту встановлення - запускати після
    перезавантаження та через добу роботи.

.PARAMETER Share
    Тека або UNC-шлях пакета. За замовчуванням - тека, де лежить цей скрипт, або її батьківська,
    або (запуск з репозиторію) локальний пакет, зібраний з vendor\.

.PARAMETER SysmonVersion
    10.42 (за замовчуванням) або 10.2.

.PARAMETER ObserveSeconds
    Скільки секунд збирати події після встановлення. За замовчуванням 60.

.PARAMETER Force
    Продовжити, навіть якщо оновлень SHA-2 не знайдено.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File \\192.168.80.1\SecLab\lab\Test-LegacySysmon.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File \\192.168.80.1\SecLab\lab\Test-LegacySysmon.ps1 -SysmonVersion 10.2
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File \\192.168.80.1\SecLab\lab\Test-LegacySysmon.ps1 -CollectOnly
.EXAMPLE
    # з розпакованого ZIP репозиторію у VM
    powershell -ExecutionPolicy Bypass -File C:\SecLab\sec_journal_on-HEAD\windows\lab\Test-LegacySysmon.ps1
#>
[CmdletBinding()]
param(
    [string]$Share,
    [ValidateSet('10.42', '10.2')]
    [string]$SysmonVersion = '10.42',
    [int]$ObserveSeconds = 60,
    [switch]$CollectOnly,
    [switch]$SkipUpdates,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = $null
$WorkRoot = $null
if (-not $Share) {
    # пакет (шара) має теку legacy\ поруч зі Set-SecurityLogging.ps1; репозиторій - теку vendor\
    $parent = Split-Path -Parent $here
    $candidate = Split-Path -Parent $parent
    if (Test-Path -LiteralPath (Join-Path $here 'legacy')) { $Share = $here }
    elseif (Test-Path -LiteralPath (Join-Path $parent 'legacy')) { $Share = $parent }
    elseif (Test-Path -LiteralPath (Join-Path $candidate 'vendor\sysmon')) { $RepoRoot = $candidate }   # <корінь>\windows\lab\
}
$StateKey = 'SOFTWARE\SecLogging\Lab'

function Write-Step { param([string]$Text) Write-Host ''; Write-Host "==> $Text" -ForegroundColor Cyan }

function Get-RegValue {
    param([string]$Name)
    $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($StateKey)
    if (-not $k) { return $null }
    try { $k.GetValue($Name, $null) } finally { $k.Close() }
}

function Set-RegValue {
    param([string]$Name, [string]$Value)
    $k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($StateKey)
    try { $k.SetValue($Name, $Value) } finally { $k.Close() }
}

function Get-KbNumber {
    # 'windows6.1-kb4474419-v3-x64_....msu' -> 'KB4474419'
    param([string]$FileName)
    if ($FileName -match '(?i)kb(\d{6,7})') { return ('KB' + $Matches[1]) }
    $null
}

function Test-HotFix {
    param([string]$Kb)
    [bool](Get-HotFix -Id $Kb -ErrorAction SilentlyContinue)
}

function New-LocalPackage {
    # Збирає пакет для старих ОС з репозиторію: скрипт + vendor\sysmon\<версія> + vendor\sysmon-config\<версія>.
    # Хеші потім перевіряє Set-SecurityLogging.ps1 за вбудованими закріпленими значеннями.
    param([string]$Repo, [string]$Destination)
    foreach ($lv in @('10.42', '10.2')) {
        $d = Join-Path $Destination (Join-Path 'legacy' $lv)
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $Repo (Join-Path 'vendor' (Join-Path 'sysmon' (Join-Path $lv 'Sysmon.zip')))) -Destination $d -Force
        Copy-Item -LiteralPath (Join-Path $Repo (Join-Path 'vendor' (Join-Path 'sysmon-config' (Join-Path $lv 'sysmonconfig-export.xml')))) -Destination $d -Force
    }
    Copy-Item -LiteralPath (Join-Path $Repo (Join-Path 'windows' 'Set-SecurityLogging.ps1')) -Destination $Destination -Force
    $Destination
}

function Get-SysmonService {
    foreach ($n in @('Sysmon64', 'Sysmon')) {
        $s = Get-WmiObject Win32_Service -Filter "Name='$n'"
        if ($s) { return $s }
    }
    $null
}

function Save-Results {
    param([string]$Tag, [string[]]$Summary)
    $name = '{0}-{1}-{2:yyyyMMdd-HHmmss}' -f $env:COMPUTERNAME, $Tag, (Get-Date)
    $dir = $null
    foreach ($base in @((Join-Path $WorkRoot 'results'), (Join-Path $env:ProgramData 'SecLogging\lab-results'))) {
        try { New-Item -ItemType Directory -Path (Join-Path $base $name) -Force | Out-Null; $dir = Join-Path $base $name; break }
        catch { Write-Host "    не вдалося записати в $base, пробуємо локально" -ForegroundColor Yellow }
    }
    $Summary | Set-Content -LiteralPath (Join-Path $dir 'summary.txt') -Encoding UTF8
    $last = Join-Path $env:ProgramData 'SecLogging\last-report.json'
    if (Test-Path -LiteralPath $last) { Copy-Item -LiteralPath $last -Destination (Join-Path $dir 'last-report.json') }
    $svc = Get-SysmonService
    if ($svc) {
        $exe = ([string]$svc.PathName).Trim('"')
        $out = & $exe -c 2>&1 | ForEach-Object { [string]$_ }
        $out | Set-Content -LiteralPath (Join-Path $dir 'sysmon-config.txt') -Encoding UTF8
    }
    Get-HotFix | Sort-Object HotFixID | ForEach-Object { '{0}  {1}' -f $_.HotFixID, $_.InstalledOn } | Set-Content -LiteralPath (Join-Path $dir 'hotfixes.txt') -Encoding UTF8
    $dir
}

function Get-CrashEvents {
    param([datetime]$Since)
    $found = @()
    $filters = @(
        @{ LogName = 'System'; Id = 1001; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting' }
        @{ LogName = 'System'; Id = 41; ProviderName = 'Microsoft-Windows-Kernel-Power' }
        @{ LogName = 'System'; Id = 6008 }
    )
    foreach ($f in $filters) {
        $f.StartTime = $Since
        try { $found += @(Get-WinEvent -FilterHashtable $f -ErrorAction Stop) } catch { Write-Verbose 'подій не знайдено' }
    }
    $found
}

#region ---------------------------------------------------------------- основна частина

$p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Host 'Запустіть від імені адміністратора.' -ForegroundColor Red; exit 3 }
$os = Get-WmiObject Win32_OperatingSystem
Write-Host ("Test-LegacySysmon  {0} ({1}), PS {2}" -f $os.Caption, $os.Version, $PSVersionTable.PSVersion) -ForegroundColor White
if ($RepoRoot) {
    # з репозиторію: пакет збирається локально, робоча тека - та, куди розпаковано ZIP
    $WorkRoot = Split-Path -Parent $RepoRoot
    $Share = New-LocalPackage $RepoRoot (Join-Path $env:ProgramData 'SecLogging\lab-package')
    Write-Host "Запуск з репозиторію $RepoRoot; локальний пакет: $Share; робоча тека: $WorkRoot"
}
if (-not $Share -or -not (Test-Path -LiteralPath (Join-Path $Share 'Set-SecurityLogging.ps1'))) { Write-Host "Не знайдено Set-SecurityLogging.ps1 (шара: $Share) - перевірте шлях." -ForegroundColor Red; exit 2 }
if (-not $WorkRoot) { $WorkRoot = $Share }

$summary = @("Комп'ютер: $env:COMPUTERNAME", "ОС: $($os.Caption) $($os.Version) SP$($os.ServicePackMajorVersion)", "Час: $(Get-Date -Format s)")

if ($CollectOnly) {
    Write-Step 'Збір стану та пошук аварій'
    $since = Get-RegValue 'InstalledAt'
    if ($since) { $since = [datetime]$since } else { $since = (Get-Date).AddDays(-7) }
    $crashes = @(Get-CrashEvents $since)
    $svc = Get-SysmonService
    $summary += "Sysmon: $(if ($svc) { '{0} {1}' -f $svc.Name, $svc.State } else { 'не встановлено' })"
    $summary += "Встановлена версія (за записом стенду): $(Get-RegValue 'Version')"
    $summary += "Аварійних подій з $($since.ToString('s')): $($crashes.Count)"
    foreach ($c in $crashes) { $summary += ('  {0} id={1} {2}' -f $c.TimeCreated.ToString('s'), $c.Id, (([string]$c.Message) -split "`n")[0]) }
    $dir = Save-Results ('collect-sysmon' + (Get-RegValue 'Version')) $summary
    $summary | ForEach-Object { Write-Host "    $_" }
    Write-Host "Результати: $dir" -ForegroundColor Green
    if ($crashes.Count) { exit 1 } else { exit 0 }
}

# ---- 1. оновлення
if (-not $SkipUpdates) {
    Write-Step 'Оновлення з updates\'
    $updDir = Join-Path $WorkRoot 'updates'
    $needReboot = $false
    $msus = @()
    if (Test-Path -LiteralPath $updDir) { $msus = @(Get-ChildItem -LiteralPath $updDir -Filter '*.msu' | Sort-Object Name) }
    if ($msus.Count -eq 0) { Write-Host '    теки updates немає або вона порожня - пропускаємо' }
    foreach ($m in $msus) {
        $kb = Get-KbNumber $m.Name
        if ($kb -and (Test-HotFix $kb)) { Write-Host "    $kb уже встановлено"; continue }
        Write-Host "    встановлення $($m.Name) ..."
        $proc = Start-Process -FilePath 'wusa.exe' -ArgumentList @("`"$($m.FullName)`"", '/quiet', '/norestart') -Wait -PassThru
        switch ($proc.ExitCode) {
            0 { Write-Host '      OK' }
            3010 { Write-Host '      OK, потрібне перезавантаження'; $needReboot = $true }
            2359302 { Write-Host '      уже встановлено' }
            -2145124329 { Write-Host '      не підходить для цієї системи (пропущено)' -ForegroundColor Yellow }
            default { Write-Host "      код $($proc.ExitCode) - дивіться %windir%\Logs\CBS\CBS.log" -ForegroundColor Yellow }
        }
    }
    if ($needReboot) {
        Write-Host ''
        Write-Host 'Перезавантажте VM і запустіть цю саму команду ще раз.' -ForegroundColor Yellow
        exit 10
    }
}

# ---- 2. SHA-2
Write-Step 'Підтримка SHA-2 (потрібна драйверу Sysmon)'
$missing = @()
foreach ($kb in @('KB4474419', 'KB4490628')) { if (Test-HotFix $kb) { Write-Host "    ${kb}: OK" } else { $missing += $kb } }
if ($missing.Count) {
    Write-Host ("    не знайдено: {0}" -f ($missing -join ', ')) -ForegroundColor Yellow
    Write-Host "    Покладіть .msu з Microsoft Update Catalog (x64, Windows Server 2008 R2) у $(Join-Path $WorkRoot 'updates')"
    if (-not $Force) { Write-Host '    Зупинка. Щоб продовжити без них: -Force' -ForegroundColor Yellow; exit 4 }
}

# ---- 3. Sysmon
Write-Step "Встановлення Sysmon $SysmonVersion"
$before = Get-SysmonService
$started = Get-Date
$ps = Join-Path $PSHOME 'powershell.exe'
& $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Share 'Set-SecurityLogging.ps1') -SourcePath $Share -AllowLegacySysmon -LegacySysmonVersion $SysmonVersion -ReinstallSysmon -Quiet
$code = $LASTEXITCODE
Set-RegValue 'InstalledAt' ($started.ToString('s'))
Set-RegValue 'Version' $SysmonVersion
$summary += "Set-SecurityLogging: код виходу $code"
$summary += "Sysmon до: $(if ($before) { '{0} {1}' -f $before.Name, $before.State } else { 'не встановлено' })"

# ---- 4. спостереження
Write-Step "Спостереження $ObserveSeconds с"
$svc = Get-SysmonService
$summary += "Sysmon після: $(if ($svc) { '{0} {1}' -f $svc.Name, $svc.State } else { 'не встановлено' })"
if ($svc -and $svc.State -eq 'Running') {
    $exe = ([string]$svc.PathName).Trim('"')
    $summary += "Файл служби: $exe v$((Get-Item -LiteralPath $exe).VersionInfo.FileVersion)"
    $end = (Get-Date).AddSeconds($ObserveSeconds)
    while ((Get-Date) -lt $end) {
        # трохи активності, щоб побачити події 1/3/5/11
        cmd.exe /c "whoami > nul & ipconfig > nul & ping -n 2 127.0.0.1 > nul" | Out-Null
        Set-Content -LiteralPath (Join-Path $env:TEMP 'seclab-test.txt') -Value (Get-Date)
        Start-Sleep -Seconds 5
    }
    $events = @()
    try { $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; StartTime = $started } -ErrorAction Stop) }
    catch { Write-Host "    подій не прочитано: $($_.Exception.Message)" -ForegroundColor Yellow }
    $summary += "Подій Sysmon з моменту встановлення: $($events.Count)"
    foreach ($g in ($events | Group-Object Id | Sort-Object { [int]$_.Name })) { $summary += ('  EventID {0}: {1}' -f $g.Name, $g.Count) }
    $drv = Get-WmiObject Win32_SystemDriver -Filter "Name='SysmonDrv'"
    $summary += "Драйвер SysmonDrv: $(if ($drv) { $drv.State } else { 'не знайдено' })"
}
else {
    $summary += 'Служба Sysmon не працює - дивіться last-report.json і журнал System'
}

# ---- 5. результати
Write-Step 'Результати'
$dir = Save-Results ('sysmon' + $SysmonVersion) $summary
$summary | ForEach-Object { Write-Host "    $_" }
Write-Host ''
Write-Host "Збережено: $dir" -ForegroundColor Green
Write-Host 'Далі: перезавантажте VM, дайте попрацювати, потім запустіть з -CollectOnly (пошук BSOD / аварійних перезавантажень).'
exit $code

#endregion
