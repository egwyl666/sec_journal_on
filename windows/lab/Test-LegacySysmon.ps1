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

#region ---------------------------------------------------------------- вивід у консоль
# PowerShell 2.0 в англійській Windows виводить кирилицю як "????" (кодова сторінка консолі 437).
# Тоді текст для консолі транслітерується латиницею; JSON-звіт і журнал подій лишаються українською.

$Script:NeedTranslit = $false
if ($PSVersionTable.PSVersion.Major -lt 3) {
    try {
        $probe = [string][char]0x0456 + [char]0x0457 + [char]0x0454 + [char]0x0436
        $enc = [Console]::OutputEncoding
        $Script:NeedTranslit = ($enc.GetString($enc.GetBytes($probe)) -ne $probe)
    }
    catch { $Script:NeedTranslit = $false }
}

function Get-TranslitMap {
    if ($Script:TranslitMap) { return $Script:TranslitMap }
    $map = New-Object System.Collections.Hashtable ([System.StringComparer]::Ordinal)
    foreach ($pair in ('А=A Б=B В=V Г=H Ґ=G Д=D Е=E Є=Ye Ж=Zh З=Z И=Y І=I Ї=Yi Й=Y К=K Л=L М=M Н=N О=O П=P Р=R С=S Т=T У=U Ф=F Х=Kh Ц=Ts Ч=Ch Ш=Sh Щ=Shch Ь= Ю=Yu Я=Ya Ё=Yo Ы=Y Э=E Ъ=' -split ' ')) {
        $kv = $pair.Split('=')
        $map[$kv[0]] = $kv[1]
        $map[$kv[0].ToLower()] = $kv[1].ToLower()
    }
    $map[[string][char]0x02BC] = "'"
    $Script:TranslitMap = $map
    $map
}

function ConvertTo-ConsoleText {
    param([string]$Text, [switch]$Force)
    if ((-not $Script:NeedTranslit -and -not $Force) -or -not $Text) { return $Text }
    $map = Get-TranslitMap
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.ToCharArray()) {
        $k = [string]$ch
        if ($map.ContainsKey($k)) { [void]$sb.Append($map[$k]) } else { [void]$sb.Append($ch) }
    }
    $sb.ToString()
}

function Write-Host {
    # Заміна Write-Host у межах скрипта: транслітерація за потреби; вивід через $Host.UI (без рекурсії)
    param([Parameter(Position = 0, ValueFromRemainingArguments = $true)]$Object, [ConsoleColor]$ForegroundColor, [switch]$NoNewline)
    $text = ConvertTo-ConsoleText ((@($Object) | ForEach-Object { [string]$_ }) -join ' ')
    if ($PSBoundParameters.ContainsKey('ForegroundColor')) {
        if ($NoNewline) { $Host.UI.Write($ForegroundColor, $Host.UI.RawUI.BackgroundColor, $text) }
        else { $Host.UI.WriteLine($ForegroundColor, $Host.UI.RawUI.BackgroundColor, $text) }
    }
    elseif ($NoNewline) { $Host.UI.Write($text) }
    else { $Host.UI.WriteLine($text) }
}

#endregion

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
        $out = Invoke-Quiet $exe @('-c')
        $out | Set-Content -LiteralPath (Join-Path $dir 'sysmon-config.txt') -Encoding UTF8
    }
    Get-HotFix | Sort-Object HotFixID | ForEach-Object { '{0}  {1}' -f $_.HotFixID, $_.InstalledOn } | Set-Content -LiteralPath (Join-Path $dir 'hotfixes.txt') -Encoding UTF8
    $dir
}

function Invoke-Quiet {
    # Запуск зовнішньої програми: stderr не стає винятком (ErrorActionPreference=Stop), вивід - рядками
    param([string]$FilePath, [string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    @(& $FilePath @Arguments 2>&1 | ForEach-Object { [string]$_ })
}

function Get-DriverState {
    # Стан драйвера через sc.exe (WMI Win32_SystemDriver на 2008 R2 його не завжди показує).
    # Назви полів sc локалізовані, назви станів - ні.
    param([string]$Name)
    $out = Invoke-Quiet 'sc.exe' @('query', $Name)
    $m = [regex]::Match(($out -join "`n"), '\d\s+(STOPPED|START_PENDING|STOP_PENDING|RUNNING|CONTINUE_PENDING|PAUSE_PENDING|PAUSED)\b')
    if ($m.Success) { return $m.Groups[1].Value }
    if (Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$Name") { return 'зареєстровано, стан невідомий' }
    'не знайдено'
}

function ConvertFrom-EventXml {
    # Розбирає вивід "wevtutil qe ... /f:xml" без .NET 3.5 -> @{ Id; Time; Provider }
    param([string[]]$Lines)
    $events = @()
    foreach ($chunk in (($Lines -join "`n") -split '</Event>')) {
        $m = [regex]::Match($chunk, '<EventID[^>]*>(\d+)</EventID>')
        if (-not $m.Success) { continue }
        $t = [regex]::Match($chunk, "SystemTime=['""]([^'""]+)['""]").Groups[1].Value
        $pv = [regex]::Match($chunk, "Provider Name=['""]([^'""]+)['""]").Groups[1].Value
        $events += @{ Id = [int]$m.Groups[1].Value; Time = $t; Provider = $pv }
    }
    $events
}

function Get-LogEvents {
    # Події журналу з моменту $Since через wevtutil (Get-WinEvent потребує .NET 3.5, якого на 2008 R2 може не бути)
    param([string]$LogName, [datetime]$Since, [int[]]$Ids)
    $ms = [long]((Get-Date) - $Since).TotalMilliseconds
    if ($ms -lt 1000) { $ms = 1000 }
    $cond = "TimeCreated[timediff(@SystemTime) <= $ms]"
    if ($Ids) { $cond = '(' + (($Ids | ForEach-Object { "EventID=$_" }) -join ' or ') + ') and ' + $cond }
    $out = Invoke-Quiet 'wevtutil.exe' @('qe', $LogName, "/q:*[System[$cond]]", '/c:20000', '/f:xml')
    @(ConvertFrom-EventXml $out)
}

function Get-CrashEvents {
    # BSOD (1001 від WER-SystemErrorReporting), неочікуване перезавантаження (41 Kernel-Power, 6008)
    param([datetime]$Since)
    $found = @()
    foreach ($e in (Get-LogEvents 'System' $Since @(41, 1001, 6008))) {
        if ($e.Id -eq 1001 -and $e.Provider -notlike '*SystemErrorReporting*') { continue }
        $found += $e
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
    foreach ($c in $crashes) { $summary += ('  {0} EventID={1} {2}' -f $c.Time, $c.Id, $c.Provider) }
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
    $events = @(Get-LogEvents 'Microsoft-Windows-Sysmon/Operational' $started)
    $summary += "Подій Sysmon з моменту встановлення: $($events.Count)"
    $byId = @{}
    foreach ($e in $events) { $byId[$e.Id] = 1 + [int]$byId[$e.Id] }
    foreach ($id in ($byId.Keys | Sort-Object)) { $summary += ('  EventID {0}: {1}' -f $id, $byId[$id]) }
    $summary += "Драйвер SysmonDrv: $(Get-DriverState 'SysmonDrv')"
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
