#Requires -Version 2.0
<#
.SYNOPSIS
    Одна команда для будь-якої Windows: завантажує все потрібне, визначає тип машини й налаштовує журналювання.

.DESCRIPTION
    Запуск (PowerShell або cmd від імені адміністратора, потрібен інтернет). У рядку навмисно
    немає змінних ($): інакше PowerShell, у який його вставили, підставив би їх ще до запуску.

      powershell -NoProfile -ExecutionPolicy Bypass -Command "try{[Net.ServicePointManager]::SecurityProtocol=3072}catch{}; & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString((New-Object Net.WebClient).DownloadData('https://raw.githubusercontent.com/egwyl666/sec_journal_on/v1.3.3/windows/Start-SecLogging.ps1')).TrimStart([char]0xFEFF)))"

    Що робить:
      1. Завантажує архів репозиторію з GitHub (або бере -Source).
      2. Визначає тип машини: робоча станція / сервер / контролер домену, стара ОС (2008/2008 R2/Win7).
      3. Збирає пакет (Sysmon з перевіркою підпису Microsoft і SHA256, конфіги) і налаштовує цю машину:
         журнали, їхні розміри, політику аудиту, журналювання PowerShell, Sysmon, збір агентом Wazuh.
      4. На контролері домену додатково створює/оновлює GPO, щоб усі машини домену
         налаштовувалися самі при кожному завантаженні, і вмикає аудит DCSync на корені домену.
      5. Знімає стан "до" і "після" та записує, що саме змінилося (було -> стало):
         %ProgramData%\SecLogging\changes\<дата>-changes.txt (+ .csv для Excel).
      6. Друкує підсумок і шляхи до звітів.

    Повторний запуск безпечний: змінюється лише те, чого бракує.

.PARAMETER AuditOnly
    Лише перевірити й показати, що було б змінено. На DC - пробний прогін GPO (-WhatIf).
.PARAMETER Source
    Тека з розпакованим репозиторієм або .zip архів (для машин без доступу до GitHub).
.PARAMETER Ref
    Гілка/тег/коміт репозиторію. За замовчуванням - закріплений реліз (див. $Ref нижче).
.PARAMETER SkipSysmon
    Не встановлювати Sysmon (лише журнали й аудит).
.PARAMETER NoGpo
    На DC не чіпати GPO (лише налаштувати сам DC).
.PARAMETER LegacySysmonVersion
    Версія Sysmon для 2008/2008 R2/Win7: 10.42 (за замовчуванням) або 10.2.
.PARAMETER NoLegacySysmon
    На старій ОС не встановлювати Sysmon.
.PARAMETER KeepPowerShellV2
    Не вимикати PowerShell 2.0 (за замовчуванням вимикається на Win8/2012 і новіших:
    через "powershell -version 2" зловмисник обходить журналювання PowerShell).
.EXAMPLE
    # з параметрами: той самий рядок, параметри після останньої дужки
    powershell -NoProfile -ExecutionPolicy Bypass -Command "... .TrimStart([char]0xFEFF))) -AuditOnly"
.EXAMPLE
    # без інтернету: репозиторій завантажено й розпаковано заздалегідь
    powershell -ExecutionPolicy Bypass -File D:\sec_journal_on\windows\Start-SecLogging.ps1 -Source D:\sec_journal_on
#>
param(
    [switch]$AuditOnly,
    [string]$Source,
    [string]$Ref = 'v1.3.3',
    [switch]$SkipSysmon,
    [switch]$NoGpo,
    [ValidateSet('10.42', '10.2')]
    [string]$LegacySysmonVersion = '10.42',
    [switch]$NoLegacySysmon,
    [switch]$KeepPowerShellV2,
    [string]$RepoOwner = 'egwyl666',
    [string]$RepoName = 'sec_journal_on'
)

$ErrorActionPreference = 'Stop'

# PowerShell 2.0 в англійській Windows не показує кирилицю: тоді повідомлення латиницею.
$Script:Latin = $false
if ($PSVersionTable.PSVersion.Major -lt 3) {
    try {
        $probe = [string][char]0x0456 + [char]0x0436
        $enc = [Console]::OutputEncoding
        $Script:Latin = ($enc.GetString($enc.GetBytes($probe)) -ne $probe)
    }
    catch { $Script:Latin = $false }
}

function Say {
    # Say 'український текст' 'latin text' [колір]
    param([string]$Uk, [string]$En, [string]$Color = 'Gray')
    $t = $Uk; if ($Script:Latin) { $t = $En }
    Write-Host $t -ForegroundColor $Color
}

function Get-StartPlan {
    # Що запускати для цієї машини. ProductType: 1 = робоча станція, 2 = DC, 3 = сервер.
    param([int]$ProductType, [version]$OSVersion, [bool]$AuditOnly, [bool]$SkipSysmon, [bool]$NoGpo, [bool]$NoLegacySysmon, [string]$LegacySysmonVersion, [bool]$KeepPowerShellV2 = $false)
    $role = @{ 1 = 'Workstation'; 2 = 'DomainController'; 3 = 'Server' }[$ProductType]
    if (-not $role) { $role = 'Server' }
    $legacy = ($OSVersion -lt [version]'6.2')
    $local = @('-Mode', 'Local')
    if ($AuditOnly) { $local += '-AuditOnly' }
    if ($SkipSysmon -or ($legacy -and $NoLegacySysmon)) { $local += '-SkipSysmon' }
    elseif ($legacy) { $local += @('-AllowLegacySysmon', '-LegacySysmonVersion', $LegacySysmonVersion) }
    if (-not $legacy -and -not $KeepPowerShellV2) { $local += '-DisablePowerShellV2' }
    $local += '-ConfigureWazuh'
    $gpo = $null
    if ($role -eq 'DomainController' -and -not $NoGpo) {
        # пакет уже зібрано локальним кроком; startup-скрипт на старих ОС ставить Sysmon $LegacySysmonVersion
        $gpo = @('-Mode', 'Domain', '-NoBuild', '-SetDomainRootSacl', '-AllowLegacySysmon', '-LegacySysmonVersion', $LegacySysmonVersion)
        if ($SkipSysmon) { $gpo += '-SkipSysmon' }
        if (-not $KeepPowerShellV2) { $gpo += '-DisablePowerShellV2' }   # на старих ОС скрипт сам пропускає
        if ($AuditOnly) { $gpo += '-WhatIfGpo' }
    }
    @{ Role = $role; Legacy = $legacy; Local = $local; Gpo = $gpo }
}

function Expand-Zip {
    param([string]$ZipPath, [string]$Destination)
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    # повні шляхи: і ZipFile, і Shell.Application рахують відносні від поточної теки процесу, а не від $PWD
    $ZipPath = (Resolve-Path -LiteralPath $ZipPath).ProviderPath
    $Destination = (Resolve-Path -LiteralPath $Destination).ProviderPath
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $Destination)
    }
    catch {
        # .NET < 4.5 (Server 2008 R2 без оновлень): через Shell
        $shell = New-Object -ComObject Shell.Application
        $shell.NameSpace($Destination).CopyHere($shell.NameSpace($ZipPath).Items(), 0x14)
    }
}

function Remove-OldRepoCopies {
    # Кожен запуск розпаковує репозиторій у нову теку repo-<час>; старі копії більше не потрібні
    param([string]$WorkDir, [string]$Keep)
    foreach ($d in @(Get-ChildItem -LiteralPath $WorkDir -Filter 'repo-*' -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer })) {
        if ($Keep -and $d.FullName -eq $Keep) { continue }
        Remove-Item -LiteralPath $d.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Find-RepoRoot {
    param([string]$Dir)
    if (Test-Path -LiteralPath (Join-Path $Dir 'windows\Install-SecLogging.ps1')) { return $Dir }
    foreach ($d in @(Get-ChildItem -LiteralPath $Dir | Where-Object { $_.PSIsContainer })) {
        if (Test-Path -LiteralPath (Join-Path $d.FullName 'windows\Install-SecLogging.ps1')) { return $d.FullName }
    }
    $null
}

function ConvertTo-ArgLine {
    # Командний рядок для Start-Process: аргументи з пробілами/порожні - у лапках
    param([string[]]$Arguments)
    $parts = @()
    foreach ($a in $Arguments) {
        if ($a -eq '' -or $a -match '[\s"]') { $parts += ('"' + ($a -replace '"', '\"') + '"') } else { $parts += $a }
    }
    $parts -join ' '
}

function Invoke-Step {
    # Запускає скрипт в окремому процесі powershell.exe; повертає лише код виходу.
    # Вивід іде прямо в консоль (Start-Process), інакше він змішався б з кодом виходу.
    param([string]$Script, [string[]]$Arguments)
    $ps = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $ps)) { $ps = 'powershell.exe' }
    $line = ConvertTo-ArgLine (@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Script) + $Arguments)
    $proc = Start-Process -FilePath $ps -ArgumentList $line -NoNewWindow -Wait -PassThru
    [int]$proc.ExitCode
}

if ($MyInvocation.InvocationName -eq '.') { return }   # dot-source для тестів: лише функції

# ---------------------------------------------------------------- 0. середовище і права
if ($PSVersionTable.PSEdition -eq 'Core') {
    # PowerShell 7 не має Get-WmiObject і частини модулів Windows: скрипти розраховані на Windows PowerShell
    Say 'Запустіть у Windows PowerShell (powershell.exe), а не в PowerShell 7 (pwsh).' 'Run in Windows PowerShell (powershell.exe), not PowerShell 7 (pwsh).' Red
    return
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Say 'Потрібні права адміністратора: відкрийте PowerShell через "Запуск від імені адміністратора" і вставте команду ще раз.' 'Administrator rights required: open PowerShell with "Run as administrator" and paste the command again.' Red
    return
}

$work = Join-Path $env:ProgramData 'SecLogging'
New-Item -ItemType Directory -Path $work -Force | Out-Null
$os = Get-WmiObject Win32_OperatingSystem
$plan = Get-StartPlan ([int]$os.ProductType) ([version]$os.Version) ([bool]$AuditOnly) ([bool]$SkipSysmon) ([bool]$NoGpo) ([bool]$NoLegacySysmon) $LegacySysmonVersion ([bool]$KeepPowerShellV2)
Say ('SecLogging: {0} ({1}), роль {2}{3}' -f $os.Caption, $os.Version, $plan.Role, $(if ($AuditOnly) { ', ЛИШЕ ПЕРЕВІРКА' } else { '' })) ('SecLogging: {0} ({1}), role {2}{3}' -f $os.Caption, $os.Version, $plan.Role, $(if ($AuditOnly) { ', CHECK ONLY' } else { '' })) White

# ---------------------------------------------------------------- 1. файли
$root = $null
if ($Source) {
    if ($Source -like '*.zip') {
        $dst = Join-Path $work ('repo-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
        Expand-Zip $Source $dst
        $root = Find-RepoRoot $dst
    }
    else { $root = Find-RepoRoot $Source }
}
else {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch { $null = $_ }
    $url = 'https://github.com/{0}/{1}/archive/{2}.zip' -f $RepoOwner, $RepoName, $Ref
    $zip = Join-Path $work 'repo.zip'
    $dst = Join-Path $work ('repo-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Say "==> Завантаження $url" "==> Downloading $url" Cyan
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
        $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
        $wc.DownloadFile($url, $zip)
        Expand-Zip $zip $dst
        $root = Find-RepoRoot $dst
    }
    catch {
        Say "Не вдалося завантажити: $($_.Exception.Message)" "Download failed: $($_.Exception.Message)" Red
        Say 'Немає інтернету або TLS 1.2 (старі ОС)? Завантажте архів на іншому комп''ютері й запустіть з -Source <шлях до .zip>.' 'No internet or TLS 1.2 (old OS)? Download the archive on another computer and run with -Source <path to .zip>.' Yellow
        return
    }
}
if (-not $root) { Say 'Не знайдено windows\Install-SecLogging.ps1 у джерелі.' 'windows\Install-SecLogging.ps1 not found in the source.' Red; return }
if ($dst -and $root.StartsWith($dst)) { Remove-OldRepoCopies $work $dst }
$installer = Join-Path $root 'windows\Install-SecLogging.ps1'
$mainScript = Join-Path $root 'windows\Set-SecurityLogging.ps1'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$snapDir = Join-Path $work 'changes'
$snapBefore = Join-Path $snapDir "$stamp-before.tsv"
$snapAfter = Join-Path $snapDir "$stamp-after.tsv"
$changesFile = Join-Path $snapDir "$stamp-changes.txt"

Say '==> Знімок стану "до"' '==> Snapshot "before"' Cyan
$null = Invoke-Step $mainScript @('-Snapshot', $snapBefore)

# ---------------------------------------------------------------- 2. ця машина
Say '==> Налаштування цієї машини' '==> Configuring this machine' Cyan
$codeLocal = Invoke-Step $installer $plan.Local

# ---------------------------------------------------------------- 3. домен (лише DC)
$codeGpo = 0
if ($plan.Gpo) {
    # GPO не залежать від того, чи все вдалося на самому DC (напр. один журнал без доступу), тому крок виконується завжди:
    # без GPO доменна політика аудиту за кілька хвилин скидає локальні налаштування DC
    if ($codeLocal -ne 0) { Say '    (на цьому DC були помилки - див. звіт; GPO все одно створюємо)' '    (this DC had errors - see the report; creating GPOs anyway)' Yellow }
    Say '==> Доменні GPO (усі машини домену налаштуються самі при завантаженні)' '==> Domain GPOs (all domain machines will configure themselves at boot)' Cyan
    $codeGpo = Invoke-Step $installer $plan.Gpo
}

# ---------------------------------------------------------------- 4. що змінилося
$haveChanges = $false
if (-not $AuditOnly -and (Test-Path -LiteralPath $snapBefore)) {
    Write-Host ''
    Say '==> Знімок стану "після" і порівняння' '==> Snapshot "after" and comparison' Cyan
    $null = Invoke-Step $mainScript @('-Snapshot', $snapAfter)
    if (Test-Path -LiteralPath $snapAfter) {
        $null = Invoke-Step $mainScript @('-CompareBefore', $snapBefore, '-CompareAfter', $snapAfter, '-CompareOut', $changesFile)
        $haveChanges = Test-Path -LiteralPath $changesFile
    }
}

# ---------------------------------------------------------------- 5. підсумок
$report = Join-Path $work 'last-report.json'
Write-Host ''
if ($codeLocal -eq 0 -and $codeGpo -eq 0) {
    if ($AuditOnly) { Say 'ГОТОВО: перевірку виконано, нічого не змінено.' 'DONE: check completed, nothing changed.' Green }
    else { Say 'ГОТОВО: журналювання безпеки налаштовано.' 'DONE: security logging configured.' Green }
}
else {
    Say ("ЗАВЕРШЕНО З ПОМИЛКАМИ (коди: машина {0}, GPO {1}). Надішліть файл звіту адміністратору." -f $codeLocal, $codeGpo) ("FINISHED WITH ERRORS (codes: machine {0}, GPO {1}). Send the report file to the administrator." -f $codeLocal, $codeGpo) Red
}
Say "Звіт:           $report" "Report:          $report" White
if ($haveChanges) { Say "Що змінилося:   $changesFile" "What changed:    $changesFile" White }
elseif (Test-Path -LiteralPath $snapBefore) { Say "Стан до запуску: $snapBefore" "State before:    $snapBefore" White }
