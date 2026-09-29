#Requires -Version 2.0
<#
.SYNOPSIS
    Автоматизація "завантажити -> зібрати пакет -> встановити" для SecLogging на Windows.

.DESCRIPTION
    Одна команда замість кількох ручних кроків:

      1. Скрипти: беруться з теки поруч (клон репозиторію) або, з -Fetch, завантажуються
         архівом з GitHub (https://github.com/<RepoOwner>/<RepoName>/archive/<RepoRef>.zip).
      2. Пакет: Set-SecurityLogging.ps1 -BuildPackage (Sysmon, конфіги, перевірка підпису
         й SHA256, sources.ini). Готовий пакет використовується повторно; -Rebuild збирає заново.
      3. Дія за режимом:
           Build  - лише зібрати пакет (і за -UpdateRepoPins оновити windows\sources.ini);
           Local  - встановити на цю машину з пакета (Set-SecurityLogging.ps1 -SourcePath);
           Share  - скопіювати пакет на мережеву шару для машин без інтернету;
           Domain - на DC: створити/оновити GPO (New-SecLoggingGpo.ps1) з цим пакетом.

    Кожен крок запускається в окремому процесі powershell.exe, коди виходу передаються далі.

.PARAMETER Mode
    Build | Local | Share | Domain. За замовчуванням Local.

.PARAMETER PackagePath
    Тека пакета. За замовчуванням %ProgramData%\SecLogging\package.

.PARAMETER SharePath
    Режим Share: тека або UNC-шлях, куди викласти пакет.

.PARAMETER Fetch
    Завантажити скрипти з GitHub, навіть якщо поруч є локальні.

.PARAMETER RepoRef
    Гілка/тег/коміт для -Fetch. За замовчуванням закріплений реліз; HEAD - остання версія.
    Для гілки зі скісною рискою: refs/heads/<назва>.

.PARAMETER Rebuild
    Зібрати пакет заново, навіть якщо в PackagePath уже є коректний.

.PARAMETER NoBuild
    Не завантажувати нічого: використати наявний пакет у PackagePath (машина без інтернету).

.PARAMETER UpdateRepoPins
    Після збирання скопіювати sources.ini пакета у windows\sources.ini локального клону.

.PARAMETER WhatIfGpo
    Режим Domain: запустити New-SecLoggingGpo.ps1 з -WhatIf (нічого не створює).

.EXAMPLE
    # машина з інтернетом: усе одразу
    .\Install-SecLogging.ps1
.EXAMPLE
    # лише перевірка, без змін
    .\Install-SecLogging.ps1 -AuditOnly
.EXAMPLE
    # підготувати шару для машин без інтернету
    .\Install-SecLogging.ps1 -Mode Share -SharePath \\fileserver\SecLogging
.EXAMPLE
    # на DC1: пакет + GPO, спершу пробний прогін
    .\Install-SecLogging.ps1 -Mode Domain -WhatIfGpo
#>
[CmdletBinding()]
param(
    [ValidateSet('Build', 'Local', 'Share', 'Domain')]
    [string]$Mode = 'Local',
    [string]$PackagePath,
    [string]$SharePath,
    [switch]$Fetch,
    [string]$RepoOwner = 'egwyl666',
    [string]$RepoName = 'sec_journal_on',
    [string]$RepoRef = 'v1.3.3',
    [switch]$Rebuild,
    [switch]$NoBuild,
    [switch]$UpdateRepoPins,
    # --- передаються в Set-SecurityLogging.ps1
    [switch]$AuditOnly,
    [switch]$SkipSysmon,
    [switch]$UpgradeSysmon,
    [switch]$AllowUnpinnedSysmon,
    [switch]$AllowLegacySysmon,
    [switch]$DisablePowerShellV2,
    [switch]$ConfigureWazuh,
    [string]$TranscriptionPath,
    [ValidateSet('10.42', '10.2')]
    [string]$LegacySysmonVersion = '10.42',
    [switch]$ReinstallSysmon,
    [switch]$AcceptNewSysmon,
    # --- передаються в New-SecLoggingGpo.ps1
    [string[]]$LinkTargets,
    [switch]$SetDomainRootSacl,
    [switch]$WhatIfGpo
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

$InstallerPath = $MyInvocation.MyCommand.Path
$InstallerDir = Split-Path -Parent $InstallerPath
$WorkDir = Join-Path $env:ProgramData 'SecLogging'
if (-not $PackagePath) { $PackagePath = Join-Path $WorkDir 'package' }

function Write-Step { param([string]$Text) Write-Host ''; Write-Host "==> $Text" -ForegroundColor Cyan }

#region ---------------------------------------------------------------- допоміжні функції (покриті юніт-тестами)

function Get-FileSha256 {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead($Path)
    try { $hash = $sha.ComputeHash($fs) } finally { $fs.Close(); $sha.Clear() }
    -join ($hash | ForEach-Object { $_.ToString('x2') })
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

function Test-Package {
    # Перевіряє пакет: скрипт, sources.ini, файли Sysmon і їхні SHA256. Повертає @{ Ok; Problems }
    param([string]$Dir, [bool]$NeedSysmon)
    $problems = @()
    if (-not (Test-Path -LiteralPath (Join-Path $Dir 'Set-SecurityLogging.ps1'))) { $problems += 'немає Set-SecurityLogging.ps1' }
    $ini = Read-IniFile (Join-Path $Dir 'sources.ini')
    if ($ini.Count -eq 0) { $problems += 'немає sources.ini' }
    $files = @(
        @{ Rel = 'Sysmon.zip'; Key = 'SysmonZipSha256'; Required = $NeedSysmon }
        @{ Rel = 'sysmonconfig-export.xml'; Key = 'ConfigSha256'; Required = $NeedSysmon }
        @{ Rel = 'legacy\10.42\Sysmon.zip'; Key = 'Legacy1042ZipSha256'; Required = $NeedSysmon }
        @{ Rel = 'legacy\10.42\sysmonconfig-export.xml'; Key = 'Legacy1042ConfigSha256'; Required = $NeedSysmon }
        @{ Rel = 'legacy\10.2\Sysmon.zip'; Key = 'Legacy102ZipSha256'; Required = $NeedSysmon }
        @{ Rel = 'legacy\10.2\sysmonconfig-export.xml'; Key = 'Legacy102ConfigSha256'; Required = $NeedSysmon }
    )
    foreach ($f in $files) {
        $p = Join-Path $Dir $f.Rel
        if (-not (Test-Path -LiteralPath $p)) {
            if ($f.Required) { $problems += "немає $($f.Rel)" }
            continue
        }
        $pin = $ini[$f.Key]
        if (-not $pin) { $problems += "$($f.Rel): немає хешу $($f.Key) у sources.ini"; continue }
        $h = Get-FileSha256 $p
        if ($h -ne $pin.ToLower()) { $problems += "$($f.Rel): SHA256 $h не збігається з $pin" }
    }
    @{ Ok = ($problems.Count -eq 0); Problems = $problems }
}

function Get-ScriptVersion {
    # Версія зі рядка "$ScriptVersion = 'x.y.z'" у скрипті; '?' якщо не знайдено
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return '?' }
    $m = [regex]::Match([System.IO.File]::ReadAllText($Path), '(?m)^\$ScriptVersion\s*=\s*''([^'']+)''')
    if ($m.Success) { return $m.Groups[1].Value }
    '?'
}

function Update-PackageScript {
    # Повторно використаний пакет несе копію Set-SecurityLogging.ps1 з моменту збирання.
    # Якщо поруч свіжіший скрипт (інший SHA256) - замінює копію в пакеті. Повертає @{ Updated; From; To }.
    param([string]$SrcDir, [string]$PkgDir)
    $src = Join-Path $SrcDir 'Set-SecurityLogging.ps1'; $dst = Join-Path $PkgDir 'Set-SecurityLogging.ps1'
    $r = @{ Updated = $false; From = (Get-ScriptVersion $dst); To = (Get-ScriptVersion $src) }
    if (-not (Test-Path -LiteralPath $src) -or -not (Test-Path -LiteralPath $PkgDir)) { return $r }
    if ((Test-Path -LiteralPath $dst) -and (Get-FileSha256 $src) -eq (Get-FileSha256 $dst)) { return $r }
    Copy-Item -LiteralPath $src -Destination $dst -Force
    $r.Updated = $true
    $r
}

function Get-PinnedHashes {
    # Хеші, закріплені в самому Set-SecurityLogging.ps1 ($DefaultPins): конфіги Sysmon і Sysmon для старих ОС
    param([string]$ScriptPath)
    $h = @{}
    if (-not (Test-Path -LiteralPath $ScriptPath)) { return $h }
    foreach ($m in [regex]::Matches([System.IO.File]::ReadAllText($ScriptPath), "(?m)^\s*(ConfigSha256|Legacy\w+Sha256)\s*=\s*'([0-9a-fA-F]{64})'")) {
        $h[$m.Groups[1].Value] = $m.Groups[2].Value.ToLower()
    }
    $h
}

function Test-PackagePins {
    # Пакет зібрано старішою версією, якщо його sources.ini не збігається з хешами, закріпленими у свіжому скрипті
    # (новий реліз оновив конфіг Sysmon тощо). Повертає назви ключів, що розійшлися.
    param([string]$SrcDir, [string]$PkgDir)
    $want = Get-PinnedHashes (Join-Path $SrcDir 'Set-SecurityLogging.ps1')
    $ini = Read-IniFile (Join-Path $PkgDir 'sources.ini')
    $diff = @()
    foreach ($k in @($want.Keys | Sort-Object)) { if ([string]$ini[$k] -ne $want[$k]) { $diff += $k } }
    $diff
}

function Get-ArchiveUrl {
    param([string]$Owner, [string]$Repo, [string]$Ref)
    'https://github.com/{0}/{1}/archive/{2}.zip' -f $Owner, $Repo, $Ref
}

function Find-SourceRoot {
    # Шукає в розпакованому архіві теку, що містить windows\Set-SecurityLogging.ps1
    param([string]$Dir)
    if (Test-Path -LiteralPath (Join-Path $Dir 'windows\Set-SecurityLogging.ps1')) { return $Dir }
    foreach ($d in @(Get-ChildItem -LiteralPath $Dir | Where-Object { $_.PSIsContainer })) {
        if (Test-Path -LiteralPath (Join-Path $d.FullName 'windows\Set-SecurityLogging.ps1')) { return $d.FullName }
    }
    $null
}

function Add-SwitchArgs {
    # Додає до списку аргументів "-Name" для увімкнених перемикачів і "-Name value" для непорожніх рядків
    param([string[]]$List, [hashtable]$Values, [string[]]$Order)
    $out = @($List)
    foreach ($k in $Order) {
        if (-not $Values.ContainsKey($k)) { continue }
        $v = $Values[$k]
        if ($v -is [System.Management.Automation.SwitchParameter] -or $v -is [bool]) { if ([bool]$v) { $out += "-$k" } }
        elseif ($v -is [array]) { if ($v.Count) { $out += "-$k"; $out += ($v -join ';') } }   # ';' - DN самі містять коми
        elseif ($v) { $out += "-$k"; $out += [string]$v }
    }
    $out
}

#endregion
#region ---------------------------------------------------------------- завантаження й запуск

function Save-Download {
    param([string]$Url, [string]$Destination)
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 }
    catch { Write-Verbose 'TLS 1.2 недоступний у цій версії .NET' }
    $wc = New-Object System.Net.WebClient
    $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
    $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    $wc.DownloadFile($Url, $Destination)
}

function Expand-ZipFile {
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
        $shell = New-Object -ComObject Shell.Application
        $zip = $shell.NameSpace($ZipPath)
        if (-not $zip) { throw "Не вдалося відкрити zip $ZipPath" }
        $shell.NameSpace($Destination).CopyHere($zip.Items(), 0x14)
    }
}

function ConvertTo-ArgumentString {
    # Збирає командний рядок для Start-Process: аргументи з пробілами/порожні - у лапках
    param([string[]]$Arguments)
    $parts = @()
    foreach ($a in $Arguments) {
        if ($a -eq '' -or $a -match '[\s"]') { $parts += ('"' + ($a -replace '"', '\"') + '"') } else { $parts += $a }
    }
    $parts -join ' '
}

function Invoke-ChildScript {
    # Запускає .ps1 в окремому процесі Windows PowerShell; повертає лише код виходу.
    # Вивід дочірнього процесу йде прямо в консоль (не перехоплюється): інакше він змішується
    # з кодом виходу, а кирилиця псується кодовою сторінкою консолі.
    param([string]$Script, [string[]]$Arguments)
    $ps = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $ps)) { $ps = 'powershell.exe' }
    $argLine = ConvertTo-ArgumentString (@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Script) + $Arguments)
    Write-Host ("    {0} {1}" -f (Split-Path -Leaf $Script), ($Arguments -join ' ')) -ForegroundColor DarkGray
    $proc = Start-Process -FilePath $ps -ArgumentList $argLine -NoNewWindow -Wait -PassThru
    [int]$proc.ExitCode
}

function Test-IsAdmin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

#endregion
#region ---------------------------------------------------------------- основна частина

if ($MyInvocation.InvocationName -eq '.') { return }   # dot-source для тестів: лише функції

if ($Mode -ne 'Build' -and $Mode -ne 'Share' -and -not (Test-IsAdmin)) {
    Write-Host 'Запустіть від імені адміністратора (з підвищеними правами).' -ForegroundColor Red
    exit 3
}
if ($Mode -eq 'Share' -and -not $SharePath) { Write-Host 'Для режиму Share потрібен -SharePath.' -ForegroundColor Red; exit 64 }
if (-not (Test-Path -LiteralPath $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }

Write-Host ("Install-SecLogging  режим: {0}  пакет: {1}" -f $Mode, $PackagePath) -ForegroundColor White

# ---- 1. скрипти
Write-Step 'Скрипти'
$srcWindows = $null
$fetched = $false
if (-not $Fetch -and (Test-Path -LiteralPath (Join-Path $InstallerDir 'Set-SecurityLogging.ps1'))) {
    $srcWindows = $InstallerDir
    Write-Host "    локальні: $srcWindows"
}
elseif ($NoBuild -and (Test-Path -LiteralPath (Join-Path $PackagePath 'Set-SecurityLogging.ps1')) -and $Mode -ne 'Domain') {
    Write-Host '    використовуються скрипти з пакета (-NoBuild)'
}
else {
    $url = Get-ArchiveUrl $RepoOwner $RepoName $RepoRef
    $zip = Join-Path $WorkDir 'repo.zip'
    $dst = Join-Path $WorkDir ('repo-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    Write-Host "    завантаження $url"
    try { Save-Download $url $zip; Expand-ZipFile $zip $dst }
    catch { Write-Host "    не вдалося завантажити скрипти: $($_.Exception.Message)" -ForegroundColor Red; exit 2 }
    $root = Find-SourceRoot $dst
    if (-not $root) { Write-Host '    в архіві немає windows\Set-SecurityLogging.ps1' -ForegroundColor Red; exit 2 }
    $srcWindows = Join-Path $root 'windows'
    $fetched = $true
    Write-Host "    завантажено: $srcWindows"
}

# ---- 2. пакет
Write-Step 'Пакет'
$needSysmon = -not $SkipSysmon
$check = Test-Package $PackagePath $needSysmon
# пакет від попереднього релізу: хеші, закріплені у свіжому скрипті, могли змінитися
$stalePins = @()
if ($check.Ok -and $srcWindows) { $stalePins = @(Test-PackagePins $srcWindows $PackagePath) }
if ($NoBuild) {
    if (-not $check.Ok) {
        Write-Host ("    пакет некоректний: {0}" -f ($check.Problems -join '; ')) -ForegroundColor Red
        exit 2
    }
    if ($stalePins.Count) { Write-Host ("    УВАГА: пакет зібрано іншою версією (розбіжні хеші: {0}); без -NoBuild його буде перезібрано" -f ($stalePins -join ', ')) -ForegroundColor Yellow }
    Write-Host '    наявний пакет перевірено (-NoBuild)'
}
elseif ($check.Ok -and -not $Rebuild -and $stalePins.Count -eq 0) {
    Write-Host '    наявний пакет коректний, використовується повторно (-Rebuild щоб зібрати заново)'
    # Sysmon і конфіги лишаються (перевірені за SHA256), а скрипт - завжди найсвіжіший
    if ($srcWindows) {
        $upd = Update-PackageScript $srcWindows $PackagePath
        if ($upd.Updated) { Write-Host ("    скрипт у пакеті оновлено: {0} -> {1}" -f $upd.From, $upd.To) -ForegroundColor Green }
    }
}
else {
    if (-not $check.Ok -and (Test-Path -LiteralPath $PackagePath)) { Write-Host ("    збираємо заново: {0}" -f ($check.Problems -join '; ')) }
    elseif ($stalePins.Count) { Write-Host ("    збираємо заново: у новій версії змінилися закріплені хеші ({0})" -f ($stalePins -join ', ')) }
    $buildArgs = Add-SwitchArgs @('-BuildPackage', $PackagePath) @{ AcceptNewSysmon = $AcceptNewSysmon } @('AcceptNewSysmon')
    $code = Invoke-ChildScript (Join-Path $srcWindows 'Set-SecurityLogging.ps1') $buildArgs
    if ($code -ne 0) { Write-Host "    збирання пакета завершилося з кодом $code" -ForegroundColor Red; exit $code }
    $check = Test-Package $PackagePath $needSysmon
    if (-not $check.Ok) { Write-Host ("    пакет після збирання некоректний: {0}" -f ($check.Problems -join '; ')) -ForegroundColor Red; exit 2 }
    Write-Host '    пакет зібрано й перевірено' -ForegroundColor Green
}

if ($UpdateRepoPins) {
    if ($fetched -or -not $srcWindows) { Write-Host '    -UpdateRepoPins працює лише з локальним клоном репозиторію' -ForegroundColor Yellow }
    else {
        Copy-Item -LiteralPath (Join-Path $PackagePath 'sources.ini') -Destination (Join-Path $srcWindows 'sources.ini') -Force
        Write-Host "    оновлено $(Join-Path $srcWindows 'sources.ini') - закомітьте його" -ForegroundColor Green
    }
}

# ---- 3. дія
$localArgs = Add-SwitchArgs @('-SourcePath', $PackagePath) @{
    AuditOnly = $AuditOnly; SkipSysmon = $SkipSysmon; UpgradeSysmon = $UpgradeSysmon; AllowUnpinnedSysmon = $AllowUnpinnedSysmon
    AllowLegacySysmon = $AllowLegacySysmon; LegacySysmonVersion = $LegacySysmonVersion; ReinstallSysmon = $ReinstallSysmon
    DisablePowerShellV2 = $DisablePowerShellV2; ConfigureWazuh = $ConfigureWazuh; TranscriptionPath = $TranscriptionPath
} @('AuditOnly', 'SkipSysmon', 'UpgradeSysmon', 'AllowUnpinnedSysmon', 'AllowLegacySysmon', 'LegacySysmonVersion', 'ReinstallSysmon', 'DisablePowerShellV2', 'ConfigureWazuh', 'TranscriptionPath')

switch ($Mode) {
    'Build' {
        Write-Step 'Готово'
        Write-Host "    пакет: $PackagePath"
        exit 0
    }
    'Local' {
        Write-Step 'Встановлення на цю машину'
        $code = Invoke-ChildScript (Join-Path $PackagePath 'Set-SecurityLogging.ps1') $localArgs
        exit $code
    }
    'Share' {
        Write-Step "Публікація пакета в $SharePath"
        if (-not (Test-Path -LiteralPath $SharePath)) { New-Item -ItemType Directory -Path $SharePath -Force | Out-Null }
        foreach ($item in @(Get-ChildItem -LiteralPath $PackagePath)) { Copy-Item -LiteralPath $item.FullName -Destination $SharePath -Recurse -Force }
        $remote = Test-Package $SharePath $needSysmon
        if (-not $remote.Ok) { Write-Host ("    перевірка копії не пройдена: {0}" -f ($remote.Problems -join '; ')) -ForegroundColor Red; exit 2 }
        Copy-Item -LiteralPath $InstallerPath -Destination $SharePath -Force
        # стендовий скрипт для старих ОС і теки для оновлень (.msu) та результатів
        if ($srcWindows -and (Test-Path -LiteralPath (Join-Path $srcWindows 'lab'))) {
            Copy-Item -LiteralPath (Join-Path $srcWindows 'lab') -Destination $SharePath -Recurse -Force
        }
        foreach ($d in @('updates', 'results')) { New-Item -ItemType Directory -Path (Join-Path $SharePath $d) -Force | Out-Null }
        Write-Host '    скопійовано й перевірено' -ForegroundColor Green
        Write-Host ''
        Write-Host '    Права на шару: Domain Computers / Authenticated Users - лише читання, адміністратори - запис.' -ForegroundColor Yellow
        Write-Host '    На машині без інтернету (від адміністратора):'
        Write-Host ("      powershell -ExecutionPolicy Bypass -File {0}\Set-SecurityLogging.ps1 -SourcePath {0}" -f $SharePath)
        exit 0
    }
    'Domain' {
        Write-Step 'Доменні GPO'
        $gpoScript = $null
        if ($srcWindows) { $gpoScript = Join-Path $srcWindows 'New-SecLoggingGpo.ps1' }
        if (-not $gpoScript -or -not (Test-Path -LiteralPath $gpoScript)) { Write-Host '    не знайдено New-SecLoggingGpo.ps1' -ForegroundColor Red; exit 2 }
        $gpoArgs = Add-SwitchArgs @('-PackagePath', $PackagePath) @{
            LinkTargets = $LinkTargets; SetDomainRootSacl = $SetDomainRootSacl; SkipSysmon = $SkipSysmon; UpgradeSysmon = $UpgradeSysmon
            DisablePowerShellV2 = $DisablePowerShellV2; AllowLegacySysmon = $AllowLegacySysmon; LegacySysmonVersion = $LegacySysmonVersion
            TranscriptionPath = $TranscriptionPath; WhatIf = $WhatIfGpo
        } @('LinkTargets', 'SetDomainRootSacl', 'SkipSysmon', 'UpgradeSysmon', 'DisablePowerShellV2', 'AllowLegacySysmon', 'LegacySysmonVersion', 'TranscriptionPath', 'WhatIf')
        $code = Invoke-ChildScript $gpoScript $gpoArgs
        exit $code
    }
}

#endregion
