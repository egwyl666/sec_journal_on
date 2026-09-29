#Requires -Version 5.1
<#
.SYNOPSIS
    Створює/оновлює доменні GPO для журналювання безпеки (запускати на контролері домену).

.DESCRIPTION
    Створюються дві GPO (Default Domain / Default DC Policy ніколи не змінюються):

      SEC-Logging-Baseline           -> прив'язується до кореня домену (або -LinkTargets)
      SEC-Logging-DomainControllers  -> прив'язується до OU=Domain Controllers

    Кожна GPO містить:
      * Advanced Audit Policy (audit.csv, за GUID підкатегорій, набір залежно від ролі)
      * Політики реєстру: примусові підкатегорії аудиту, командний рядок у 4688,
        ScriptBlock/Module logging PowerShell (Windows PowerShell і PowerShell 7),
        аудит NTLM, за бажанням Transcription
      * Лише GPO для DC: розміри/режим класичних журналів, аудит NTLM у домені,
        діагностика LDAP-інтерфейсу (2889)
      * Startup-скрипт комп'ютера: Set-SecurityLogging.ps1 з NETLOGON
        (вмикає operational-канали, розміри за роллю, Sysmon з пакета)

    Офлайн-пакет (Set-SecurityLogging.ps1 -BuildPackage) викладається в
    \\<домен>\NETLOGON\SecLogging і перевіряється за SHA256.

    Підтримує -WhatIf.

.PARAMETER PackagePath
    Тека з пакетом, зібраним через Set-SecurityLogging.ps1 -BuildPackage.
    За замовчуванням: тека цього скрипта.

.PARAMETER LinkTargets
    Distinguished names, до яких прив'язати базову GPO. За замовчуванням: корінь домену.
    Кілька DN можна передати масивом або одним рядком через ';'.

.PARAMETER SkipSysmon
    Startup-скрипт запускається з -SkipSysmon (лише журнали/аудит).

.PARAMETER UpgradeSysmon / DisablePowerShellV2 / AllowLegacySysmon / LegacySysmonVersion
    Передаються в startup-скрипт.

.PARAMETER TranscriptionPath
    UNC-шлях для PowerShell Transcription (лише політика; ACL шари налаштуйте самі).

.PARAMETER SetDomainRootSacl
    Додати записи SACL на корінь домену, щоб 4662 фіксувалася для DCSync
    (розширені права реплікації) і для змін DACL/власника.

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
    [ValidateSet('10.42', '10.2')]
    [string]$LegacySysmonVersion = '10.42',
    [string]$TranscriptionPath,
    [switch]$SetDomainRootSacl
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $PackagePath) { $PackagePath = $here }

# Пари GUID клієнтських розширень (CSE): [CSE}{Tool]
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

#region ---------------------------------------------------------------- чисті функції (покриті юніт-тестами)

function Merge-GpoExtensionNames {
    # gPCMachineExtensionNames: "[{cse}{tool}][{cse}{tool}]", відсортовано за GUID CSE.
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
    # Адмін-шаблон "Windows Components/Event Log Service": MaxSize у КБ, Retention "0" = перезаписувати.
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
#region ---------------------------------------------------------------- робота з AD / SYSVOL

function Update-GpoFiles {
    # Записує audit.csv + scripts.ini у теку GPO, реєструє CSE, підвищує версію комп'ютерної частини.
    param($Gpo, [string[]]$AuditCsv, [string[]]$ScriptsIni, [string]$DcName, [string]$DomainDns)
    $gpoPath = "\\$DcName\SYSVOL\$DomainDns\Policies\{$($Gpo.Id)}"
    $auditDir = Join-Path $gpoPath 'Machine\Microsoft\Windows NT\Audit'
    $scriptDir = Join-Path $gpoPath 'Machine\Scripts'
    $auditFile = Join-Path $auditDir 'audit.csv'
    $scriptsFile = Join-Path $scriptDir 'scripts.ini'
    $de = [ADSI]"LDAP://$DcName/CN={$($Gpo.Id)},CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)"
    $curExt = [string]$de.Properties['gPCMachineExtensionNames'].Value
    $ext = Merge-GpoExtensionNames $curExt @($CseRegistry, $CseScripts, $CseAudit)
    # нічого не змінилося - версію не піднімаємо, інакше всі машини домену щоразу заново застосовують GPO
    if ((Test-GpoFileSame $auditFile $AuditCsv) -and (Test-GpoFileSame $scriptsFile $ScriptsIni) -and $ext -eq $curExt.ToUpper()) { return $false }

    New-Item -ItemType Directory -Path $auditDir -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $scriptDir 'Startup') -Force | Out-Null
    [IO.File]::WriteAllLines($auditFile, [string[]]$AuditCsv, (New-Object Text.UTF8Encoding($false)))
    # scripts.ini має бути в UTF-16 LE
    [IO.File]::WriteAllLines($scriptsFile, [string[]]$ScriptsIni, [Text.Encoding]::Unicode)

    $version = [int]$de.Properties['versionNumber'].Value + 1   # молодше слово = версія комп'ютерної частини
    $de.Properties['gPCMachineExtensionNames'].Value = $ext
    $de.Properties['versionNumber'].Value = $version
    $de.CommitChanges()

    $gptIni = Join-Path $gpoPath 'GPT.INI'
    $content = @(Get-Content -LiteralPath $gptIni)
    if ($content -match '^Version=') { $content = $content -replace '^Version=\d+', "Version=$version" }
    else { $content += "Version=$version" }
    Set-Content -LiteralPath $gptIni -Value $content -Encoding ASCII
    $true
}

function Test-GpoFileSame {
    # Чи вже має файл GPO такий самий вміст (кодування визначає BOM; порівнюються рядки)
    param([string]$Path, [string[]]$Lines)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $cur = @([IO.File]::ReadAllLines($Path))
    ($cur -join "`n") -ceq (@($Lines) -join "`n")
}

function Test-GpoValueSame {
    # Значення з Get-GPRegistryValue збігається з потрібним (тип і значення)
    param($Current, $Item)
    if (-not $Current) { return $false }
    ([string]$Current.Type -eq [string]$Item.Type) -and ([string]$Current.Value -ceq [string]$Item.Value)
}

function Set-GpoRegistryList {
    param([string]$GpoName, $Items, [string]$DcName)
    $changed = 0
    foreach ($i in $Items) {
        # кожен Set-GPRegistryValue піднімає версію GPO, тож однакові значення не перезаписуємо
        $cur = Get-GPRegistryValue -Name $GpoName -Key $i.Key -ValueName $i.Name -Server $DcName -ErrorAction SilentlyContinue
        if (Test-GpoValueSame $cur $i) { continue }
        $params = @{ Name = $GpoName; Key = $i.Key; ValueName = $i.Name; Type = $i.Type; Value = $i.Value; Server = $DcName }
        Set-GPRegistryValue @params | Out-Null
        Write-Host ("    {0}\{1} = {2}" -f $i.Key, $i.Name, $i.Value)
        $changed++
    }
    if (-not $changed) { Write-Host '    політики реєстру: без змін' }
}

function Get-OrNewGpo {
    param([string]$Name, [string]$Comment, [string]$DcName)
    $g = Get-GPO -Name $Name -Server $DcName -ErrorAction SilentlyContinue
    if ($g) { Write-Host "    існує: $Name {$($g.Id)}"; return $g }
    $g = New-GPO -Name $Name -Comment $Comment -Server $DcName
    Write-Host "    створено: $Name {$($g.Id)}"
    $g
}

function Add-GpoLinkOnce {
    param([string]$GpoName, [string]$Target, [string]$DcName)
    $links = (Get-GPInheritance -Target $Target -Server $DcName).GpoLinks | ForEach-Object { $_.DisplayName }
    if ($links -contains $GpoName) { Write-Host "    вже прив'язано: $Target"; return }
    New-GPLink -Name $GpoName -Target $Target -LinkEnabled Yes -Server $DcName | Out-Null
    Write-Host "    прив'язано: $Target"
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
    if ($added -eq 0) { Write-Host '    SACL уже налаштовано'; return }
    $de.psbase.CommitChanges()
    Write-Host "    додано правил аудиту: $added на $DomainDn"
}

#endregion
#region ---------------------------------------------------------------- основна частина

if ($MyInvocation.InvocationName -eq '.') { return }   # dot-source для тестів: лише функції

$os = Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -ne 2) { throw 'Запустіть цей скрипт на контролері домену.' }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Запустіть з підвищеними правами (Domain Admin).' }
Import-Module GroupPolicy, ActiveDirectory

$domain = Get-ADDomain
$domainDns = $domain.DNSRoot
$domainDn = $domain.DistinguishedName
$dcName = $env:COMPUTERNAME
# Кілька DN можна передати одним рядком через ';' (DN самі містять коми)
$LinkTargets = @($LinkTargets | ForEach-Object { $_ -split ';' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if (-not $LinkTargets) { $LinkTargets = @($domainDn) }
$dcOu = $domain.DomainControllersContainer

Write-Step "Домен $domainDns, працюємо з DC $dcName"

# ---- 1. пакет
Write-Step "Перевірка пакета $PackagePath"
$mainScript = Join-Path $PackagePath 'Set-SecurityLogging.ps1'
if (-not (Test-Path -LiteralPath $mainScript)) { $mainScript = Join-Path $here 'Set-SecurityLogging.ps1' }
if (-not (Test-Path -LiteralPath $mainScript)) { throw "Set-SecurityLogging.ps1 не знайдено в $PackagePath" }
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
        @{ Rel = 'legacy\10.42\Sysmon.zip'; Pin = $settings.Pins.Legacy1042ZipSha256 }
        @{ Rel = 'legacy\10.42\sysmonconfig-export.xml'; Pin = $settings.Pins.Legacy1042ConfigSha256 }
        @{ Rel = 'legacy\10.2\Sysmon.zip'; Pin = $settings.Pins.Legacy102ZipSha256 }
        @{ Rel = 'legacy\10.2\sysmonconfig-export.xml'; Pin = $settings.Pins.Legacy102ConfigSha256 })) {
    $src = Join-Path $PackagePath $f.Rel
    if (-not (Test-Path -LiteralPath $src)) {
        if (-not $SkipSysmon -and $f.Rel -notlike 'legacy*') { throw "$($f.Rel) відсутній у пакеті. Зберіть його: Set-SecurityLogging.ps1 -BuildPackage $PackagePath" }
        Write-Host "    пропущено (відсутній): $($f.Rel)"; continue
    }
    $h = (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash.ToLower()
    if ($f.Pin -and $h -ne $f.Pin.ToLower()) { throw "$($f.Rel): SHA256 $h не збігається із закріпленим $($f.Pin)" }
    if (-not $f.Pin) { throw "$($f.Rel): у sources.ini немає закріпленого SHA256 - перезберіть пакет через -BuildPackage" }
    Write-Host "    OK $($f.Rel) $h"
    $files += @{ Rel = $f.Rel; Pin = $h; Src = $src }
}

$share = "\\$domainDns\NETLOGON\SecLogging"
$localShare = "\\$dcName\NETLOGON\SecLogging"
Write-Step "Викладаємо пакет у $localShare (реплікується на всі DC через SYSVOL)"
if ($PSCmdlet.ShouldProcess($localShare, 'Копіювання пакета')) {
    foreach ($f in $files) {
        $dst = Join-Path $localShare $f.Rel
        New-Item -ItemType Directory -Path (Split-Path -Parent $dst) -Force | Out-Null
        Copy-Item -LiteralPath $f.Src -Destination $dst -Force
        if ($f.Pin -and (Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash.ToLower() -ne $f.Pin) { throw "Перевірка копії не пройдена: $dst" }
    }
    Write-Host '    скопійовано й перевірено'
}

# ---- 2. командний рядок startup-скрипта
$startupArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$share\Set-SecurityLogging.ps1`" -SourcePath `"$share`" -Quiet"
if ($SkipSysmon) { $startupArgs += ' -SkipSysmon' }
if ($UpgradeSysmon) { $startupArgs += ' -UpgradeSysmon' }
if ($DisablePowerShellV2) { $startupArgs += ' -DisablePowerShellV2' }
if ($AllowLegacySysmon) { $startupArgs += " -AllowLegacySysmon -LegacySysmonVersion $LegacySysmonVersion" }
if ($TranscriptionPath) { $startupArgs += " -TranscriptionPath `"$TranscriptionPath`"" }
$scriptsIni = New-ScriptsIni 'powershell.exe' $startupArgs

# ---- 3. списки політик реєстру
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
        @{ Name = $BaselineGpoName; Role = 'Workstation'; Registry = $common; Links = $LinkTargets; Comment = 'Базове журналювання безпеки: політика аудиту, журналювання PowerShell/NTLM, startup-скрипт Sysmon. Керується New-SecLoggingGpo.ps1' }
        @{ Name = $DcGpoName; Role = 'DomainController'; Registry = $dcRegistry; Links = @($dcOu); Comment = 'Журналювання безпеки для контролерів домену: аудит DC, розміри журналів, аудит NTLM/LDAP. Керується New-SecLoggingGpo.ps1' })) {
    Write-Step "GPO $($g.Name)"
    if (-not $PSCmdlet.ShouldProcess($g.Name, 'Створення/оновлення GPO, політик реєстру, audit.csv, startup-скрипта, прив''язок')) { continue }
    $gpo = Get-OrNewGpo $g.Name $g.Comment $dcName
    Set-GpoRegistryList $g.Name $g.Registry $dcName
    # Базовий audit.csv використовує набір робочої станції (рядові сервери отримують той самий; відрізняється лише File Share).
    # GPO для DC містить повний набір DC, тож результат коректний незалежно від того, чи об'єднуються файли audit.csv.
    $csv = New-AuditCsv $settings.AuditPolicy $g.Role
    if (Update-GpoFiles -Gpo $gpo -AuditCsv $csv -ScriptsIni $scriptsIni -DcName $dcName -DomainDns $domainDns) {
        Write-Host "    audit.csv: підкатегорій $($csv.Count - 1); startup-скрипт налаштовано"
    }
    else { Write-Host "    audit.csv і startup-скрипт: без змін" }
    foreach ($t in $g.Links) { Add-GpoLinkOnce $g.Name $t $dcName }
}

# ---- 5. SACL для DCSync / зловживань ACL
if ($SetDomainRootSacl) {
    Write-Step "SACL на $domainDn (4662 для прав реплікації, WriteDacl/WriteOwner)"
    if ($PSCmdlet.ShouldProcess($domainDn, 'Додавання правил аудиту')) { Set-DomainRootSacl $domainDn $dcName }
}
else {
    Write-Host ''
    Write-Host 'Примітка: без -SetDomainRootSacl подія 4662 для DCSync може не генеруватися.' -ForegroundColor Yellow
}

Write-Host ''
Write-Host 'Готово. Перевірте на клієнті / DC:' -ForegroundColor Green
Write-Host '  gpupdate /force'
Write-Host '  gpresult /h C:\gp.html            (обидві SEC-Logging GPO застосовано?)'
Write-Host '  auditpol /get /category:*'
Write-Host '  після перезавантаження: type C:\ProgramData\SecLogging\last-report.json'

#endregion
