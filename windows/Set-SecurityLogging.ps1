#Requires -Version 2.0
<#
.SYNOPSIS
    Визначає роль хоста, перевіряє та вмикає журнали безпеки й телеметрії,
    Advanced Audit Policy, журналювання PowerShell, аудит NTLM і Sysmon.

.DESCRIPTION
    Порядок роботи: визначення хоста -> читання поточного стану -> застосування
    лише того, чого бракує -> повторне читання й перевірка -> звіт
    (консоль + JSON + подія в журналі Application).

    Сумісний з Windows PowerShell 2.0 (Windows Server 2008 / 2008 R2)
    і до Windows 11 / Server 2025. Усі значення лише підвищуються: розміри
    журналів і налаштування аудиту, які на хості вже більші/суворіші, залишаються.

    Джерела Sysmon (один із трьох способів встановлення):
      1. Online  - без -SourcePath: Sysmon.zip з download.sysinternals.com,
                   конфіг SwiftOnSecurity (закріплений коміт), перевірка SHA256.
      2. Offline - -SourcePath <тека|UNC> з пакетом, зібраним через -BuildPackage.
      3. GPO     - New-SecLoggingGpo.ps1 викладає пакет у NETLOGON і запускає
                   цей скрипт як startup-скрипт комп'ютера (спосіб 2).

.PARAMETER AuditOnly
    Лише показати поточний стан і що буде змінено. Нічого не змінює.

.PARAMETER SourcePath
    Тека або UNC-шлях до офлайн-пакета (зібраного через -BuildPackage).

.PARAMETER Online
    Разом із -SourcePath: докачати з інтернету файли, яких немає в пакеті.

.PARAMETER Role
    Перевизначити визначену роль: Workstation, Server, DomainController.

.PARAMETER SkipSysmon
    Не встановлювати й не налаштовувати Sysmon.

.PARAMETER UpgradeSysmon
    Оновити встановлений Sysmon, старіший за версію з пакета (видалення + встановлення).

.PARAMETER AllowUnpinnedSysmon
    Прийняти Sysmon.zip без закріпленого SHA256 (перевіряється лише дійсний
    підпис Microsoft Authenticode). Використовуйте, лише якщо хеш закріпити неможливо.

.PARAMETER AllowLegacySysmon
    Дозволити встановлення Sysmon на Windows 7 / Server 2008 / 2008 R2 (NT 6.0/6.1).
    Версія - -LegacySysmonVersion; файли з пакета (legacy\<версія>\) або з репозиторію.
    Спершу перевірте на одному хості.

.PARAMETER LegacySysmonVersion
    Sysmon для старих ОС: 10.42 (за замовчуванням, конфіг SwiftOnSecurity схеми 4.22)
    або 10.2 (підтримує схеми лише до 4.21, тому конфіг SwiftOnSecurity схеми 4.00, без DNS-подій).

.PARAMETER ReinstallSysmon
    Якщо встановлена версія Sysmon відрізняється від версії з пакета (старша чи новіша) -
    видалити її й установити версію з пакета (наприклад, перехід з 10.42 на 10.2 для перевірки).
    Якщо версії збігаються, нічого не перевстановлюється.

.PARAMETER DisablePowerShellV2
    Видалити компонент рушія PowerShell 2.0 (Windows 8 / 2012 і новіші).

.PARAMETER TranscriptionPath
    Увімкнути PowerShell Transcription у цю теку (локальна тека отримує ACL лише на запис).

.PARAMETER ConfigureWazuh
    Додати відсутні записи eventchannel <localfile> в ossec.conf локального агента Wazuh.

.PARAMETER SkipAuditPolicy
    Не змінювати Advanced Audit Policy.

.PARAMETER ReportPath
    Шлях до JSON-звіту. За замовчуванням: %ProgramData%\SecLogging\report-<час>.json

.PARAMETER Quiet
    Виводити лише підсумок (для запуску як startup-скрипт GPO).

.PARAMETER BuildPackage
    Зібрати офлайн-пакет у цю теку (потрібен інтернет): завантажує Sysmon і конфіги,
    перевіряє підписи/хеші, копіює цей скрипт, записує sources.ini.

.PARAMETER AcceptNewSysmon
    Разом із -BuildPackage: прийняти Sysmon.zip, хеш якого відрізняється від
    закріпленого (новий реліз Microsoft). Підпис усе одно перевіряється.

.PARAMETER Snapshot
    Записати знімок поточного стану (аудит, журнали, реєстр, Sysmon, Wazuh, GPO) у файл і вийти.
    Нічого не змінює. Знімки "до" і "після" порівнюються через -CompareBefore/-CompareAfter.

.PARAMETER CompareBefore
    Знімок "до" для порівняння (разом з -CompareAfter). Звіт про зміни - у -CompareOut і на екран.

.PARAMETER CompareAfter
    Знімок "після" для порівняння.

.PARAMETER CompareOut
    Файл звіту про зміни (.txt; поруч записується .csv для Excel).

.PARAMETER ExportSettings
    Повернути таблицю налаштувань (використовує New-SecLoggingGpo.ps1).

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
    [ValidateSet('10.42', '10.2')]
    [string]$LegacySysmonVersion = '10.42',
    [switch]$ReinstallSysmon,
    [switch]$DisablePowerShellV2,
    [string]$TranscriptionPath,
    [switch]$ConfigureWazuh,
    [switch]$SkipAuditPolicy,
    [string]$ReportPath,
    [switch]$Quiet,
    [string]$BuildPackage,
    [switch]$AcceptNewSysmon,
    [switch]$ExportSettings,
    [string]$Snapshot,
    [string]$CompareBefore,
    [string]$CompareAfter,
    [string]$CompareOut
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

$ScriptVersion = '1.1.0'
$ScriptPath = $MyInvocation.MyCommand.Path
$ScriptDir = Split-Path -Parent $ScriptPath
$StateRegPath = 'SOFTWARE\SecLogging'
$WorkDir = Join-Path $env:ProgramData 'SecLogging'

# Закріплені джерела. sources.ini поруч зі скриптом (його пише -BuildPackage) перевизначає ці значення.
# SysmonZipSha256 змінюється з кожним релізом Sysmon: заповнюється через -BuildPackage.
$DefaultPins = @{
    SysmonZipUrl          = 'https://download.sysinternals.com/files/Sysmon.zip'
    SysmonZipSha256       = ''
    SysmonVersion         = ''
    ConfigUrl             = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/1836897f12fbd6a0a473665ef6abc34a6b497e31/sysmonconfig-export.xml'
    ConfigSha256          = '055febc600e6d7448cdf3812307275912927a62b1f94d0d933b64b294bc87162'
    # Sysmon для NT 6.0/6.1 зберігається в репозиторії (vendor\sysmon\<версія>, див. README там).
    # 10.42 підтримує схеми конфігу до 4.23 -> SwiftOnSecurity схеми 4.22 (коміт c00581f8).
    # 10.2 підтримує схеми лише до 4.21   -> SwiftOnSecurity схеми 4.00 (коміт 9fb44e98, без DnsQuery).
    Legacy1042ZipUrl      = 'https://raw.githubusercontent.com/egwyl666/sec_journal_on/HEAD/vendor/sysmon/10.42/Sysmon.zip'
    Legacy1042ZipSha256   = '11681051bc9846130f378b5b6441ab27a05e1076dd62f58eda7c973fcf188828'
    Legacy1042ConfigUrl   = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/c00581f8a75671bdb1d79d6193f429ee28dc6adc/sysmonconfig-export.xml'
    Legacy1042ConfigSha256 = 'bf7800825bd025d77fc0af6985f6a08fb201048a772f3085564351b5a0b66e3f'
    Legacy102ZipUrl       = 'https://raw.githubusercontent.com/egwyl666/sec_journal_on/HEAD/vendor/sysmon/10.2/Sysmon.zip'
    Legacy102ZipSha256    = '8a07b9341eb3bc31065eca885c3398acb87da38451939f8cf468b2bdb3cf1ed9'
    Legacy102ConfigUrl    = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/9fb44e9813ccef1e00f8a4bc22a9eb3e2d29023e/sysmonconfig-export.xml'
    Legacy102ConfigSha256 = 'e845a2773fb4d3387cfc0e62bf2349008eeb8d1ff48be0c062fe8fa3cafea910'
}

#region ---------------------------------------------------------------- налаштування

function New-OD { New-Object System.Collections.Specialized.OrderedDictionary }

function Get-SecLoggingSettings {
    # Розміри журналів у МБ за профілем і класом журналу. Класичні журнали - до ~4 ГБ.
    $sizes = @{
        DomainController = @{ Security = 3072; Sysmon = 1536; PowerShell = 1024; System = 384; Application = 256; DirSvc = 512; Other = 192 }
        Server           = @{ Security = 1536; Sysmon = 1024; PowerShell = 768;  System = 256; Application = 256; DirSvc = 256; Other = 192 }
        Workstation      = @{ Security = 768;  Sysmon = 512;  PowerShell = 384;  System = 192; Application = 192; DirSvc = 128; Other = 96 }
        Minimal          = @{ Security = 256;  Sysmon = 256;  PowerShell = 128;  System = 64;  Application = 64;  DirSvc = 128; Other = 32 }
    }

    # N = канал, C = клас розміру, DC = лише на контролерах домену, NoWazuh = лише локально (не слати у Wazuh)
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
        @{ N = 'Microsoft-Windows-Shell-Core/Operational'; C = 'Other' }
        @{ N = 'Microsoft-Windows-GroupPolicy/Operational'; C = 'Other' }
        @{ N = 'Microsoft-Windows-LAPS/Operational'; C = 'Other' }
        @{ N = 'Directory Service'; C = 'DirSvc'; DC = $true }
        @{ N = 'DNS Server'; C = 'Other'; DC = $true }
        @{ N = 'Microsoft-Windows-DNSServer/Audit'; C = 'Other'; DC = $true }
        @{ N = 'DFS Replication'; C = 'Other'; DC = $true }
        @{ N = 'Active Directory Web Services'; C = 'Other'; DC = $true }
    )

    # Advanced Audit Policy за GUID підкатегорії (не залежить від мови ОС).
    # Значення: 0 = не керуємо, 1 = Успіх, 2 = Відмова, 3 = Успіх і відмова.
    $audit = @()
    # Назва|суфікс GUID|Робоча станція|Сервер|DC
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
        # --- DS Access (лише DC)
        'Directory Service Access|923B|0|0|3'
        'Directory Service Changes|923C|0|0|1'
        # --- Logon/Logoff
        'Logon|9215|3|3|3'
        'Logoff|9216|1|1|1'
        'Account Lockout|9217|3|3|3'
        'Special Logon|921B|1|1|1'
        'Other Logon/Logoff Events|921C|3|3|3'
        'Group Membership|9249|1|1|1'
        # --- Object Access (точково, мало шуму)
        'File Share|9224|3|1|3'
        'Detailed File Share|9244|2|2|2'
        'Removable Storage|9245|3|3|3'
        'Other Object Access Events|9227|3|3|3'
        'Certification Services|9221|0|3|3'
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

    # Параметри реєстру. Mode Min = підняти DWORD щонайменше до Value; Exact = встановити як є.
    $pol = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    $core = 'SOFTWARE\Policies\Microsoft\PowerShellCore'
    $registry = @(
        @{ Path = 'SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'SCENoApplyLegacyAuditPolicy'; Type = 'DWord'; Value = 1; Mode = 'Min'; DC = $false; Why = 'Примусово застосовувати підкатегорії аудиту' }
        @{ Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Type = 'DWord'; Value = 1; Mode = 'Min'; DC = $false; Why = 'Командний рядок у 4688' }
        @{ Path = "$pol\ScriptBlockLogging"; Name = 'EnableScriptBlockLogging'; Type = 'DWord'; Value = 1; Mode = 'Min'; DC = $false; Why = 'PowerShell 4104' }
        @{ Path = "$pol\ModuleLogging"; Name = 'EnableModuleLogging'; Type = 'DWord'; Value = 1; Mode = 'Min'; DC = $false; Why = 'PowerShell 4103' }
        @{ Path = "$pol\ModuleLogging\ModuleNames"; Name = '*'; Type = 'String'; Value = '*'; Mode = 'Exact'; DC = $false; Why = 'Module logging для всіх модулів' }
        @{ Path = "$core\ScriptBlockLogging"; Name = 'EnableScriptBlockLogging'; Type = 'DWord'; Value = 1; Mode = 'Min'; DC = $false; Why = 'PowerShell 7 4104' }
        @{ Path = "$core\ModuleLogging"; Name = 'EnableModuleLogging'; Type = 'DWord'; Value = 1; Mode = 'Min'; DC = $false; Why = 'PowerShell 7 4103' }
        @{ Path = "$core\ModuleLogging\ModuleNames"; Name = '*'; Type = 'String'; Value = '*'; Mode = 'Exact'; DC = $false; Why = 'Module logging для PowerShell 7' }
        @{ Path = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'AuditReceivingNTLMTraffic'; Type = 'DWord'; Value = 2; Mode = 'Min'; DC = $false; Why = 'Аудит вхідного NTLM (8001-8003)' }
        @{ Path = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'RestrictSendingNTLMTraffic'; Type = 'DWord'; Value = 1; Mode = 'Min'; DC = $false; Why = 'Аудит вихідного NTLM (8001)' }
        @{ Path = 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'AuditNTLMInDomain'; Type = 'DWord'; Value = 7; Mode = 'Min'; DC = $true; Why = 'Аудит NTLM у домені (8004)' }
        @{ Path = 'SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'; Name = '16 LDAP Interface Events'; Type = 'DWord'; Value = 2; Mode = 'Min'; DC = $true; Why = 'LDAP без підпису / simple bind (2889)' }
    )

    @{ Sizes = $sizes; Channels = $channels; AuditPolicy = $audit; Registry = $registry; Pins = $DefaultPins; ScriptVersion = $ScriptVersion }
}

#endregion
#region ---------------------------------------------------------------- звіт

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

function Format-JsonText {
    # Екранує рядок для JSON (без рекурсії)
    param([string]$Text)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($ch in $Text.ToCharArray()) {
        $code = [int]$ch
        if ($code -eq 34) { [void]$sb.Append('\"') }
        elseif ($code -eq 92) { [void]$sb.Append('\\') }
        elseif ($code -eq 10) { [void]$sb.Append('\n') }
        elseif ($code -eq 13) { [void]$sb.Append('\r') }
        elseif ($code -eq 9) { [void]$sb.Append('\t') }
        elseif ($code -lt 32) { [void]$sb.Append(('\u{0:x4}' -f $code)) }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"')
    $sb.ToString()
}

function ConvertTo-JsonString {
    # Простий JSON-серіалізатор для PowerShell 2.0 (ConvertTo-Json з'явився лише в 3.0).
    # Захист від нескінченної рекурсії: обмеження глибини, розгортання PSObject, самопосилання -> рядок.
    param($Value, [int]$Depth = 0)
    if ($null -eq $Value) { return 'null' }
    $base = $Value
    if ($base -is [System.Management.Automation.PSObject]) { $base = $base.PSObject.BaseObject }
    if ($null -eq $base) { return 'null' }
    if ($Depth -gt 20) { return (Format-JsonText ([string]$base)) }
    $pad = '  ' * $Depth
    $pad1 = '  ' * ($Depth + 1)
    $type = $base.GetType()
    if ($base -is [bool]) { if ($base) { return 'true' } else { return 'false' } }
    if ($base -is [char]) { return (Format-JsonText ([string]$base)) }
    if ($type.IsPrimitive -or $base -is [decimal]) { return $base.ToString([System.Globalization.CultureInfo]::InvariantCulture) }
    if ($base -is [datetime]) { return (Format-JsonText $base.ToString('o')) }
    if ($base -is [string] -or $base -is [guid] -or $base -is [version] -or $base -is [enum]) { return (Format-JsonText ([string]$base)) }
    if ($base -is [System.Collections.IDictionary]) {
        if ($base.Count -eq 0) { return '{}' }
        $parts = @()
        foreach ($k in @($base.Keys)) { $parts += ('{0}{1}: {2}' -f $pad1, (Format-JsonText ([string]$k)), (ConvertTo-JsonString $base[$k] ($Depth + 1))) }
        return "{`n" + ($parts -join ",`n") + "`n$pad}"
    }
    if ($base -is [System.Collections.IEnumerable]) {
        $parts = @()
        foreach ($i in $base) {
            $ib = $i
            if ($ib -is [System.Management.Automation.PSObject]) { $ib = $ib.PSObject.BaseObject }
            if ([object]::ReferenceEquals($ib, $base)) { $parts += ($pad1 + (Format-JsonText ([string]$ib))); continue }
            $parts += ($pad1 + (ConvertTo-JsonString $i ($Depth + 1)))
        }
        if ($parts.Count -eq 0) { return '[]' }
        return "[`n" + ($parts -join ",`n") + "`n$pad]"
    }
    Format-JsonText ([string]$base)
}

#endregion
#region ---------------------------------------------------------------- допоміжні функції

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

function Get-LegacyKey {
    # '10.42' -> 'Legacy1042' (префікс ключів у закріплених значеннях і sources.ini)
    param([string]$Version)
    'Legacy' + $Version.Replace('.', '')
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
    # Запускає зовнішню програму, повертає @{ Code; Output }
    param([string]$FilePath, [string[]]$Arguments)
    # stderr зовнішніх утиліт не повинен ставати фатальною помилкою при ErrorActionPreference=Stop
    $ErrorActionPreference = 'Continue'
    $out = & $FilePath @Arguments 2>&1 | ForEach-Object { [string]$_ }
    @{ Code = $LASTEXITCODE; Output = (($out | Where-Object { $_ -ne '' }) -join "`n") }
}

function Save-Download {
    param([string]$Url, [string]$Destination)
    try {
        # TLS 1.2 (3072) відсутній у enum на .NET 3.5, тому числове значення.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
    }
    catch { Write-Verbose 'TLS 1.2 недоступний у цій версії .NET' }
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
        # .NET < 4.5 (Server 2008 / 2008 R2): zip через Shell
        $shell = New-Object -ComObject Shell.Application
        $zip = $shell.NameSpace($ZipPath)
        if (-not $zip) { throw "Не вдалося відкрити zip $ZipPath (немає .NET 4.5 і підтримки zip у Shell)" }
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
#region ---------------------------------------------------------------- визначення хоста

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
#region ---------------------------------------------------------------- канали журналів подій

# System.Core (.NET 3.5) потрібен для EventLogConfiguration; на 2008 R2 без .NET 3.5.1 - запасний шлях через wevtutil
$Script:HasEventingApi = $false
try {
    [void][Reflection.Assembly]::LoadWithPartialName('System.Core')
    $Script:HasEventingApi = [bool]('System.Diagnostics.Eventing.Reader.EventLogConfiguration' -as [type])
}
catch { $Script:HasEventingApi = $false }

function Get-ChannelState {
    # Стан каналу журналу. Спершу через .NET (System.Core, .NET 3.5+); якщо його немає
    # (Server 2008 R2 без компонента .NET 3.5.1) - через wevtutil gl /f:xml.
    param([string]$Name)
    $st = New-OD
    $st.Name = $Name
    $st.Exists = $false
    if ($Script:HasEventingApi) {
        try {
            $cfg = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($Name)
            $st.Exists = $true
            $st.Enabled = [bool]$cfg.IsEnabled
            $st.MaxBytes = [long]$cfg.MaximumSizeInBytes
            $st.Mode = [string]$cfg.LogMode
            $cfg.Dispose()
        }
        catch { $st.Exists = $false }
        return $st
    }
    $r = Invoke-Native 'wevtutil.exe' @('gl', $Name, '/f:xml')
    if ($r.Code -ne 0 -or -not $r.Output) { return $st }
    $parsed = ConvertFrom-ChannelXml $r.Output
    if (-not $parsed) { return $st }
    foreach ($k in @($parsed.Keys)) { $st[$k] = $parsed[$k] }
    $st
}

function ConvertFrom-ChannelXml {
    # Розбирає вивід "wevtutil gl <канал> /f:xml" -> @{ Exists; Enabled; MaxBytes; Mode }
    param([string]$Xml)
    try { $x = [xml]($Xml -replace '^\s*<\?xml[^>]*\?>', '') } catch { return $null }
    $ch = $x.DocumentElement
    if (-not $ch) { return $null }
    $log = $ch.SelectSingleNode('*[local-name()="logging"]')
    $h = @{ Exists = $true; Enabled = ([string]$ch.GetAttribute('enabled') -eq 'true'); MaxBytes = 0L; Mode = 'Circular' }
    if ($log) {
        $max = $log.SelectSingleNode('*[local-name()="maxSize"]')
        if ($max) { $h.MaxBytes = [long]$max.InnerText }
        $ret = $log.SelectSingleNode('*[local-name()="retention"]')
        $ab = $log.SelectSingleNode('*[local-name()="autoBackup"]')
        if ($ab -and $ab.InnerText -eq 'true') { $h.Mode = 'AutoBackup' }
        elseif ($ret -and $ret.InnerText -eq 'true') { $h.Mode = 'Retain' }
    }
    $h
}

function Get-ChannelPolicy {
    # Адмін-шаблон GPO "Event Log Service" охоплює лише чотири класичні журнали.
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
    # Повертає профіль, приріст якого вміщується в 50% вільного місця; за потреби знижує профіль.
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
        Add-Result 'EventLog' 'Профіль розмірів' 'Warning' ("Недостатньо вільного місця на {0} (вільно {1} МБ): розміри не збільшуються, лише ввімкнення/режим перезапису." -f $env:SystemDrive, $HostInfo.SystemDriveFreeMB)
    }
    elseif ($plan.Profile -ne $RoleName) {
        Add-Result 'EventLog' 'Профіль розмірів' 'Warning' ("Профіль '{0}' не вміщується у вільне місце, використовується '{1}' (+{2} МБ)" -f $RoleName, $plan.Profile, $plan.GrowthMB)
    }
    else {
        Add-Result 'EventLog' 'Профіль розмірів' 'OK' ("{0} (приріст +{1} МБ, вільно {2} МБ)" -f $plan.Profile, $plan.GrowthMB, $HostInfo.SystemDriveFreeMB)
    }

    foreach ($s in $states) {
        $name = $s.Name; $st = $s.State
        if (-not $st.Exists) { Add-Result 'EventLog' $name 'Skipped' 'Каналу немає на цьому хості'; continue }

        $wantBytes = $st.MaxBytes
        if ($plan.Profile) { $wantBytes = [long]$Settings.Sizes[$plan.Profile][$s.Class] * 1MB }
        $policy = Get-ChannelPolicy $name
        $notes = @()
        if ($policy) {
            if ($null -ne $policy.MaxBytes -and $policy.MaxBytes -lt $wantBytes) {
                $notes += ('GPO обмежує розмір до {0} МБ (потрібно {1} МБ) - змініть GPO' -f [long]($policy.MaxBytes / 1MB), [long]($wantBytes / 1MB))
                $wantBytes = $st.MaxBytes
            }
            if ($null -ne $policy.Retention -and [string]$policy.Retention -ne '0') { $notes += "GPO Retention='$($policy.Retention)' (не 'перезаписувати за потреби')" }
            if ($null -ne $policy.AutoBackup -and [string]$policy.AutoBackup -ne '0') { $notes += 'У GPO увімкнено AutoBackupLogFiles' }
        }

        $needEnable = -not $st.Enabled
        $needSize = $wantBytes -gt $st.MaxBytes
        $needMode = $st.Mode -ne 'Circular'
        $before = '{0}; {1} МБ; {2}' -f $(if ($st.Enabled) { 'увімкнено' } else { 'вимкнено' }), [long]($st.MaxBytes / 1MB), $st.Mode

        if (-not ($needEnable -or $needSize -or $needMode)) {
            if ($notes.Count) { Add-Result 'EventLog' $name 'Warning' ($notes -join '; ') $before $before }
            else { Add-Result 'EventLog' $name 'OK' $before $before $before }
            continue
        }
        $target = '{0}; {1} МБ; Circular' -f 'увімкнено', [long]([math]::Max($wantBytes, $st.MaxBytes) / 1MB)
        if ($AuditOnly) { Add-Result 'EventLog' $name 'WouldChange' ((@("-> $target") + $notes) -join '; ') $before $target; continue }

        $wargs = @('sl', $name)
        if ($needEnable) { $wargs += '/e:true' }
        if ($needMode) { $wargs += '/rt:false'; $wargs += '/ab:false' }
        if ($needSize) { $wargs += ('/ms:{0}' -f $wantBytes) }
        $r = Invoke-Native 'wevtutil.exe' $wargs
        $after = Get-ChannelState $name
        $afterText = '{0}; {1} МБ; {2}' -f $(if ($after.Enabled) { 'увімкнено' } else { 'вимкнено' }), [long]($after.MaxBytes / 1MB), $after.Mode
        $ok = $after.Enabled -and $after.Mode -eq 'Circular' -and $after.MaxBytes -ge $wantBytes
        if ($r.Code -eq 0 -and $ok) {
            $status = 'Changed'; if ($notes.Count) { $status = 'Warning' }
            Add-Result 'EventLog' $name $status ((@("$before -> $afterText") + $notes) -join '; ') $before $afterText
        }
        else {
            Add-Result 'EventLog' $name 'Error' ("wevtutil код {0}: {1}; зараз: {2}" -f $r.Code, $r.Output, $afterText) $before $afterText
        }
    }
}

#endregion
#region ---------------------------------------------------------------- політика аудиту

function ConvertFrom-AuditCsv {
    # Розбирає auditpol /backup або audit.csv з GPO; повертає @{ GUID(верхній регістр) = SettingValue }
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
    if ($r.Code -ne 0) { throw "auditpol /backup завершився помилкою: $($r.Output)" }
    try { return (ConvertFrom-AuditCsv (Get-Content -LiteralPath $tmp)) }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}

function Format-AuditValue {
    param([int]$V)
    @('Без аудиту', 'Успіх', 'Відмова', 'Успіх і відмова')[$V]
}

function Invoke-AuditPolicy {
    param($Settings, [string]$RoleName)
    $current = Get-AuditPolicyMap
    $gpoFile = Join-Path $env:SystemRoot 'security\audit\audit.csv'
    $gpo = @{}
    if (Test-Path -LiteralPath $gpoFile) { $gpo = ConvertFrom-AuditCsv (Get-Content -LiteralPath $gpoFile) }
    if ($gpo.Count) { Add-Result 'AuditPolicy' 'GPO' 'OK' ("Advanced Audit Policy надходить із GPO ({0} підкатегорій); локальні зміни можуть бути перезаписані при оновленні GPO" -f $gpo.Count) }

    foreach ($a in $Settings.AuditPolicy) {
        $want = [int]$a[$RoleName]
        if ($want -eq 0) { continue }
        $guid = $a.Guid.ToUpper()
        if ($current.Count -gt 0 -and -not $current.ContainsKey($guid)) {
            # auditpol /backup перелічує всі підкатегорії ОС; якщо GUID немає - його не підтримує ця версія Windows
            Add-Result 'AuditPolicy' $a.Name 'Skipped' 'Підкатегорія не підтримується цією версією Windows'
            continue
        }
        $cur = 0; if ($current.ContainsKey($guid)) { $cur = $current[$guid] }
        $target = $cur -bor $want
        $item = $a.Name
        $gpoNote = ''
        if ($gpo.ContainsKey($guid) -and (($gpo[$guid] -bor $want) -ne $gpo[$guid])) {
            $gpoNote = ('GPO задає {0}, потрібно щонайменше {1} - оновіть GPO' -f (Format-AuditValue $gpo[$guid]), (Format-AuditValue $want))
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
        if ($r.Code -ne 0) { Add-Result 'AuditPolicy' $item 'Error' ("auditpol код {0}: {1}" -f $r.Code, $r.Output) (Format-AuditValue $cur) $null }
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
            if ($gpo.ContainsKey($guid) -and (($gpo[$guid] -bor $a.Pending) -ne $gpo[$guid])) { $status = 'Warning'; $msg += '; GPO це перезапише - оновіть GPO' }
            Add-Result 'AuditPolicy' $a.Name $status $msg (Format-AuditValue $was) (Format-AuditValue $now)
        }
        else { Add-Result 'AuditPolicy' $a.Name 'Error' ('не застосовано, зараз {0}' -f (Format-AuditValue $now)) (Format-AuditValue $was) (Format-AuditValue $now) }
    }
}

#endregion
#region ---------------------------------------------------------------- реєстр

function Invoke-RegistrySettings {
    param($Settings, [string]$RoleName)
    $items = @()
    foreach ($r in $Settings.Registry) { if (-not $r.DC -or $RoleName -eq 'DomainController') { $items += $r } }
    # Центр сертифікації (AD CS): без AuditFilter CA не пише подій 4886-4899 навіть за увімкненого аудиту
    $ca = Get-RegValue 'SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' 'Active'
    if ($ca) {
        $items += @{ Path = "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$ca"; Name = 'AuditFilter'; Type = 'DWord'; Value = 127; Mode = 'Min'; Why = 'Аудит CA (4886-4899); діє після перезапуску служби certsvc' }
    }
    if ($TranscriptionPath) {
        $t = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        $items += @{ Path = $t; Name = 'EnableTranscripting'; Type = 'DWord'; Value = 1; Mode = 'Min'; Why = 'PowerShell Transcription' }
        $items += @{ Path = $t; Name = 'EnableInvocationHeader'; Type = 'DWord'; Value = 1; Mode = 'Min'; Why = 'Мітки часу в Transcription' }
        $items += @{ Path = $t; Name = 'OutputDirectory'; Type = 'String'; Value = $TranscriptionPath; Mode = 'Exact'; Why = 'Тека для Transcription' }
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
        Add-Result 'PowerShell' 'Шара для Transcription' 'Warning' 'UNC-шлях: ACL шари налаштуйте самі (Authenticated Users: лише запис, адміністратори: повний доступ)'
        return
    }
    if (Test-Path -LiteralPath $Path) { Add-Result 'PowerShell' 'Тека Transcription' 'OK' $Path; return }
    if ($AuditOnly) { Add-Result 'PowerShell' 'Тека Transcription' 'WouldChange' "створити $Path з ACL лише на запис"; return }
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    # SYSTEM + Administrators: повний доступ; Authenticated Users: лише запис (не можуть читати чужі транскрипти)
    $r = Invoke-Native 'icacls.exe' @($Path, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-11:(OI)(CI)(W)')
    if ($r.Code -eq 0) { Add-Result 'PowerShell' 'Тека Transcription' 'Changed' "$Path створено, ACL лише на запис" }
    else { Add-Result 'PowerShell' 'Тека Transcription' 'Error' $r.Output }
}

#endregion
#region ---------------------------------------------------------------- PowerShell v2

function Invoke-PowerShellV2Check {
    param($HostInfo)
    if ($HostInfo.IsLegacyOS) { Add-Result 'PowerShell' 'PowerShell 2.0 engine' 'Skipped' 'Стара ОС: v2 - основний рушій, видалити неможливо'; return }
    if (-not (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)) { Add-Result 'PowerShell' 'PowerShell 2.0 engine' 'Skipped' 'Командлети DISM недоступні'; return }
    try { $features = @(Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like 'MicrosoftWindowsPowerShellV2*' }) }
    catch { Add-Result 'PowerShell' 'PowerShell 2.0 engine' 'Error' $_.Exception.Message; return }
    if ($features.Count -eq 0) { Add-Result 'PowerShell' 'PowerShell 2.0 engine' 'OK' 'Відсутній у цій ОС'; return }
    foreach ($f in $features) {
        $state = [string]$f.State
        if ($state -notlike 'Enabled*') { Add-Result 'PowerShell' $f.FeatureName 'OK' "Стан: $state"; continue }
        if (-not $DisablePowerShellV2) { Add-Result 'PowerShell' $f.FeatureName 'Warning' 'PowerShell 2.0 увімкнено (downgrade-атака обходить журналювання). Використайте -DisablePowerShellV2'; continue }
        if ($AuditOnly) { Add-Result 'PowerShell' $f.FeatureName 'WouldChange' 'вимкнути'; continue }
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName $f.FeatureName -NoRestart -WarningAction SilentlyContinue | Out-Null
            Add-Result 'PowerShell' $f.FeatureName 'Changed' 'Вимкнено'
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
    # Шукає файл пакета в -SourcePath або завантажує його (online); перевіряє закріплений SHA256.
    param([string]$RelPath, [string]$Url, [string]$Pin, [string]$Label, [switch]$AllowUnpinned)
    $file = $null
    if ($SourcePath) {
        $candidate = Join-Path $SourcePath $RelPath
        if (Test-Path -LiteralPath $candidate) { $file = $candidate }
        elseif (-not $Online) { throw "$Label не знайдено в пакеті: $candidate" }
    }
    if (-not $file) {
        if (-not $Url) { throw "$Label відсутній у пакеті й не може бути завантажений" }
        $file = Join-Path $WorkDir ('cache\' + $RelPath)
        Save-Download $Url $file
    }
    $hash = Get-FileSha256 $file
    if ($Pin) {
        if ($hash -ne $Pin.ToLower()) { throw "${Label}: SHA256 не збігається: отримано $hash, закріплено $Pin ($file). Новий реліз або підміна - перезберіть пакет через -BuildPackage." }
    }
    elseif (-not $AllowUnpinned) {
        throw "${Label}: немає закріпленого SHA256 (отримано $hash). Зберіть пакет через -BuildPackage або використайте -AllowUnpinnedSysmon."
    }
    @{ Path = $file; Sha256 = $hash }
}

function Invoke-Sysmon {
    param($HostInfo)
    $state = Get-SysmonState
    $desc = 'не встановлено'
    if ($state.Installed) { $desc = '{0} v{1} ({2})' -f $state.ServiceName, $state.Version, $state.State }
    if ($SkipSysmon) { Add-Result 'Sysmon' 'Sysmon' 'Skipped' "-SkipSysmon; зараз: $desc"; return }
    if (-not $state.Installed -and $state.ChannelExists) {
        Add-Result 'Sysmon' 'Sysmon' 'Warning' 'Канал Sysmon існує, але служби Sysmon/Sysmon64 немає: встановлено під іншою назвою? Не чіпаємо.'
        return
    }

    $pins = Get-Pins
    $legacy = $HostInfo.IsLegacyOS
    if ($legacy) {
        if (-not $AllowLegacySysmon) {
            Add-Result 'Sysmon' 'Sysmon' $(if ($state.Installed) { 'OK' } else { 'Warning' }) "Стара ОС ($($HostInfo.OSCaption)): сучасний Sysmon може спричинити зависання/BSOD. Зараз: $desc. Використайте -AllowLegacySysmon (Sysmon $LegacySysmonVersion)."
            return
        }
        if ([version]$HostInfo.OSVersion -ge [version]'6.1') {
            Add-Result 'Sysmon' 'Підтримка SHA-2' 'Warning' 'Server 2008 R2 / Win7: драйверу Sysmon потрібна підтримка підпису SHA-2 (KB4474419 + KB4490628). Перевірте перед встановленням.'
        }
        $lk = Get-LegacyKey $LegacySysmonVersion
        $zipRel = "legacy\$LegacySysmonVersion\Sysmon.zip"; $cfgRel = "legacy\$LegacySysmonVersion\sysmonconfig-export.xml"
        $zipPin = $pins["${lk}ZipSha256"]; $cfgPin = $pins["${lk}ConfigSha256"]; $cfgUrl = $pins["${lk}ConfigUrl"]; $zipUrl = $pins["${lk}ZipUrl"]
    }
    else {
        $zipRel = 'Sysmon.zip'; $cfgRel = 'sysmonconfig-export.xml'
        $zipPin = $pins.SysmonZipSha256; $cfgPin = $pins.ConfigSha256; $cfgUrl = $pins.ConfigUrl; $zipUrl = $pins.SysmonZipUrl
    }

    try {
        $cfg = Resolve-SourceFile $cfgRel $cfgUrl $cfgPin 'Конфіг Sysmon'
        Add-Result 'Sysmon' 'Джерело конфігу' 'OK' ('{0} sha256={1}' -f $cfg.Path, $cfg.Sha256)
    }
    catch { Add-Result 'Sysmon' 'Джерело конфігу' 'Error' $_.Exception.Message; return }

    $configOk = $state.Installed -and $state.AppliedConfigSha256 -eq $cfg.Sha256
    $needInstall = -not $state.Installed
    $zip = $null; $pkgExe = $null; $pkgVersion = $null
    $mightUpgrade = $state.Installed -and ($UpgradeSysmon -or $ReinstallSysmon -or $AuditOnly)
    if ($needInstall -or $mightUpgrade) {
        try {
            $zip = Resolve-SourceFile $zipRel $zipUrl $zipPin 'Sysmon.zip' -AllowUnpinned:$AllowUnpinnedSysmon
            $extract = Join-Path $WorkDir 'sysmon-extract'
            Expand-ZipFile $zip.Path $extract
            $pkgExe = Join-Path $extract (Get-SysmonExeName $HostInfo.Architecture)
            if (-not (Test-Path -LiteralPath $pkgExe)) { throw "$(Split-Path -Leaf $pkgExe) не знайдено в Sysmon.zip" }
            $sig = Test-MicrosoftSignature $pkgExe
            if (-not $sig.Valid) {
                # Стара ОС без інтернету може не мати кореня Microsoft Root CA 2011 (NotTrusted/UnknownError).
                # Тоді довіряємо закріпленому SHA256 (підпис перевірено при додаванні у vendor). Інші статуси - блокуємо.
                if ($legacy -and $zipPin -and ($sig.Status -eq 'NotTrusted' -or $sig.Status -eq 'UnknownError')) {
                    Add-Result 'Sysmon' 'Підпис' 'Warning' ("Підпис не перевірено ({0}): на системі немає кореневого сертифіката Microsoft; файл перевірено за закріпленим SHA256" -f $sig.Status)
                }
                else { throw "Перевірка підпису Authenticode не пройдена: $($sig.Status) $($sig.Subject)" }
            }
            $pkgVersion = Get-VersionFromString (Get-Item -LiteralPath $pkgExe).VersionInfo.FileVersion
            Add-Result 'Sysmon' 'Пакет' 'OK' ('v{0}, sha256={1}, підпис: {2}' -f $pkgVersion, $zip.Sha256, $sig.Status)
        }
        catch {
            Add-Result 'Sysmon' 'Пакет' $(if ($needInstall) { 'Error' } else { 'Warning' }) $_.Exception.Message
            if ($needInstall) { return }
        }
    }

    $installedVersion = Get-VersionFromString $state.Version
    $outdated = $state.Installed -and $pkgVersion -and $installedVersion -and ($installedVersion -lt $pkgVersion)
    $differs = $state.Installed -and $pkgVersion -and $installedVersion -and ($installedVersion -ne $pkgVersion)
    $doReinstall = $differs -and ($ReinstallSysmon -or ($outdated -and $UpgradeSysmon))

    if ($AuditOnly) {
        if ($needInstall) { Add-Result 'Sysmon' 'Sysmon' 'WouldChange' "встановити v$pkgVersion" }
        elseif ($differs -and $ReinstallSysmon) { Add-Result 'Sysmon' 'Sysmon' 'WouldChange' "$desc -> перевстановити v$pkgVersion (-ReinstallSysmon)" }
        elseif ($outdated) { Add-Result 'Sysmon' 'Sysmon' 'WouldChange' "$desc -> v$pkgVersion (потрібен -UpgradeSysmon)" }
        else { Add-Result 'Sysmon' 'Sysmon' 'OK' $desc }
        if (-not $needInstall -and -not $configOk) { Add-Result 'Sysmon' 'Конфіг' 'WouldChange' "застосувати $($cfg.Sha256)" }
        elseif ($configOk) { Add-Result 'Sysmon' 'Конфіг' 'OK' $cfg.Sha256 }
        return
    }

    if ($doReinstall) {
        $r = Invoke-Native $state.Path @('-u', 'force')
        if ($r.Code -ne 0) { Add-Result 'Sysmon' 'Видалення старої версії' 'Error' $r.Output; return }
        Add-Result 'Sysmon' 'Видалення старої версії' 'Changed' "видалено $desc"
        $needInstall = $true
    }
    elseif ($outdated) { Add-Result 'Sysmon' 'Версія' 'Warning' "$desc старіший за пакет v$pkgVersion (використайте -UpgradeSysmon)" }
    elseif ($differs) {
        Add-Result 'Sysmon' 'Версія' 'Warning' "$desc відрізняється від пакета v$pkgVersion (для переходу: -ReinstallSysmon)"
    }

    if ($needInstall) {
        $r = Invoke-Native $pkgExe @('-accepteula', '-i', $cfg.Path)
        $after = Get-SysmonState
        if ($r.Code -eq 0 -and $after.Installed -and $after.State -eq 'Running') {
            Set-RegValue $StateRegPath 'SysmonConfigSha256' $cfg.Sha256 'String'
            Add-Result 'Sysmon' 'Sysmon' 'Changed' ('встановлено {0} v{1}, конфіг {2}' -f $after.ServiceName, $after.Version, $cfg.Sha256)
        }
        else { Add-Result 'Sysmon' 'Sysmon' 'Error' ("встановлення: код {0}: {1}" -f $r.Code, $r.Output) }
        return
    }

    if ($configOk) { Add-Result 'Sysmon' 'Sysmon' 'OK' "$desc, конфіг $($cfg.Sha256)"; return }
    $r = Invoke-Native $state.Path @('-c', $cfg.Path)
    if ($r.Code -eq 0) {
        Set-RegValue $StateRegPath 'SysmonConfigSha256' $cfg.Sha256 'String'
        Add-Result 'Sysmon' 'Конфіг' 'Changed' ('застосовано {0}' -f $cfg.Sha256) $state.AppliedConfigSha256 $cfg.Sha256
    }
    else { Add-Result 'Sysmon' 'Конфіг' 'Error' ("sysmon -c код {0}: {1}" -f $r.Code, $r.Output) }
}

#endregion
#region ---------------------------------------------------------------- знімки стану "до / після"

function Get-AuditSubcategoryNames {
    # Усі підкатегорії Advanced Audit Policy (суфікс GUID 0CCExxxx-69AE-11D9-BED3-505054503030 | англійська назва)
    @('9210|Security State Change', '9211|Security System Extension', '9212|System Integrity', '9213|IPsec Driver', '9214|Other System Events',
        '9215|Logon', '9216|Logoff', '9217|Account Lockout', '9218|IPsec Main Mode', '9219|IPsec Quick Mode', '921A|IPsec Extended Mode',
        '921B|Special Logon', '921C|Other Logon/Logoff Events', '921D|File System', '921E|Registry', '921F|Kernel Object', '9220|SAM',
        '9221|Certification Services', '9222|Application Generated', '9223|Handle Manipulation', '9224|File Share',
        '9225|Filtering Platform Packet Drop', '9226|Filtering Platform Connection', '9227|Other Object Access Events',
        '9228|Sensitive Privilege Use', '9229|Non Sensitive Privilege Use', '922A|Other Privilege Use Events', '922B|Process Creation',
        '922C|Process Termination', '922D|DPAPI Activity', '922E|RPC Events', '922F|Audit Policy Change', '9230|Authentication Policy Change',
        '9231|Authorization Policy Change', '9232|MPSSVC Rule-Level Policy Change', '9233|Filtering Platform Policy Change',
        '9234|Other Policy Change Events', '9235|User Account Management', '9236|Computer Account Management', '9237|Security Group Management',
        '9238|Distribution Group Management', '9239|Application Group Management', '923A|Other Account Management Events',
        '923B|Directory Service Access', '923C|Directory Service Changes', '923D|Directory Service Replication',
        '923E|Detailed Directory Service Replication', '923F|Credential Validation', '9240|Kerberos Service Ticket Operations',
        '9241|Other Account Logon Events', '9242|Kerberos Authentication Service', '9243|Network Policy Server', '9244|Detailed File Share',
        '9245|Removable Storage', '9246|Central Policy Staging', '9247|User / Device Claims', '9248|Plug and Play Events',
        '9249|Group Membership', '924A|Token Right Adjusted Events')
}

function Get-StateSnapshot {
    # Рядки "Область<TAB>Елемент<TAB>Значення" - усе, що скрипт перевіряє або змінює.
    param($Settings)
    $lines = @()
    $names = @{}
    foreach ($pair in (Get-AuditSubcategoryNames)) { $kv = $pair.Split('|'); $names[('0CCE{0}-69AE-11D9-BED3-505054503030' -f $kv[0])] = $kv[1] }
    foreach ($a in $Settings.AuditPolicy) { $names[$a.Guid.ToUpper()] = $a.Name }
    try {
        $map = Get-AuditPolicyMap
        foreach ($g in $map.Keys) {
            $n = $names[$g]; if (-not $n) { $n = "{$g}" }
            $lines += "AuditPolicy`t$n`t$(Format-AuditValue $map[$g])"
        }
    }
    catch { $lines += "AuditPolicy`t(помилка)`t$($_.Exception.Message)" }
    foreach ($c in $Settings.Channels) {
        $st = Get-ChannelState $c.N
        if ($st.Exists) { $v = 'увімкнено={0}; розмір={1} МБ; режим={2}' -f $st.Enabled, [math]::Round([double]$st.MaxBytes / 1MB), $st.Mode }
        else { $v = 'немає в цій ОС' }
        $lines += "EventLog`t$($c.N)`t$v"
    }
    $reg = @($Settings.Registry)
    $t = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    $reg += @{ Path = $t; Name = 'EnableTranscripting' }, @{ Path = $t; Name = 'OutputDirectory' }
    $ca = Get-RegValue 'SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' 'Active'
    if ($ca) { $reg += @{ Path = "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$ca"; Name = 'AuditFilter' } }
    foreach ($r in $reg) {
        $v = Get-RegValue $r.Path $r.Name; if ($null -eq $v) { $v = '(не задано)' }
        $lines += "Registry`t$($r.Path)\$($r.Name)`t$v"
    }
    $sm = Get-SysmonState
    if ($sm.Installed) {
        $lines += "Sysmon`tСлужба`t$($sm.ServiceName) ($($sm.State))"
        $lines += "Sysmon`tВерсія`t$($sm.Version)"
    }
    else { $lines += "Sysmon`tСлужба`tне встановлено" }
    $cfg = $sm.AppliedConfigSha256; if (-not $cfg) { $cfg = '(невідомо)' }
    $lines += "Sysmon`tКонфіг (SHA256)`t$cfg"
    $svc = $null
    foreach ($n in @('WazuhSvc', 'OssecSvc')) { $svc = Get-WmiObject Win32_Service -Filter "Name='$n'"; if ($svc) { break } }
    if ($svc -and [string]$svc.PathName -match '^"?([^"]+?\.exe)') {
        $dir = Split-Path -Parent $Matches[1]
        $lines += "Wazuh`tАгент`t$($svc.State)"
        foreach ($l in @(Get-WazuhLocations @((Join-Path $dir 'ossec.conf'), (Join-Path $dir 'shared\agent.conf')) | Sort-Object -Unique)) { $lines += "Wazuh`t$l`tзбирається" }
    }
    else { $lines += "Wazuh`tАгент`tне встановлено" }
    # GPO (лише там, де є модуль GroupPolicy - зазвичай DC)
    if (Get-Module -ListAvailable -Name GroupPolicy -ErrorAction SilentlyContinue) {
        try {
            Import-Module GroupPolicy -ErrorAction Stop
            foreach ($g in @('SEC-Logging-Baseline', 'SEC-Logging-DomainControllers')) {
                $o = Get-GPO -Name $g -ErrorAction SilentlyContinue
                if ($o) { $lines += "GPO`t$g`tверсія комп'ютера $($o.Computer.DSVersion), змінено $($o.ModificationTime.ToString('yyyy-MM-dd HH:mm'))" }
                else { $lines += "GPO`t$g`tнемає" }
            }
        }
        catch { $lines += "GPO`t(помилка)`t$($_.Exception.Message)" }
    }
    $lines | Sort-Object
}

function Save-StateSnapshot {
    param([string]$Path, [string[]]$Lines, $HostInfo)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $head = @(('# SecLogging знімок стану; {0}; {1} {2}; {3:yyyy-MM-dd HH:mm:ss}; скрипт {4}' -f $env:COMPUTERNAME, $HostInfo.OSCaption, $HostInfo.OSVersion, (Get-Date), $ScriptVersion),
        "# Область`tЕлемент`tЗначення")
    [System.IO.File]::WriteAllLines($Path, [string[]]($head + $Lines), (New-Object System.Text.UTF8Encoding($true)))
}

function Read-StateSnapshot {
    # -> @{ 'Область<TAB>Елемент' = Значення }
    param([string[]]$Lines)
    $h = @{}
    foreach ($l in $Lines) {
        if (-not $l -or $l.StartsWith('#')) { continue }
        $p = $l.Split("`t")
        if ($p.Count -lt 3) { continue }
        $h["$($p[0])`t$($p[1])"] = ($p[2..($p.Count - 1)] -join "`t")
    }
    $h
}

function Compare-StateSnapshot {
    # -> масив @{ Area; Item; Before; After }, відсортований за областю й елементом
    param([string[]]$Before, [string[]]$After)
    $b = Read-StateSnapshot $Before; $a = Read-StateSnapshot $After
    $keys = @($b.Keys) + @($a.Keys) | Sort-Object -Unique
    $out = @()
    foreach ($k in $keys) {
        $vb = $b[$k]; $va = $a[$k]
        if ($vb -eq $va) { continue }
        if ($null -eq $vb) { $vb = '(не було)' }
        if ($null -eq $va) { $va = '(зникло)' }
        $p = $k.Split("`t")
        $out += @{ Area = $p[0]; Item = $p[1]; Before = $vb; After = $va }
    }
    $out
}

function Write-StateComparison {
    # Текстовий звіт (і CSV поруч) про зміни між двома знімками; повертає кількість змін
    param([string]$BeforePath, [string]$AfterPath, [string]$OutPath)
    $enc = New-Object System.Text.UTF8Encoding($true)
    $before = [System.IO.File]::ReadAllLines($BeforePath); $after = [System.IO.File]::ReadAllLines($AfterPath)
    $changes = @(Compare-StateSnapshot $before $after)
    $text = @(
        'SecLogging: що змінилося',
        ('До:    {0}' -f ($before | Select-Object -First 1)),
        ('Після: {0}' -f ($after | Select-Object -First 1)),
        ('Змін: {0}' -f $changes.Count),
        ''
    )
    $area = ''
    foreach ($c in $changes) {
        if ($c.Area -ne $area) { $area = $c.Area; $text += ''; $text += "[$area]" }
        $text += ('  {0}' -f $c.Item)
        $text += ('      було:  {0}' -f $c.Before)
        $text += ('      стало: {0}' -f $c.After)
    }
    if (-not $changes.Count) { $text += 'Змін немає.' }
    if ($OutPath) {
        $dir = Split-Path -Parent $OutPath
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        [System.IO.File]::WriteAllLines($OutPath, [string[]]$text, $enc)
        $csv = @('Область;Елемент;Було;Стало')
        foreach ($c in $changes) { $csv += (@($c.Area, $c.Item, $c.Before, $c.After) | ForEach-Object { '"' + ([string]$_ -replace '"', '""') + '"' }) -join ';' }
        [System.IO.File]::WriteAllLines([System.IO.Path]::ChangeExtension($OutPath, '.csv'), [string[]]$csv, $enc)
    }
    foreach ($l in $text) { Write-Host $l }
    $changes.Count
}

#endregion
#region ---------------------------------------------------------------- Wazuh

function Get-WazuhLocations {
    param([string[]]$Files)
    $loc = @()
    foreach ($f in $Files) {
        if (-not (Test-Path -LiteralPath $f)) { continue }
        $text = [System.IO.File]::ReadAllText($f)
        # власний попередній блок теж враховується як налаштований
        foreach ($m in [regex]::Matches($text, '<location>\s*([^<]+?)\s*</location>')) { $loc += $m.Groups[1].Value.ToLower() }
    }
    $loc
}

function New-WazuhBlock {
    param([string[]]$Channels)
    $lines = @('<!-- SecLogging BEGIN (керується Set-SecurityLogging.ps1) -->', '<ossec_config>')
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
    if (-not $svc) { Add-Result 'Wazuh' 'Агент' 'Warning' 'Агент Wazuh не встановлено - журнали залишаються лише локально'; return }
    $exe = $null
    if ([string]$svc.PathName -match '^"?([^"]+?\.exe)') { $exe = $Matches[1] }
    $dir = Split-Path -Parent $exe
    $conf = Join-Path $dir 'ossec.conf'
    $shared = Join-Path $dir 'shared\agent.conf'
    $ver = ''
    foreach ($vf in @('VERSION', 'VERSION.json')) { $p = Join-Path $dir $vf; if (Test-Path -LiteralPath $p) { $ver = ((Get-Content -LiteralPath $p) -join ' ').Trim(); break } }
    Add-Result 'Wazuh' 'Агент' 'OK' ('{0} ({1}) {2}' -f $svc.Name, $svc.State, $ver)

    $present = Get-WazuhLocations @($conf, $shared)
    $missing = @()
    foreach ($c in $Settings.Channels) {
        if ($c.NoWazuh) { continue }
        if ($c.DC -and $RoleName -ne 'DomainController') { continue }
        if (-not (Get-ChannelState $c.N).Exists) { continue }
        if ($present -notcontains $c.N.ToLower()) { $missing += $c.N }
    }
    if ($missing.Count -eq 0) { Add-Result 'Wazuh' 'eventchannel' 'OK' 'Усі локальні канали безпеки збираються'; return }
    if (-not $ConfigureWazuh) {
        Add-Result 'Wazuh' 'eventchannel' 'Warning' ('Не збираються: {0}. Використайте групу agent.conf на менеджері (wazuh\shared) або -ConfigureWazuh' -f ($missing -join ', '))
        return
    }
    if ($AuditOnly) { Add-Result 'Wazuh' 'eventchannel' 'WouldChange' ('додати {0}' -f ($missing -join ', ')); return }
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
        Add-Result 'Wazuh' 'eventchannel' 'Changed' ('додано {0}; агента перезапущено (резервна копія: ossec.conf.seclogging.bak)' -f ($missing -join ', '))
    }
    catch { Add-Result 'Wazuh' 'eventchannel' 'Error' $_.Exception.Message }
}

#endregion
#region ---------------------------------------------------------------- збирання пакета

function Invoke-BuildPackage {
    param([string]$OutDir)
    $pins = Get-Pins
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    foreach ($lv in @('10.42', '10.2')) { New-Item -ItemType Directory -Path (Join-Path $OutDir "legacy\$lv") -Force | Out-Null }

    Write-Host "Завантаження $($pins.SysmonZipUrl)"
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
        if (-not $sig.Valid) { throw "${exe}: недійсний підпис: $($sig.Status) $($sig.Subject)" }
        $version = Get-VersionFromString (Get-Item -LiteralPath $p).VersionInfo.FileVersion
        Write-Host "  $exe v$version, підпис Microsoft: OK"
    }
    Remove-Item -LiteralPath $ex -Recurse -Force
    if ($pins.SysmonZipSha256 -and $pins.SysmonZipSha256 -ne $zipHash) {
        if (-not $AcceptNewSysmon) { throw "Хеш Sysmon.zip $zipHash відрізняється від закріпленого $($pins.SysmonZipSha256). Новий реліз? Запустіть повторно з -AcceptNewSysmon." }
        Write-Warning "Приймаємо новий Sysmon.zip $zipHash (був $($pins.SysmonZipSha256))"
    }

    $configs = @(@{ Url = $pins.ConfigUrl; Pin = $pins.ConfigSha256; Rel = 'sysmonconfig-export.xml' })
    foreach ($lv in @('10.42', '10.2')) {
        $lk = Get-LegacyKey $lv
        $configs += @{ Url = $pins["${lk}ConfigUrl"]; Pin = $pins["${lk}ConfigSha256"]; Rel = "legacy\$lv\sysmonconfig-export.xml"; Vendor = (Join-Path $ScriptDir "..\vendor\sysmon-config\$lv\sysmonconfig-export.xml") }
    }
    foreach ($c in $configs) {
        $dst = Join-Path $OutDir $c.Rel
        if ($c.Vendor -and (Test-Path -LiteralPath $c.Vendor)) { Copy-Item -LiteralPath $c.Vendor -Destination $dst -Force }
        else {
            Write-Host "Завантаження $($c.Url)"
            Save-Download $c.Url $dst
        }
        $h = Get-FileSha256 $dst
        if ($h -ne $c.Pin) { throw "$($c.Rel): хеш $h не збігається із закріпленим $($c.Pin)" }
        Write-Host "  $($c.Rel) sha256: OK"
    }

    # Sysmon для старих ОС: vendor\sysmon\<версія> з клону, інакше завантаження з репозиторію; хеш закріплено
    foreach ($lv in @('10.42', '10.2')) {
        $lk = Get-LegacyKey $lv
        $dst = Join-Path $OutDir "legacy\$lv\Sysmon.zip"
        $vendorZip = Join-Path $ScriptDir "..\vendor\sysmon\$lv\Sysmon.zip"
        if (Test-Path -LiteralPath $vendorZip) { Copy-Item -LiteralPath $vendorZip -Destination $dst -Force }
        else {
            Write-Host "Завантаження $($pins["${lk}ZipUrl"])"
            Save-Download $pins["${lk}ZipUrl"] $dst
        }
        $h = Get-FileSha256 $dst
        if ($h -ne $pins["${lk}ZipSha256"]) { throw "legacy\$lv\Sysmon.zip: хеш $h не збігається із закріпленим $($pins["${lk}ZipSha256"])" }
        $ex = Join-Path $env:TEMP ('sysmon-' + [guid]::NewGuid())
        Expand-ZipFile $dst $ex
        foreach ($exe in @('Sysmon.exe', 'Sysmon64.exe')) {
            $p = Join-Path $ex $exe
            if (-not (Test-Path -LiteralPath $p)) { continue }
            $sig = Test-MicrosoftSignature $p
            if (-not $sig.Valid) { throw "legacy $lv ${exe}: недійсний підпис: $($sig.Status)" }
        }
        Remove-Item -LiteralPath $ex -Recurse -Force
        Write-Host "  legacy Sysmon $lv sha256 OK, підпис Microsoft: OK"
    }

    Copy-Item -LiteralPath $ScriptPath -Destination (Join-Path $OutDir 'Set-SecurityLogging.ps1') -Force
    $ini = @(
        "; Згенеровано Set-SecurityLogging.ps1 -BuildPackage $(Get-Date -Format s)"
        "SysmonZipUrl=$($pins.SysmonZipUrl)"
        "SysmonZipSha256=$zipHash"
        "SysmonVersion=$version"
        "ConfigUrl=$($pins.ConfigUrl)"
        "ConfigSha256=$($pins.ConfigSha256)"
        "Legacy1042ZipUrl=$($pins.Legacy1042ZipUrl)"
        "Legacy1042ZipSha256=$($pins.Legacy1042ZipSha256)"
        "Legacy1042ConfigUrl=$($pins.Legacy1042ConfigUrl)"
        "Legacy1042ConfigSha256=$($pins.Legacy1042ConfigSha256)"
        "Legacy102ZipUrl=$($pins.Legacy102ZipUrl)"
        "Legacy102ZipSha256=$($pins.Legacy102ZipSha256)"
        "Legacy102ConfigUrl=$($pins.Legacy102ConfigUrl)"
        "Legacy102ConfigSha256=$($pins.Legacy102ConfigSha256)"
    )
    [System.IO.File]::WriteAllLines((Join-Path $OutDir 'sources.ini'), $ini)
    Write-Host ''
    Write-Host "Пакет готовий: $OutDir" -ForegroundColor Green
    Write-Host 'Закомітьте sources.ini у репозиторій (windows\sources.ini), щоб online-встановлення теж перевірялося за хешем.'
}

#endregion
#region ---------------------------------------------------------------- основна частина

if ($ExportSettings) { return (Get-SecLoggingSettings) }

# 32-бітний PowerShell на 64-бітній Windows потрапить під перенаправлення реєстру/файлів: перезапуск у 64-біт.
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

if ($CompareBefore -or $CompareAfter) {
    if (-not ($CompareBefore -and $CompareAfter)) { Write-Host 'Потрібні обидва: -CompareBefore і -CompareAfter.' -ForegroundColor Red; exit 64 }
    try { $null = Write-StateComparison $CompareBefore $CompareAfter $CompareOut; exit 0 }
    catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 2 }
}

if (-not (Test-IsAdmin)) { Write-Error 'Запустіть від імені адміністратора (з підвищеними правами).'; exit 3 }

if ($Snapshot) {
    try { Save-StateSnapshot $Snapshot (Get-StateSnapshot (Get-SecLoggingSettings)) (Get-HostInfo); Write-Host "Знімок стану: $Snapshot"; exit 0 }
    catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 2 }
}

$mutex = New-Object System.Threading.Mutex($false, 'Global\SecLoggingRun')
if (-not $mutex.WaitOne(0)) { Write-Host 'Інший запуск Set-SecurityLogging уже виконується, вихід.'; exit 0 }

try {
    if (-not (Test-Path -LiteralPath $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }
    $started = Get-Date
    $settings = Get-SecLoggingSettings
    $hostInfo = Get-HostInfo
    $roleName = $hostInfo.DetectedRole
    if ($Role -ne 'Auto') { $roleName = $Role }

    if (-not $Quiet) {
        Write-Host ''
        Write-Host ('Set-SecurityLogging {0}  режим: {1}' -f $ScriptVersion, $(if ($AuditOnly) { 'ЛИШЕ ПЕРЕВІРКА' } else { 'ЗАСТОСУВАННЯ' })) -ForegroundColor White
        Write-Host ('{0}: {1} ({2}), роль {3}, домен {4}, {5}, PS {6}, вільно {7} МБ' -f $hostInfo.ComputerName, $hostInfo.OSCaption, $hostInfo.OSVersion, $roleName, $(if ($hostInfo.PartOfDomain) { $hostInfo.Domain } else { '-' }), $hostInfo.Architecture, $hostInfo.PSVersion, $hostInfo.SystemDriveFreeMB)
        if ($SourcePath) { Write-Host "Джерело: пакет $SourcePath" } else { Write-Host 'Джерело: online (закріплені URL)' }
        Write-Host ''
    }
    Add-Result 'Host' 'Роль' 'OK' ('{0} (визначено {1}, стара ОС: {2})' -f $roleName, $hostInfo.DetectedRole, $hostInfo.IsLegacyOS)

    # Спершу Sysmon: його канал має існувати до налаштування розмірів.
    foreach ($step in @(
            @{ Name = 'Sysmon'; Block = { Invoke-Sysmon $hostInfo } }
            @{ Name = 'Registry'; Block = { Invoke-RegistrySettings $settings $roleName } }
            @{ Name = 'AuditPolicy'; Block = { if ($SkipAuditPolicy) { Add-Result 'AuditPolicy' 'AuditPolicy' 'Skipped' '-SkipAuditPolicy' } else { Invoke-AuditPolicy $settings $roleName } } }
            @{ Name = 'PowerShell'; Block = { Invoke-PowerShellV2Check $hostInfo } }
            @{ Name = 'EventLog'; Block = { Invoke-Channels $settings $roleName $hostInfo } }
            @{ Name = 'Wazuh'; Block = { Invoke-Wazuh $settings $roleName } }
        )) {
        try { & $step.Block }
        catch { Add-Result $step.Name 'Крок завершився помилкою' 'Error' $_.Exception.Message }
    }

    if (-not $AuditOnly) {
        Set-RegValue $StateRegPath 'LastRun' (Get-Date -Format s) 'String'
        Set-RegValue $StateRegPath 'ScriptVersion' $ScriptVersion 'String'
    }

    $summary = 'OK={0} Changed={1} WouldChange={2} Warning={3} Error={4} Skipped={5}' -f $Script:Counts.OK, $Script:Counts.Changed, $Script:Counts.WouldChange, $Script:Counts.Warning, $Script:Counts.Error, $Script:Counts.Skipped
    # Не $report: у PowerShell імена змінних без урахування регістру, і на рівні скрипта
    # $report - це той самий $Script:Report (список результатів). Звідси колись звіт "сам у собі".
    $reportDoc = New-OD
    $reportDoc.Tool = 'Set-SecurityLogging'
    $reportDoc.Version = $ScriptVersion
    $reportDoc.Mode = $(if ($AuditOnly) { 'AuditOnly' } else { 'Apply' })
    $reportDoc.Started = $started
    $reportDoc.Finished = Get-Date
    $reportDoc.Host = $hostInfo
    $reportDoc.Role = $roleName
    $reportDoc.Source = $(if ($SourcePath) { $SourcePath } else { 'online' })
    $reportDoc.Summary = $Script:Counts
    $reportDoc.Results = $Script:Report
    if (-not $ReportPath) { $ReportPath = Join-Path $WorkDir ('report-{0:yyyyMMdd-HHmmss}.json' -f $started) }
    try { $json = ConvertTo-JsonString $reportDoc }
    catch {
        Write-Host "Не вдалося сформувати JSON-звіт: $($_.Exception.Message)" -ForegroundColor Yellow
        $json = '{ "Tool": "Set-SecurityLogging", "Error": ' + (Format-JsonText ([string]$_.Exception.Message)) + ', "Summary": ' + (Format-JsonText $summary) + ' }'
    }
    [System.IO.File]::WriteAllText($ReportPath, $json, (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $WorkDir 'last-report.json'), $json, (New-Object System.Text.UTF8Encoding($false)))

    if (-not $AuditOnly) {
        # Підсумкова подія для SIEM (журнал Application, джерело SecLogging): 1000 - ок, 1001 - попередження, 1002 - помилки.
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists('SecLogging')) { New-EventLog -LogName Application -Source SecLogging }
            $id = 1000; $type = 'Information'
            if ($Script:Counts.Warning) { $id = 1001; $type = 'Warning' }
            if ($Script:Counts.Error) { $id = 1002; $type = 'Error' }
            $problems = @($Script:Report | Where-Object { $_.Status -eq 'Error' -or $_.Status -eq 'Warning' } | ForEach-Object { '{0} | {1} | {2} | {3}' -f $_.Status, $_.Area, $_.Item, $_.Message })
            Write-EventLog -LogName Application -Source SecLogging -EventId $id -EntryType $type -Message ("Set-SecurityLogging $ScriptVersion role=$roleName $summary`r`n" + ($problems -join "`r`n"))
        }
        catch { Write-Verbose "Не вдалося записати підсумкову подію: $($_.Exception.Message)" }
    }

    Write-Host ''
    Write-Host "Підсумок: $summary" -ForegroundColor White
    Write-Host "Звіт:     $ReportPath"
    if ($Script:Counts.Error) { exit 2 }
    exit 0
}
finally {
    $mutex.ReleaseMutex()
    $mutex.Close()
}

#endregion
