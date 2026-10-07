# sec_journal_on — увімкнення журналів безпеки та телеметрії

[English](README.md) | **Українська**

Скрипти для Windows (робочі станції, сервери, контролери домену) і Linux, які:

1. **визначають, що це за машина**: роль, ОС, членство в домені, мова, архітектура, вільне місце;
2. **перевіряють поточний стан** журналів, політики аудиту, Sysmon і Wazuh;
3. **вмикають або підвищують лише те, чого бракує**: розміри журналів тільки ростуть, налаштування аудиту тільки додаються;
4. **перевіряють результат** і пишуть звіт (консоль + JSON + подія для SIEM).

Кожен скрипт має режим «лише подивитися» (`-AuditOnly` / `--check`), який показує, що буде змінено.

```
windows/Set-SecurityLogging.ps1   єдиний скрипт для будь-якої Windows (WS / Server / DC), PowerShell 2.0+
windows/New-SecLoggingGpo.ps1     надбудова GPO для домену (запускати на DC)
windows/Start-SecLogging.ps1      одна команда для будь-кого: завантажити, визначити, налаштувати, звіт до/після
windows/Install-SecLogging.ps1    автоматизація: завантажити -> зібрати пакет -> встановити / шара / GPO
linux/set-security-logging.sh     єдиний скрипт для будь-якого Linux (сімейства deb, rpm, SUSE, Arch, Alpine; див. таблицю)
linux/install.sh                  автоматизація: офлайн-комплект (build) і встановлення (онлайн або --from)
vendor/sysmon/10.42, 10.2/        Sysmon для Windows 7 / 2008 / 2008 R2 (перевірено, хеш закріплено)
vendor/sysmon-config/             конфіги SwiftOnSecurity для цих версій (CC BY 4.0, хеш закріплено)
windows/lab/Test-LegacySysmon.ps1 стендова перевірка legacy Sysmon у VM (одна команда)
wazuh/shared/<група>/agent.conf   централізований збір журналів для груп менеджера Wazuh
tests/                            тести (pwsh + docker)
```

> Довідка, коментарі та повідомлення в консолі всередині скриптів — українською. Машиночитані значення залишені англійською: статуси (`OK`, `Changed`, `WouldChange`, `Warning`, `Error`, `Skipped`), ключі JSON, назви параметрів і журналів. Так простіше писати правила й фільтри в SIEM.
> Файли `.ps1` збережено в **UTF-8 з BOM**. Без BOM Windows PowerShell 5.1/2.0 неправильно читає кирилицю. Якщо редагуєте скрипти, зберігайте BOM.

## Одна команда (без роздумів)

Відкрийте **PowerShell або cmd від імені адміністратора** (Windows; той самий рядок працює в обох) чи root-консоль (Linux), вставте один рядок і дочекайтеся `ГОТОВО`. Потрібен інтернет.

**Windows** (10/11, Server 2008 R2 … 2025, контролери домену):

```
powershell -NoProfile -ExecutionPolicy Bypass -Command "try{[Net.ServicePointManager]::SecurityProtocol=3072}catch{}; & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString((New-Object Net.WebClient).DownloadData('https://raw.githubusercontent.com/egwyl666/sec_journal_on/v1.3.4/windows/Start-SecLogging.ps1')).TrimStart([char]0xFEFF)))"
```

**Linux** (будь-який дистрибутив із таблиці нижче; рядок використовує `curl`, а де його немає — `wget`, наприклад на Ubuntu Desktop):

```bash
(curl -fsSL https://raw.githubusercontent.com/egwyl666/sec_journal_on/v1.3.4/linux/install.sh 2>/dev/null || wget -qO- https://raw.githubusercontent.com/egwyl666/sec_journal_on/v1.3.4/linux/install.sh) | sudo bash
```

Що відбувається:

1. Скрипти завантажуються з GitHub.
2. Визначається тип машини: робоча станція, сервер, контролер домену, стара ОС (2008 / 2008 R2 / Win7), дистрибутив Linux.
3. Зберігається знімок поточного стану («до»).
4. Вмикається все, чого бракує: журнали та їхні розміри, політика аудиту, журналювання PowerShell, Sysmon (Windows), auditd і journald (Linux), збір агентом Wazuh, якщо він встановлений. На **контролері домену** додатково створюються доменні GPO, щоб кожна машина домену налаштовувалася сама при завантаженні, і вмикається аудит DCSync.
5. Зберігається другий знімок («після») і **записується все, що змінилося, у вигляді «було → стало»**.

Результати:

| | Windows | Linux |
|---|---|---|
| Що змінилося (було → стало) | `C:\ProgramData\SecLogging\changes\<час>-changes.txt` (+ `.csv` для Excel) | `/var/log/seclogging/changes/<час>-changes.txt` |
| Повні знімки | `...\changes\<час>-before.tsv`, `<час>-after.tsv` | та сама тека |
| Детальний звіт | `C:\ProgramData\SecLogging\last-report.json` | `/var/log/seclogging/last-report.json` |

Повторний запуск безпечний: змінюється лише те, чого бракує, і повторний запуск покаже `Змін немає`.

Подивитися, що змінилося після запуску:

```powershell
# Windows (PowerShell)
Get-Content (Get-ChildItem C:\ProgramData\SecLogging\changes\*-changes.txt | Sort-Object LastWriteTime | Select-Object -Last 1).FullName -Encoding UTF8
```
```bash
# Linux
sudo sh -c 'cat "$(ls -t /var/log/seclogging/changes/*-changes.txt | head -1)"'
```

Приклад (Ubuntu, перший запуск):

```
[auditd.conf]
  max_log_file
      було:  (не задано)
      стало: 100
```

Лише перевірка, нічого не змінювати:

```
powershell -NoProfile -ExecutionPolicy Bypass -Command "try{[Net.ServicePointManager]::SecurityProtocol=3072}catch{}; & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString((New-Object Net.WebClient).DownloadData('https://raw.githubusercontent.com/egwyl666/sec_journal_on/v1.3.4/windows/Start-SecLogging.ps1')).TrimStart([char]0xFEFF))) -AuditOnly"
```
```bash
(curl -fsSL https://raw.githubusercontent.com/egwyl666/sec_journal_on/v1.3.4/linux/install.sh 2>/dev/null || wget -qO- https://raw.githubusercontent.com/egwyl666/sec_journal_on/v1.3.4/linux/install.sh) | sudo bash -s -- --check
```

Машина без інтернету: завантажте `https://github.com/egwyl666/sec_journal_on/archive/refs/tags/v1.3.4.zip` на іншому комп'ютері, перенесіть і запустіть `powershell -ExecutionPolicy Bypass -File <розпаковано>\windows\Start-SecLogging.ps1 -Source <шлях до zip>` (Linux: офлайн-комплект, див. нижче).

Порівняти будь-які два знімки пізніше: `Set-SecurityLogging.ps1 -CompareBefore a.tsv -CompareAfter b.tsv -CompareOut changes.txt` / `set-security-logging.sh --compare a.tsv b.tsv`.

### Версії та оновлення

Команди вище закріплені на **релізі** (`v1.3.4`), а не на останньому коміті: зміна в репозиторії не потрапить на машини, доки не вийде новий реліз, і зламана гілка не зможе розіслати код на всі машини. Щоб розгорнути новий реліз, замініть у команді `v1.3.4` на новий тег. `-Ref HEAD` (Windows) / `-s -- --ref HEAD` (Linux) запускає останню версію з розробки для перевірки.

## Швидкий старт (автоматично)

Установники роблять «завантажити → зібрати пакет → встановити» однією командою. Окремі кроки нижче виконувати не обов'язково, якщо не хочете.

**Windows** (PowerShell від адміністратора):

```powershell
# машина з інтернетом: завантажити установник з GitHub і запустити (вставити в PowerShell)
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
$f = "$env:TEMP\Install-SecLogging.ps1"
(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/egwyl666/sec_journal_on/v1.3.4/windows/Install-SecLogging.ps1', $f)
powershell -ExecutionPolicy Bypass -File $f -Fetch -AuditOnly

# з клону репозиторію (спершу дозволити скрипти лише в цьому вікні;
# для ZIP, завантаженого з GitHub, також зняти позначку "завантажено з інтернету")
Set-ExecutionPolicy -Scope Process Bypass -Force
Get-ChildItem -Recurse | Unblock-File
.\windows\Install-SecLogging.ps1 -AuditOnly                                 # лише перевірка
.\windows\Install-SecLogging.ps1                                            # зібрати пакет + встановити тут
.\windows\Install-SecLogging.ps1 -Mode Build -UpdateRepoPins                # лише зібрати, записати windows\sources.ini
.\windows\Install-SecLogging.ps1 -Mode Share -SharePath \\fileserver\SecLogging  # викласти для машин без інтернету
.\windows\Install-SecLogging.ps1 -Mode Domain -WhatIfGpo                    # на DC1: пакет + пробний прогін GPO
.\windows\Install-SecLogging.ps1 -Mode Domain -SetDomainRootSacl            # на DC1: пакет + GPO
```

| Режим | Що робить |
|---|---|
| `Local` (за замовчуванням) | за потреби збирає пакет (`%ProgramData%\SecLogging\package`), потім запускає на цій машині `Set-SecurityLogging.ps1 -SourcePath <пакет>` |
| `Build` | лише збирає пакет; `-UpdateRepoPins` копіює новий `sources.ini` у `windows\` клону, щоб його закомітити |
| `Share` | збирає пакет і копіює його в `-SharePath`, повторно перевіряючи кожен хеш на шарі; також копіює `lab\` і створює `updates\` та `results\` |
| `Domain` | збирає пакет і запускає з ним `New-SecLoggingGpo.ps1` (`-WhatIfGpo` — пробний прогін, `-LinkTargets`, `-SetDomainRootSacl`) |

- Коректний пакет використовується повторно. `-Rebuild` збирає його заново, а `-NoBuild` на машині без інтернету бере лише наявний пакет.
- `-Fetch` завантажує скрипти архівом з GitHub (`-RepoRef` — гілка/тег/коміт, типово закріплений реліз `v1.3.4`).
- Усі параметри `Set-SecurityLogging.ps1` (`-AuditOnly`, `-SkipSysmon`, `-UpgradeSysmon`, `-DisablePowerShellV2`, `-ConfigureWazuh`, `-AllowLegacySysmon`, `-LegacySysmonVersion`, `-ReinstallSysmon`, `-TranscriptionPath`, …) передаються далі.

**Linux** (root):

```bash
# одним рядком на хості з інтернетом
curl -fsSL https://raw.githubusercontent.com/egwyl666/sec_journal_on/v1.3.4/linux/install.sh -o install.sh && sudo bash install.sh --fetch --check

# з клону
sudo ./linux/install.sh --check                      # лише перевірка
sudo ./linux/install.sh --configure-wazuh            # встановити онлайн
sudo ./linux/install.sh build                        # офлайн-комплект для цього дистрибутива/версії/архітектури
sudo ./seclogging-bundle-*/install.sh --from ./seclogging-bundle-ubuntu-22.04-x86_64   # на хості без інтернету
```

`build` створює теку комплекту, у якій:
- обидва скрипти;
- пакет `auditd` разом із **повним деревом залежностей**;
- `SHA256SUMS`;
- `bundle.info` — для якого дистрибутива, версії й архітектури зібрано комплект.

`install --from` перевіряє `SHA256SUMS` і відмовляється працювати зі зміненим комплектом. Він встановлює лише відсутні на хості або старіші пакети й ніколи не відкочує версії, а потім запускає `set-security-logging.sh`. Збирайте комплект на тому самому дистрибутиві, версії та архітектурі, що й цільові хости. Інші параметри (`--check`, `--configure-wazuh`, `--profile`, `--immutable`, …) передаються в `set-security-logging.sh`.

---

## Windows

### Три способи встановлення

| Спосіб | Коли | Як |
|---|---|---|
| **1. Online** | є інтернет, машина поза доменом або разовий запуск | `Set-SecurityLogging.ps1`: Sysmon завантажується з `download.sysinternals.com`, конфіг — з GitHub (закріплений коміт). Усе перевіряється за SHA256 |
| **2. Офлайн-пакет** | немає інтернету (флешка, мережева шара) | один раз зібрати пакет через `-BuildPackage`, потім запускати `Set-SecurityLogging.ps1 -SourcePath <тека або \\server\share>` |
| **3. GPO** | доменні машини | на DC: `New-SecLoggingGpo.ps1` викладає пакет у `NETLOGON\SecLogging` і створює GPO зі startup-скриптом (спосіб 2 при кожному завантаженні) та політикою аудиту |

### Крок 0. Зібрати пакет і закріпити хеш Sysmon (один раз, на машині з інтернетом)

```powershell
.\windows\Set-SecurityLogging.ps1 -BuildPackage D:\SecLogging
```

Скрипт:
- завантажує `Sysmon.zip`;
- перевіряє **підпис Microsoft** (Authenticode) у `Sysmon.exe`, `Sysmon64.exe` і `Sysmon64a.exe`;
- рахує SHA256;
- завантажує конфіги SwiftOnSecurity (їхні хеші вже закріплені в скрипті);
- записує `sources.ini` з усіма хешами.

**Скопіюйте `D:\SecLogging\sources.ini` у `windows\sources.ini` і закомітьте.** Після цього й online-встановлення перевірятиме Sysmon.zip за закріпленим хешем.

> Хеш `Sysmon.zip` змінюється з кожним релізом Microsoft. Якщо хеш не збігся, скрипт **зупиняється**: це або новий реліз, або підміна. Щоб оновити, запустіть `-BuildPackage ... -AcceptNewSysmon` (підпис однаково перевіряється) і знову закомітьте `sources.ini`.
> Без закріпленого хешу online-встановлення Sysmon відмовить. Обійти це можна лише явно: `-AllowUnpinnedSysmon`, тоді залишиться тільки перевірка підпису.

### Способи 1 і 2: запуск на машині

```powershell
# подивитися, що буде зроблено (нічого не змінює)
powershell -ExecutionPolicy Bypass -File .\Set-SecurityLogging.ps1 -AuditOnly

# застосувати (online)
powershell -ExecutionPolicy Bypass -File .\Set-SecurityLogging.ps1

# застосувати з пакета
powershell -ExecutionPolicy Bypass -File .\Set-SecurityLogging.ps1 -SourcePath \\fileserver\SecLogging
```

| Параметр | Що робить |
|---|---|
| `-AuditOnly` | лише звіт, нічого не змінює |
| `-Role Workstation\|Server\|DomainController` | перевизначити визначену роль |
| `-SkipSysmon` / `-UpgradeSysmon` | не чіпати Sysmon / оновити стару версію (видалення + встановлення) |
| `-DisablePowerShellV2` | видалити компонент PowerShell 2.0 (див. нижче) |
| `-TranscriptionPath <шлях>` | увімкнути PowerShell Transcription (локальна тека отримує ACL лише на запис) |
| `-ConfigureWazuh` | додати відсутні `eventchannel` в `ossec.conf` локального агента |
| `-AllowLegacySysmon` | дозволити Sysmon на 2008/2008 R2/Win7 (див. нижче) |
| `-Quiet` | виводити лише підсумок (для GPO) |

Результат:
- JSON-звіт у `C:\ProgramData\SecLogging\last-report.json`;
- подія в журналі **Application**, джерело `SecLogging`: ID 1000 — усе гаразд, 1001 — є попередження, 1002 — є помилки. За нею у Wazuh зручно шукати машини, де налаштування «роз'їхалися».

Коди виходу: `0` — успіх, `2` — були помилки, `3` — запущено не від адміністратора.

### Спосіб 3: GPO (на DC1)

```powershell
# пробний прогін
.\windows\New-SecLoggingGpo.ps1 -PackagePath D:\SecLogging -WhatIf

# застосувати + SACL на корінь домену для 4662 (DCSync)
.\windows\New-SecLoggingGpo.ps1 -PackagePath D:\SecLogging -SetDomainRootSacl
```

Скрипт створює **дві окремі GPO**. Default Domain Policy і Default Domain Controllers Policy не змінюються.

| GPO | Прив'язка | Вміст |
|---|---|---|
| `SEC-Logging-Baseline` | корінь домену (або `-LinkTargets`) | Advanced Audit Policy (набір для WS/Server), примусові підкатегорії, командний рядок у 4688, ScriptBlock/Module logging PowerShell (5.1 і 7), аудит NTLM, startup-скрипт |
| `SEC-Logging-DomainControllers` | OU=Domain Controllers | повний набір аудиту DC (Kerberos, DS Access…), розміри Security/System/Application для DC, `AuditNTLMInDomain`, діагностика LDAP (2889), startup-скрипт |

Startup-скрипт при кожному завантаженні запускає `\\domain\NETLOGON\SecLogging\Set-SecurityLogging.ps1 -SourcePath ... -Quiet`. Він вмикає operational-журнали, виставляє розміри за роллю, встановлює або перевіряє Sysmon. Якщо все вже налаштовано, повторні запуски нічого не змінюють.

Advanced Audit Policy не можна задати через `Set-GPRegistryValue`. Тому скрипт сам записує `audit.csv` у SYSVOL, реєструє клієнтське розширення в `gPCMachineExtensionNames` і підвищує версію GPO. **Цю частину обов'язково перевірте на стенді:**

```cmd
gpupdate /force
gpresult /h C:\gp.html          :: обидві SEC-Logging GPO застосовано?
auditpol /get /category:*        :: підкатегорії виставлено?
type C:\ProgramData\SecLogging\last-report.json   :: після перезавантаження
```

Буває, що на машину вже приходить GPO з меншими розмірами журналів або слабшим аудитом, ніж у нас. Локальний скрипт **це бачить і пише Warning**, а не вдає, що зміни застосовано.

Якщо в домені вже є GPO з Advanced Audit Policy, Windows при кожному оновленні політик (на DC — кожні 5 хвилин) замінює **всю** локальну політику аудиту результатом GPO. Підкатегорії, яких у GPO немає, повертаються до «Без аудиту». Тому на таких машинах локальні зміни `auditpol` тимчасові (у звіті вони позначені Warning), і закріпити їх може лише GPO. Через це `Start-SecLogging.ps1` на DC завжди виконує крок GPO, навіть якщо налаштування самого DC завершилося з помилками. Налаштування аудиту з кількох GPO об'єднуються по підкатегоріях. Якщо наявна GPO задає ту саму підкатегорію слабше і має вищий пріоритет (наприклад, меншим порядком прив'язки на OU=Domain Controllers), діє її значення. Підніміть `SEC-Logging-DomainControllers` у порядку прив'язки або виправте ту GPO.

### Що налаштовується

**Журнали.** Вимкнені журнали вмикаються. Розміри тільки ростуть. Режим — *Overwrite events as needed*, тож журнали ніколи не зупиняються і не забивають диск.

| Клас | Журнали | WS | Server | DC |
|---|---|---|---|
| Security | Security | 768 МБ | 1,5 ГБ | 3 ГБ |
| Sysmon | Microsoft-Windows-Sysmon/Operational | 512 МБ | 1 ГБ | 1,5 ГБ |
| PowerShell | PowerShell/Operational, Windows PowerShell, PowerShellCore/Operational | 384 МБ | 768 МБ | 1 ГБ |
| System | System | 192 МБ | 256 МБ | 384 МБ |
| Application | Application | 192 МБ | 256 МБ | 256 МБ |
| DirSvc | Directory Service (DC) | — | — | 512 МБ |
| Other | Defender, TaskScheduler, TerminalServices-* / RdpCoreTS, WMI-Activity, Bits-Client, CodeIntegrity, AppLocker/*, NTLM, DNS-Client, Firewall, PrintService, WinRM, SMBServer/SMBClient Security, OpenSSH, DriverFrameworks-UserMode (USB), Security-Mitigations, LSA; на DC ще DNS Server, DNSServer/Audit, DFS Replication | 96 МБ | 192 МБ | 192 МБ |

Якщо приріст не вміщується в 50 % вільного місця на системному диску, профіль знижується (DC → Server → Workstation → Minimal) з попередженням. Журнали, яких на машині немає, пропускаються, наприклад DNS Server на хості без ролі DNS.

**Advanced Audit Policy** задається за GUID підкатегорій, тому однаково працює на RU/UA/EN Windows. Скрипт лише додає Success/Failure і ніколи нічого не вимикає. Повний список — таблиця `$auditTable` у `Set-SecurityLogging.ps1`.

**Реєстр:**
- `SCENoApplyLegacyAuditPolicy=1`;
- `ProcessCreationIncludeCmdLine_Enabled=1`;
- ScriptBlock і Module logging (`*`) для Windows PowerShell і PowerShell 7;
- `AuditReceivingNTLMTraffic=2`, `RestrictSendingNTLMTraffic=1` (лише аудит);
- на DC — `AuditNTLMInDomain=7` і `16 LDAP Interface Events=2`;
- `Image File Execution Options\LSASS.exe\AuditLevel=8`: події 3065/3066 у CodeIntegrity/Operational, коли в LSASS намагається завантажитися непідписаний модуль (лише аудит, нічого не блокується);
- на центрі сертифікації AD CS — `AuditFilter=127` (без нього CA нічого не пише; діє після перезапуску `certsvc`).

**Синхронізація часу** лише перевіряється, не змінюється: `NoSync` або вимкнена служба W32Time дають попередження, бо події з різних машин неможливо зіставити, коли годинники розходяться.

### PowerShell 2.0: навіщо вимикати

Рушій PowerShell 2.0 з'явився раніше за всі механізми захисту. У ньому **немає** Script Block Logging (4104), нормального Module Logging, AMSI і Constrained Language Mode. Якщо компонент встановлено, зловмисник запускає `powershell.exe -Version 2 -c ...`, і весь його код оминає журналювання, яке ми налаштовуємо. Залишиться лише подія 400 у журналі «Windows PowerShell» з `EngineVersion=2.0`. Якщо видалити рушій, такий обхід стає неможливим.

* **Win10/11 і Server 2016+:** компонент `MicrosoftWindowsPowerShellV2(Root)` є, але майже нікому не потрібен. У Win11 24H2 і Server 2025 його вже прибрала сама Microsoft. Ламається лише дуже старе ПЗ, яке явно викликає `-Version 2`, наприклад старі скрипти Exchange 2010 чи SCCM.
* **2008/2008 R2:** 2.0 — основний PowerShell, видалити його неможливо. Скрипт це враховує.
* **За замовчуванням** запуск однією командою (`Start-SecLogging.ps1` і доменна GPO, яку він створює) **видаляє** компонент на Win8/2012 і новіших; `-KeepPowerShellV2` залишає його. Сам `Set-SecurityLogging.ps1` без `-DisablePowerShellV2` лише попереджає.

### Старі системи (2008 / 2008 R2 / Win7)

* Журнали, аудит і реєстр налаштовуються. Скрипт працює з PowerShell 2.0 і .NET 3.5.
* **Sysmon за замовчуванням не встановлюється.** Сучасний Sysmon не підтримує NT 6.0/6.1, відомі зависання і BSOD. Microsoft старі збірки більше не роздає, тому дві з них **зберігаються в цьому репозиторії** з перевіреними підписами Microsoft і закріпленими хешами (походження: [vendor/sysmon/README.md](vendor/sysmon/README.md)):

  | `-LegacySysmonVersion` | Sysmon | Конфіг (SwiftOnSecurity, закріплений коміт) | Примітки |
  |---|---|---|---|
  | `10.42` (за замовчуванням) | `vendor/sysmon/10.42` | схема 4.22, `c00581f8` (2020) | 10.42 підтримує схеми до 4.23 |
  | `10.2` | `vendor/sysmon/10.2` | схема 4.00, `9fb44e98` (2019) | 10.2 підтримує схеми лише до 4.21, а конфігу 4.21 у SwiftOnSecurity немає, тому використовується старіший і слабший: **без подій DNS-запитів (22)** |

  * `-BuildPackage` кладе обидві в пакет (`legacy\10.42\`, `legacy\10.2\`). Хости з інтернетом можуть також завантажити їх прямо з репозиторію.
  * Встановлення: `-AllowLegacySysmon [-LegacySysmonVersion 10.2]`. Щоб змінити вже встановлену версію (наприклад, 10.42 → 10.2), додайте `-ReinstallSysmon`: він видаляє і встановлює лише тоді, коли встановлена версія відрізняється.
  * У чистій 2008 R2 без інтернету немає кореня *Microsoft Root Certificate Authority 2011*, тож Windows не може перевірити підпис 10.42. У такому разі скрипт покладається на закріплений SHA256 і пише Warning. Будь-яка інша проблема з підписом, як і раніше, блокує встановлення.
  * На 2008 R2 драйверу потрібні оновлення SHA-2: KB4474419 і KB4490628.
  * [SwiftOnSecurity/sysmon-config#103](https://github.com/SwiftOnSecurity/sysmon-config/issues/103) показує, що 10.42 завантажує конфіг 4.22 на Windows 7 («Configuration file validated»). Сам issue — про те, що не спрацювало власне виключення, а не про стабільність, і він досі відкритий.
  * **Спершу на одному хості:** див. стендову перевірку нижче.
* Командний рядок у 4688 на 2008 R2 з'являється лише з KB3004375.

### Стендова перевірка Sysmon для старих ОС

`windows/lab/Test-LegacySysmon.ps1` перевіряє Sysmon у VM з Windows 7 / 2008 R2 однією командою. Усе завантаження відбувається на хості, бо чиста 2008 R2 не має TLS 1.2 і не може звернутися до GitHub.

1. **Хост** (з інтернетом, PowerShell від адміністратора, з клону):
   ```powershell
   .\windows\Install-SecLogging.ps1 -Mode Share -SharePath C:\SecLab
   New-SmbShare -Name SecLab -Path C:\SecLab -FullAccess "$env:USERDOMAIN\$env:USERNAME"
   ```
   Завантажте з [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/) x64-пакети для Windows Server 2008 R2 у `C:\SecLab\updates`: **KB4474419** і **KB4490628**, а також **KB3020369**, якщо перші два не встановлюються.
2. **VM** (`cmd` від адміністратора; хост зазвичай доступний за адресою `.1` мережі VM, наприклад `192.168.80.1`):
   ```cmd
   net use \\192.168.80.1\SecLab /user:HOSTNAME\user
   powershell -ExecutionPolicy Bypass -File \\192.168.80.1\SecLab\lab\Test-LegacySysmon.ps1
   ```
   Якщо оновлення вимагають перезавантаження, скрипт зупиниться. Перезавантажте VM і запустіть ту саму команду ще раз. Після завершення він встановить Sysmon 10.42, згенерує трохи активності, порахує події Sysmon і збереже результати в `C:\SecLab\results\`.
3. Після перезавантаження та певного часу роботи шукаємо BSOD і аварійні перезавантаження:
   ```cmd
   powershell -ExecutionPolicy Bypass -File \\192.168.80.1\SecLab\lab\Test-LegacySysmon.ps1 -CollectOnly
   ```
4. Перейти на 10.2 і повторити кроки 2–3 (перед кожною версією зробіть снапшот VM):
   ```cmd
   powershell -ExecutionPolicy Bypass -File \\192.168.80.1\SecLab\lab\Test-LegacySysmon.ps1 -SysmonVersion 10.2
   ```

**Без прав адміністратора на хості.** Тоді хосту потрібен лише браузер, а решту робить VM, де ви адміністратор:

1. **VM** (`cmd` від адміністратора): створити шару для файлів і показати IP-адресу VM.
   ```cmd
   mkdir C:\SecLab\updates & net share SecLab=C:\SecLab /grant:Everyone,FULL & icacls C:\SecLab /grant Everyone:(OI)(CI)F & netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes & ipconfig
   ```
2. **Хост** (браузер, без прав адміністратора):
   - завантажте ZIP репозиторію: <https://github.com/egwyl666/sec_journal_on/archive/refs/tags/v1.3.4.zip>;
   - завантажте KB4474419 і KB4490628 (Windows Server 2008 R2, x64) з Microsoft Update Catalog;
   - у Провіднику відкрийте `\\<IP VM>\SecLab` (вхід як `<VM>\Administrator`), скопіюйте туди ZIP, а файли `.msu` — у `updates`.
3. **VM**: правою кнопкою по ZIP → *Extract All…* → `C:\SecLab`, потім запустіть:
   ```cmd
   powershell -ExecutionPolicy Bypass -File C:\SecLab\sec_journal_on-<коміт>\windows\lab\Test-LegacySysmon.ps1
   ```
   Запущений з репозиторію, скрипт збирає локальний пакет з `vendor\`, не потребує мережі, бере оновлення з `C:\SecLab\updates` і пише результати в `C:\SecLab\results`. Хост може прочитати результати через ту саму шару. `-SysmonVersion 10.2` і `-CollectOnly` працюють так само.

### Конфіг Sysmon

SwiftOnSecurity `sysmonconfig-export.xml`, закріплений на коміті `1836897` (SHA256 у скрипті). Зверніть увагу: репозиторій не оновлювався з жовтня 2021. Щоб пізніше перейти на olafhartong/sysmon-modular, достатньо змінити `ConfigUrl` і `ConfigSha256` у `sources.ini`, код чіпати не потрібно.

---

## Linux

```bash
sudo ./linux/set-security-logging.sh --check          # лише звіт
sudo ./linux/set-security-logging.sh                  # застосувати
sudo ./linux/set-security-logging.sh --configure-wazuh
```

| Що | Як |
|---|---|
| Визначення | `/etc/os-release` (`ID`, потім `ID_LIKE`, тому похідні дистрибутиви теж розпізнаються), інакше — за наявним пакетним менеджером. Також визначає систему ініціалізації (systemd / OpenRC / SysV), контейнер і вільне місце на `/var`. `graphical.target` означає робочу станцію, інакше — сервер |
| auditd | встановлює пакет. `auditd.conf`: `max_log_file` 50/100 МБ × `num_logs` 10, `ROTATE`, `ENRICHED` (auditd ≥ 2.6) |
| Правила | `/etc/audit/rules.d/50-seclogging.rules`: облікові записи, sudoers, PAM, SSH, cron/at/systemd/rc/profile, ld.so.preload, модулі ядра, hostname, час, ptrace-ін'єкції, монтування, execve у сесіях користувачів (ключ `audit-wazuh-c` під стандартні правила Wazuh), execve від облікових записів веб-сервера (`webshell`). Рядки `-w` пишуться, лише якщо шлях існує. Якщо ввімкнено незмінний режим (`-e 2`), скрипт попереджає, що потрібне перезавантаження. `--immutable` сам додає `-e 2` |
| journald | `Storage=persistent`, `SystemMaxUse` 1G (WS) / 2G (сервер) через drop-in, лише збільшення |
| Auth-лог | перевіряє rsyslog і фактичний auth-лог (`/var/log/auth.log`, `/var/log/secure`, інакше типовий для сімейства), а також що logrotate зберігає не менше 7 днів |
| sshd | `LogLevel VERBOSE`, щоб у журнал автентифікації потрапляв відбиток ключа, яким увійшли. Drop-in `sshd_config.d/01-seclogging.conf`, якщо `Include` стоїть на початку `sshd_config`, інакше рядок на початок `sshd_config` (з резервною копією). `sshd -t` має пройти, інакше зміну скасовано; потім `reload` |
| Час | перевіряє синхронізацію NTP (`timedatectl`, `chronyc`, `ntpstat`) і попереджає, якщо годинник не синхронізовано; нічого не змінює |
| Wazuh | перевіряє агента і збір audit/auth-журналів. З `--configure-wazuh` дописує керований блок в `ossec.conf` |

Звіт — у `/var/log/seclogging/last-report.json`, підсумковий рядок іде в syslog (тег `seclogging`).

### Підтримувані дистрибутиви

Один скрипт для всіх: він сам визначає, що це за хост, і вибирає пакетний менеджер, назви пакетів, шляхи журналів і команди служб. Про дистрибутив нічого вказувати не треба.

| Сімейство | Дистрибутиви | Пакетний менеджер | Офлайн-комплект (`install.sh build`) |
|---|---|---|---|
| deb | Ubuntu, Debian, Mint, Astra, Pop!_OS, Kali та інші похідні | apt | так |
| rpm | RHEL, CentOS 7/8/Stream, Rocky, Alma, Oracle, Fedora, Amazon Linux | dnf / yum | так |
| suse | SLES, openSUSE Leap/Tumbleweed | zypper | ні (лише онлайн) |
| arch | Arch, Manjaro, EndeavourOS | pacman | ні (лише онлайн) |
| alpine | Alpine (OpenRC, потрібен `apk add bash`) | apk | ні (лише онлайн) |
| інші | будь-що з `/etc/os-release` | немає | ні |

На невідомому дистрибутиві auditd має бути вже встановлений. Тоді скрипт налаштує все інше, а замість встановлення пакетів покаже попередження.

CentOS 7 і 8 більше не підтримуються: їхні типові репозиторії не працюють. Скрипт про це повідомляє і пропонує `vault.centos.org` або офлайн-комплект.

**Чому без Sysmon for Linux.** Штатні засоби вже покривають головне: auditd записує запуск процесів з повним командним рядком і користувачем, зміни файлів і конфігурації, модулі ядра та підвищення привілеїв, а journald/syslog — входи, sudo і служби. Wazuh розбирає все це з коробки. Sysmon for Linux додав би ще один агент з eBPF-сенсором (ядро ≥ 4.15), пакети не з репозиторіїв дистрибутива і XML-події, які Wazuh не розбирає без власних декодерів.

---

## Wazuh

Налаштуйте збір журналів централізовано, через групи менеджера. Це краще, ніж правити `ossec.conf` на кожному агенті.

```bash
# на менеджері
for g in windows windows-dc linux linux-journald; do
  /var/ossec/bin/agent_groups -a -g $g -q
  cp wazuh/shared/$g/agent.conf /var/ossec/etc/shared/$g/agent.conf
done
/var/ossec/bin/agent_groups -a -i <ID> -g windows          # усі Windows-агенти
/var/ossec/bin/agent_groups -a -i <ID> -g windows-dc       # DC додатково
/var/ossec/bin/agent_groups -a -i <ID> -g linux            # усі Linux-агенти
/var/ossec/bin/agent_groups -a -i <ID> -g linux-journald   # Linux без rsyslog (Wazuh 4.8+)
```

`windows/agent.conf` згенеровано з того самого списку каналів, що й у скрипті. DNS-Client/Operational навмисно не відправляється: він дуже шумний, а DNS-запити вже є в Sysmon (подія 22).

### Правила оповіщень

`wazuh/rules/seclogging_rules.xml` — правила оповіщень для подій, які вмикають скрипти. Встановлення на менеджері:

```bash
cp wazuh/rules/seclogging_rules.xml /var/ossec/etc/rules/
chown wazuh:wazuh /var/ossec/etc/rules/seclogging_rules.xml
systemctl restart wazuh-manager
```

| Рівень | Що |
|---|---|
| 14 | Можливий DCSync: 4662 з правами реплікації від облікового запису, який не є DC (`...$`) |
| 12 | Очищено журнал Security (1102); встановлено службу з каталогу, куди може писати користувач (Users, Temp, AppData, ProgramData, Downloads); додано до привілейованої групи — за SID, тож працює з будь-якою мовою Windows (4728/4732/4756); змінено пароль DSRM (4794); Sysmon зупинено; Linux: зміна `/var/log/audit`, ключі SSH root, `ld.so.preload`, веб-сервер запустив програму |
| 10 | Очищено інший журнал (104), зупинено службу журналу (1100), змінено політику аудиту (4719), змінено конфіг Sysmon (16), Kerberoasting (4769 RC4 на службовий обліковий запис), AS-REP roasting (4768 без попередньої автентифікації), непідписаний модуль у LSASS (3065/3066), збій SecLogging (Windows 1002 / Linux `Error>0`); Linux: конфіг аудиту, sudoers, PAM, ін'єкція через ptrace |
| 8 | Встановлено службу (4697/7045), змінено GPO (5136); Linux: облікові записи/групи, конфіг sshd, cron, профілі оболонки, login.defs |
| 3–6 | LDAP без підпису (2889), підсумок SecLogging; Linux: юніти systemd, модулі ядра, зміна часу, passwd, мережа/mount/sudo |

ID 12300–12343. Правила прив'язані до конкретних вузлів стандартного набору (`if_sid`), тож стандартні правила працюють як раніше, а наші підвищують рівень там, де треба. `tests/wazuh-rules.sh` запускає справжній wazuh-manager 4.14 у Docker, подає 64 події так само, як агент, і перевіряє, яке правило спрацювало.

Налаштування: 4769 RC4 шумить там, де RC4 ще використовується, а 7045/4697 — під час розгортання програм. Знизити рівень можна в `/var/ossec/etc/rules/local_rules.xml`: `<rule id="12313" level="5" overwrite="yes">` (скопіюйте тіло правила).

---

## Тести й що перевірено

| Перевірка | Де | Результат |
|---|---|---|
| Синтаксис обох `.ps1`, PSScriptAnalyzer (Warning/Error) | pwsh 7 на Linux | чисто |
| PowerShell 2.0: немає конструкцій PS3+ | grep + PSUseCompatibleSyntax | чисто |
| Юніт-тести `tests/windows-unit.ps1`: налаштування, розбір auditpol з локалізованими назвами, JSON, планування розмірів, перевірка хешів, блок Wazuh, `audit.csv`/`scripts.ini`/CSE, логіка аудиту й журналів на підмінених auditpol/wevtutil, повторний запуск нічого не змінює, запасні шляхи PowerShell 2.0 | pwsh 7 | 160/160 |
| Правила Wazuh `tests/wazuh-rules.sh`: менеджер стартує з `seclogging_rules.xml`, 64 події (Windows через декодер eventchannel, auditd, syslog) подаються так, як їх шле агент; для кожної спрацьовує очікуване правило, а на звичайних подіях наші мовчать | wazuh-manager 4.14 у Docker | 64/64 |
| `tests/linux-docker.sh`: check → apply → повторний apply без змін | Ubuntu 26.04 / 24.04 / 20.04, Mint 21.3, Oracle Linux 9 зі справжнім auditd; Debian 12, Rocky 9 / 8, Alma 9, CentOS 7, Fedora 40, Amazon Linux 2023, openSUSE Leap 15.6, Arch із заглушкою auditctl (їхні дзеркала були недоступні з пісочниці) | успішно (14 дистрибутивів) |
| Встановлення auditd самим скриптом через пакетний менеджер | Ubuntu 24.04 (apt), Oracle Linux 9 (dnf) | успішно |
| Стенд Server 2008 R2: Sysmon 10.42 з конфігом схеми 4.22 | VM, PowerShell 2.0 | працює, події пишуться; стабільний після перезавантаження (`-CollectOnly`: збоїв немає) |
| Одна команда на справжніх машинах: звіт до/після, повторний запуск без змін | Windows 10 Pro 22H2 (ru-RU), Ubuntu 26.04 | успішно |
| Одна команда на контролері домену: локальні налаштування, обидві GPO створено й прив'язано, SACL для DCSync на корені домену, блок агента Wazuh, звіт до/після | Windows Server 2022 DC (ru-RU), наявна доменна GPO аудиту, системний диск 30 ГБ | успішно (подробиці нижче) |
| GPO застосовано: `gpresult` показує обидві, `auditpol` — повний набір для DC, значення тримаються після оновлення політик; повторний запуск не піднімає версії GPO | той самий DC | успішно |
| Перевірка покриття незалежним інструментом (SOC_Audit) після розгортання | той самий DC | усі цільові події видно; «частково» — лише там, де так вирішено свідомо, див. нижче |
| sshd `LogLevel VERBOSE`: з `Include` і без, з блоком `Match`; `sshd -t` проходить; повторний запуск нічого не змінює | Ubuntu 24.04, Oracle Linux 9 | успішно |
| Завантаження згенерованих правил auditd у справжнє ядро | privileged-контейнер | прийнято 57/57 правил |
| `tests/linux-bundle.sh`: `install.sh build` → встановлення з комплекту на чистий контейнер **без мережі** → повторний запуск без змін → змінений комплект відхилено | Ubuntu 22.04, Ubuntu 24.04, Oracle Linux 9 (rpm) | успішно |
| `install.sh --fetch` завантажує основний скрипт з GitHub | Ubuntu 24.04 | успішно |
| Sysmon 10.42 і 10.2 у `vendor/`: Authenticode (Microsoft, дійсний на момент мітки часу), FileVersion, закріплений хеш | osslsigncode + юніт-тест | успішно |

### Чого навчив справжній контролер домену

Windows Server 2022 DC з російським інтерфейсом, у домені вже були свої GPO аудиту:

- **Доменна GPO аудиту замінює всю локальну політику аудиту** при кожному оновленні політик (на DC — кожні 5 хвилин). Локальні зміни `auditpol` зникали за кілька хвилин, тому на DC крок GPO тепер виконується завжди, навіть якщо налаштування самого DC завершилося з помилками.
- **Конфлікти вирішує порядок прив'язки.** Налаштування з кількох GPO об'єднуються по підкатегоріях, і перемагає GPO, вища в порядку прив'язки на OU=Domain Controllers. `SEC-Logging-DomainControllers` має лишатися першою.
- **Скрипт більше не чіпає підкатегорії, які задає GPO.** Локальна зміна призводила до того, що скрипт і групова політика перезаписували одне одного, а це близько сотні подій 4719 на добу (і стільки ж алертів у Wazuh). Тепер скрипт лише попереджає, якщо значення в GPO слабше за потрібне.
- **Розмір журналу «Active Directory Web Services» адміністратор змінити не може:** його налаштування захищені ACL служби. Це тепер Warning, і решту запуску воно не блокує.
- **Текст помилок `wevtutil` виходив «кракозябрами»** (ANSI, прочитаний як OEM). Тепер він перекодовується.
- **Другий DC (DC02) не міг редагувати GPO.** Їх створили на DC01, а в SYSVOL на DC02 їхніх тек не було, тож групова політика падала там із «шлях не знайдено». Тепер GPO завжди редагуються на емуляторі PDC, як це робить консоль GPMC, незалежно від того, на якому DC запущено скрипт. GPO без теки в SYSVOL зупиняє запуск зрозумілим повідомленням, а не винятком. Наприкінці скрипт перевіряє SYSVOL кожного DC і попереджає, якщо на якомусь бракує наших GPO (там не працює реплікація SYSVOL).
- **Версії GPO росли з кожним запуском,** бо кожне значення переписувалося. Тепер записуються лише реальні зміни.
- **Малий системний диск змушує брати профіль Minimal.** При 6,6 ГБ вільних із 30 ГБ DC отримав Security 256 МБ (близько тижня історії) і PowerShell 128 МБ (кілька днів, менше, коли інструмент аудиту заливає журнал модулів). Це нормально, поки агент Wazuh відправляє події. На більшому диску наступний запуск сам вибере більший профіль.
- **Свідомо не збирається**, і інструменти аудиту позначають це як «частково»: успішні 5145 на SYSVOL/NETLOGON (Detailed File Share на DC — лише «Відмова»), WFP 5156/5152 (замість них збирається `pfirewall.log`), 4663 без SACL на конкретних теках, аналітичний журнал DNS.

Що варто перевірити на DC після розгортання:

```powershell
gpresult /scope computer /r | findstr SEC-Logging        # обидві GPO застосовано
auditpol /get /category:*                                  # повний набір, стабільний через 10 хвилин
(Get-GPInheritance -Target (Get-ADDomain).DomainControllersContainer).GpoLinks | Select Order, DisplayName   # наша перша
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4719; StartTime=(Get-Date).AddDays(-1)} |
  ForEach-Object { '{0}  {1}' -f $_.Properties[1].Value, $_.Properties[6].Value } | Group-Object | Sort-Object Count -Descending
```

У російській Windows `auditpol /subcategory:` приймає лише локалізовані назви або GUID у лапках: `auditpol /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}"`.

**Ще не перевірено:**
- робочі станції й рядові сервери домену, які налаштовує startup-скрипт GPO (в процесі);
- англійська Windows на справжній машині;
- Alpine (дзеркала недоступні з пісочниці) і встановлення пакетів на SUSE, Arch, Amazon Linux, CentOS 7;
- `install.sh build` на CentOS 7 (`repotrack`).

```bash
pwsh -NoProfile -File tests/windows-unit.ps1
./tests/linux-docker.sh          # IMAGES="ubuntu:24.04 debian:12" щоб вибрати образи
./tests/linux-bundle.sh          # IMAGE=ubuntu:22.04 або IMAGE=oraclelinux:9
./tests/wazuh-rules.sh           # WAZUH_IMAGE=wazuh/wazuh-manager:4.14.0
# за проксі лише з HTTPS: CA_FILE=/path/ca.crt PROXY=$HTTPS_PROXY ./tests/linux-docker.sh
```
