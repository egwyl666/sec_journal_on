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
windows/Install-SecLogging.ps1    автоматизація: завантажити -> зібрати пакет -> встановити / шара / GPO
linux/set-security-logging.sh     єдиний скрипт для Linux (Debian/Ubuntu, RHEL/Rocky/Alma, SUSE)
linux/install.sh                  автоматизація: офлайн-комплект (build) і встановлення (онлайн або --from)
vendor/sysmon/10.42/              Sysmon 10.42 для Windows 7 / 2008 / 2008 R2 (перевірено, хеш закріплено)
wazuh/shared/<група>/agent.conf   централізований збір журналів для груп менеджера Wazuh
tests/                            тести (pwsh + docker)
```

> Довідка, коментарі та повідомлення в консолі всередині скриптів — українською. Машиночитані значення залишені англійською: статуси (`OK`, `Changed`, `WouldChange`, `Warning`, `Error`, `Skipped`), ключі JSON, назви параметрів і журналів. Так простіше писати правила й фільтри в SIEM.
> Файли `.ps1` збережено в **UTF-8 з BOM**. Без BOM Windows PowerShell 5.1/2.0 неправильно читає кирилицю. Якщо редагуєте скрипти, зберігайте BOM.

## Швидкий старт (автоматично)

Установники роблять «завантажити → зібрати пакет → встановити» однією командою. Окремі кроки нижче виконувати не обов'язково, якщо не хочете.

**Windows** (PowerShell від адміністратора):

```powershell
# машина з інтернетом: завантажити установник з GitHub і запустити (вставити в PowerShell)
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
$f = "$env:TEMP\Install-SecLogging.ps1"
(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/egwyl666/sec_journal_on/HEAD/windows/Install-SecLogging.ps1', $f)
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
| `Share` | збирає пакет і копіює його в `-SharePath`, повторно перевіряючи кожен хеш на шарі |
| `Domain` | збирає пакет і запускає з ним `New-SecLoggingGpo.ps1` (`-WhatIfGpo` — пробний прогін, `-LinkTargets`, `-SetDomainRootSacl`) |

- Коректний пакет використовується повторно. `-Rebuild` збирає його заново, а `-NoBuild` на машині без інтернету бере лише наявний пакет.
- `-Fetch` завантажує скрипти архівом з GitHub (`-RepoRef` — гілка/тег/коміт, типово `HEAD`).
- Усі параметри `Set-SecurityLogging.ps1` (`-AuditOnly`, `-SkipSysmon`, `-UpgradeSysmon`, `-DisablePowerShellV2`, `-ConfigureWazuh`, `-AllowLegacySysmon`, `-TranscriptionPath`, …) передаються далі.

**Linux** (root):

```bash
# одним рядком на хості з інтернетом
curl -fsSL https://raw.githubusercontent.com/egwyl666/sec_journal_on/HEAD/linux/install.sh -o install.sh && sudo bash install.sh --fetch --check

# з клону
sudo ./linux/install.sh --check                      # лише перевірка
sudo ./linux/install.sh --configure-wazuh            # встановити онлайн
sudo ./linux/install.sh build --with-sysmon          # офлайн-комплект для цього дистрибутива/версії/архітектури
sudo ./seclogging-bundle-*/install.sh --from ./seclogging-bundle-ubuntu-22.04-x86_64 --with-sysmon   # на хості без інтернету
```

`build` створює теку комплекту, у якій:
- обидва скрипти;
- пакети `auditd` і `sysmon` разом із **повним деревом залежностей**;
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

### Що налаштовується

**Журнали.** Вимкнені журнали вмикаються. Розміри тільки ростуть. Режим — *Overwrite events as needed*, тож журнали ніколи не зупиняються і не забивають диск.

| Клас | Журнали | WS | Server | DC |
|---|---|---|---|---|
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
- на DC — `AuditNTLMInDomain=7` і `16 LDAP Interface Events=2`.

### PowerShell 2.0: навіщо вимикати

Рушій PowerShell 2.0 з'явився раніше за всі механізми захисту. У ньому **немає** Script Block Logging (4104), нормального Module Logging, AMSI і Constrained Language Mode. Якщо компонент встановлено, зловмисник запускає `powershell.exe -Version 2 -c ...`, і весь його код оминає журналювання, яке ми налаштовуємо. Залишиться лише подія 400 у журналі «Windows PowerShell» з `EngineVersion=2.0`. Якщо видалити рушій, такий обхід стає неможливим.

* **Win10/11 і Server 2016+:** компонент `MicrosoftWindowsPowerShellV2(Root)` є, але майже нікому не потрібен. У Win11 24H2 і Server 2025 його вже прибрала сама Microsoft. Ламається лише дуже старе ПЗ, яке явно викликає `-Version 2`, наприклад старі скрипти Exchange 2010 чи SCCM.
* **2008/2008 R2:** 2.0 — основний PowerShell, видалити його неможливо. Скрипт це враховує.
* **За замовчуванням** скрипт лише **попереджає**. Видаляє компонент тільки з параметром `-DisablePowerShellV2`. Спершу пройдіться по машинах з `-AuditOnly` і подивіться, на скількох він увімкнений.

### Старі системи (2008 / 2008 R2 / Win7)

* Журнали, аудит і реєстр налаштовуються. Скрипт працює з PowerShell 2.0 і .NET 3.5.
* **Sysmon за замовчуванням не встановлюється.** Сучасний Sysmon не підтримує NT 6.0/6.1, відомі зависання і BSOD. Стабільною для 2008 R2 вважається версія **10.42**. Microsoft її більше не роздає, тому вона **зберігається в цьому репозиторії**: `vendor/sysmon/10.42/Sysmon.zip`. Підпис Microsoft перевірено, походження та хеші — у [vendor/sysmon/README.md](vendor/sysmon/README.md).
  * `-BuildPackage` автоматично кладе її в пакет як `legacy\Sysmon.zip`, а її хеш закріплено в скрипті. Хости з інтернетом можуть також завантажити її прямо з репозиторію. Щоб узяти іншу збірку, передайте `-LegacySysmonZip <шлях>`.
  * Встановлення: `-AllowLegacySysmon`. Старі хости отримують **старий конфіг SwiftOnSecurity зі схемою 4.22**, бо поточний потребує Sysmon 13+. Його хеш уже закріплено в скрипті.
  * **Чому не 10.2:** Sysmon 10.0/10.2 підтримують схеми конфігу лише до 4.21. SwiftOnSecurity ніколи не публікував конфіг під 4.21 (в історії після 4.00 одразу 4.22), тож 10.2 не прийме наш конфіг. 10.4x підтримує 4.22. [SwiftOnSecurity/sysmon-config#103](https://github.com/SwiftOnSecurity/sysmon-config/issues/103) показує, що 10.42 завантажує цей конфіг на Windows 7 («Configuration file validated»). Сам issue — про те, що не спрацювало власне виключення, а не про стабільність, і він досі відкритий.
  * На 2008 R2 драйверу потрібні оновлення SHA-2: KB4474419 і KB4490628.
  * **Спершу на одному хості.**
* Командний рядок у 4688 на 2008 R2 з'являється лише з KB3004375.

### Конфіг Sysmon

SwiftOnSecurity `sysmonconfig-export.xml`, закріплений на коміті `1836897` (SHA256 у скрипті). Зверніть увагу: репозиторій не оновлювався з жовтня 2021. Щоб пізніше перейти на olafhartong/sysmon-modular, достатньо змінити `ConfigUrl` і `ConfigSha256` у `sources.ini`, код чіпати не потрібно.

---

## Linux

```bash
sudo ./linux/set-security-logging.sh --check          # лише звіт
sudo ./linux/set-security-logging.sh                  # застосувати
sudo ./linux/set-security-logging.sh --with-sysmon --configure-wazuh
```

| Що | Як |
|---|---|
| Визначення | `/etc/os-release` дає сімейство deb/rpm/suse. `graphical.target` означає робочу станцію, інакше — сервер. Також перевіряється, чи це контейнер, і вільне місце на `/var` |
| auditd | встановлює пакет. `auditd.conf`: `max_log_file` 50/100 МБ × `num_logs` 10, `ROTATE`, `ENRICHED` (auditd ≥ 2.6) |
| Правила | `/etc/audit/rules.d/50-seclogging.rules`: облікові записи, sudoers, PAM, SSH, cron/at/systemd/rc/profile, ld.so.preload, модулі ядра, hostname, час, ptrace-ін'єкції, монтування, execve у сесіях користувачів (ключ `audit-wazuh-c` під стандартні правила Wazuh), execve від облікових записів веб-сервера (`webshell`). Рядки `-w` пишуться, лише якщо шлях існує. Якщо ввімкнено незмінний режим (`-e 2`), скрипт попереджає, що потрібне перезавантаження. `--immutable` сам додає `-e 2` |
| journald | `Storage=persistent`, `SystemMaxUse` 1G (WS) / 2G (сервер) через drop-in, лише збільшення |
| Auth-лог | перевіряє rsyslog і `/var/log/auth.log` / `/var/log/secure`, а також що logrotate зберігає не менше 7 днів |
| Sysmon for Linux | `--with-sysmon`: встановлення з packages.microsoft.com (підписано GPG) або офлайн через `--sysmon-package-dir DIR` (потрібен файл `SHA256SUMS`). Вбудований конфіг: процеси, мережа без loopback, створення файлів у місцях закріплення |
| Wazuh | перевіряє агента і збір audit/auth-журналів. З `--configure-wazuh` дописує керований блок в `ossec.conf` |

Звіт — у `/var/log/seclogging/last-report.json`, підсумковий рядок іде в syslog (тег `seclogging`).

**Чи є сенс у Sysmon for Linux?** Помірний. Основою залишається auditd. Sysmon додає мережеві з'єднання з прив'язкою до процесу (через auditd це шумно й незручно) та спільну з Windows схему подій. Мінуси:
- потрібен eBPF (ядро ≥ 4.15);
- пакета немає в репозиторіях дистрибутива;
- події приходять у syslog у вигляді XML, і **Wazuh потрібні додаткові декодери**.

Тому за замовчуванням він вимкнений. Спершу увімкніть на кількох серверах і подивіться на обсяг подій.

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

Алерти, які варто зробити одразу:
- **1102 / 104** — очищення журналів;
- **4719** — зміна політики аудиту;
- **SecLogging 1002** — скрипт не зміг застосувати налаштування;
- **Sysmon 16** — зміна конфігурації Sysmon;
- **4697 / 7045** — встановлення служби.

---

## Тести й що перевірено

| Перевірка | Де | Результат |
|---|---|---|
| Синтаксис обох `.ps1`, PSScriptAnalyzer (Warning/Error) | pwsh 7 на Linux | чисто |
| PowerShell 2.0: немає конструкцій PS3+ | grep + PSUseCompatibleSyntax | чисто |
| Юніт-тести `tests/windows-unit.ps1`: налаштування, розбір auditpol з локалізованими назвами, JSON, планування розмірів, перевірка хешів, блок Wazuh, `audit.csv`/`scripts.ini`/CSE, логіка аудиту й журналів на підмінених auditpol/wevtutil, повторний запуск нічого не змінює | pwsh 7 | 66/66 |
| `tests/linux-docker.sh`: check → apply → повторний apply без змін | Ubuntu 24.04 і 20.04 зі справжнім auditd; Debian 12 і Rocky 9 із заглушкою auditctl (дзеркала пакетів були недоступні з пісочниці) | успішно |
| Завантаження згенерованих правил auditd у справжнє ядро | privileged-контейнер | прийнято 57/57 правил |
| Встановлення sysmonforlinux з packages.microsoft.com | Ubuntu 22.04 | встановлюється (1.5.3) |
| `tests/linux-bundle.sh`: `install.sh build` → встановлення з комплекту на чистий контейнер **без мережі** → повторний запуск без змін → змінений комплект відхилено | Ubuntu 22.04 (із Sysmon), Ubuntu 24.04 | успішно |
| `install.sh --fetch` завантажує основний скрипт з GitHub | Ubuntu 24.04 | успішно |
| Sysmon 10.42 у `vendor/`: Authenticode (Microsoft, дійсний на момент мітки часу), FileVersion, закріплений хеш | osslsigncode + юніт-тест | успішно |

**Ще не перевірено (потрібен реальний стенд):**
- увесь Windows-код, що звертається до ОС: wevtutil, auditpol, встановлення Sysmon, реєстр, DISM;
- `New-SecLoggingGpo.ps1` на справжньому AD/SYSVOL;
- робота на Server 2008/R2, зокрема Sysmon 10.42 там;
- `Install-SecLogging.ps1` на справжній Windows (юніт-тестами покрито лише його допоміжні функції);
- `linux/install.sh build` на сімействі RHEL (дзеркала пакетів були недоступні з пісочниці);
- Sysmon for Linux на хості з systemd (у контейнері sysmon приймає будь-який конфіг без перевірки).

Рекомендований порядок:

1. Запустити `-AuditOnly` на робочій станції, сервері й DC (RU та EN) і зібрати JSON-звіти.
2. Застосувати на одному тестовому хості кожного типу. Повторний запуск має показати `Changed=0`.
3. Запустити `New-SecLoggingGpo.ps1 -WhatIf`, потім застосувати до тестової OU (`-LinkTargets "OU=Test,DC=corp,DC=local"`), після чого перевірити `gpresult` і `auditpol`.

```bash
pwsh -NoProfile -File tests/windows-unit.ps1
./tests/linux-docker.sh          # IMAGES="ubuntu:24.04 debian:12" щоб вибрати образи
./tests/linux-bundle.sh          # IMAGE=ubuntu:22.04 WITH_SYSMON=1
```
