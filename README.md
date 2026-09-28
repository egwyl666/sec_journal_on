# sec_journal_on — включение журналов безопасности и телеметрии

Скрипты, которые на Windows (рабочие станции, серверы, DC) и Linux:

1. **определяют, что за машина** (роль, ОС, домен, язык, архитектура, свободное место);
2. **проверяют текущее состояние** журналов, аудита, Sysmon, Wazuh;
3. **включают/увеличивают только недостающее** (размеры только растут, аудит только добавляется);
4. **перепроверяют** результат и пишут отчёт (консоль + JSON + событие для SIEM).

Любой скрипт можно сначала запустить в режиме «только посмотреть» (`-AuditOnly` / `--check`).

```
windows/Set-SecurityLogging.ps1   единый скрипт для любой Windows (WS / Server / DC), PS 2.0+
windows/New-SecLoggingGpo.ps1     надстройка GPO для домена (запускать на DC)
linux/set-security-logging.sh     единый скрипт для Linux (Debian/Ubuntu, RHEL/Rocky/Alma, SUSE)
wazuh/shared/<group>/agent.conf   централизованный сбор журналов для групп Wazuh-менеджера
tests/                            тесты (pwsh + docker)
```

---

## Windows

### Три способа установки

| Сценарий | Когда | Как |
|---|---|---|
| **1. Online** | есть интернет, машина вне домена или разовый запуск | `Set-SecurityLogging.ps1` — Sysmon скачивается с `download.sysinternals.com`, конфиг с GitHub (закреплённый коммит), всё проверяется по SHA256 |
| **2. Offline-пакет** | нет интернета (флешка, шара) | один раз собрать пакет `-BuildPackage`, потом `Set-SecurityLogging.ps1 -SourcePath <папка или \\server\share>` |
| **3. GPO** | доменные машины | на DC: `New-SecLoggingGpo.ps1` — выкладывает пакет в `NETLOGON\SecLogging` и создаёт GPO со startup-скриптом (сценарий 2 на каждой машине при загрузке) + политики аудита |

### Шаг 0. Собрать пакет и закрепить хеш Sysmon (один раз, на машине с интернетом)

```powershell
.\windows\Set-SecurityLogging.ps1 -BuildPackage D:\SecLogging
```

Скрипт скачивает `Sysmon.zip`, проверяет **подпись Microsoft** (Authenticode) у `Sysmon.exe/Sysmon64.exe/Sysmon64a.exe`, считает SHA256, скачивает конфиги SwiftOnSecurity (их хеши уже закреплены в скрипте) и пишет `sources.ini` со всеми хешами.

**Скопируйте `D:\SecLogging\sources.ini` в `windows\sources.ini` и закоммитьте** — после этого и online-режим будет проверять Sysmon.zip по закреплённому хешу.

> Хеш `Sysmon.zip` меняется с каждым релизом Microsoft. Если хеш не совпал — скрипт **останавливается** (новый релиз или подмена). Обновление: `-BuildPackage ... -AcceptNewSysmon` (подпись всё равно проверяется), затем снова закоммитить `sources.ini`.
> Без закреплённого хеша online-установка Sysmon откажет; обойти можно только явно: `-AllowUnpinnedSysmon` (останется только проверка подписи).

### Сценарий 1/2: запуск на машине

```powershell
# посмотреть, что будет сделано (ничего не меняет)
powershell -ExecutionPolicy Bypass -File .\Set-SecurityLogging.ps1 -AuditOnly

# применить (online)
powershell -ExecutionPolicy Bypass -File .\Set-SecurityLogging.ps1

# применить из пакета
powershell -ExecutionPolicy Bypass -File .\Set-SecurityLogging.ps1 -SourcePath \\fileserver\SecLogging
```

Полезные ключи:

| Ключ | Что делает |
|---|---|
| `-AuditOnly` | только отчёт, ничего не меняет |
| `-Role Workstation\|Server\|DomainController` | переопределить определённую роль |
| `-SkipSysmon` / `-UpgradeSysmon` | не трогать Sysmon / обновить старую версию (uninstall + install) |
| `-DisablePowerShellV2` | удалить компонент PowerShell 2.0 (см. ниже) |
| `-TranscriptionPath <путь>` | включить PowerShell Transcription (локальная папка получает write-only ACL) |
| `-ConfigureWazuh` | дописать недостающие `eventchannel` в `ossec.conf` локального агента |
| `-AllowLegacySysmon` | разрешить Sysmon на 2008/2008 R2/Win7 (см. ниже) |
| `-Quiet` | только итог (для GPO) |

Результат: `C:\ProgramData\SecLogging\last-report.json` + событие в журнале **Application**, источник `SecLogging` (ID 1000 — всё ок, 1001 — есть предупреждения, 1002 — ошибки). По нему в Wazuh удобно ловить машины, где настройка «разъехалась».

Коды выхода: `0` — ок, `2` — были ошибки, `3` — не администратор.

### Сценарий 3: GPO (на DC1)

```powershell
# сухой прогон
.\windows\New-SecLoggingGpo.ps1 -PackagePath D:\SecLogging -WhatIf

# применить + SACL на корень домена для 4662 (DCSync)
.\windows\New-SecLoggingGpo.ps1 -PackagePath D:\SecLogging -SetDomainRootSacl
```

Создаются **две отдельные GPO** (Default Domain Policy / Default DC Policy не трогаются):

| GPO | Привязка | Содержимое |
|---|---|---|
| `SEC-Logging-Baseline` | корень домена (или `-LinkTargets`) | Advanced Audit Policy (набор WS/Server), Force subcategory, cmdline в 4688, PowerShell ScriptBlock/Module logging (5.1 и 7), аудит NTLM, startup-скрипт |
| `SEC-Logging-DomainControllers` | OU=Domain Controllers | полный набор аудита DC (Kerberos, DS Access…), размеры Security/System/Application для DC, `AuditNTLMInDomain`, LDAP-диагностика (2889), startup-скрипт |

Startup-скрипт каждую загрузку запускает `\\domain\NETLOGON\SecLogging\Set-SecurityLogging.ps1 -SourcePath ... -Quiet`: включает operational-журналы, выставляет размеры по роли, ставит/проверяет Sysmon. Повторные запуски ничего не меняют, если всё уже настроено.

Advanced Audit Policy нельзя задать через `Set-GPRegistryValue`, поэтому скрипт пишет `audit.csv` в SYSVOL, регистрирует CSE в `gPCMachineExtensionNames` и повышает версию GPO. **Это место обязательно проверить на стенде:**

```cmd
gpupdate /force
gpresult /h C:\gp.html          :: обе SEC-Logging GPO применились?
auditpol /get /category:*        :: подкатегории выставлены?
type C:\ProgramData\SecLogging\last-report.json   :: после перезагрузки
```

Если на машину уже приходит GPO с размерами журналов или аудитом слабее нашего, локальный скрипт это **видит и пишет Warning** («GPO limits size…», «GPO will overwrite…»), а не делает вид, что всё применилось.

### Что настраивается

**Журналы** (включаются, если выключены; размер только растёт; режим — *Overwrite as needed*):

| Класс | Журналы | WS | Server | DC |
|---|---|---|---|---|
| Security | Security | 768 МБ | 1.5 ГБ | 3 ГБ |
| Sysmon | Microsoft-Windows-Sysmon/Operational | 512 МБ | 1 ГБ | 1.5 ГБ |
| PowerShell | PowerShell/Operational, Windows PowerShell, PowerShellCore/Operational | 384 МБ | 768 МБ | 1 ГБ |
| System | System | 192 МБ | 256 МБ | 384 МБ |
| Application | Application | 192 МБ | 256 МБ | 256 МБ |
| DirSvc | Directory Service (DC) | — | — | 512 МБ |
| Other | Defender, TaskScheduler, TerminalServices-* / RdpCoreTS, WMI-Activity, Bits-Client, CodeIntegrity, AppLocker/*, NTLM, DNS-Client, Firewall, PrintService, WinRM, SMBServer/SMBClient Security, OpenSSH, DriverFrameworks-UserMode (USB), Security-Mitigations, LSA; на DC ещё DNS Server, DNSServer/Audit, DFS Replication | 96 МБ | 192 МБ | 192 МБ |

Если прирост не влезает в 50 % свободного места на системном диске, профиль понижается (DC → Server → Workstation → Minimal) с предупреждением. Журналов, которых нет на машине (например, DNS Server не на DNS-сервере), скрипт просто пропускает.

**Advanced Audit Policy** — по GUID подкатегорий (не зависит от языка ОС: RU/UA/EN), только добавляет Success/Failure, никогда не выключает. Полный список — таблица `$auditTable` в `Set-SecurityLogging.ps1`.

**Реестр:** `SCENoApplyLegacyAuditPolicy=1`, `ProcessCreationIncludeCmdLine_Enabled=1`, ScriptBlock + Module logging (`*`) для Windows PowerShell и PowerShell 7, `AuditReceivingNTLMTraffic=2`, `RestrictSendingNTLMTraffic=1` (только аудит), на DC `AuditNTLMInDomain=7` и `16 LDAP Interface Events=2`.

### PowerShell 2.0 — зачем отключать

Движок PowerShell 2.0 появился раньше всех механизмов защиты: в нём **нет** Script Block Logging (4104), Module Logging в нормальном виде, AMSI и Constrained Language Mode. Если компонент установлен, атакующий запускает `powershell.exe -Version 2 -c ...`, и весь его код проходит мимо журналов, которые мы настраиваем. В журнале «Windows PowerShell» останется только событие 400 с `EngineVersion=2.0`. Ловить это событие полезно, но если просто удалить движок, такой обход вообще невозможен.

* Win10/11 и Server 2016+: компонент `MicrosoftWindowsPowerShellV2(Root)` есть, но нужен почти никому. В Win11 24H2 и Server 2025 его уже убрали сами Microsoft. Ломается только очень старый софт, который явно вызывает `-Version 2`, например древние скрипты Exchange 2010 или SCCM.
* 2008/2008 R2: там 2.0 и есть основной PowerShell, удалить его нельзя (скрипт это учитывает).
* По умолчанию скрипт только **предупреждает**. Удаляет с ключом `-DisablePowerShellV2`. Рекомендую сначала пройтись с `-AuditOnly` и посмотреть, на скольких машинах компонент включён.

### Старые системы (2008 / 2008 R2 / Win7)

* Журналы, аудит и реестр настраиваются, скрипт совместим с PowerShell 2.0 и .NET 3.5.
* **Sysmon по умолчанию не ставится.** Современный Sysmon на NT 6.0/6.1 не поддерживается, известны зависания и BSOD. Стабильной для 2008 R2 считается версия **10.42**, её нет на сайте Microsoft, архив нужно найти самим.
  * Собрать пакет: `-BuildPackage D:\SecLogging -LegacySysmonZip D:\Sysmon-10.42.zip` (подпись проверяется, хеш закрепляется).
  * Установка: `-AllowLegacySysmon`. Для legacy используется **старый конфиг SwiftOnSecurity со схемой 4.22** (текущий требует Sysmon 13+). Он уже закреплён в скрипте.
  * На 2008 R2 для драйвера нужны обновления SHA-2 (KB4474419, KB4490628).
  * **Сначала на одном хосте.**
* Командная строка в 4688 на 2008 R2 появляется только с KB3004375.

### Конфиг Sysmon

SwiftOnSecurity `sysmonconfig-export.xml`, закреплён на коммите `1836897` (SHA256 в скрипте). Учтите, что репозиторий не обновлялся с октября 2021. Если позже захотите olafhartong/sysmon-modular, достаточно поменять `ConfigUrl`/`ConfigSha256` в `sources.ini`, код трогать не нужно.

---

## Linux

```bash
sudo ./linux/set-security-logging.sh --check          # только отчёт
sudo ./linux/set-security-logging.sh                  # применить
sudo ./linux/set-security-logging.sh --with-sysmon --configure-wazuh
```

| Что | Как |
|---|---|
| Определение | `/etc/os-release` → семейство deb/rpm/suse; workstation, если `graphical.target`, иначе server; контейнер; свободное место на `/var` |
| auditd | установка пакета; `auditd.conf`: `max_log_file` 50/100 МБ × `num_logs` 10, `ROTATE`, `ENRICHED` (если auditd ≥ 2.6) |
| Правила | `/etc/audit/rules.d/50-seclogging.rules`: identity, sudoers, PAM, SSH, cron/at/systemd/rc/profile, ld.so.preload, модули ядра, hostname, время, ptrace-инъекции, mount, execve пользовательских сессий (ключ `audit-wazuh-c` под штатные правила Wazuh), execve от web-пользователей (`webshell`). Строки `-w` пишутся, только если путь существует. Если стоит immutable (`-e 2`), скрипт предупреждает, что нужна перезагрузка. `--immutable` сам добавляет `-e 2` |
| journald | `Storage=persistent`, `SystemMaxUse` 1G (WS) / 2G (server) через drop-in, только увеличение |
| auth log | наличие rsyslog и `/var/log/auth.log` / `/var/log/secure`, проверка ротации logrotate (≥ 7 дней) |
| Sysmon for Linux | `--with-sysmon`: репозиторий packages.microsoft.com (подписанный GPG) или offline `--sysmon-package-dir DIR` (обязателен `SHA256SUMS`), встроенный конфиг (процессы, сеть без loopback, создание файлов в местах persistence) |
| Wazuh | проверка агента и сбора audit/auth. С ключом `--configure-wazuh` дописывает управляемый блок в `ossec.conf` |

Отчёт: `/var/log/seclogging/last-report.json`. Итоговая строка уходит в syslog (`seclogging`).

**Есть ли смысл в Sysmon for Linux?** Умеренный. auditd остаётся основой. Sysmon добавляет сетевые соединения с привязкой к процессу (через auditd это шумно и неудобно) и общую с Windows схему событий. Минусы: нужен eBPF (ядро ≥ 4.15), пакет не из репозиториев дистрибутива, события приходят в syslog в виде XML, и **Wazuh нужны дополнительные декодеры**. Поэтому по умолчанию он выключен. Предлагаю включить на паре серверов и посмотреть на объём событий.

---

## Wazuh

Централизованно через группы менеджера (рекомендуется вместо правки `ossec.conf` на каждом агенте):

```bash
# на менеджере
for g in windows windows-dc linux linux-journald; do
  /var/ossec/bin/agent_groups -a -g $g -q
  cp wazuh/shared/$g/agent.conf /var/ossec/etc/shared/$g/agent.conf
done
/var/ossec/bin/agent_groups -a -i <ID> -g windows      # все Windows
/var/ossec/bin/agent_groups -a -i <ID> -g windows-dc   # DC дополнительно
/var/ossec/bin/agent_groups -a -i <ID> -g linux        # все Linux
/var/ossec/bin/agent_groups -a -i <ID> -g linux-journald   # Linux без rsyslog (Wazuh 4.8+)
```

`windows/agent.conf` сгенерирован из того же списка журналов, что и скрипт. DNS-Client/Operational намеренно не отправляется: он очень шумный, а DNS-запросы уже есть в Sysmon (событие 22).

Алерты, которые стоит сделать сразу: **1102 / 104** (очистка журналов), **4719** (изменение аудит-политики), **SecLogging 1002** (скрипт не смог применить настройки), **Sysmon 16** (изменение конфигурации Sysmon), **4697 / 7045** (установка сервиса).

---

## Тесты и что проверено

| Проверка | Где | Результат |
|---|---|---|
| Синтаксис обоих `.ps1`, PSScriptAnalyzer (Warning/Error) | pwsh 7 на Linux | чисто |
| PS 2.0: нет конструкций PS3+ | grep + PSUseCompatibleSyntax | чисто |
| Юнит-тесты `tests/windows-unit.ps1`: настройки, парсинг auditpol (русские имена), JSON, план размеров, проверка хешей, блок Wazuh, `audit.csv`/`scripts.ini`/CSE, логика аудита и журналов на моках auditpol/wevtutil, повторный прогон = no-op | pwsh 7 | 56/56 |
| `tests/linux-docker.sh`: check → apply → повторный apply без изменений | Ubuntu 24.04, 20.04 (настоящий auditd); Debian 12, Rocky 9 (заглушка auditctl, зеркала пакетов недоступны из песочницы) | ок |
| Загрузка сгенерированных правил auditd в реальное ядро | privileged-контейнер | 50/50 правил приняты |
| Установка sysmonforlinux из packages.microsoft.com | Ubuntu 22.04 | ставится (1.5.3) |

**Не проверено (нужен реальный стенд):** весь Windows-код, который обращается к ОС (wevtutil, auditpol, установка Sysmon, реестр, DISM), `New-SecLoggingGpo.ps1` против настоящего AD/SYSVOL, работа на Server 2008/R2, запуск Sysmon for Linux на хосте с systemd (в контейнере sysmon принимает любой конфиг без проверки). Порядок проверки:

1. `-AuditOnly` на WS, сервере и DC (RU и EN), прислать JSON-отчёты;
2. apply на одном тестовом хосте каждого типа, повторный запуск должен дать `Changed=0`;
3. `New-SecLoggingGpo.ps1 -WhatIf`, затем на тестовой OU (`-LinkTargets "OU=Test,DC=corp,DC=local"`), потом `gpresult` и `auditpol`.

```bash
pwsh -NoProfile -File tests/windows-unit.ps1
./tests/linux-docker.sh          # IMAGES="ubuntu:24.04 debian:12" для выборки
```
