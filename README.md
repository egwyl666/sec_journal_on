# sec_journal_on — security log and telemetry enablement

**English** | [Українська](README.uk.md)

Scripts for Windows (workstations, servers, domain controllers) and Linux that:

1. **detect the machine**: role, OS, domain membership, language, architecture, free space;
2. **check the current state** of event logs, audit policy, Sysmon and Wazuh;
3. **enable or raise only what is missing**: log sizes only grow, audit settings are only added;
4. **re-check** the result and write a report (console + JSON + an event for the SIEM).

Every script has a read-only mode (`-AuditOnly` / `--check`) that shows what it would change.

```
windows/Set-SecurityLogging.ps1   single script for any Windows (WS / Server / DC), PowerShell 2.0+
windows/New-SecLoggingGpo.ps1     domain GPO add-on (run on a DC)
windows/Start-SecLogging.ps1      one command for anyone: download, detect, configure, before/after report
windows/Install-SecLogging.ps1    automation: download -> build package -> install / share / GPO
linux/set-security-logging.sh     single script for any Linux (deb, rpm, SUSE, Arch, Alpine families; see the table)
linux/install.sh                  automation: offline bundle (build) and install (online or --from)
vendor/sysmon/10.42, 10.2/        Sysmon for Windows 7 / 2008 / 2008 R2 (verified, pinned)
vendor/sysmon-config/             SwiftOnSecurity configs for those versions (CC BY 4.0, pinned)
windows/lab/Test-LegacySysmon.ps1 lab test of legacy Sysmon in a VM (one command)
wazuh/shared/<group>/agent.conf   centralized log collection for Wazuh manager groups
tests/                            tests (pwsh + docker)
```

> Help text, comments and console messages inside the scripts are in Ukrainian. Machine-readable values stay in English: statuses (`OK`, `Changed`, `WouldChange`, `Warning`, `Error`, `Skipped`), JSON keys, parameter names, log channel names. This keeps SIEM rules and filters simple.
> The `.ps1` files are saved as **UTF-8 with BOM**. Without the BOM, Windows PowerShell 5.1/2.0 reads the Cyrillic text incorrectly. If you edit the scripts, keep the BOM.

## One command (no decisions needed)

Open **PowerShell or cmd as administrator** (Windows) or a root shell (Linux), paste one line, and wait for `DONE`. The machine needs internet access.

**Windows** (10/11, Server 2008 R2 … 2025, domain controllers):

```
powershell -NoProfile -ExecutionPolicy Bypass -Command "try{[Net.ServicePointManager]::SecurityProtocol=3072}catch{}; $w=New-Object Net.WebClient; $w.Encoding=[Text.Encoding]::UTF8; & ([scriptblock]::Create($w.DownloadString('https://raw.githubusercontent.com/egwyl666/sec_journal_on/HEAD/windows/Start-SecLogging.ps1').TrimStart([char]0xFEFF)))"
```

**Linux** (any distribution from the table below; the line uses `curl`, or `wget` where there is no `curl`, e.g. Ubuntu Desktop):

```bash
(curl -fsSL https://raw.githubusercontent.com/egwyl666/sec_journal_on/HEAD/linux/install.sh 2>/dev/null || wget -qO- https://raw.githubusercontent.com/egwyl666/sec_journal_on/HEAD/linux/install.sh) | sudo bash
```

What happens:

1. The scripts are downloaded from GitHub.
2. The machine type is detected: workstation, server, domain controller, old OS (2008 / 2008 R2 / Win7), Linux distribution.
3. A snapshot of the current state is saved ("before").
4. Everything that is missing is enabled: event logs and their sizes, audit policy, PowerShell logging, Sysmon (Windows), auditd and journald (Linux), Wazuh collection if the agent is installed. On a **domain controller** the domain GPOs are also created, so every domain machine configures itself at boot, and DCSync auditing is enabled.
5. A second snapshot is saved ("after"), and **everything that changed is written as "before → after"**.

Results:

| | Windows | Linux |
|---|---|---|
| What changed (before → after) | `C:\ProgramData\SecLogging\changes\<time>-changes.txt` (+ `.csv` for Excel) | `/var/log/seclogging/changes/<time>-changes.txt` |
| Full snapshots | `...\changes\<time>-before.tsv`, `<time>-after.tsv` | same folder |
| Detailed report | `C:\ProgramData\SecLogging\last-report.json` | `/var/log/seclogging/last-report.json` |

Running it again is safe: only what is missing changes, and a second run reports `Змін немає` (no changes).

View what changed after a run:

```powershell
# Windows (PowerShell)
Get-Content (Get-ChildItem C:\ProgramData\SecLogging\changes\*-changes.txt | Sort-Object LastWriteTime | Select-Object -Last 1).FullName -Encoding UTF8
```
```bash
# Linux
sudo sh -c 'cat "$(ls -t /var/log/seclogging/changes/*-changes.txt | head -1)"'
```

Example (Ubuntu, first run):

```
[auditd.conf]
  max_log_file
      було:  (не задано)
      стало: 100
```

Check only, change nothing:

```
powershell -NoProfile -ExecutionPolicy Bypass -Command "try{[Net.ServicePointManager]::SecurityProtocol=3072}catch{}; $w=New-Object Net.WebClient; $w.Encoding=[Text.Encoding]::UTF8; & ([scriptblock]::Create($w.DownloadString('https://raw.githubusercontent.com/egwyl666/sec_journal_on/HEAD/windows/Start-SecLogging.ps1').TrimStart([char]0xFEFF))) -AuditOnly"
```
```bash
(curl -fsSL https://raw.githubusercontent.com/egwyl666/sec_journal_on/HEAD/linux/install.sh 2>/dev/null || wget -qO- https://raw.githubusercontent.com/egwyl666/sec_journal_on/HEAD/linux/install.sh) | sudo bash -s -- --check
```

No internet on the machine: download `https://github.com/egwyl666/sec_journal_on/archive/HEAD.zip` elsewhere, copy it over and run `powershell -ExecutionPolicy Bypass -File <unpacked>\windows\Start-SecLogging.ps1 -Source <path to the zip>` (Linux: the offline bundle, see below).

To compare any two snapshots later: `Set-SecurityLogging.ps1 -CompareBefore a.tsv -CompareAfter b.tsv -CompareOut changes.txt` / `set-security-logging.sh --compare a.tsv b.tsv`.

## Quick start (automated)

The installers do "download → build package → install" in one command. You do not need to run the individual steps below unless you want to.

**Windows** (elevated PowerShell):

```powershell
# machine with internet: download the installer from GitHub and run it (paste into PowerShell)
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
$f = "$env:TEMP\Install-SecLogging.ps1"
(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/egwyl666/sec_journal_on/HEAD/windows/Install-SecLogging.ps1', $f)
powershell -ExecutionPolicy Bypass -File $f -Fetch -AuditOnly

# from a clone of the repository (first allow scripts in this window only;
# for a ZIP downloaded from GitHub also remove the "downloaded from internet" mark)
Set-ExecutionPolicy -Scope Process Bypass -Force
Get-ChildItem -Recurse | Unblock-File
.\windows\Install-SecLogging.ps1 -AuditOnly                                 # check only
.\windows\Install-SecLogging.ps1                                            # build package + install here
.\windows\Install-SecLogging.ps1 -Mode Build -UpdateRepoPins                # build only, write windows\sources.ini
.\windows\Install-SecLogging.ps1 -Mode Share -SharePath \\fileserver\SecLogging  # publish for machines without internet
.\windows\Install-SecLogging.ps1 -Mode Domain -WhatIfGpo                    # on DC1: package + GPO dry run
.\windows\Install-SecLogging.ps1 -Mode Domain -SetDomainRootSacl            # on DC1: package + GPO
```

| Mode | What it does |
|---|---|
| `Local` (default) | builds the package if needed (`%ProgramData%\SecLogging\package`), then runs `Set-SecurityLogging.ps1 -SourcePath <package>` on this machine |
| `Build` | builds the package only; `-UpdateRepoPins` copies the new `sources.ini` into `windows\` of the clone so you can commit it |
| `Share` | builds the package and copies it to `-SharePath`, re-checking every hash on the share; also copies `lab\` and creates `updates\` and `results\` |
| `Domain` | builds the package and runs `New-SecLoggingGpo.ps1` with it (`-WhatIfGpo` for a dry run, `-LinkTargets`, `-SetDomainRootSacl`) |

- A valid package is reused. Use `-Rebuild` to build it again, or `-NoBuild` on a machine without internet to use an existing package only.
- `-Fetch` downloads the scripts as a zip from GitHub (`-RepoRef` picks a branch/tag/commit, default `HEAD`).
- All `Set-SecurityLogging.ps1` switches (`-AuditOnly`, `-SkipSysmon`, `-UpgradeSysmon`, `-DisablePowerShellV2`, `-ConfigureWazuh`, `-AllowLegacySysmon`, `-LegacySysmonVersion`, `-ReinstallSysmon`, `-TranscriptionPath`, …) are passed through.

**Linux** (root):

```bash
# one-liner on a host with internet
curl -fsSL https://raw.githubusercontent.com/egwyl666/sec_journal_on/HEAD/linux/install.sh -o install.sh && sudo bash install.sh --fetch --check

# from a clone
sudo ./linux/install.sh --check                      # check only
sudo ./linux/install.sh --configure-wazuh            # install online
sudo ./linux/install.sh build                        # offline bundle for this distro/version/arch
sudo ./seclogging-bundle-*/install.sh --from ./seclogging-bundle-ubuntu-22.04-x86_64   # on the offline host
```

`build` produces a bundle folder with:
- both scripts;
- the `auditd` package together with its **full dependency tree**;
- `SHA256SUMS`;
- `bundle.info`, which records the distro, version and architecture it was built for.

`install --from` checks `SHA256SUMS` and refuses a modified bundle. It installs only packages that are missing or older on the host and never downgrades anything. Then it runs `set-security-logging.sh`. Build the bundle on the same distro, version and architecture as the target hosts. Any other options (`--check`, `--configure-wazuh`, `--profile`, `--immutable`, …) are passed to `set-security-logging.sh`.

---

## Windows

### Three installation modes

| Mode | When | How |
|---|---|---|
| **1. Online** | internet access, machine outside the domain, one-off run | `Set-SecurityLogging.ps1`: Sysmon is downloaded from `download.sysinternals.com` and the config from GitHub (pinned commit). Everything is checked against SHA256 |
| **2. Offline package** | no internet (USB stick, file share) | build the package once with `-BuildPackage`, then run `Set-SecurityLogging.ps1 -SourcePath <folder or \\server\share>` |
| **3. GPO** | domain machines | on the DC, `New-SecLoggingGpo.ps1` copies the package to `NETLOGON\SecLogging` and creates GPOs with a startup script (mode 2 on every boot) plus the audit policy |

### Step 0. Build the package and pin the Sysmon hash (once, on a machine with internet)

```powershell
.\windows\Set-SecurityLogging.ps1 -BuildPackage D:\SecLogging
```

The script:
- downloads `Sysmon.zip`;
- checks the **Microsoft Authenticode signature** of `Sysmon.exe`, `Sysmon64.exe` and `Sysmon64a.exe`;
- computes the SHA256;
- downloads the SwiftOnSecurity configs (their hashes are already pinned in the script);
- writes `sources.ini` with all hashes.

**Copy `D:\SecLogging\sources.ini` to `windows\sources.ini` and commit it.** After that, online installs also check Sysmon.zip against the pinned hash.

> The `Sysmon.zip` hash changes with every Microsoft release. If the hash does not match, the script **stops**: it is either a new release or tampering. To update, run `-BuildPackage ... -AcceptNewSysmon` (the signature is still checked) and commit `sources.ini` again.
> Without a pinned hash, online Sysmon installation is refused. The only way around it is explicit: `-AllowUnpinnedSysmon`, which leaves only the signature check.

### Modes 1 and 2: running on a machine

```powershell
# show what would be done (changes nothing)
powershell -ExecutionPolicy Bypass -File .\Set-SecurityLogging.ps1 -AuditOnly

# apply (online)
powershell -ExecutionPolicy Bypass -File .\Set-SecurityLogging.ps1

# apply from a package
powershell -ExecutionPolicy Bypass -File .\Set-SecurityLogging.ps1 -SourcePath \\fileserver\SecLogging
```

| Switch | What it does |
|---|---|
| `-AuditOnly` | report only, changes nothing |
| `-Role Workstation\|Server\|DomainController` | override the detected role |
| `-SkipSysmon` / `-UpgradeSysmon` | leave Sysmon alone / upgrade an old version (uninstall + install) |
| `-DisablePowerShellV2` | remove the PowerShell 2.0 feature (see below) |
| `-TranscriptionPath <path>` | enable PowerShell Transcription (a local folder gets a write-only ACL) |
| `-ConfigureWazuh` | add missing `eventchannel` entries to the local agent `ossec.conf` |
| `-AllowLegacySysmon` | allow Sysmon on 2008/2008 R2/Win7 (see below) |
| `-Quiet` | print only the summary (for GPO) |

Results:
- a JSON report in `C:\ProgramData\SecLogging\last-report.json`;
- an event in the **Application** log, source `SecLogging`: ID 1000 means everything is fine, 1001 means warnings, 1002 means errors. In Wazuh this makes it easy to find machines whose settings have drifted.

Exit codes: `0` success, `2` errors occurred, `3` not running as administrator.

### Mode 3: GPO (on DC1)

```powershell
# dry run
.\windows\New-SecLoggingGpo.ps1 -PackagePath D:\SecLogging -WhatIf

# apply, plus a SACL on the domain root for 4662 (DCSync)
.\windows\New-SecLoggingGpo.ps1 -PackagePath D:\SecLogging -SetDomainRootSacl
```

The script creates **two separate GPOs**. Default Domain Policy and Default Domain Controllers Policy are not touched.

| GPO | Linked to | Contents |
|---|---|---|
| `SEC-Logging-Baseline` | domain root (or `-LinkTargets`) | Advanced Audit Policy (WS/Server set), force subcategories, command line in 4688, PowerShell ScriptBlock/Module logging (5.1 and 7), NTLM auditing, startup script |
| `SEC-Logging-DomainControllers` | OU=Domain Controllers | full DC audit set (Kerberos, DS Access…), Security/System/Application sizes for DCs, `AuditNTLMInDomain`, LDAP diagnostics (2889), startup script |

On every boot, the startup script runs `\\domain\NETLOGON\SecLogging\Set-SecurityLogging.ps1 -SourcePath ... -Quiet`. It enables the operational logs, sets sizes by role, and installs or checks Sysmon. If everything is already configured, repeated runs change nothing.

Advanced Audit Policy cannot be set with `Set-GPRegistryValue`. The script therefore writes `audit.csv` to SYSVOL itself, registers the client-side extension in `gPCMachineExtensionNames` and bumps the GPO version. **Test this part in a lab first:**

```cmd
gpupdate /force
gpresult /h C:\gp.html          :: were both SEC-Logging GPOs applied?
auditpol /get /category:*        :: are the subcategories set?
type C:\ProgramData\SecLogging\last-report.json   :: after a reboot
```

Sometimes a GPO already sets smaller log sizes or weaker audit settings than ours. The local script **detects this and reports a Warning** instead of pretending the change was applied.

### What gets configured

**Event logs.** Disabled logs are enabled. Sizes only grow. Retention is set to *Overwrite events as needed*, so logs never stop or fill the disk.

| Class | Logs | WS | Server | DC |
|---|---|---|---|
| Security | Security | 768 MB | 1.5 GB | 3 GB |
| Sysmon | Microsoft-Windows-Sysmon/Operational | 512 MB | 1 GB | 1.5 GB |
| PowerShell | PowerShell/Operational, Windows PowerShell, PowerShellCore/Operational | 384 MB | 768 MB | 1 GB |
| System | System | 192 MB | 256 MB | 384 MB |
| Application | Application | 192 MB | 256 MB | 256 MB |
| DirSvc | Directory Service (DC) | — | — | 512 MB |
| Other | Defender, TaskScheduler, TerminalServices-* / RdpCoreTS, WMI-Activity, Bits-Client, CodeIntegrity, AppLocker/*, NTLM, DNS-Client, Firewall, PrintService, WinRM, SMBServer/SMBClient Security, OpenSSH, DriverFrameworks-UserMode (USB), Security-Mitigations, LSA; on DCs also DNS Server, DNSServer/Audit, DFS Replication | 96 MB | 192 MB | 192 MB |

If the growth does not fit into 50% of the free space on the system drive, the profile steps down (DC → Server → Workstation → Minimal) with a warning. Logs that do not exist on the machine are skipped, for example DNS Server on a host without the DNS role.

**Advanced Audit Policy** is set by subcategory GUID, so it works the same on RU/UA/EN Windows. The script only adds Success/Failure and never disables anything. The full list is the `$auditTable` table in `Set-SecurityLogging.ps1`.

**Registry:**
- `SCENoApplyLegacyAuditPolicy=1`;
- `ProcessCreationIncludeCmdLine_Enabled=1`;
- ScriptBlock and Module logging (`*`) for Windows PowerShell and PowerShell 7;
- `AuditReceivingNTLMTraffic=2`, `RestrictSendingNTLMTraffic=1` (audit only);
- on DCs, `AuditNTLMInDomain=7` and `16 LDAP Interface Events=2`.

### PowerShell 2.0: why disable it

The PowerShell 2.0 engine predates all the protection mechanisms. It has **no** Script Block Logging (4104), no proper Module Logging, no AMSI and no Constrained Language Mode. If the feature is installed, an attacker can run `powershell.exe -Version 2 -c ...`, and their code bypasses all the logging we configure. The only trace is event 400 in the "Windows PowerShell" log with `EngineVersion=2.0`. Removing the engine closes the bypass completely.

* **Win10/11 and Server 2016+:** the `MicrosoftWindowsPowerShellV2(Root)` feature is present but almost nobody needs it. Microsoft removed it in Win11 24H2 and Server 2025. Only very old software that explicitly calls `-Version 2` breaks, such as old Exchange 2010 or SCCM scripts.
* **2008/2008 R2:** 2.0 is the main PowerShell and cannot be removed. The script takes this into account.
* **Default behaviour:** the script only **warns**. It removes the feature only with `-DisablePowerShellV2`. Run `-AuditOnly` across the fleet first to see how many machines have it enabled.

### Legacy systems (2008 / 2008 R2 / Win7)

* Logs, audit policy and registry settings are configured. The script works with PowerShell 2.0 and .NET 3.5.
* **Sysmon is not installed by default.** Modern Sysmon does not support NT 6.0/6.1, and hangs and BSODs have been reported. Microsoft no longer hosts old builds, so two of them are **kept in this repository** with verified Microsoft signatures and pinned hashes (provenance: [vendor/sysmon/README.md](vendor/sysmon/README.md)):

  | `-LegacySysmonVersion` | Sysmon | Config (SwiftOnSecurity, pinned commit) | Notes |
  |---|---|---|---|
  | `10.42` (default) | `vendor/sysmon/10.42` | schema 4.22, `c00581f8` (2020) | 10.42 supports schemas up to 4.23 |
  | `10.2` | `vendor/sysmon/10.2` | schema 4.00, `9fb44e98` (2019) | 10.2 supports schemas only up to 4.21, and SwiftOnSecurity has no 4.21 config, so an older and weaker one is used: **no DNS query events (22)** |

  * `-BuildPackage` puts both into the package (`legacy\10.42\`, `legacy\10.2\`). Hosts with internet can also download them straight from the repository.
  * Install with `-AllowLegacySysmon [-LegacySysmonVersion 10.2]`. To switch an already installed version (for example 10.42 → 10.2), add `-ReinstallSysmon`: it uninstalls and installs only when the installed version differs.
  * A fresh 2008 R2 without internet does not have the *Microsoft Root Certificate Authority 2011* root, so Windows cannot validate the 10.42 signature. In that case the script relies on the pinned SHA256 and reports a Warning. Any other signature problem still blocks the install.
  * On 2008 R2, the driver needs the SHA-2 updates KB4474419 and KB4490628.
  * [SwiftOnSecurity/sysmon-config#103](https://github.com/SwiftOnSecurity/sysmon-config/issues/103) shows 10.42 loading the 4.22 config on Windows 7 ("Configuration file validated"). The issue itself is about a custom exclusion not taking effect, not about stability, and it is still open.
  * **Try it on one host first:** see the lab test below.
* On 2008 R2, the command line in 4688 appears only with KB3004375.

### Lab test for legacy Sysmon

`windows/lab/Test-LegacySysmon.ps1` tests Sysmon on a Windows 7 / 2008 R2 VM with one command. Downloads happen on the host, because a fresh 2008 R2 has no TLS 1.2 and cannot reach GitHub.

1. **Host** (with internet, elevated PowerShell, from a clone):
   ```powershell
   .\windows\Install-SecLogging.ps1 -Mode Share -SharePath C:\SecLab
   New-SmbShare -Name SecLab -Path C:\SecLab -FullAccess "$env:USERDOMAIN\$env:USERNAME"
   ```
   Download the x64 packages for Windows Server 2008 R2 from the [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/) into `C:\SecLab\updates`: **KB4474419** and **KB4490628**, plus **KB3020369** if the others refuse to install.
2. **VM** (elevated `cmd`; the host is usually reachable at the `.1` address of the VM network, for example `192.168.80.1`):
   ```cmd
   net use \\192.168.80.1\SecLab /user:HOSTNAME\user
   powershell -ExecutionPolicy Bypass -File \\192.168.80.1\SecLab\lab\Test-LegacySysmon.ps1
   ```
   If the updates ask for a reboot, the script stops. Reboot and run the same command again. When it finishes, it installs Sysmon 10.42, generates some activity, counts Sysmon events, and saves the results to `C:\SecLab\results\`.
3. After a reboot and some uptime, look for BSODs and unexpected restarts:
   ```cmd
   powershell -ExecutionPolicy Bypass -File \\192.168.80.1\SecLab\lab\Test-LegacySysmon.ps1 -CollectOnly
   ```
4. Switch to 10.2 and repeat steps 2–3 (take a VM snapshot before each version):
   ```cmd
   powershell -ExecutionPolicy Bypass -File \\192.168.80.1\SecLab\lab\Test-LegacySysmon.ps1 -SysmonVersion 10.2
   ```

**Without admin rights on the host.** The host then only needs a browser, and the VM, where you are the administrator, does the rest:

1. **VM** (elevated `cmd`): create a share for the files and show the VM's IP address.
   ```cmd
   mkdir C:\SecLab\updates & net share SecLab=C:\SecLab /grant:Everyone,FULL & icacls C:\SecLab /grant Everyone:(OI)(CI)F & netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes & ipconfig
   ```
2. **Host** (browser, no admin):
   - download the repository ZIP: <https://github.com/egwyl666/sec_journal_on/archive/HEAD.zip>;
   - download KB4474419 and KB4490628 (Windows Server 2008 R2, x64) from the Microsoft Update Catalog;
   - in Explorer, open `\\<VM IP>\SecLab` (log in as `<VM>\Administrator`), copy the ZIP there and the `.msu` files into `updates`.
3. **VM**: right-click the ZIP → *Extract All…* → `C:\SecLab`, then run:
   ```cmd
   powershell -ExecutionPolicy Bypass -File C:\SecLab\sec_journal_on-<commit>\windows\lab\Test-LegacySysmon.ps1
   ```
   Started from the repository, the script builds a local package from `vendor\`, needs no network, reads updates from `C:\SecLab\updates` and writes results to `C:\SecLab\results`. The host can read the results from the same share. `-SysmonVersion 10.2` and `-CollectOnly` work the same way.

### Sysmon config

SwiftOnSecurity `sysmonconfig-export.xml`, pinned to commit `1836897` (SHA256 in the script). Note that the repository has not been updated since October 2021. To switch to olafhartong/sysmon-modular later, change `ConfigUrl` and `ConfigSha256` in `sources.ini`; no code changes are needed.

---

## Linux

```bash
sudo ./linux/set-security-logging.sh --check          # report only
sudo ./linux/set-security-logging.sh                  # apply
sudo ./linux/set-security-logging.sh --configure-wazuh
```

| What | How |
|---|---|
| Detection | `/etc/os-release` (`ID`, then `ID_LIKE`, so derivatives are covered), otherwise by the package manager present. Also detects the init system (systemd / OpenRC / SysV), a container and the free space on `/var`. `graphical.target` means workstation, otherwise server |
| auditd | installs the package. `auditd.conf`: `max_log_file` 50/100 MB × `num_logs` 10, `ROTATE`, `ENRICHED` (auditd ≥ 2.6) |
| Rules | `/etc/audit/rules.d/50-seclogging.rules`: identity, sudoers, PAM, SSH, cron/at/systemd/rc/profile, ld.so.preload, kernel modules, hostname, time, ptrace injection, mounts, execve in user sessions (key `audit-wazuh-c` for the stock Wazuh rules), execve by web server accounts (`webshell`). `-w` lines are written only if the path exists. If immutable mode (`-e 2`) is on, the script warns that a reboot is needed. `--immutable` adds `-e 2` itself |
| journald | `Storage=persistent`, `SystemMaxUse` 1G (WS) / 2G (server) via a drop-in, only increased |
| Auth log | checks for rsyslog and the auth log actually present (`/var/log/auth.log`, `/var/log/secure`, otherwise the family default), and that logrotate keeps at least 7 days |
| Wazuh | checks the agent and whether audit/auth logs are collected. With `--configure-wazuh`, appends a managed block to `ossec.conf` |

The report goes to `/var/log/seclogging/last-report.json`, and a summary line is sent to syslog (tag `seclogging`).

### Supported distributions

One script for all of them: it checks what the host is and picks the package manager, package names, log paths and service commands itself. Nothing needs to be told about the distribution.

| Family | Distributions | Package manager | Offline bundle (`install.sh build`) |
|---|---|---|---|
| deb | Ubuntu, Debian, Mint, Astra, Pop!_OS, Kali and other derivatives | apt | yes |
| rpm | RHEL, CentOS 7/8/Stream, Rocky, Alma, Oracle, Fedora, Amazon Linux | dnf / yum | yes |
| suse | SLES, openSUSE Leap/Tumbleweed | zypper | no (online only) |
| arch | Arch, Manjaro, EndeavourOS | pacman | no (online only) |
| alpine | Alpine (OpenRC, needs `apk add bash`) | apk | no (online only) |
| other | anything with `/etc/os-release` | none | no |

On an unknown distribution auditd must already be installed. The script then configures everything else and reports a warning instead of installing packages.

CentOS 7 and 8 are end-of-life: their default repositories no longer work. The script says so and suggests `vault.centos.org` or the offline bundle.

**Why no Sysmon for Linux.** The built-in tools already cover what matters: auditd records process execution with the full command line and user, file and configuration changes, kernel modules and privilege escalation, and journald/syslog cover logins, sudo and services. Wazuh parses all of this out of the box. Sysmon for Linux would add another agent with an eBPF sensor (kernel ≥ 4.15), packages from outside the distribution repositories, and XML events that Wazuh cannot decode without custom decoders.

---

## Wazuh

Configure log collection centrally through manager groups. This is recommended over editing `ossec.conf` on every agent.

```bash
# on the manager
for g in windows windows-dc linux linux-journald; do
  /var/ossec/bin/agent_groups -a -g $g -q
  cp wazuh/shared/$g/agent.conf /var/ossec/etc/shared/$g/agent.conf
done
/var/ossec/bin/agent_groups -a -i <ID> -g windows          # all Windows agents
/var/ossec/bin/agent_groups -a -i <ID> -g windows-dc       # DCs, in addition
/var/ossec/bin/agent_groups -a -i <ID> -g linux            # all Linux agents
/var/ossec/bin/agent_groups -a -i <ID> -g linux-journald   # Linux without rsyslog (Wazuh 4.8+)
```

`windows/agent.conf` is generated from the same channel list as the script. DNS-Client/Operational is deliberately not forwarded: it is very noisy, and Sysmon event 22 already covers DNS queries.

Alerts worth creating right away:
- **1102 / 104**: event log cleared;
- **4719**: audit policy changed;
- **SecLogging 1002**: the script failed to apply settings;
- **Sysmon 16**: Sysmon configuration changed;
- **4697 / 7045**: service installed.

---

## Tests and what has been verified

| Check | Where | Result |
|---|---|---|
| Syntax of both `.ps1` files, PSScriptAnalyzer (Warning/Error) | pwsh 7 on Linux | clean |
| PowerShell 2.0: no PS3+ constructs | grep + PSUseCompatibleSyntax | clean |
| Unit tests `tests/windows-unit.ps1`: settings, auditpol parsing with localized names, JSON, size planning, hash checks, Wazuh block, `audit.csv`/`scripts.ini`/CSE, audit and event log logic with mocked auditpol/wevtutil, second run is a no-op, PowerShell 2.0 fallbacks | pwsh 7 | 109/109 |
| `tests/linux-docker.sh`: check → apply → second apply with no changes | Ubuntu 24.04 / 20.04, Mint 21.3, Oracle Linux 9 with real auditd; Debian 12, Rocky 9 / 8, Alma 9, CentOS 7, Fedora 40, Amazon Linux 2023, openSUSE Leap 15.6, Arch with a stub auditctl (their mirrors were unreachable from the sandbox) | pass (13 distributions) |
| auditd installed by the script itself through the package manager | Ubuntu 24.04 (apt), Oracle Linux 9 (dnf) | pass |
| Server 2008 R2 lab: Sysmon 10.42 with the schema 4.22 config | VM, PowerShell 2.0 | running, events logged |
| Generated auditd rules loaded into a real kernel | privileged container | 57/57 rules accepted |
| `tests/linux-bundle.sh`: `install.sh build` → install from the bundle on a clean container **without network** → second run with no changes → modified bundle rejected | Ubuntu 22.04, Ubuntu 24.04, Oracle Linux 9 (rpm) | pass |
| `install.sh --fetch` downloads the main script from GitHub | Ubuntu 24.04 | pass |
| Sysmon 10.42 and 10.2 in `vendor/`: Authenticode (Microsoft, valid at timestamp), FileVersion, pinned hash | osslsigncode + unit test | pass |

**Not verified yet (needs a real lab):**
- all Windows code that talks to the OS: wevtutil, auditpol, Sysmon installation, registry, DISM;
- `New-SecLoggingGpo.ps1` against a real AD/SYSVOL;
- long-term stability of Sysmon 10.42/10.2 on Server 2008/R2 (installation verified; use `-CollectOnly` after a few hours and a reboot);
- `Install-SecLogging.ps1` on real Windows (only its helper functions are unit-tested);
- Alpine (no mirrors in the sandbox) and package installation on SUSE, Arch, Amazon Linux, CentOS 7;
- `install.sh build` on CentOS 7 (`repotrack`);

Suggested order:

1. Run `-AuditOnly` on a workstation, a server and a DC (RU and EN) and collect the JSON reports.
2. Apply on one test host of each type. A second run must report `Changed=0`.
3. Run `New-SecLoggingGpo.ps1 -WhatIf`, then apply to a test OU (`-LinkTargets "OU=Test,DC=corp,DC=local"`), then check `gpresult` and `auditpol`.

```bash
pwsh -NoProfile -File tests/windows-unit.ps1
./tests/linux-docker.sh          # IMAGES="ubuntu:24.04 debian:12" to pick images
./tests/linux-bundle.sh          # IMAGE=ubuntu:22.04 or IMAGE=oraclelinux:9
# behind an HTTPS-only proxy: CA_FILE=/path/ca.crt PROXY=$HTTPS_PROXY ./tests/linux-docker.sh
```
