# Sysmon 10.42 for legacy Windows / Sysmon 10.42 для старих Windows

**EN.** Windows 7 / Server 2008 / 2008 R2 (NT 6.0/6.1) are not supported by modern Sysmon, and hangs/BSODs are known. Version 10.42 is the last one considered stable there. Microsoft no longer hosts it, so it is kept here. `Set-SecurityLogging.ps1 -BuildPackage` puts it into the package as `legacy\Sysmon.zip`. Hosts with `-AllowLegacySysmon` install it together with the SwiftOnSecurity config for schema 4.22.

**UA.** Сучасний Sysmon не підтримує Windows 7 / Server 2008 / 2008 R2 (NT 6.0/6.1), відомі зависання та BSOD. Остання версія, яку там вважають стабільною, — 10.42. Microsoft її більше не роздає, тому вона зберігається тут. `Set-SecurityLogging.ps1 -BuildPackage` кладе її в пакет як `legacy\Sysmon.zip`. Хости з `-AllowLegacySysmon` встановлюють її разом із конфігом SwiftOnSecurity для схеми 4.22.

## Provenance / Походження

| File | SHA256 |
|---|---|
| `10.42/Sysmon.zip` (pinned in `Set-SecurityLogging.ps1`) | `11681051bc9846130f378b5b6441ab27a05e1076dd62f58eda7c973fcf188828` |
| `Sysmon.exe` 10.42 | `bd75af02c99374bbc4acb7f02502426bbba007e4e44ff7f439d7f8a7b9bb4c5c` |
| `Sysmon64.exe` 10.42 | `80b110b91730729be60c7d79c55fff0ec893fd4cfb5f44d04c433ee8e95c5e20` |

- Source / Джерело: <https://github.com/super0xbad1dea/SysmonVersions> (folder `10.42`). The binary hashes match the VirusTotal links in that repository's README. / Хеші бінарників збігаються з посиланнями VirusTotal у README того репозиторію.
- Authenticode (checked with `osslsigncode` against Microsoft Root Certificate Authority 2011, SHA1 `8F43288AD272F3103B6FB1428485EA3014C0BCFE`, at the timestamp time) / перевірено `osslsigncode` щодо кореня Microsoft Root Certificate Authority 2011 на момент мітки часу:
  - signer / підписант: `CN=Microsoft Corporation, O=Microsoft Corporation`, issuer `Microsoft Code Signing PCA 2011`;
  - timestamp / мітка часу: 2019-12-10 (Sysmon.exe 21:57:24 UTC, Sysmon64.exe 21:53:14 UTC);
  - result / результат: `Signature verification: ok` for both files / для обох файлів.
- `FileVersion` of both files / обох файлів: `10.42`.
- The zip was created deterministically (fixed file dates 2019-12-10), so its SHA256 is stable. / Zip створено детерміновано (фіксовані дати файлів 2019-12-10), тому його SHA256 стабільний.

`Set-SecurityLogging.ps1` checks the zip SHA256 and the Microsoft signature again before every install. / Перед кожним встановленням `Set-SecurityLogging.ps1` знову перевіряє SHA256 архіву та підпис Microsoft.

> **License / Ліцензія.** Sysmon is covered by the Sysinternals Software License Terms, which do not allow publishing the software for others to copy. Keep this in mind while the repository is public: consider making it private. / Sysmon підпадає під ліцензію Sysinternals, яка не дозволяє публікувати програму для копіювання іншими. Поки репозиторій публічний, майте це на увазі: варто зробити його приватним.
