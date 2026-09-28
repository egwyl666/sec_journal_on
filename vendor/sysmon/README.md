# Sysmon for legacy Windows / Sysmon для старих Windows

**EN.** Windows 7 / Server 2008 / 2008 R2 (NT 6.0/6.1) are not supported by modern Sysmon, and hangs/BSODs are known. Microsoft no longer hosts old builds, so two are kept here. `Set-SecurityLogging.ps1 -BuildPackage` puts them into the package as `legacy\<version>\Sysmon.zip`. Hosts with `-AllowLegacySysmon -LegacySysmonVersion <version>` install one of them with a matching SwiftOnSecurity config:
- **10.42** (default): config schema 4.22 (commit `c00581f8`). 10.42 supports schemas up to 4.23.
- **10.2**: config schema 4.00 (commit `9fb44e98`, no DNS query events). 10.2 supports schemas only up to 4.21, and there is no SwiftOnSecurity 4.21 config.

**UA.** Сучасний Sysmon не підтримує Windows 7 / Server 2008 / 2008 R2 (NT 6.0/6.1), відомі зависання та BSOD. Microsoft старі збірки більше не роздає, тому дві з них зберігаються тут. `Set-SecurityLogging.ps1 -BuildPackage` кладе їх у пакет як `legacy\<версія>\Sysmon.zip`. Хости з `-AllowLegacySysmon -LegacySysmonVersion <версія>` встановлюють одну з них з відповідним конфігом SwiftOnSecurity:
- **10.42** (за замовчуванням): конфіг схеми 4.22 (коміт `c00581f8`). 10.42 підтримує схеми до 4.23.
- **10.2**: конфіг схеми 4.00 (коміт `9fb44e98`, без подій DNS-запитів). 10.2 підтримує схеми лише до 4.21, а конфігу 4.21 у SwiftOnSecurity немає.

## Provenance / Походження

| File | SHA256 |
|---|---|
| `10.42/Sysmon.zip` (pinned in `Set-SecurityLogging.ps1`) | `11681051bc9846130f378b5b6441ab27a05e1076dd62f58eda7c973fcf188828` |
| `Sysmon.exe` 10.42 | `bd75af02c99374bbc4acb7f02502426bbba007e4e44ff7f439d7f8a7b9bb4c5c` |
| `Sysmon64.exe` 10.42 | `80b110b91730729be60c7d79c55fff0ec893fd4cfb5f44d04c433ee8e95c5e20` |
| `10.2/Sysmon.zip` (pinned in `Set-SecurityLogging.ps1`) | `8a07b9341eb3bc31065eca885c3398acb87da38451939f8cf468b2bdb3cf1ed9` |
| `Sysmon.exe` 10.2 | `e88ef7754bc8c7fb5b17b9756df0895820f3cd6a182fde7816c039346a4dc7ca` |
| `Sysmon64.exe` 10.2 | `981792616e29b07ca33749e4f3da9769a850c61ced86f71716e0af475bbd2df1` |

- Source / Джерело: <https://github.com/super0xbad1dea/SysmonVersions> (folders `10.42`, `10.2`). The binary hashes match the VirusTotal links in that repository's README. / Хеші бінарників збігаються з посиланнями VirusTotal у README того репозиторію.
- Authenticode (checked with `osslsigncode` against Microsoft Root Certificate Authority 2011, SHA1 `8F43288AD272F3103B6FB1428485EA3014C0BCFE`, at the timestamp time) / перевірено `osslsigncode` щодо кореня Microsoft Root Certificate Authority 2011 на момент мітки часу:
  - signer / підписант: `CN=Microsoft Corporation, O=Microsoft Corporation`, issuer `Microsoft Code Signing PCA 2011`;
  - timestamp / мітка часу: 10.42 — 2019-12-10 (Sysmon.exe 21:57:24 UTC, Sysmon64.exe 21:53:14 UTC); 10.2 — 2019-06-28 (16:12:20 / 16:10:02 UTC);
  - 10.2 is dual-signed (SHA1 + SHA256); the SHA256 signature verifies. / 10.2 має подвійний підпис (SHA1 + SHA256); підпис SHA256 перевіряється;
  - result / результат: `Signature verification: ok` for all four files / для всіх чотирьох файлів.
- `FileVersion`: `10.42` and `10.2` respectively / відповідно.
- The zips were created deterministically (fixed file dates), so their SHA256 is stable. / Zip-архіви створено детерміновано (фіксовані дати файлів), тому їхній SHA256 стабільний.

`Set-SecurityLogging.ps1` checks the zip SHA256 and the Microsoft signature again before every install. / Перед кожним встановленням `Set-SecurityLogging.ps1` знову перевіряє SHA256 архіву та підпис Microsoft.

> **License / Ліцензія.** Sysmon is covered by the Sysinternals Software License Terms, which do not allow publishing the software for others to copy. Keep this in mind while the repository is public: consider making it private. / Sysmon підпадає під ліцензію Sysinternals, яка не дозволяє публікувати програму для копіювання іншими. Поки репозиторій публічний, майте це на увазі: варто зробити його приватним.
