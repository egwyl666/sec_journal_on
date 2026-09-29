#!/usr/bin/env python3
# Тестові події для wazuh/rules/seclogging_rules.xml у форматі, який шле агент Wazuh.
# Рядок виводу: назва <TAB> очікуване правило <TAB> тип черги <TAB> location <TAB> подія
# Очікуване правило "-" - наше правило НЕ має спрацювати (перевіряється, що id не з 1100xx-1101xx).
import json
from xml.sax.saxutils import escape

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
SEC, AUD = "Security", "Microsoft-Windows-Security-Auditing"


def win(name, want, ch, prov, eid, data, level=None, kw="0x8020000000000000"):
    if level is None:
        level = 0 if ch == SEC else 4   # події аудиту Security мають Level 0
    d = "".join(f"<Data Name='{k}'>{escape(v)}</Data>" for k, v in data.items())
    x = (f"<Event xmlns='{NS}'><System><Provider Name='{prov}'/><EventID>{eid}</EventID><Version>0</Version>"
         f"<Level>{level}</Level><Task>0</Task><Opcode>0</Opcode><Keywords>{kw}</Keywords>"
         f"<TimeCreated SystemTime='2026-09-29T12:00:00.0000000Z'/><EventRecordID>1</EventRecordID>"
         f"<Execution ProcessID='4' ThreadID='8'/><Channel>{ch}</Channel><Computer>DC01.corp.local</Computer>"
         f"<Security/></System><EventData>{d}</EventData></Event>")
    print("\t".join([name, want, "f", "EventChannel", json.dumps({"Message": name, "Event": x}, ensure_ascii=False)]))


def audit(name, want, key, exe="/usr/bin/vim.basic"):
    line = (f'type=SYSCALL msg=audit(1727600000.123:4242): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c '
            f'a1=55 a2=241 a3=1b6 items=2 ppid=100 pid=200 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 '
            f'fsgid=0 tty=pts0 ses=3 comm="x" exe="{exe}" key="{key}" name="{name}"')
    print("\t".join([name, want, "1", "/var/log/audit/audit.log", line]))


def syslog(name, want, msg):
    print("\t".join([name, want, "1", "/var/log/auth.log", f"Sep 29 12:00:00 web1 seclogging: {msg} [{name}]"]))


# ---- журнали й аудит
win("1102 очищено Security", "110001", SEC, "Microsoft-Windows-Eventlog", 1102, {"SubjectUserName": "admin"}, level=4, kw="0x4020000000000000")
win("104 очищено журнал", "110002", "System", "Microsoft-Windows-Eventlog", 104, {"Channel": "Application"})
win("1100 зупинка eventlog", "110003", SEC, "Microsoft-Windows-Eventlog", 1100, {}, level=4, kw="0x4020000000000000")
win("4719 політика аудиту", "110004", SEC, AUD, 4719, {"SubjectUserName": "admin", "SubcategoryGuid": "{0CCE922B-69AE-11D9-BED3-505054503030}"})
# ---- Sysmon і SecLogging
win("sysmon 4 зупинено", "110010", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 4, {"State": "Stopped"})
win("sysmon 4 запущено", "-", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 4, {"State": "Started"})
win("sysmon 16 конфіг", "110011", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 16, {"Configuration": "C:\\x.xml"})
win("seclogging 1002", "110012", "Application", "SecLogging", 1002, {"Data": "Set-SecurityLogging 1.3.2 Error=1"}, level=2)
win("seclogging 1001", "110013", "Application", "SecLogging", 1001, {"Data": "Warning=2"}, level=3)
win("seclogging 1000", "110014", "Application", "SecLogging", 1000, {"Data": "ok"})
# ---- служби
win("4697 служба", "110020", SEC, AUD, 4697, {"ServiceName": "evil", "ServiceFileName": "C:\\t\\e.exe"})
win("7045 служба", "110021", "System", "Service Control Manager", 7045, {"ServiceName": "evil", "ImagePath": "C:\\t\\e.exe"})
# ---- привілейовані групи (SID, мова не важлива)
win("4728 Domain Admins рос.", "110030", SEC, AUD, 4728, {"TargetUserName": "Администраторы домена", "TargetSid": "S-1-5-21-1-2-3-512", "MemberName": "CN=bob"})
win("4732 Administrators", "110030", SEC, AUD, 4732, {"TargetUserName": "Administrators", "TargetSid": "S-1-5-32-544", "MemberName": "bob"})
win("4756 Enterprise Admins", "110030", SEC, AUD, 4756, {"TargetUserName": "Enterprise Admins", "TargetSid": "S-1-5-21-1-2-3-519", "MemberName": "bob"})
win("4728 звичайна група", "-", SEC, AUD, 4728, {"TargetUserName": "Sales", "TargetSid": "S-1-5-21-1-2-3-1512", "MemberName": "CN=bob"})
# ---- атаки на AD
win("4662 DCSync користувачем", "110040", SEC, AUD, 4662, {"SubjectUserName": "bob", "ObjectServer": "DS", "AccessMask": "0x100",
    "Properties": "%%7688\n\t\t{1131F6AD-9C07-11D1-F79F-00C04FC2DCD2}\n\t{19195a5b-6da0-11d0-afd3-00c04fd930c9}"})
win("4662 реплікація від DC$", "-", SEC, AUD, 4662, {"SubjectUserName": "DC02$", "ObjectServer": "DS", "AccessMask": "0x100",
    "Properties": "%%7688\n\t\t{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}"})
win("4662 інший доступ", "-", SEC, AUD, 4662, {"SubjectUserName": "bob", "ObjectServer": "DS", "AccessMask": "0x20",
    "Properties": "%%7684\n\t\t{bf967a86-0de6-11d0-a285-00aa003049e2}"})
win("4769 RC4 на службу", "110041", SEC, AUD, 4769, {"ServiceName": "svc_sql", "TicketEncryptionType": "0x17", "Status": "0x0", "TargetUserName": "bob@CORP"})
win("4769 AES", "-", SEC, AUD, 4769, {"ServiceName": "svc_sql", "TicketEncryptionType": "0x12", "Status": "0x0"})
win("4769 RC4 на машину", "-", SEC, AUD, 4769, {"ServiceName": "WS01$", "TicketEncryptionType": "0x17", "Status": "0x0"})
win("4768 без preauth", "110042", SEC, AUD, 4768, {"TargetUserName": "bob", "PreAuthType": "0", "Status": "0x0"})
win("4768 звичайний", "-", SEC, AUD, 4768, {"TargetUserName": "bob", "PreAuthType": "2", "Status": "0x0"})
win("4794 DSRM", "110043", SEC, AUD, 4794, {"SubjectUserName": "admin"})
win("5136 GPO", "110044", SEC, AUD, 5136, {"ObjectClass": "groupPolicyContainer", "ObjectDN": "CN={X},CN=Policies"})
win("5136 користувач", "-", SEC, AUD, 5136, {"ObjectClass": "user", "ObjectDN": "CN=bob"})
win("2889 LDAP без підпису", "110045", "Directory Service", "Microsoft-Windows-ActiveDirectory_DomainService", 2889, {"param1": "10.0.0.5:5000", "param2": "CORP\\bob"})
win("3065 LSASS", "110050", "Microsoft-Windows-CodeIntegrity/Operational", "Microsoft-Windows-CodeIntegrity", 3065, {"FileNameBuffer": "x.dll"}, level=3)
win("3066 LSASS", "110050", "Microsoft-Windows-CodeIntegrity/Operational", "Microsoft-Windows-CodeIntegrity", 3066, {"FileNameBuffer": "x.dll"})
# ---- звичайні події: наші правила мовчать
win("4624 вхід", "-", SEC, AUD, 4624, {"TargetUserName": "bob", "LogonType": "3"})
win("4625 невдалий вхід", "-", SEC, AUD, 4625, {"TargetUserName": "bob"}, kw="0x8010000000000000")
win("4688 процес", "-", SEC, AUD, 4688, {"NewProcessName": "C:\\Windows\\notepad.exe"})

# ---- Linux auditd
for key, rid in [("auditlog", "110100"), ("auditconfig", "110101"), ("audittools", "110102"), ("rootkey", "110103"),
                 ("preload", "110104"), ("webshell", "110105"), ("sudoers", "110106"), ("pam", "110107"),
                 ("code_injection", "110108"), ("identity", "110109"), ("user_mgmt", "110110"), ("sshd", "110111"),
                 ("cron", "110112"), ("shellprofile", "110113"), ("login", "110114"), ("systemd", "110115"),
                 ("init", "110115"), ("modules", "110116"), ("time", "110117"), ("passwd_change", "110118"),
                 ("netconf", "110119"), ("mount", "110119"), ("priv_esc", "110119")]:
    audit(f"auditd {key}", rid, key)
audit("auditd чужий ключ", "-", "somethingelse")
audit("auditd audit-wazuh-c", "-", "audit-wazuh-c")
# ---- Linux: підсумок set-security-logging.sh
syslog("linux помилки", "110152", "set-security-logging 1.3.2 role=server OK=10 Changed=0 WouldChange=0 Warning=3 Error=2 Skipped=1")
syslog("linux попередження", "110151", "set-security-logging 1.3.2 role=server OK=10 Changed=0 WouldChange=0 Warning=3 Error=0 Skipped=1")
syslog("linux ок", "110150", "set-security-logging 1.3.2 role=server OK=10 Changed=0 WouldChange=0 Warning=0 Error=0 Skipped=1")
