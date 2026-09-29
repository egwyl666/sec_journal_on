#!/usr/bin/env bash
# Виконується всередині контейнера з tests/linux-docker.sh: check -> apply -> повторний apply.
set -u
if ! command -v auditctl >/dev/null; then
    # дзеркала пакетів недоступні: заглушка auditctl + стандартний auditd.conf для перевірки логіки конфігурації
    echo "ПРИМІТКА: використовується заглушка auditctl"
    printf '#!/bin/sh\n[ "$1" = -v ] && echo "auditctl version 3.1.2"\nexit 0\n' > /usr/sbin/auditctl; chmod +x /usr/sbin/auditctl
    mkdir -p /etc/audit/rules.d; cp /tests/fixtures/auditd.conf /etc/audit/auditd.conf
fi
# налаштування адміністратора, які скрипт мусить зберегти: власний -b у rules.d і Port у sshd_config
mkdir -p /etc/audit/rules.d; printf -- '-b 16384\n' > /etc/audit/rules.d/60-admin.rules
[ -f /etc/ssh/sshd_config ] && printf '\nPort 2222\nLogLevel INFO\n' >> /etc/ssh/sshd_config
# фейковий конфіг агента Wazuh
mkdir -p /var/ossec/etc && printf '<ossec_config>\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/dpkg.log</location>\n  </localfile>\n</ossec_config>\n' > /var/ossec/etc/ossec.conf
echo "--- check"; out=$(bash /src/set-security-logging.sh --check); rc=$?; echo "$out" | sed -n '2,3p'; echo "$out" | tail -2; echo "rc=$rc"
echo "--- apply"; bash /src/set-security-logging.sh --configure-wazuh --quiet; rc1=$?; echo "rc=$rc1"
echo "--- повторний apply"; out=$(bash /src/set-security-logging.sh --configure-wazuh); rc2=$?; echo "$out" | tail -2; echo "rc=$rc2"
echo "$out" | grep -E '^\[(Changed|Error|Warning)'
echo "$out" | grep -qE '^\[(Changed|Error)' && { echo "НЕ ІДЕМПОТЕНТНО"; exit 1; }
grep -qE '"Version": "[0-9]+\.[0-9]+\.[0-9]+"' /var/log/seclogging/last-report.json || { echo "НЕПРАВИЛЬНА ВЕРСІЯ У ЗВІТІ"; exit 1; }
grep -qx -- '-b 16384' /etc/audit/rules.d/zz-seclogging-backlog.rules || { echo "-b НЕ ОСТАННІЙ АБО МЕНШИЙ ЗА АДМІНСЬКИЙ"; exit 1; }
if [ -f /etc/ssh/sshd_config ]; then
    grep -q '^Port 2222' /etc/ssh/sshd_config || { echo "ВТРАЧЕНО Port 2222 У sshd_config"; exit 1; }
    if command -v sshd >/dev/null || [ -x /usr/sbin/sshd ]; then
        mkdir -p /run/sshd
        lv=$(/usr/sbin/sshd -T 2>/dev/null | awk '$1=="loglevel"{print $2}')
        [ -z "$lv" ] || [ "$lv" = VERBOSE ] || { echo "sshd LogLevel=$lv, очікувано VERBOSE"; exit 1; }
        echo "sshd: LogLevel=${lv:-?}, Port 2222 збережено"
    fi
fi
echo "правил аудиту: $(grep -c '^-[wa] ' /etc/audit/rules.d/50-seclogging.rules)"
grep -E '^(max_log_file|num_logs|max_log_file_action|log_format) ' /etc/audit/auditd.conf | tr '\n' ' '; echo
grep -h '<location>' /var/ossec/etc/ossec.conf | tr -d ' ' | tr '\n' ' '; echo
if command -v python3 >/dev/null; then python3 -c 'import json;json.load(open("/var/log/seclogging/last-report.json"));print("json ok")' || exit 1; fi
exit $rc2
