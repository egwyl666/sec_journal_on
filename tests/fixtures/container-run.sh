#!/usr/bin/env bash
# Виконується всередині контейнера з tests/linux-docker.sh: check -> apply -> повторний apply.
set -u
if ! command -v auditctl >/dev/null; then
    # дзеркала пакетів недоступні: заглушка auditctl + стандартний auditd.conf для перевірки логіки конфігурації
    echo "ПРИМІТКА: використовується заглушка auditctl"
    printf '#!/bin/sh\n[ "$1" = -v ] && echo "auditctl version 3.1.2"\nexit 0\n' > /usr/sbin/auditctl; chmod +x /usr/sbin/auditctl
    mkdir -p /etc/audit/rules.d; cp /tests/fixtures/auditd.conf /etc/audit/auditd.conf
fi
# фейковий конфіг агента Wazuh
mkdir -p /var/ossec/etc && printf '<ossec_config>\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/dpkg.log</location>\n  </localfile>\n</ossec_config>\n' > /var/ossec/etc/ossec.conf
echo "--- check"; out=$(bash /src/set-security-logging.sh --check); rc=$?; echo "$out" | sed -n '2,3p'; echo "$out" | tail -2; echo "rc=$rc"
echo "--- apply"; bash /src/set-security-logging.sh --configure-wazuh --quiet; rc1=$?; echo "rc=$rc1"
echo "--- повторний apply"; out=$(bash /src/set-security-logging.sh --configure-wazuh); rc2=$?; echo "$out" | tail -2; echo "rc=$rc2"
echo "$out" | grep -E '^\[(Changed|Error|Warning)'
echo "$out" | grep -qE '^\[(Changed|Error)' && { echo "НЕ ІДЕМПОТЕНТНО"; exit 1; }
grep -qE '"Version": "[0-9]+\.[0-9]+\.[0-9]+"' /var/log/seclogging/last-report.json || { echo "НЕПРАВИЛЬНА ВЕРСІЯ У ЗВІТІ"; exit 1; }
echo "правил аудиту: $(grep -c '^-[wa] ' /etc/audit/rules.d/50-seclogging.rules)"
grep -E '^(max_log_file|num_logs|max_log_file_action|log_format) ' /etc/audit/auditd.conf | tr '\n' ' '; echo
grep -h '<location>' /var/ossec/etc/ossec.conf | tr -d ' ' | tr '\n' ' '; echo
if command -v python3 >/dev/null; then python3 -c 'import json;json.load(open("/var/log/seclogging/last-report.json"));print("json ok")' || exit 1; fi
exit $rc2
