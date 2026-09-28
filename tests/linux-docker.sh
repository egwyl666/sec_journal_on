#!/usr/bin/env bash
# Запускає linux/set-security-logging.sh у контейнерах дистрибутивів: check -> apply -> apply (ідемпотентність).
# Частини рівня ядра (завантаження auditctl, перезапуск служб) у контейнерах навмисно пропускаються.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
IMAGES=${IMAGES:-"ubuntu:24.04 ubuntu:20.04 debian:12 rockylinux:9"}
fail=0
for img in $IMAGES; do
    echo "=================== $img"
    docker run --rm -v "$ROOT/linux:/src:ro" -v "$ROOT/tests:/tests:ro" "$img" bash -c '
        set -u
        if command -v apt-get >/dev/null; then apt-get update -qq >/dev/null; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq rsyslog logrotate >/dev/null 2>&1
        else dnf install -y -q rsyslog logrotate >/dev/null 2>&1; fi
        if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get install -y -qq auditd >/dev/null 2>&1; else dnf install -y -q audit >/dev/null 2>&1; fi
        if ! command -v auditctl >/dev/null; then
            # дзеркала пакетів недоступні: заглушка auditctl + стандартний auditd.conf для перевірки логіки конфігурації
            echo "ПРИМІТКА: використовується заглушка auditctl"
            printf "#!/bin/sh\n[ \"\$1\" = -v ] && echo \"auditctl version 3.1.2\"\nexit 0\n" > /usr/sbin/auditctl; chmod +x /usr/sbin/auditctl
            mkdir -p /etc/audit/rules.d; cp /tests/fixtures/auditd.conf /etc/audit/auditd.conf
        fi
        touch /var/log/auth.log /var/log/secure
        # фейковий конфіг агента Wazuh
        mkdir -p /var/ossec/etc && printf "<ossec_config>\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/dpkg.log</location>\n  </localfile>\n</ossec_config>\n" > /var/ossec/etc/ossec.conf
        echo "--- check"; /src/set-security-logging.sh --check --quiet; echo "rc=$?"
        echo "--- apply"; /src/set-security-logging.sh --configure-wazuh --quiet; rc1=$?; echo "rc=$rc1"
        echo "--- повторний apply"; out=$(/src/set-security-logging.sh --configure-wazuh); rc2=$?; echo "$out" | tail -3; echo "rc=$rc2"
        echo "$out" | grep -E "^\[(Changed|Error)" && { echo "НЕ ІДЕМПОТЕНТНО"; exit 1; }
        grep -qE "\"Version\": \"[0-9]+\.[0-9]+\.[0-9]+\"" /var/log/seclogging/last-report.json || { echo "НЕПРАВИЛЬНА ВЕРСІЯ У ЗВІТІ"; exit 1; }
        grep -c "^-[wa] " /etc/audit/rules.d/50-seclogging.rules
        grep -E "^(max_log_file|num_logs|max_log_file_action|log_format) " /etc/audit/auditd.conf
        cat /etc/systemd/journald.conf.d/50-seclogging.conf 2>/dev/null
        grep -c "<localfile>" /var/ossec/etc/ossec.conf
        python3 -c "import json;d=json.load(open(\"/var/log/seclogging/last-report.json\"));print(\"json ok\",d[\"Summary\"])" 2>/dev/null || grep -c Status /var/log/seclogging/last-report.json
        exit $rc2
    ' || { echo "ПОМИЛКА: $img"; fail=1; }
done
exit $fail
