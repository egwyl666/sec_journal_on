#!/usr/bin/env bash
# Запускає linux/set-security-logging.sh у контейнерах дистрибутивів: check -> apply -> apply (ідемпотентність).
# Частини рівня ядра (завантаження auditctl, перезапуск служб) у контейнерах навмисно пропускаються.
#   IMAGES="ubuntu:24.04 rockylinux:9" ./tests/linux-docker.sh
#   За корпоративним проксі (лише HTTPS): CA_FILE=/path/ca.crt PROXY=$HTTPS_PROXY ./tests/linux-docker.sh
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
IMAGES=${IMAGES:-"ubuntu:24.04 ubuntu:20.04 debian:12 linuxmintd/mint21.3-amd64 rockylinux:9 rockylinux:8 almalinux:9 oraclelinux:9 centos:7 fedora:40 amazonlinux:2023 opensuse/leap:15.6 archlinux:latest alpine:3.20"}
net_args=(); [ -n "${PROXY:-}" ] && net_args=(--network host -e "https_proxy=$PROXY" -e "HTTPS_PROXY=$PROXY")
[ -n "${CA_FILE:-}" ] && net_args+=(-v "$CA_FILE:/ca.crt:ro")
fail=0; passed=(); skipped=()
for img in $IMAGES; do
    echo "=================== $img"
    docker run --rm "${net_args[@]}" -v "$ROOT/linux:/src:ro" -v "$ROOT/tests:/tests:ro" "$img" sh -c '
        [ -f /ca.crt ] && [ -n "${https_proxy:-}" ] && sh /tests/fixtures/container-net.sh >/dev/null 2>&1
        # пакети: rsyslog, logrotate, auditd - якщо дзеркала доступні
        if command -v apt-get >/dev/null; then apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq rsyslog logrotate auditd >/dev/null 2>&1
        elif command -v dnf >/dev/null; then dnf install -y -q rsyslog logrotate audit >/dev/null 2>&1
        elif command -v yum >/dev/null; then yum install -y -q rsyslog logrotate audit >/dev/null 2>&1
        elif command -v zypper >/dev/null; then zypper -n -q in rsyslog logrotate audit >/dev/null 2>&1
        elif command -v pacman >/dev/null; then pacman -S --noconfirm --needed audit logrotate >/dev/null 2>&1
        elif command -v apk >/dev/null; then apk add -q bash audit logrotate >/dev/null 2>&1; fi
        command -v bash >/dev/null || { echo "ПРОПУЩЕНО: немає bash і дзеркала недоступні"; exit 77; }
        exec bash /tests/fixtures/container-run.sh
    '; rc=$?
    case $rc in 0) passed+=("$img") ;; 77) skipped+=("$img") ;; *) echo "ПОМИЛКА: $img"; fail=1 ;; esac
done
echo
echo "Пройшли:   ${passed[*]:-немає}"
echo "Пропущено: ${skipped[*]:-немає}"
exit $fail
