#!/usr/bin/env bash
# Перевіряє linux/install.sh: build комплекту -> офлайн-встановлення в контейнері без мережі
# (--network none) -> повторний запуск без змін -> відмова для підміненого комплекту.
#   IMAGE=ubuntu:22.04 WITH_SYSMON=1 ./tests/linux-bundle.sh
#   IMAGE=oraclelinux:9 ./tests/linux-bundle.sh                       (сімейство rpm)
#   За корпоративним проксі (лише HTTPS): CA_FILE=/path/ca.crt PROXY=$HTTPS_PROXY ./tests/linux-bundle.sh
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=${IMAGE:-ubuntu:22.04}
WITH_SYSMON=${WITH_SYSMON:-0}
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
sysmon_flag=""; [ "$WITH_SYSMON" -eq 1 ] && sysmon_flag="--with-sysmon"
net_args=(); [ -n "${PROXY:-}" ] && net_args=(--network host -e "https_proxy=$PROXY" -e "HTTPS_PROXY=$PROXY")
[ -n "${CA_FILE:-}" ] && net_args+=(-v "$CA_FILE:/ca.crt:ro" -e CURL_CA_BUNDLE=/ca.crt)

echo "=== build ($IMAGE)"
docker run --rm "${net_args[@]}" -v "$ROOT/linux:/src:ro" -v "$ROOT/tests:/tests:ro" -v "$OUT:/out" "$IMAGE" bash -c '
    [ -f /ca.crt ] && [ -n "${https_proxy:-}" ] && sh /tests/fixtures/container-net.sh >/dev/null 2>&1
    if command -v apt-get >/dev/null; then apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates >/dev/null 2>&1; fi
    /src/install.sh build '"$sysmon_flag"' --out /out/b' || { echo "ПОМИЛКА: build"; exit 1; }
ls "$OUT/b/auditd" | head -20

echo "=== офлайн-встановлення (--network none)"
docker run --rm --network none -v "$OUT/b:/bundle:ro" "$IMAGE" bash -c "
    command -v auditctl >/dev/null && { echo 'auditctl уже є в образі - тест не показовий'; exit 1; }
    /bundle/install.sh --from /bundle $sysmon_flag --quiet || exit 1
    command -v auditctl >/dev/null || { echo 'auditctl не встановлено'; cat /tmp/seclogging-offline.log; exit 1; }
    if command -v dpkg >/dev/null; then [ \$(dpkg -l | grep -cE '^(iU|iF|iH)') -eq 0 ] || { echo 'є напіввстановлені пакети'; exit 1; }
    else rpm -Va audit >/dev/null 2>&1; rpm -q audit || exit 1; fi
    if [ '$WITH_SYSMON' = 1 ]; then command -v sysmon >/dev/null || { echo 'sysmon не встановлено'; exit 1; }; fi
    out=\$(/bundle/install.sh --from /bundle $sysmon_flag)
    echo \"\$out\" | grep -E '^\[(Changed|Error)' && { echo 'НЕ ІДЕМПОТЕНТНО'; exit 1; }
    exit 0" || { echo "ПОМИЛКА: офлайн-встановлення"; exit 1; }

echo "=== підмінений комплект має бути відхилено"
echo "# tampered" >> "$OUT/b/set-security-logging.sh"
if docker run --rm --network none -v "$OUT/b:/bundle:ro" "$IMAGE" /bundle/install.sh --from /bundle --check >/dev/null 2>&1; then
    echo "ПОМИЛКА: підміну не виявлено"; exit 1
fi
echo "OK"
