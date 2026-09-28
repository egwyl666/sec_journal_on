#!/usr/bin/env bash
# Перевіряє linux/install.sh: build комплекту -> офлайн-встановлення в контейнері без мережі
# (--network none) -> повторний запуск без змін -> відмова для підміненого комплекту.
#   IMAGE=ubuntu:22.04 WITH_SYSMON=1 [CA_FILE=/path/ca.crt DOCKER_BUILD_ARGS="--network host -e https_proxy=..."] ./tests/linux-bundle.sh
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=${IMAGE:-ubuntu:22.04}
WITH_SYSMON=${WITH_SYSMON:-0}
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
sysmon_flag=""; [ "$WITH_SYSMON" -eq 1 ] && sysmon_flag="--with-sysmon"

echo "=== build ($IMAGE)"
# CA_FILE - необов'язковий корпоративний CA для HTTPS через проксі
ca_mount=(); [ -n "${CA_FILE:-}" ] && ca_mount=(-v "$CA_FILE:/ca.crt:ro" -e CURL_CA_BUNDLE=/ca.crt)
# shellcheck disable=SC2086
docker run --rm ${DOCKER_BUILD_ARGS:-} "${ca_mount[@]}" -v "$ROOT/linux:/src:ro" -v "$OUT:/out" "$IMAGE" bash -c '
    [ -f /ca.crt ] && echo "Acquire::https::CAInfo \"/ca.crt\";" > /etc/apt/apt.conf.d/99ca
    apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates >/dev/null 2>&1
    /src/install.sh build '"$sysmon_flag"' --out /out/b' || { echo "ПОМИЛКА: build"; exit 1; }

echo "=== офлайн-встановлення (--network none)"
docker run --rm --network none -v "$OUT/b:/bundle:ro" "$IMAGE" bash -c "
    /bundle/install.sh --from /bundle $sysmon_flag --quiet || exit 1
    command -v auditctl >/dev/null || { echo 'auditctl не встановлено'; exit 1; }
    [ \$(dpkg -l | grep -cE '^(iU|iF|iH)') -eq 0 ] || { echo 'є напіввстановлені пакети'; exit 1; }
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
