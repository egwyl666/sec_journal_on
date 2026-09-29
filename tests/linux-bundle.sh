#!/usr/bin/env bash
# Перевіряє linux/install.sh: build комплекту -> офлайн-встановлення в контейнері без мережі
# (--network none) -> повторний запуск без змін -> відмова для підміненого комплекту.
#   IMAGE=ubuntu:22.04 ./tests/linux-bundle.sh
#   IMAGE=oraclelinux:9 ./tests/linux-bundle.sh                       (сімейство rpm)
#   За корпоративним проксі (лише HTTPS): CA_FILE=/path/ca.crt PROXY=$HTTPS_PROXY ./tests/linux-bundle.sh
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=${IMAGE:-ubuntu:22.04}
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
net_args=(); [ -n "${PROXY:-}" ] && net_args=(--network host -e "https_proxy=$PROXY" -e "HTTPS_PROXY=$PROXY")
[ -n "${CA_FILE:-}" ] && net_args+=(-v "$CA_FILE:/ca.crt:ro" -e CURL_CA_BUNDLE=/ca.crt)

echo "=== build ($IMAGE)"
docker run --rm "${net_args[@]}" -v "$ROOT/linux:/src:ro" -v "$ROOT/tests:/tests:ro" -v "$OUT:/out" "$IMAGE" bash -c '
    [ -f /ca.crt ] && [ -n "${https_proxy:-}" ] && sh /tests/fixtures/container-net.sh >/dev/null 2>&1
    if command -v apt-get >/dev/null; then apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates >/dev/null 2>&1; fi
    /src/install.sh build --out /out/b' || { echo "ПОМИЛКА: build"; exit 1; }
ls "$OUT/b/auditd" | head -20

# "curl ... | bash -s build": $0 - це bash, install.sh має потрапити в комплект із GitHub (реліз PIPE_REF)
PIPE_REF=${PIPE_REF:-$(sed -n 's/^REF="\([^"]*\)".*/\1/p' "$ROOT/linux/install.sh")}
echo "=== build через конвеєр (--ref $PIPE_REF)"
docker run --rm "${net_args[@]}" -v "$ROOT/linux:/src:ro" -v "$ROOT/tests:/tests:ro" "$IMAGE" bash -c '
    [ -f /ca.crt ] && [ -n "${https_proxy:-}" ] && sh /tests/fixtures/container-net.sh >/dev/null 2>&1
    if command -v apt-get >/dev/null; then apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates >/dev/null 2>&1; fi
    bash -s build --out /tmp/p --ref "$1" < /src/install.sh >/dev/null || exit 1
    [ -x /tmp/p/install.sh ] && [ -x /tmp/p/set-security-logging.sh ] && bash -n /tmp/p/install.sh' _ "$PIPE_REF" \
    || { echo "ПОМИЛКА: build через конвеєр"; exit 1; }

echo "=== офлайн-встановлення (--network none)"
docker run --rm --network none -v "$OUT/b:/bundle:ro" "$IMAGE" bash -c "
    command -v auditctl >/dev/null && { echo 'auditctl уже є в образі - тест не показовий'; exit 1; }
    /bundle/install.sh --from /bundle --quiet || exit 1
    command -v auditctl >/dev/null || { echo 'auditctl не встановлено'; cat /tmp/seclogging-offline.log; exit 1; }
    if command -v dpkg >/dev/null; then [ \$(dpkg -l | grep -cE '^(iU|iF|iH)') -eq 0 ] || { echo 'є напіввстановлені пакети'; exit 1; }
    else rpm -Va audit >/dev/null 2>&1; rpm -q audit || exit 1; fi
    out=\$(/bundle/install.sh --from /bundle)
    echo \"\$out\" | grep -E '^\[(Changed|Error)' && { echo 'НЕ ІДЕМПОТЕНТНО'; exit 1; }
    exit 0" || { echo "ПОМИЛКА: офлайн-встановлення"; exit 1; }

echo "=== підмінений комплект має бути відхилено"
echo "# tampered" >> "$OUT/b/set-security-logging.sh"
if docker run --rm --network none -v "$OUT/b:/bundle:ro" "$IMAGE" /bundle/install.sh --from /bundle --check >/dev/null 2>&1; then
    echo "ПОМИЛКА: підміну не виявлено"; exit 1
fi
echo "OK"
