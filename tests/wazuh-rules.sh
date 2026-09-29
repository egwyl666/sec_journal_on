#!/usr/bin/env bash
# Перевіряє wazuh/rules/seclogging_rules.xml на справжньому wazuh-manager у Docker:
# менеджер стартує з нашими правилами (якщо правила ламають analysisd - тест падає), події шлються в чергу
# analysisd так само, як від агента, а отримані алерти звіряються з очікуваними (tests/fixtures/wazuh-events.py).
#   ./tests/wazuh-rules.sh                      WAZUH_IMAGE=wazuh/wazuh-manager:4.14.0 за замовчуванням
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=${WAZUH_IMAGE:-wazuh/wazuh-manager:4.14.0}
NAME=seclogging-wazuh-test
TMP=$(mktemp -d)
trap 'docker rm -f "$NAME" >/dev/null 2>&1; rm -rf "$TMP"' EXIT

python3 "$ROOT/tests/fixtures/wazuh-events.py" > "$TMP/events.tsv" || exit 1
docker rm -f "$NAME" >/dev/null 2>&1
docker run -d --name "$NAME" "$IMAGE" >/dev/null || exit 1
docker cp "$ROOT/wazuh/rules/seclogging_rules.xml" "$NAME:/var/ossec/etc/rules/seclogging_rules.xml"
docker cp "$ROOT/tests/fixtures/wazuh-inject.py" "$NAME:/tmp/inject.py"
docker cp "$TMP/events.tsv" "$NAME:/tmp/events.tsv"
# алерти від рівня 1, щоб бачити й низькорівневі правила; перезапуск - щоб analysisd прочитав наші правила
docker exec "$NAME" sh -c "chown wazuh:wazuh /var/ossec/etc/rules/seclogging_rules.xml; sed -i 's#<log_alert_level>3</log_alert_level>#<log_alert_level>1</log_alert_level>#' /var/ossec/etc/ossec.conf"
docker restart "$NAME" >/dev/null
for _ in $(seq 1 60); do
    docker exec "$NAME" sh -c '/var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-analysisd is running" && [ -S /var/ossec/queue/sockets/queue ]' && break
    sleep 3
done
sleep 5
if ! docker exec "$NAME" sh -c '/var/ossec/bin/wazuh-control status | grep -q "wazuh-analysisd is running"'; then
    echo "ПОМИЛКА: wazuh-analysisd не запустився з нашими правилами"
    docker exec "$NAME" sh -c 'grep -E "analysisd.*(ERROR|CRITICAL)" /var/ossec/logs/ossec.log | grep -v "resource limit" | tail -5'
    exit 1
fi
docker exec "$NAME" /var/ossec/framework/python/bin/python3 /tmp/inject.py /tmp/events.tsv
