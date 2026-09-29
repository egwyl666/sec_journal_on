# Виконується в контейнері wazuh-manager: шле події в чергу analysisd (як агент) і звіряє алерти з очікуваними.
import json, socket, sys, time

cases = [l.rstrip("\n").split("\t", 4) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
alerts = open("/var/ossec/logs/alerts/alerts.json", encoding="utf-8")
alerts.seek(0, 2)
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.connect("/var/ossec/queue/sockets/queue")
for name, want, q, loc, ev in cases:
    s.send(f"{q}:[001] (DC01) any->{loc}:{ev}".encode())
    time.sleep(0.05)
time.sleep(5)
got = []
for line in alerts:
    try:
        got.append(json.loads(line))
    except ValueError:
        pass   # рядок, який Wazuh саме дописував у момент seek, або порожній


def key_of(a):
    # назва випадку: Message для Windows, "[назва]" / name="..." у тексті для Linux
    msg = a.get("data", {}).get("win", {}).get("system", {}).get("message", "")
    if msg:
        return msg.strip('"')
    fl = a.get("full_log", "")
    if fl.endswith("]") and "[" in fl:
        return fl[fl.rindex("[") + 1:-1]
    if 'name="' in fl:
        return fl.split('name="')[-1].split('"')[0]
    return None


by = {}
for a in got:
    by.setdefault(key_of(a), []).append(a["rule"])
fail = 0
for name, want, *_ in cases:
    rules = by.get(name, [])
    ours = [r for r in rules if 12300 <= int(r["id"]) <= 12399]
    shown = ", ".join(f"{r['id']}/{r['level']}" for r in rules) or "немає алерту"
    ok = (want == "-" and not ours) or (want != "-" and any(r["id"] == want for r in rules))
    if not ok:
        fail += 1
    print(f"{'ОК  ' if ok else 'ЗБІЙ'} {name:28} очікувано {want:7} отримано {shown}")
print(f"\nПройдено: {len(cases) - fail}  Не пройдено: {fail}")
sys.exit(1 if fail else 0)
