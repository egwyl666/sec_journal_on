#!/usr/bin/env bash
# set-security-logging.sh - визначає хост, перевіряє та вмикає журналювання безпеки Linux:
#   auditd (+ правила), постійне зберігання і розмір journald, наявність/ротація auth-логу,
#   LogLevel VERBOSE для sshd (відбиток ключа при вході), перевірка синхронізації часу,
#   збір журналів агентом Wazuh. Лише штатні засоби Linux, без сторонніх агентів.
#
# Порядок: визначення -> поточний стан -> застосувати лише відсутнє -> перевірка -> звіт.
# Значення лише підвищуються: більші ліміти, вже налаштовані на хості, залишаються.
#
# Використання: sudo ./set-security-logging.sh [параметри]
#   --check                 лише перевірка, нічого не змінює
#   --profile P             auto|workstation|server (за замовчуванням auto)
#   --configure-wazuh       додати відсутні <localfile> в ossec.conf агента Wazuh
#   --immutable             заблокувати правила аудиту (-e 2) до перезавантаження
#   --report FILE           шлях до JSON-звіту (типово /var/log/seclogging/report-<час>.json)
#   --quiet                 виводити лише підсумок
#   --snapshot FILE         записати знімок поточного стану у FILE і вийти (нічого не змінює)
#   --compare BEFORE AFTER  показати, що змінилося між двома знімками (було -> стало)
#   --compare-out FILE      зберегти результат --compare у FILE
#   -h|--help

set -u
umask 027

SCRIPT_VERSION="1.3.1"
CHECK=0
PROFILE="auto"
CONFIGURE_WAZUH=0
IMMUTABLE=0
REPORT=""
QUIET=0
SNAPSHOT=""
CMP_BEFORE=""; CMP_AFTER=""; CMP_OUT=""

RULES_FILE="/etc/audit/rules.d/50-seclogging.rules"
# augenrules бере ОСТАННЄ -b у порядку файлів: наш -b - в окремому файлі, що обробляється останнім
BACKLOG_FILE="/etc/audit/rules.d/zz-seclogging-backlog.rules"
JOURNALD_DROPIN="/etc/systemd/journald.conf.d/50-seclogging.conf"
MARK_BEGIN="<!-- SecLogging BEGIN (managed by set-security-logging.sh) -->"
MARK_END="<!-- SecLogging END -->"

usage() { sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --check) CHECK=1 ;;
        --profile) PROFILE="${2:-}"; shift ;;
        --with-sysmon|--sysmon-package-dir) echo "Sysmon for Linux більше не підтримується: достатньо auditd і journald" >&2; exit 64 ;;
        --configure-wazuh) CONFIGURE_WAZUH=1 ;;
        --immutable) IMMUTABLE=1 ;;
        --report) REPORT="${2:-}"; shift ;;
        --quiet) QUIET=1 ;;
        --snapshot) SNAPSHOT="${2:-}"; shift ;;
        --compare) CMP_BEFORE="${2:-}"; CMP_AFTER="${3:-}"; shift 2 ;;
        --compare-out) CMP_OUT="${2:-}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Невідомий параметр: $1" >&2; usage; exit 64 ;;
    esac
    shift
done
case "$PROFILE" in auto|workstation|server) ;; *) echo "Неправильний --profile: $PROFILE" >&2; exit 64 ;; esac

# ------------------------------------------------------------------ звіт

RESULTS=()
N_OK=0; N_CHANGED=0; N_WOULD=0; N_WARN=0; N_ERR=0; N_SKIP=0

json_escape() {
    local s="$1"
    s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\r'/}; s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

# result ОБЛАСТЬ ЕЛЕМЕНТ СТАТУС ПОВІДОМЛЕННЯ
result() {
    local area="$1" item="$2" status="$3" msg="${4:-}" color
    case "$status" in
        OK) N_OK=$((N_OK+1)); color=32 ;;
        Changed) N_CHANGED=$((N_CHANGED+1)); color=36 ;;
        WouldChange) N_WOULD=$((N_WOULD+1)); color=33 ;;
        Warning) N_WARN=$((N_WARN+1)); color=33 ;;
        Error) N_ERR=$((N_ERR+1)); color=31 ;;
        Skipped) N_SKIP=$((N_SKIP+1)); color=90 ;;
    esac
    RESULTS+=("{\"Area\": \"$(json_escape "$area")\", \"Item\": \"$(json_escape "$item")\", \"Status\": \"$status\", \"Message\": \"$(json_escape "$msg")\"}")
    if [ "$QUIET" -eq 0 ] || [ "$status" = "Error" ]; then
        if [ -t 1 ]; then printf '\033[%sm[%-11s]\033[0m %-10s %s%s\n' "$color" "$status" "$area" "$item" "${msg:+ - $msg}"
        else printf '[%-11s] %-10s %s%s\n' "$status" "$area" "$item" "${msg:+ - $msg}"; fi
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# ver_ge A B: A >= B (числові частини через крапку; без sort -V - його немає в busybox)
ver_ge() {
    awk -v a="$1" -v b="$2" 'BEGIN{na=split(a,x,/[^0-9]+/); nb=split(b,y,/[^0-9]+/); n=(na>nb?na:nb)
        for(i=1;i<=n;i++){ if((x[i]+0)>(y[i]+0)) exit 0; if((x[i]+0)<(y[i]+0)) exit 1 } exit 0}'
}

# імʼя хоста: утиліти hostname немає в мінімальних образах (Fedora, Amazon Linux, openSUSE, Arch)
host_name() { cat /proc/sys/kernel/hostname 2>/dev/null || uname -n; }

# рядок розміру (100M, 1G, 512K, байти) -> МБ
to_mb() {
    local v="${1:-}" n u
    n=$(printf '%s' "$v" | sed -E 's/^([0-9]+).*/\1/')
    u=$(printf '%s' "$v" | sed -E 's/^[0-9]+([A-Za-z]?).*/\1/' | tr '[:lower:]' '[:upper:]')
    [ -z "$n" ] && { echo 0; return; }
    case "$u" in
        K) echo $((n / 1024)) ;; M) echo "$n" ;; G) echo $((n * 1024)) ;; T) echo $((n * 1024 * 1024)) ;;
        *) echo $((n / 1024 / 1024)) ;;
    esac
}

backup_once() { [ -f "$1" ] && [ ! -f "$1.seclogging.bak" ] && cp -p "$1" "$1.seclogging.bak"; }

# ------------------------------------------------------------------ визначення хоста

OS_ID=""; OS_LIKE=""; OS_VER=""; OS_NAME=""; FAMILY="unknown"; PKG=""
HAS_SYSTEMD=0; HAS_OPENRC=0; IN_CONTAINER=0; ROLE=""; ARCH=$(uname -m); KERNEL=$(uname -r)

detect_host() {
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_ID="${ID:-}"; OS_LIKE="${ID_LIKE:-}"; OS_VER="${VERSION_ID:-}"; OS_NAME="${PRETTY_NAME:-$OS_ID}"
    elif [ -r /etc/redhat-release ]; then
        OS_ID="rhel"; OS_NAME=$(head -1 /etc/redhat-release); OS_VER=$(grep -oE '[0-9]+(\.[0-9]+)?' /etc/redhat-release | head -1)
    fi
    # 1) за os-release (ID, потім ID_LIKE - так покриваються похідні: Mint, Astra, Rocky, Oracle, Amazon, ...)
    case " $OS_ID $OS_LIKE " in
        *" altlinux "*) FAMILY="alt"; PKG="apt" ;;                     # ALT: apt-rpm
        *" debian "*|*" ubuntu "*) FAMILY="deb"; PKG="apt" ;;
        *" rhel "*|*" fedora "*|*" centos "*|*" amzn "*) FAMILY="rpm" ;;
        *" suse "*|*" sles "*|*" opensuse "*) FAMILY="suse"; PKG="zypper" ;;
        *" arch "*|*" archlinux "*) FAMILY="arch"; PKG="pacman" ;;
        *" alpine "*) FAMILY="alpine"; PKG="apk" ;;
    esac
    # 2) невідомий дистрибутив: за наявним пакетним менеджером
    if [ "$FAMILY" = "unknown" ]; then
        if have apt-get && have dpkg; then FAMILY="deb"; PKG="apt"
        elif have dnf || have yum; then FAMILY="rpm"
        elif have zypper; then FAMILY="suse"; PKG="zypper"
        elif have pacman; then FAMILY="arch"; PKG="pacman"
        elif have apk; then FAMILY="alpine"; PKG="apk"; fi
    fi
    if [ "$FAMILY" = "rpm" ]; then if have dnf; then PKG="dnf"; else PKG="yum"; fi; fi
    [ -d /run/systemd/system ] && HAS_SYSTEMD=1
    [ "$HAS_SYSTEMD" -eq 0 ] && have rc-service && HAS_OPENRC=1
    if have systemd-detect-virt && systemd-detect-virt -cq 2>/dev/null; then IN_CONTAINER=1
    elif [ -f /.dockerenv ] || [ -f /run/.containerenv ] || grep -qaE '(docker|lxc|kubepods|containerd)' /proc/1/cgroup 2>/dev/null; then IN_CONTAINER=1; fi

    if [ "$PROFILE" = "auto" ]; then
        ROLE="server"
        if [ "$HAS_SYSTEMD" -eq 1 ] && [ "$(systemctl get-default 2>/dev/null)" = "graphical.target" ]; then ROLE="workstation"; fi
    else
        ROLE="$PROFILE"
    fi
}

init_name() { if [ "$HAS_SYSTEMD" -eq 1 ]; then echo systemd; elif [ "$HAS_OPENRC" -eq 1 ]; then echo openrc; else echo sysv; fi; }

# Значення профілю (МБ / кількість)
set_profile() {
    if [ "$ROLE" = "workstation" ]; then
        JOURNAL_MAX_MB=1024; AUDIT_FILE_MB=50; AUDIT_NUM_LOGS=10
    else
        JOURNAL_MAX_MB=2048; AUDIT_FILE_MB=100; AUDIT_NUM_LOGS=10
    fi
    # Не плануємо більше 50% вільного місця на /var
    local free_mb need
    free_mb=$(df -Pm /var 2>/dev/null | awk 'NR==2{print $4}')
    FREE_MB=${free_mb:-0}
    need=$((JOURNAL_MAX_MB + AUDIT_FILE_MB * AUDIT_NUM_LOGS))
    if [ "$FREE_MB" -gt 0 ] && [ "$need" -gt $((FREE_MB / 2)) ]; then
        JOURNAL_MAX_MB=512; AUDIT_FILE_MB=50; AUDIT_NUM_LOGS=5
        result Host "Профіль розмірів" Warning "На /var вільно лише ${FREE_MB} МБ: мінімальні розміри (journald 512M, auditd 50M x5)"
    else
        result Host "Профіль розмірів" OK "$ROLE: journald ${JOURNAL_MAX_MB}M, auditd ${AUDIT_FILE_MB}M x${AUDIT_NUM_LOGS} (вільно ${FREE_MB} МБ на /var)"
    fi
}

pkg_install() {
    case "$PKG" in
        apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" >/tmp/seclogging-pkg.log 2>&1 || { apt-get update -q >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" >/tmp/seclogging-pkg.log 2>&1; } ;;
        dnf) dnf install -y -q "$@" >/tmp/seclogging-pkg.log 2>&1 ;;
        yum) yum install -y -q "$@" >/tmp/seclogging-pkg.log 2>&1 ;;
        zypper) zypper --non-interactive install "$@" >/tmp/seclogging-pkg.log 2>&1 ;;
        pacman) pacman -S --noconfirm --needed "$@" >/tmp/seclogging-pkg.log 2>&1 ;;
        apk) apk add --no-progress "$@" >/tmp/seclogging-pkg.log 2>&1 ;;
        *) echo "невідомий пакетний менеджер" >/tmp/seclogging-pkg.log; return 1 ;;
    esac
}

# Підказка до помилки встановлення: репозиторії дистрибутивів, що вийшли з підтримки
pkg_hint() {
    case "$OS_ID:${OS_VER%%.*}" in
        centos:7|centos:8) echo " - репозиторії CentOS ${OS_VER%%.*} перенесено на vault.centos.org (виправте /etc/yum.repos.d або використайте офлайн-комплект install.sh)" ;;
        *) grep -qiE 'Could not resolve|Failed to (download|fetch)|Cannot find a valid baseurl|Temporary failure' /tmp/seclogging-pkg.log 2>/dev/null \
               && echo " - немає доступу до репозиторіїв (без інтернету використайте офлайн-комплект install.sh)" ;;
    esac
}

# назва пакета auditd у сімействі
audit_pkg_name() { case "$FAMILY" in deb) echo auditd ;; *) echo audit ;; esac; }

svc_restart() {
    # RHEL відмовляє в "systemctl restart auditd"; обгортка service працює всюди.
    local s="$1"
    if [ "$HAS_OPENRC" -eq 1 ]; then rc-service "$s" restart >/dev/null 2>&1; return $?; fi
    if have service; then service "$s" restart >/dev/null 2>&1 && return 0; fi
    if [ "$HAS_SYSTEMD" -eq 1 ]; then systemctl restart "$s" >/dev/null 2>&1 && return 0; fi
    [ -x "/etc/init.d/$s" ] && "/etc/init.d/$s" restart >/dev/null 2>&1
}

svc_reload_or_restart() {
    local s="$1"
    if [ "$HAS_SYSTEMD" -eq 1 ]; then systemctl reload-or-restart "$s" >/dev/null 2>&1; return $?; fi
    svc_restart "$s"
}

svc_start() {
    local s="$1"
    if [ "$HAS_SYSTEMD" -eq 1 ]; then systemctl start "$s" >/dev/null 2>&1; return $?; fi
    if [ "$HAS_OPENRC" -eq 1 ]; then rc-service "$s" start >/dev/null 2>&1; return $?; fi
    svc_restart "$s"
}

svc_enable() {
    local s="$1"
    if [ "$HAS_SYSTEMD" -eq 1 ]; then systemctl enable "$s" >/dev/null 2>&1
    elif [ "$HAS_OPENRC" -eq 1 ]; then rc-update add "$s" default >/dev/null 2>&1
    elif have chkconfig; then chkconfig "$s" on >/dev/null 2>&1
    elif have update-rc.d; then update-rc.d "$s" enable >/dev/null 2>&1; fi
}

svc_active() {
    local s="$1"
    if [ "$HAS_SYSTEMD" -eq 1 ]; then systemctl is-active --quiet "$s"; return $?; fi
    if [ "$HAS_OPENRC" -eq 1 ]; then rc-service "$s" status >/dev/null 2>&1; return $?; fi
    have service && service "$s" status >/dev/null 2>&1
}

# ------------------------------------------------------------------ auditd

# Шаблон правил. Рядки "-w ШЛЯХ" потрапляють у файл, лише якщо ШЛЯХ існує;
# рядки "@b32" - лише на x86_64 (32-бітний ABI системних викликів). Ключ audit-wazuh-c відповідає правилам аудиту Wazuh.
AUDIT_RULES_TEMPLATE='
## --- самозахист: конфігурація та утиліти аудиту
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k auditconfig
-w /sbin/auditctl -p x -k audittools
-w /usr/sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools
-w /usr/sbin/auditd -p x -k audittools
-w /var/log/audit/ -p wa -k auditlog
## --- облікові записи та автентифікація
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/ -p wa -k pam
-w /etc/login.defs -p wa -k login
-w /etc/nsswitch.conf -p wa -k login
## --- ssh
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /root/.ssh/ -p wa -k rootkey
## --- закріплення (persistence): cron, at, systemd, rc, profile
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /var/spool/at/ -p wa -k cron
-w /etc/at.allow -p wa -k cron
-w /etc/at.deny -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd
-w /usr/lib/systemd/system/ -p wa -k systemd
-w /lib/systemd/system/ -p wa -k systemd
-w /etc/systemd/user/ -p wa -k systemd
-w /etc/rc.local -p wa -k init
-w /etc/init.d/ -p wa -k init
-w /etc/profile -p wa -k shellprofile
-w /etc/profile.d/ -p wa -k shellprofile
-w /etc/bash.bashrc -p wa -k shellprofile
-w /etc/bashrc -p wa -k shellprofile
## --- підвантаження бібліотек / підміна компонувальника
-w /etc/ld.so.preload -p wa -k preload
-w /etc/ld.so.conf -p wa -k preload
-w /etc/ld.so.conf.d/ -p wa -k preload
## --- модулі ядра
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /usr/sbin/insmod -p x -k modules
-w /usr/sbin/rmmod -p x -k modules
-w /usr/sbin/modprobe -p x -k modules
-w /usr/bin/kmod -p x -k modules
-w /etc/modprobe.d/ -p wa -k modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
@b32 -a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k modules
## --- мережа / ідентичність хоста
-w /etc/hosts -p wa -k netconf
-w /etc/hostname -p wa -k netconf
-a always,exit -F arch=b64 -S sethostname,setdomainname -k netconf
## --- час
-w /etc/localtime -p wa -k time
-a always,exit -F arch=b64 -S settimeofday,clock_settime -F a0=0x0 -k time
## --- інʼєкції в процеси (PTRACE_POKETEXT/POKEDATA/POKEUSER)
-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k code_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k code_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k code_injection
## --- монтування користувачами
-a always,exit -F arch=b64 -S mount,umount2 -F auid!=4294967295 -k mount
## --- утиліти підвищення привілеїв і керування обліковими записами
-w /usr/bin/sudo -p x -k priv_esc
-w /bin/su -p x -k priv_esc
-w /usr/bin/su -p x -k priv_esc
-w /usr/bin/passwd -p x -k passwd_change
-w /usr/sbin/useradd -p x -k user_mgmt
-w /usr/sbin/userdel -p x -k user_mgmt
-w /usr/sbin/usermod -p x -k user_mgmt
-w /usr/sbin/groupadd -p x -k user_mgmt
-w /usr/sbin/groupmod -p x -k user_mgmt
## --- виконання команд користувачами в сесіях (auid задано), включно з root-сесіями та sudo
-a always,exit -F arch=b64 -S execve -F auid!=4294967295 -k audit-wazuh-c
@b32 -a always,exit -F arch=b32 -S execve -F auid!=4294967295 -k audit-wazuh-c
'

# потрібний розмір черги аудиту: не менше 8192 і не менше найбільшого -b в інших файлах (лише підвищуємо)
backlog_want() {
    local b f
    b=$(for f in /etc/audit/rules.d/*.rules; do
            [ "$f" != "$RULES_FILE" ] && [ "$f" != "$BACKLOG_FILE" ] && [ -f "$f" ] && grep -hsE '^-b[[:space:]]+[0-9]+' "$f"
        done | awk '{print $2}' | sort -n | tail -1)
    if [ "${b:-0}" -gt 8192 ]; then echo "$b"; else echo 8192; fi
}

render_backlog_rules() {
    echo "## Керується set-security-logging.sh: файл обробляється останнім, тому цей -b діє (augenrules бере останній)"
    echo "-b $(backlog_want)"
}

render_audit_rules() {
    local line path uid u
    echo "## Керується set-security-logging.sh $SCRIPT_VERSION - не редагуйте, натомість перезапустіть скрипт"
    # -b тут - для завантаження без augenrules (auditctl -R лише цього файлу); з augenrules діє $BACKLOG_FILE
    echo "-b $(backlog_want)"
    echo "-a always,exclude -F msgtype=EOE"
    while IFS= read -r line; do
        case "$line" in
            ''|'##'*) [ -n "$line" ] && echo "$line"; continue ;;
            '@b32 '*) [ "$ARCH" = "x86_64" ] && echo "${line#@b32 }"; continue ;;
            '-w '*)
                path=$(printf '%s' "$line" | awk '{print $2}')
                [ -e "$path" ] && echo "$line"; continue ;;
            *) echo "$line" ;;
        esac
    done <<< "$AUDIT_RULES_TEMPLATE"
    # Веб-шели: будь-який execve від облікового запису веб-сервера
    for u in www-data apache nginx httpd; do
        uid=$(id -u "$u" 2>/dev/null) || continue
        echo "-a always,exit -F arch=b64 -S execve -F euid=$uid -k webshell"
    done
}

# set_kv ФАЙЛ КЛЮЧ ЗНАЧЕННЯ  (формат key = value)
set_kv() {
    local f="$1" k="$2" v="$3"
    if grep -qE "^[[:space:]]*${k}[[:space:]]*=" "$f"; then
        sed -i -E "s|^[[:space:]]*${k}[[:space:]]*=.*|$k = $v|" "$f"
    else
        printf '%s = %s\n' "$k" "$v" >> "$f"
    fi
}

get_kv() { awk -F= -v k="$2" '{gsub(/^[ \t]+|[ \t]+$/,"",$1)} $1==k {gsub(/^[ \t]+|[ \t]+$/,"",$2); v=$2} END{print v}' "$1" 2>/dev/null; }

audit_version_ge() {
    # auditctl -v на старих версіях потребує CAP_AUDIT_CONTROL: беремо версію пакета
    local cur; cur=$( { auditctl -v 2>/dev/null; dpkg-query -W -f='${Version}\n' auditd 2>/dev/null; rpm -q --qf '%{VERSION}\n' audit 2>/dev/null; } \
        | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
    [ -n "$cur" ] && ver_ge "$cur" "$1"
}

# Перечитати auditd.conf без перезапуску: RHEL забороняє "systemctl restart auditd" (RefuseManualStop),
# а утиліти service у мінімальній установці може не бути. SIGHUP - штатне перечитування конфігу auditd.
auditd_reload() {
    auditctl --signal reload >/dev/null 2>&1 && return 0
    local pid; pid=$(pidof auditd 2>/dev/null) || return 1
    # shellcheck disable=SC2086
    kill -HUP $pid 2>/dev/null
}

# Наші правила завантажені в ядро? auditctl -l друкує ключ як "-k identity" для -w і "-F key=identity" для -a
rules_active() { auditctl -l 2>/dev/null | grep -qE '(-k |key=)identity( |$)'; }

do_auditd() {
    if ! have auditctl; then
        if [ "$CHECK" -eq 1 ]; then result auditd package WouldChange "встановити auditd"; return
        fi
        local pkgname; pkgname=$(audit_pkg_name)
        if pkg_install "$pkgname" && have auditctl; then result auditd package Changed "встановлено $pkgname"
        else result auditd package Error "не вдалося встановити $pkgname через ${PKG:-?} (див. /tmp/seclogging-pkg.log)$(pkg_hint)"; return; fi
    else
        result auditd package OK "$(auditctl -v 2>/dev/null | head -1 || true)"
    fi

    # --- auditd.conf
    local conf=/etc/audit/auditd.conf key cur want changes=""
    if [ -f "$conf" ]; then
        for key in max_log_file num_logs; do
            cur=$(get_kv "$conf" "$key"); cur=${cur:-0}
            if [ "$key" = max_log_file ]; then want=$AUDIT_FILE_MB; else want=$AUDIT_NUM_LOGS; fi
            if [ "$cur" -lt "$want" ] 2>/dev/null; then changes+="$key=$cur->$want "; fi
        done
        cur=$(get_kv "$conf" max_log_file_action)
        [ "${cur^^}" != "ROTATE" ] && changes+="max_log_file_action=${cur:-unset}->ROTATE "
        cur=$(get_kv "$conf" log_format)
        ENRICHED_OK=0
        audit_version_ge 2.6 && ENRICHED_OK=1
        [ "$ENRICHED_OK" -eq 1 ] && [ "${cur^^}" != "ENRICHED" ] && changes+="log_format=${cur:-unset}->ENRICHED "
        if [ -z "$changes" ]; then
            result auditd auditd.conf OK "max_log_file=$(get_kv "$conf" max_log_file) num_logs=$(get_kv "$conf" num_logs) action=ROTATE format=$(get_kv "$conf" log_format)"
        elif [ "$CHECK" -eq 1 ]; then
            result auditd auditd.conf WouldChange "$changes"
        else
            backup_once "$conf"
            cur=$(get_kv "$conf" max_log_file); [ "${cur:-0}" -lt "$AUDIT_FILE_MB" ] 2>/dev/null && set_kv "$conf" max_log_file "$AUDIT_FILE_MB"
            cur=$(get_kv "$conf" num_logs); [ "${cur:-0}" -lt "$AUDIT_NUM_LOGS" ] 2>/dev/null && set_kv "$conf" num_logs "$AUDIT_NUM_LOGS"
            set_kv "$conf" max_log_file_action ROTATE
            [ "$ENRICHED_OK" -eq 1 ] && set_kv "$conf" log_format ENRICHED
            AUDITD_RESTART=1
            result auditd auditd.conf Changed "$changes"
        fi
    else
        result auditd auditd.conf Error "$conf не знайдено"
    fi

    # --- файл правил
    local tmp new_hash old_hash=""
    tmp=$(mktemp)
    render_audit_rules > "$tmp"
    new_hash=$(sha256sum "$tmp" | awk '{print $1}')
    [ -f "$RULES_FILE" ] && old_hash=$(sha256sum "$RULES_FILE" | awk '{print $1}')
    local nrules; nrules=$(grep -cE '^-(w|a) ' "$tmp")
    if [ "$new_hash" = "$old_hash" ]; then
        result auditd "$RULES_FILE" OK "правил: $nrules, актуально"
    elif [ "$CHECK" -eq 1 ]; then
        result auditd "$RULES_FILE" WouldChange "записати правил: $nrules"
    else
        mkdir -p "$(dirname "$RULES_FILE")"
        install -m 0640 "$tmp" "$RULES_FILE"
        RULES_CHANGED=1
        result auditd "$RULES_FILE" Changed "записано правил: $nrules"
    fi
    rm -f "$tmp"

    # --- розмір черги аудиту (-b), окремим останнім файлом
    local want_b; want_b=$(backlog_want)
    if [ -f "$BACKLOG_FILE" ] && [ "$(render_backlog_rules)" = "$(cat "$BACKLOG_FILE")" ]; then
        result auditd "-b (черга)" OK "$want_b"
    elif [ "$CHECK" -eq 1 ]; then
        result auditd "-b (черга)" WouldChange "$BACKLOG_FILE: -b $want_b"
    else
        render_backlog_rules > "$BACKLOG_FILE"; chmod 0640 "$BACKLOG_FILE"
        RULES_CHANGED=1
        result auditd "-b (черга)" Changed "-b $want_b ($BACKLOG_FILE)"
    fi

    if [ "$IMMUTABLE" -eq 1 ]; then
        local fin=/etc/audit/rules.d/99-finalize.rules
        if grep -qsE '^-e[[:space:]]+2' /etc/audit/rules.d/*.rules; then result auditd immutable OK "-e 2 присутній"
        elif [ "$CHECK" -eq 1 ]; then result auditd immutable WouldChange "додати -e 2 ($fin)"
        else echo "-e 2" > "$fin"; chmod 0640 "$fin"; RULES_CHANGED=1; result auditd immutable Changed "додано -e 2 ($fin), правила заблоковано до перезавантаження"; fi
    fi

    # --- стан у ядрі (runtime)
    if [ "$IN_CONTAINER" -eq 1 ]; then
        result auditd runtime Skipped "контейнер: аудит ядра належить хосту"
        return
    fi
    local enabled; enabled=$(auditctl -s 2>/dev/null | awk '/^enabled/{print $2}')
    if [ "$CHECK" -eq 1 ]; then
        if svc_active auditd; then result auditd service OK "працює, enabled=$enabled"; else result auditd service WouldChange "запустити auditd"; fi
        return
    fi
    svc_enable auditd
    if ! svc_active auditd; then
        svc_start auditd
        AUDITD_RESTART=0
    elif [ "${AUDITD_RESTART:-0}" -eq 1 ]; then
        svc_restart auditd || auditd_reload || result auditd service Error "не вдалося ні перезапустити auditd, ні перечитати конфіг (SIGHUP)"
    fi
    if svc_active auditd; then result auditd service OK "працює"; else result auditd service Error "auditd не працює"; fi

    if [ "${RULES_CHANGED:-0}" -eq 1 ] || ! rules_active; then
        if [ "$enabled" = "2" ]; then
            result auditd "завантаження правил" Warning "правила аудиту незмінні (-e 2): нові правила діятимуть після перезавантаження"
        else
            local out
            if have augenrules; then out=$(augenrules --load 2>&1); else out=$(auditctl -R "$RULES_FILE" 2>&1); fi
            if rules_active; then
                result auditd "завантаження правил" Changed "завантажено, активних правил: $(auditctl -l 2>/dev/null | grep -c .)"
            else
                result auditd "завантаження правил" Error "правила не активні: $(printf '%s' "$out" | tail -3)"
            fi
        fi
    else
        result auditd "активні правила" OK "завантажено правил: $(auditctl -l 2>/dev/null | grep -c .)"
    fi
}

# ------------------------------------------------------------------ journald

journald_value() {
    # фактичне значення КЛЮЧА з конфігу journald (перемагає останнє)
    local key="$1"
    if have systemd-analyze && systemd-analyze cat-config systemd/journald.conf >/dev/null 2>&1; then
        systemd-analyze cat-config systemd/journald.conf 2>/dev/null
    else
        cat /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null
    fi | awk -F= -v k="$key" '$1==k {v=$2} END{print v}'
}

do_journald() {
    if [ "$HAS_SYSTEMD" -eq 0 ]; then result journald journald Skipped "немає systemd"; return; fi
    local storage max max_mb persistent=0 changes=""
    storage=$(journald_value Storage); max=$(journald_value SystemMaxUse)
    max_mb=$(to_mb "${max:-0}")
    if [ "$storage" = "persistent" ] || { [ "${storage:-auto}" = "auto" ] && [ -d /var/log/journal ]; }; then persistent=1; fi
    [ "$persistent" -eq 0 ] && changes+="Storage=${storage:-auto}(volatile)->persistent "
    [ "$max_mb" -lt "$JOURNAL_MAX_MB" ] && changes+="SystemMaxUse=${max:-default}->${JOURNAL_MAX_MB}M "
    if [ -z "$changes" ]; then result journald journald.conf OK "Storage=${storage:-auto}$([ "${storage:-auto}" = persistent ] || echo " (є /var/log/journal - на диску)"), SystemMaxUse=${max}"; return; fi
    if [ "$CHECK" -eq 1 ]; then result journald journald.conf WouldChange "$changes"; return; fi
    local want=$JOURNAL_MAX_MB; [ "$max_mb" -gt "$want" ] && want=$max_mb
    mkdir -p "$(dirname "$JOURNALD_DROPIN")" /var/log/journal
    printf '# Керується set-security-logging.sh\n[Journal]\nStorage=persistent\nSystemMaxUse=%sM\n' "$want" > "$JOURNALD_DROPIN"
    have systemd-tmpfiles && systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1
    if [ "$IN_CONTAINER" -eq 0 ]; then
        systemctl restart systemd-journald >/dev/null 2>&1 || result journald restart Error "перезапуск systemd-journald не вдався"
    fi
    result journald journald.conf Changed "$changes($JOURNALD_DROPIN)"
}

# ------------------------------------------------------------------ auth-лог / logrotate

AUTH_LOG=""
do_authlog() {
    # де syslog пише автентифікацію: спершу фактичний файл, інакше типовий для сімейства
    if [ -f /var/log/auth.log ]; then AUTH_LOG=/var/log/auth.log
    elif [ -f /var/log/secure ]; then AUTH_LOG=/var/log/secure
    else case "$FAMILY" in deb) AUTH_LOG=/var/log/auth.log ;; suse|arch|alpine) AUTH_LOG=/var/log/messages ;; *) AUTH_LOG=/var/log/secure ;; esac; fi
    if have rsyslogd || have syslog-ng; then
        if [ -f "$AUTH_LOG" ]; then result authlog "$AUTH_LOG" OK "присутній"
        else result authlog "$AUTH_LOG" Warning "syslog-демон встановлено, але $AUTH_LOG відсутній (служба зупинена?)"; fi
    else
        AUTH_LOG=""
        result authlog "syslog" Warning "немає rsyslog/syslog-ng: події SSH/sudo лише в journald (Wazuh має читати journald)"
        return
    fi
    # термін зберігання auth-логу в logrotate
    local f rot period days
    f=$(grep -lsE "$AUTH_LOG" /etc/logrotate.d/* /etc/logrotate.conf 2>/dev/null | head -1)
    if [ -z "$f" ]; then result authlog logrotate Warning "немає правила logrotate для $AUTH_LOG"; return; fi
    rot=$(awk -v p="$AUTH_LOG" 'index($0,p){f=1} f&&/^[[:space:]]*rotate[[:space:]]+[0-9]+/{print $2; exit}' "$f")
    period=$(awk -v p="$AUTH_LOG" 'index($0,p){f=1} f&&/^[[:space:]]*(daily|weekly|monthly)/{print $1; exit}' "$f")
    [ -z "$rot" ] && rot=$(awk '/^[[:space:]]*rotate[[:space:]]+[0-9]+/{print $2; exit}' /etc/logrotate.conf)
    [ -z "$period" ] && period=$(awk '/^[[:space:]]*(daily|weekly|monthly)[[:space:]]*$/{print $1; exit}' /etc/logrotate.conf)
    case "${period:-weekly}" in daily) days=$(( ${rot:-4} * 1 )) ;; monthly) days=$(( ${rot:-4} * 30 )) ;; *) days=$(( ${rot:-4} * 7 )) ;; esac
    if [ "$days" -ge 7 ]; then result authlog logrotate OK "$f: rotate ${rot:-4} ${period:-weekly} (~${days} дн.)"
    else result authlog logrotate Warning "$f: зберігається лише ~${days} дн. (rotate ${rot:-?} ${period:-?}), потрібно >= 7"; fi
}

# ------------------------------------------------------------------ sshd: LogLevel VERBOSE

SSHD_DROPIN="/etc/ssh/sshd_config.d/01-seclogging.conf"

# LogLevel із файлів конфігу без sshd -T: перше значення до першого Match (drop-in-и - якщо Include на початку)
sshd_loglevel_static() {
    local files=() f
    if grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config 2>/dev/null; then
        for f in /etc/ssh/sshd_config.d/*.conf; do [ -f "$f" ] && files+=("$f"); done
    fi
    files+=(/etc/ssh/sshd_config)
    awk 'tolower($1)=="match"{exit} tolower($1)=="loglevel"{print toupper($2); found=1; exit} END{if(!found) print "INFO"}' "${files[@]}" 2>/dev/null
}

# фактичний LogLevel sshd, у верхньому регістрі: sshd -T, а якщо він не працює - з файлів конфігу
sshd_loglevel() {
    local v; v=$(sshd -T 2>/dev/null | awk 'tolower($1)=="loglevel"{print toupper($2); exit}')
    [ -n "$v" ] && { echo "$v"; return; }
    sshd_loglevel_static
}

do_ssh() {
    # VERBOSE: у журнал автентифікації потрапляє відбиток ключа, яким виконано вхід (видно, чий це ключ)
    if [ ! -f /etc/ssh/sshd_config ] || ! have sshd; then result ssh sshd Skipped "OpenSSH-сервер не встановлено"; return; fi
    local cur; cur=$(sshd_loglevel)
    # sshd -T потребує ключів хоста і /run/sshd; коли служба не запущена, їх може не бути
    if [ "$CHECK" -eq 0 ] && ! sshd -T >/dev/null 2>&1; then
        [ -d /run/sshd ] || { mkdir /run/sshd && chmod 0755 /run/sshd; } 2>/dev/null
        have ssh-keygen && ssh-keygen -A >/dev/null 2>&1
        cur=$(sshd_loglevel)
    fi
    case "$cur" in
        VERBOSE|DEBUG*) result ssh LogLevel OK "$cur"; return ;;
        '') result ssh LogLevel Warning "не вдалося прочитати конфіг (sshd -T)"; return ;;
    esac
    if [ "$CHECK" -eq 1 ]; then result ssh LogLevel WouldChange "$cur -> VERBOSE"; return; fi
    # конфіг уже з помилками - не чіпаємо: інакше sshd -t після нашої зміни впаде не через нас
    if ! sshd -t >/dev/null 2>&1; then
        result ssh LogLevel Warning "sshd -t відхиляє поточний конфіг (помилка вже є): LogLevel не змінено, виправте sshd_config"; return
    fi
    local how snap; snap=$(mktemp)
    # свіжа копія саме цього стану - для відкату (не стара .seclogging.bak з першого запуску)
    cp -p /etc/ssh/sshd_config "$snap"
    # sshd бере ПЕРШЕ знайдене значення: drop-in з "01-" діє, лише якщо Include стоїть на початку sshd_config
    if [ -d /etc/ssh/sshd_config.d ] && grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config; then
        printf '# Керується set-security-logging.sh: відбиток ключа при вході в журналі автентифікації\nLogLevel VERBOSE\n' > "$SSHD_DROPIN"
        how="$SSHD_DROPIN"
    fi
    if [ "$(sshd_loglevel)" != "VERBOSE" ]; then
        # немає Include (або його перекрито): рядок на початок sshd_config; глобальні LogLevel - у коментар,
        # LogLevel усередині блоків Match (навмисні винятки для окремих користувачів) не чіпаємо
        rm -f "$SSHD_DROPIN"
        backup_once /etc/ssh/sshd_config
        local tmp; tmp=$(mktemp)
        { echo 'LogLevel VERBOSE'
          awk 'tolower($1)=="match"{m=1} !m && tolower($1)=="loglevel"{print "# " $0 "  # замінено set-security-logging.sh"; next} {print}' "$snap"
        } > "$tmp"
        cat "$tmp" > /etc/ssh/sshd_config; rm -f "$tmp"
        how="/etc/ssh/sshd_config"
    fi
    if ! sshd -t 2>/dev/null; then
        # наша зміна зламала конфіг - повертаємо рівно те, що було перед нею; sshd не перезапускаємо
        rm -f "$SSHD_DROPIN"; cat "$snap" > /etc/ssh/sshd_config; rm -f "$snap"
        result ssh LogLevel Error "sshd -t відхилив конфіг, зміни скасовано"; return
    fi
    rm -f "$snap"
    local s
    if [ "$IN_CONTAINER" -eq 0 ]; then for s in ssh sshd; do svc_active "$s" && svc_reload_or_restart "$s" && break; done; fi
    if [ "$(sshd_loglevel)" = "VERBOSE" ]; then result ssh LogLevel Changed "$cur -> VERBOSE ($how)"
    else result ssh LogLevel Error "LogLevel лишився $(sshd_loglevel)"; fi
}

# ------------------------------------------------------------------ синхронізація часу

# стан синхронізації: yes / no / unknown
time_synced() {
    local v
    if have timedatectl; then
        v=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
        [ -z "$v" ] && v=$(timedatectl status 2>/dev/null | awk -F: 'tolower($1) ~ /synchronized/ {gsub(/ /,"",$2); print $2; exit}')
        case "$v" in yes) echo yes; return ;; no) echo no; return ;; esac
    fi
    if have chronyc; then chronyc -n tracking 2>/dev/null | grep -qiE '^Leap status *: *Normal' && { echo yes; return; }; echo no; return; fi
    if have ntpstat; then ntpstat >/dev/null 2>&1 && echo yes || echo no; return; fi
    echo unknown
}

do_time() {
    # лише перевірка: розбіжний час ламає зіставлення подій між машинами
    if [ "$IN_CONTAINER" -eq 1 ]; then result time sync Skipped "контейнер: час належить хосту"; return; fi
    case "$(time_synced)" in
        yes) result time sync OK "час синхронізовано" ;;
        no) result time sync Warning "час не синхронізовано (NTP): події на різних машинах важко зіставити - увімкніть timedatectl set-ntp true / chronyd" ;;
        *) result time sync Warning "не вдалося визначити стан синхронізації часу (немає timedatectl/chronyc/ntpstat)" ;;
    esac
}

# ------------------------------------------------------------------ Wazuh

do_wazuh() {
    local conf=/var/ossec/etc/ossec.conf shared=/var/ossec/etc/shared/agent.conf
    if [ ! -f "$conf" ]; then result wazuh agent Warning "Агент Wazuh не встановлено - журнали залишаються лише локально"; return; fi
    local ver=""; [ -x /var/ossec/bin/wazuh-control ] && ver=$(/var/ossec/bin/wazuh-control info -v 2>/dev/null)
    if svc_active wazuh-agent; then result wazuh agent OK "працює${ver:+ $ver}"; else result wazuh agent Warning "встановлено${ver:+ $ver}, але не працює"; fi

    # потрібні: "формат|розташування"
    local wanted=("audit|/var/log/audit/audit.log")
    if [ -n "$AUTH_LOG" ]; then wanted+=("syslog|$AUTH_LOG"); else wanted+=("journald|journald"); fi
    local present missing=() w loc
    present=$(cat "$conf" "$shared" 2>/dev/null | grep -oE '<location>[^<]+</location>' | sed -E 's|</?location>||g')
    for w in "${wanted[@]}"; do
        loc="${w#*|}"
        printf '%s\n' "$present" | grep -qxF "$loc" || missing+=("$w")
    done
    if [ ${#missing[@]} -eq 0 ]; then result wazuh localfile OK "журнали audit/auth збираються"; return; fi
    local list; list=$(printf '%s ' "${missing[@]#*|}")
    if [ "$CONFIGURE_WAZUH" -eq 0 ]; then result wazuh localfile Warning "не збираються: $list- використайте agent.conf групи на менеджері (wazuh/shared/linux) або --configure-wazuh"; return; fi
    if [ "$CHECK" -eq 1 ]; then result wazuh localfile WouldChange "додати $list"; return; fi

    backup_once "$conf"
    # зберігаємо записи з попереднього керованого блоку, прибираємо блок, додаємо новий
    local old=()
    while IFS= read -r w; do [ -n "$w" ] && old+=("$w"); done < <(awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
        index($0,b){f=1;next} index($0,e){f=0} f&&/<log_format>/{gsub(/.*<log_format>|<\/log_format>.*/,""); fmt=$0}
        f&&/<location>/{gsub(/.*<location>|<\/location>.*/,""); loc=$0} f&&/<\/localfile>/{print fmt "|" loc}' "$conf")
    local tmp; tmp=$(mktemp)
    awk -v b="$MARK_BEGIN" -v e="$MARK_END" 'index($0,b){f=1} !f{print} index($0,e){f=0}' "$conf" > "$tmp"
    {
        echo "$MARK_BEGIN"
        echo "<ossec_config>"
        printf '%s\n' ${old[@]+"${old[@]}"} "${missing[@]}" | awk 'NF && !seen[$0]++' | while IFS='|' read -r fmt loc; do
            printf '  <localfile>\n    <log_format>%s</log_format>\n    <location>%s</location>\n  </localfile>\n' "$fmt" "$loc"
        done
        echo "</ossec_config>"
        echo "$MARK_END"
    } >> "$tmp"
    cat "$tmp" > "$conf"; rm -f "$tmp"
    if [ "$IN_CONTAINER" -eq 0 ] && svc_restart wazuh-agent; then result wazuh localfile Changed "додано $list; агента перезапущено"
    else result wazuh localfile Changed "додано $list; перезапустіть wazuh-agent вручну"; fi
}

# ------------------------------------------------------------------ знімки стану "до / після"

# Рядки "Область<TAB>Елемент<TAB>Значення" - усе, що скрипт перевіряє або змінює
state_snapshot() {
    local k v f
    if have auditctl; then
        printf 'auditd\tпакет\t%s\n' "$( { dpkg-query -W -f='${Version}' auditd 2>/dev/null || rpm -q audit 2>/dev/null || auditctl -v 2>/dev/null; } | head -1)"
        printf 'auditd\tслужба\t%s\n' "$(svc_active auditd && echo працює || echo 'не працює')"
        v=$(auditctl -s 2>/dev/null | awk '/^enabled/{print $2}'); printf 'auditd\tаудит ядра (enabled)\t%s\n' "${v:-(невідомо)}"
        printf 'auditd\tактивних правил\t%s\n' "$(auditctl -l 2>/dev/null | grep -c '^-')"
    else
        printf 'auditd\tпакет\tне встановлено\n'
    fi
    for k in max_log_file num_logs max_log_file_action log_format space_left_action; do
        v=$(get_kv /etc/audit/auditd.conf "$k"); printf 'auditd.conf\t%s\t%s\n' "$k" "${v:-(не задано)}"
    done
    for f in /etc/audit/rules.d/*.rules; do
        [ -f "$f" ] && printf 'auditd.rules\t%s\t%s\n' "$f" "$(sha256sum "$f" | cut -c1-16) ($(grep -cE '^-(w|a) ' "$f") правил)"
    done
    if [ "$HAS_SYSTEMD" -eq 1 ]; then
        v=$(journald_value Storage); printf 'journald\tStorage\t%s\n' "${v:-auto (за замовчуванням)}"
        v=$(journald_value SystemMaxUse); printf 'journald\tSystemMaxUse\t%s\n' "${v:-(за замовчуванням)}"
        printf 'journald\t/var/log/journal\t%s\n' "$([ -d /var/log/journal ] && echo є || echo немає)"
    fi
    if have sshd && [ -f /etc/ssh/sshd_config ]; then v=$(sshd_loglevel); printf 'ssh\tLogLevel\t%s\n' "${v:-(невідомо)}"; fi
    [ "$IN_CONTAINER" -eq 0 ] && printf 'time\tсинхронізація\t%s\n' "$(time_synced)"
    printf 'syslog\tдемон\t%s\n' "$(if have rsyslogd; then echo rsyslog; elif have syslog-ng; then echo syslog-ng; else echo немає; fi)"
    for f in /var/log/auth.log /var/log/secure /var/log/messages /var/log/syslog; do
        [ -f "$f" ] && printf 'syslog\t%s\tє\n' "$f"
    done
    if [ -f /var/ossec/etc/ossec.conf ]; then
        printf 'wazuh\tагент\t%s\n' "$(svc_active wazuh-agent && echo працює || echo 'не працює')"
        cat /var/ossec/etc/ossec.conf /var/ossec/etc/shared/agent.conf 2>/dev/null | grep -oE '<location>[^<]+</location>' \
            | sed -E 's|</?location>||g' | sort -u | while IFS= read -r v; do printf 'wazuh\t%s\tзбирається\n' "$v"; done
    else
        printf 'wazuh\tагент\tне встановлено\n'
    fi
}

save_snapshot() {
    local out="$1"
    mkdir -p "$(dirname "$out")"
    {
        printf '# SecLogging знімок стану; %s; %s; %s; скрипт %s\n' "$(host_name)" "$OS_NAME" "$(date '+%Y-%m-%d %H:%M:%S')" "$SCRIPT_VERSION"
        printf '# Область\tЕлемент\tЗначення\n'
        state_snapshot | LC_ALL=C sort
    } > "$out"
}

# compare_snapshots BEFORE AFTER -> звіт "було -> стало"; повертає 0
compare_snapshots() {
    awk -F'\t' '
        FNR==1 { hdr[++nf]=$0 }
        /^#/ || NF<3 { next }
        { k=$1 FS $2; v=$3; for(i=4;i<=NF;i++) v=v FS $i
          if (NR==FNR) { b[k]=v } else { a[k]=v }; keys[k]=1 }
        END {
            n=0; for (k in keys) if (!(k in b) || !(k in a) || b[k]!=a[k]) ch[++n]=k
            # сортування за ключем (область, елемент)
            for (i=2;i<=n;i++){ t=ch[i]; j=i-1; while(j>0 && ch[j]>t){ch[j+1]=ch[j]; j--} ch[j+1]=t }
            print "SecLogging: що змінилося"
            print "До:    " hdr[1]; print "Після: " hdr[2]; print "Змін: " n
            area=""
            for (i=1;i<=n;i++) { split(ch[i], p, FS)
                if (p[1]!=area) { area=p[1]; print ""; print "[" area "]" }
                print "  " p[2]
                print "      було:  " ((ch[i] in b) ? b[ch[i]] : "(не було)")
                print "      стало: " ((ch[i] in a) ? a[ch[i]] : "(зникло)") }
            if (!n) { print ""; print "Змін немає." }
        }' "$1" "$2"
}

# ------------------------------------------------------------------ основна частина

main() {
    if [ -n "$CMP_BEFORE" ]; then
        [ -f "$CMP_BEFORE" ] && [ -f "$CMP_AFTER" ] || { echo "Для --compare потрібні два наявні файли знімків" >&2; exit 64; }
        if [ -n "$CMP_OUT" ]; then mkdir -p "$(dirname "$CMP_OUT")"; compare_snapshots "$CMP_BEFORE" "$CMP_AFTER" | tee "$CMP_OUT"
        else compare_snapshots "$CMP_BEFORE" "$CMP_AFTER"; fi
        exit 0
    fi
    if [ "$(id -u)" -ne 0 ]; then echo "Запустіть від root (sudo)." >&2; exit 3; fi
    if [ -n "$SNAPSHOT" ]; then detect_host; save_snapshot "$SNAPSHOT"; echo "Знімок стану: $SNAPSHOT"; exit 0; fi
    local started; started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    detect_host
    if [ "$QUIET" -eq 0 ]; then
        echo
        echo "set-security-logging $SCRIPT_VERSION  режим: $([ "$CHECK" -eq 1 ] && echo 'ЛИШЕ ПЕРЕВІРКА' || echo 'ЗАСТОСУВАННЯ')"
        echo "$(host_name): $OS_NAME, сімейство=$FAMILY, роль=$ROLE, ядро=$KERNEL, $ARCH, init=$(init_name), контейнер=$IN_CONTAINER"
        echo
    fi
    result Host Роль OK "$ROLE (сімейство $FAMILY, пакетний менеджер ${PKG:-немає}, init $(init_name))"
    [ "$FAMILY" = "unknown" ] && result Host Дистрибутив Warning "невідомий дистрибутив '${OS_ID:-?}' без відомого пакетного менеджера: відсутні пакети не встановлюються, решта налаштувань застосовується"
    set_profile
    AUDITD_RESTART=0; RULES_CHANGED=0
    do_auditd
    do_journald
    do_authlog
    do_ssh
    do_time
    do_wazuh

    local finished; finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local summary="OK=$N_OK Changed=$N_CHANGED WouldChange=$N_WOULD Warning=$N_WARN Error=$N_ERR Skipped=$N_SKIP"
    mkdir -p /var/log/seclogging
    [ -z "$REPORT" ] && REPORT="/var/log/seclogging/report-$(date +%Y%m%d-%H%M%S).json"
    {
        printf '{\n  "Tool": "set-security-logging", "Version": "%s", "Mode": "%s",\n' "$SCRIPT_VERSION" "$([ "$CHECK" -eq 1 ] && echo Check || echo Apply)"
        printf '  "Started": "%s", "Finished": "%s",\n' "$started" "$finished"
        printf '  "Host": {"Name": "%s", "OS": "%s", "Family": "%s", "Role": "%s", "Kernel": "%s", "Arch": "%s", "Container": %s},\n' \
            "$(json_escape "$(host_name)")" "$(json_escape "$OS_NAME")" "$FAMILY" "$ROLE" "$KERNEL" "$ARCH" "$([ "$IN_CONTAINER" -eq 1 ] && echo true || echo false)"
        printf '  "Summary": {"OK": %d, "Changed": %d, "WouldChange": %d, "Warning": %d, "Error": %d, "Skipped": %d},\n' "$N_OK" "$N_CHANGED" "$N_WOULD" "$N_WARN" "$N_ERR" "$N_SKIP"
        printf '  "Results": [\n'
        local i
        for i in "${!RESULTS[@]}"; do
            printf '    %s' "${RESULTS[$i]}"; [ "$i" -lt $(( ${#RESULTS[@]} - 1 )) ] && printf ','; printf '\n'
        done
        printf '  ]\n}\n'
    } > "$REPORT"
    cp -f "$REPORT" /var/log/seclogging/last-report.json
    # підсумковий рядок для SIEM
    if [ "$CHECK" -eq 0 ] && have logger; then logger -t seclogging -p auth.notice "set-security-logging $SCRIPT_VERSION role=$ROLE $summary"; fi
    echo
    echo "Підсумок: $summary"
    echo "Звіт:     $REPORT"
    [ "$N_ERR" -gt 0 ] && exit 2
    exit 0
}

main
