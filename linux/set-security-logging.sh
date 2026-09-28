#!/usr/bin/env bash
# set-security-logging.sh - detect host, check and enable Linux security logging:
#   auditd (+ rules), journald persistence/size, auth log presence/retention,
#   optional Sysmon for Linux, Wazuh agent log collection.
#
# Pipeline: detect -> read current state -> apply only what is missing -> verify -> report.
# Values are "raise only": larger limits already configured on the host are kept.
#
# Usage: sudo ./set-security-logging.sh [options]
#   --check                 audit only, change nothing
#   --profile P             auto|workstation|server (default auto)
#   --with-sysmon           install/configure Sysmon for Linux (packages.microsoft.com)
#   --sysmon-package-dir D  offline Sysmon: dir with .deb/.rpm files + SHA256SUMS
#   --configure-wazuh       add missing <localfile> entries to the Wazuh agent ossec.conf
#   --immutable             lock audit rules (-e 2) until reboot
#   --report FILE           JSON report path (default /var/log/seclogging/report-<ts>.json)
#   --quiet                 print only the summary
#   -h|--help

set -u
umask 027

VERSION="1.0.0"
CHECK=0
PROFILE="auto"
WITH_SYSMON=0
SYSMON_PKG_DIR=""
CONFIGURE_WAZUH=0
IMMUTABLE=0
REPORT=""
QUIET=0

RULES_FILE="/etc/audit/rules.d/50-seclogging.rules"
JOURNALD_DROPIN="/etc/systemd/journald.conf.d/50-seclogging.conf"
STATE_DIR="/var/lib/seclogging"
SYSMON_CFG="/etc/seclogging/sysmon-linux.xml"
MARK_BEGIN="<!-- SecLogging BEGIN (managed by set-security-logging.sh) -->"
MARK_END="<!-- SecLogging END -->"

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --check) CHECK=1 ;;
        --profile) PROFILE="${2:-}"; shift ;;
        --with-sysmon) WITH_SYSMON=1 ;;
        --sysmon-package-dir) SYSMON_PKG_DIR="${2:-}"; WITH_SYSMON=1; shift ;;
        --configure-wazuh) CONFIGURE_WAZUH=1 ;;
        --immutable) IMMUTABLE=1 ;;
        --report) REPORT="${2:-}"; shift ;;
        --quiet) QUIET=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 64 ;;
    esac
    shift
done
case "$PROFILE" in auto|workstation|server) ;; *) echo "Bad --profile: $PROFILE" >&2; exit 64 ;; esac

# ------------------------------------------------------------------ report

RESULTS=()
N_OK=0; N_CHANGED=0; N_WOULD=0; N_WARN=0; N_ERR=0; N_SKIP=0

json_escape() {
    local s="$1"
    s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\r'/}; s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

# result AREA ITEM STATUS MESSAGE
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

# size string (100M, 1G, 512K, bytes) -> MB
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

# ------------------------------------------------------------------ detection

OS_ID=""; OS_LIKE=""; OS_VER=""; OS_NAME=""; FAMILY="unknown"; PKG=""
HAS_SYSTEMD=0; IN_CONTAINER=0; ROLE=""; ARCH=$(uname -m); KERNEL=$(uname -r)

detect_host() {
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_ID="${ID:-}"; OS_LIKE="${ID_LIKE:-}"; OS_VER="${VERSION_ID:-}"; OS_NAME="${PRETTY_NAME:-$OS_ID}"
    fi
    case " $OS_ID $OS_LIKE " in
        *" debian "*|*" ubuntu "*) FAMILY="deb"; PKG="apt" ;;
        *" rhel "*|*" fedora "*|*" centos "*) FAMILY="rpm"; if have dnf; then PKG="dnf"; else PKG="yum"; fi ;;
        *" suse "*|*" sles "*|*" opensuse "*) FAMILY="suse"; PKG="zypper" ;;
    esac
    [ -d /run/systemd/system ] && HAS_SYSTEMD=1
    if have systemd-detect-virt && systemd-detect-virt -cq 2>/dev/null; then IN_CONTAINER=1
    elif [ -f /.dockerenv ] || [ -f /run/.containerenv ] || grep -qaE '(docker|lxc|kubepods|containerd)' /proc/1/cgroup 2>/dev/null; then IN_CONTAINER=1; fi

    if [ "$PROFILE" = "auto" ]; then
        ROLE="server"
        if [ "$HAS_SYSTEMD" -eq 1 ] && [ "$(systemctl get-default 2>/dev/null)" = "graphical.target" ]; then ROLE="workstation"; fi
    else
        ROLE="$PROFILE"
    fi
}

# Profile values (MB / counts)
set_profile() {
    if [ "$ROLE" = "workstation" ]; then
        JOURNAL_MAX_MB=1024; AUDIT_FILE_MB=50; AUDIT_NUM_LOGS=10
    else
        JOURNAL_MAX_MB=2048; AUDIT_FILE_MB=100; AUDIT_NUM_LOGS=10
    fi
    # Do not plan more than 50% of free space on /var
    local free_mb need
    free_mb=$(df -Pm /var 2>/dev/null | awk 'NR==2{print $4}')
    FREE_MB=${free_mb:-0}
    need=$((JOURNAL_MAX_MB + AUDIT_FILE_MB * AUDIT_NUM_LOGS))
    if [ "$FREE_MB" -gt 0 ] && [ "$need" -gt $((FREE_MB / 2)) ]; then
        JOURNAL_MAX_MB=512; AUDIT_FILE_MB=50; AUDIT_NUM_LOGS=5
        result Host "Size profile" Warning "Only ${FREE_MB} MB free on /var: using minimal sizes (journald 512M, auditd 50M x5)"
    else
        result Host "Size profile" OK "$ROLE: journald ${JOURNAL_MAX_MB}M, auditd ${AUDIT_FILE_MB}M x${AUDIT_NUM_LOGS} (${FREE_MB} MB free on /var)"
    fi
}

pkg_install() {
    case "$PKG" in
        apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" >/tmp/seclogging-pkg.log 2>&1 || { apt-get update -q >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" >/tmp/seclogging-pkg.log 2>&1; } ;;
        dnf) dnf install -y -q "$@" >/tmp/seclogging-pkg.log 2>&1 ;;
        yum) yum install -y -q "$@" >/tmp/seclogging-pkg.log 2>&1 ;;
        zypper) zypper --non-interactive install "$@" >/tmp/seclogging-pkg.log 2>&1 ;;
        *) return 1 ;;
    esac
}

svc_restart() {
    # RHEL refuses "systemctl restart auditd"; the service wrapper works everywhere.
    local s="$1"
    if have service; then service "$s" restart >/dev/null 2>&1 && return 0; fi
    if [ "$HAS_SYSTEMD" -eq 1 ]; then systemctl restart "$s" >/dev/null 2>&1 && return 0; fi
    [ -x "/etc/init.d/$s" ] && "/etc/init.d/$s" restart >/dev/null 2>&1
}

svc_active() {
    local s="$1"
    if [ "$HAS_SYSTEMD" -eq 1 ]; then systemctl is-active --quiet "$s"; return $?; fi
    have service && service "$s" status >/dev/null 2>&1
}

# ------------------------------------------------------------------ auditd

# Rules template. "-w PATH" lines are only emitted when PATH exists;
# "@b32" lines only on x86_64 (32-bit syscall ABI). Key audit-wazuh-c maps to Wazuh audit rules.
AUDIT_RULES_TEMPLATE='
## --- self protection: audit config and tools
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k auditconfig
-w /sbin/auditctl -p x -k audittools
-w /usr/sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools
-w /usr/sbin/auditd -p x -k audittools
-w /var/log/audit/ -p wa -k auditlog
## --- identity and authentication
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
## --- persistence: cron, at, systemd, rc, profile
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
## --- library preload / linker hijack
-w /etc/ld.so.preload -p wa -k preload
-w /etc/ld.so.conf -p wa -k preload
-w /etc/ld.so.conf.d/ -p wa -k preload
## --- kernel modules
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
## --- network / host identity
-w /etc/hosts -p wa -k netconf
-w /etc/hostname -p wa -k netconf
-a always,exit -F arch=b64 -S sethostname,setdomainname -k netconf
## --- time
-w /etc/localtime -p wa -k time
-a always,exit -F arch=b64 -S settimeofday,clock_settime -F a0=0x0 -k time
## --- process injection (PTRACE_POKETEXT/POKEDATA/POKEUSER)
-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k code_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k code_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k code_injection
## --- mounts by users
-a always,exit -F arch=b64 -S mount,umount2 -F auid!=4294967295 -k mount
## --- privilege tools
-w /usr/bin/sudo -p x -k priv_esc
-w /bin/su -p x -k priv_esc
-w /usr/bin/su -p x -k priv_esc
-w /usr/bin/passwd -p x -k passwd_change
-w /usr/sbin/useradd -p x -k user_mgmt
-w /usr/sbin/userdel -p x -k user_mgmt
-w /usr/sbin/usermod -p x -k user_mgmt
-w /usr/sbin/groupadd -p x -k user_mgmt
-w /usr/sbin/groupmod -p x -k user_mgmt
## --- command execution by logged-in users (auid set), incl. root sessions and sudo
-a always,exit -F arch=b64 -S execve -F auid!=4294967295 -k audit-wazuh-c
@b32 -a always,exit -F arch=b32 -S execve -F auid!=4294967295 -k audit-wazuh-c
'

render_audit_rules() {
    local line path uid u
    echo "## Managed by set-security-logging.sh $VERSION - do not edit, re-run the script instead"
    # backlog: only raise (other rules.d files may already set more)
    local b f
    b=$(for f in /etc/audit/rules.d/*.rules; do [ "$f" != "$RULES_FILE" ] && [ -f "$f" ] && grep -hsE '^-b[[:space:]]+[0-9]+' "$f"; done | awk '{print $2}' | sort -n | tail -1)
    [ "${b:-0}" -lt 8192 ] && echo "-b 8192"
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
    # Web shells: any execve by a web server account
    for u in www-data apache nginx httpd; do
        uid=$(id -u "$u" 2>/dev/null) || continue
        echo "-a always,exit -F arch=b64 -S execve -F euid=$uid -k webshell"
    done
}

# set_kv FILE KEY VALUE  (key = value style)
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
    # auditctl -v needs CAP_AUDIT_CONTROL on old versions: fall back to the package version
    local cur; cur=$( { auditctl -v 2>/dev/null; dpkg-query -W -f='${Version}\n' auditd 2>/dev/null; rpm -q --qf '%{VERSION}\n' audit 2>/dev/null; } \
        | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
    [ -n "$cur" ] && [ "$(printf '%s\n%s\n' "$1" "$cur" | sort -V | head -1)" = "$1" ]
}

do_auditd() {
    if ! have auditctl; then
        if [ "$CHECK" -eq 1 ]; then result auditd package WouldChange "install auditd"; return
        fi
        local pkgname="audit"; [ "$FAMILY" = "deb" ] && pkgname="auditd"
        if pkg_install "$pkgname"; then result auditd package Changed "installed $pkgname"
        else result auditd package Error "cannot install $pkgname (see /tmp/seclogging-pkg.log)"; return; fi
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
        result auditd auditd.conf Error "$conf not found"
    fi

    # --- rules file
    local tmp new_hash old_hash=""
    tmp=$(mktemp)
    render_audit_rules > "$tmp"
    new_hash=$(sha256sum "$tmp" | awk '{print $1}')
    [ -f "$RULES_FILE" ] && old_hash=$(sha256sum "$RULES_FILE" | awk '{print $1}')
    local nrules; nrules=$(grep -cE '^-(w|a) ' "$tmp")
    if [ "$new_hash" = "$old_hash" ]; then
        result auditd "$RULES_FILE" OK "$nrules rules, up to date"
    elif [ "$CHECK" -eq 1 ]; then
        result auditd "$RULES_FILE" WouldChange "write $nrules rules"
    else
        mkdir -p "$(dirname "$RULES_FILE")"
        install -m 0640 "$tmp" "$RULES_FILE"
        RULES_CHANGED=1
        result auditd "$RULES_FILE" Changed "$nrules rules written"
    fi
    rm -f "$tmp"

    if [ "$IMMUTABLE" -eq 1 ]; then
        local fin=/etc/audit/rules.d/99-finalize.rules
        if grep -qsE '^-e[[:space:]]+2' /etc/audit/rules.d/*.rules; then result auditd immutable OK "-e 2 present"
        elif [ "$CHECK" -eq 1 ]; then result auditd immutable WouldChange "add -e 2 ($fin)"
        else echo "-e 2" > "$fin"; chmod 0640 "$fin"; RULES_CHANGED=1; result auditd immutable Changed "added -e 2 ($fin), rules locked until reboot"; fi
    fi

    # --- runtime (kernel) state
    if [ "$IN_CONTAINER" -eq 1 ]; then
        result auditd runtime Skipped "container: kernel audit belongs to the host"
        return
    fi
    local enabled; enabled=$(auditctl -s 2>/dev/null | awk '/^enabled/{print $2}')
    if [ "$CHECK" -eq 1 ]; then
        if svc_active auditd; then result auditd service OK "running, enabled=$enabled"; else result auditd service WouldChange "start auditd"; fi
        return
    fi
    if [ "$HAS_SYSTEMD" -eq 1 ]; then systemctl enable auditd >/dev/null 2>&1; fi
    if ! svc_active auditd; then
        if [ "$HAS_SYSTEMD" -eq 1 ]; then systemctl start auditd >/dev/null 2>&1; else svc_restart auditd; fi
        AUDITD_RESTART=0
    elif [ "${AUDITD_RESTART:-0}" -eq 1 ]; then
        svc_restart auditd || result auditd service Error "restart failed"
    fi
    if svc_active auditd; then result auditd service OK "running"; else result auditd service Error "auditd is not running"; fi

    if [ "${RULES_CHANGED:-0}" -eq 1 ] || ! auditctl -l 2>/dev/null | grep -q 'key=identity'; then
        if [ "$enabled" = "2" ]; then
            result auditd "rules load" Warning "audit rules are immutable (-e 2): new rules apply after reboot"
        else
            local out
            if have augenrules; then out=$(augenrules --load 2>&1); else out=$(auditctl -R /etc/audit/audit.rules 2>&1); fi
            if auditctl -l 2>/dev/null | grep -q 'key=identity'; then
                result auditd "rules load" Changed "loaded, $(auditctl -l 2>/dev/null | grep -c .) rules active"
            else
                result auditd "rules load" Error "rules not active: $(printf '%s' "$out" | tail -3)"
            fi
        fi
    else
        result auditd "rules active" OK "$(auditctl -l 2>/dev/null | grep -c .) rules loaded"
    fi
}

# ------------------------------------------------------------------ journald

journald_value() {
    # effective value of KEY from journald config (last one wins)
    local key="$1"
    if have systemd-analyze && systemd-analyze cat-config systemd/journald.conf >/dev/null 2>&1; then
        systemd-analyze cat-config systemd/journald.conf 2>/dev/null
    else
        cat /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null
    fi | awk -F= -v k="$key" '$1==k {v=$2} END{print v}'
}

do_journald() {
    if [ "$HAS_SYSTEMD" -eq 0 ]; then result journald journald Skipped "no systemd"; return; fi
    local storage max max_mb persistent=0 changes=""
    storage=$(journald_value Storage); max=$(journald_value SystemMaxUse)
    max_mb=$(to_mb "${max:-0}")
    if [ "$storage" = "persistent" ] || { [ "${storage:-auto}" = "auto" ] && [ -d /var/log/journal ]; }; then persistent=1; fi
    [ "$persistent" -eq 0 ] && changes+="Storage=${storage:-auto}(volatile)->persistent "
    [ "$max_mb" -lt "$JOURNAL_MAX_MB" ] && changes+="SystemMaxUse=${max:-default}->${JOURNAL_MAX_MB}M "
    if [ -z "$changes" ]; then result journald journald.conf OK "Storage=${storage:-auto} persistent, SystemMaxUse=${max}"; return; fi
    if [ "$CHECK" -eq 1 ]; then result journald journald.conf WouldChange "$changes"; return; fi
    local want=$JOURNAL_MAX_MB; [ "$max_mb" -gt "$want" ] && want=$max_mb
    mkdir -p "$(dirname "$JOURNALD_DROPIN")" /var/log/journal
    printf '# Managed by set-security-logging.sh\n[Journal]\nStorage=persistent\nSystemMaxUse=%sM\n' "$want" > "$JOURNALD_DROPIN"
    have systemd-tmpfiles && systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1
    if [ "$IN_CONTAINER" -eq 0 ]; then
        systemctl restart systemd-journald >/dev/null 2>&1 || result journald restart Error "systemd-journald restart failed"
    fi
    result journald journald.conf Changed "$changes($JOURNALD_DROPIN)"
}

# ------------------------------------------------------------------ auth log / logrotate

AUTH_LOG=""
do_authlog() {
    if [ "$FAMILY" = "deb" ]; then AUTH_LOG=/var/log/auth.log; else AUTH_LOG=/var/log/secure; fi
    if have rsyslogd || have syslog-ng; then
        if [ -f "$AUTH_LOG" ]; then result authlog "$AUTH_LOG" OK "present"
        else result authlog "$AUTH_LOG" Warning "syslog daemon installed but $AUTH_LOG is missing (service stopped?)"; fi
    else
        AUTH_LOG=""
        result authlog "syslog" Warning "no rsyslog/syslog-ng: SSH/sudo events are only in journald (Wazuh must read journald)"
        return
    fi
    # logrotate retention for the auth log
    local f rot period days
    f=$(grep -lsE "$AUTH_LOG" /etc/logrotate.d/* /etc/logrotate.conf 2>/dev/null | head -1)
    if [ -z "$f" ]; then result authlog logrotate Warning "no logrotate rule for $AUTH_LOG"; return; fi
    rot=$(awk -v p="$AUTH_LOG" 'index($0,p){f=1} f&&/^[[:space:]]*rotate[[:space:]]+[0-9]+/{print $2; exit}' "$f")
    period=$(awk -v p="$AUTH_LOG" 'index($0,p){f=1} f&&/^[[:space:]]*(daily|weekly|monthly)/{print $1; exit}' "$f")
    [ -z "$rot" ] && rot=$(awk '/^[[:space:]]*rotate[[:space:]]+[0-9]+/{print $2; exit}' /etc/logrotate.conf)
    [ -z "$period" ] && period=$(awk '/^[[:space:]]*(daily|weekly|monthly)[[:space:]]*$/{print $1; exit}' /etc/logrotate.conf)
    case "${period:-weekly}" in daily) days=$(( ${rot:-4} * 1 )) ;; monthly) days=$(( ${rot:-4} * 30 )) ;; *) days=$(( ${rot:-4} * 7 )) ;; esac
    if [ "$days" -ge 7 ]; then result authlog logrotate OK "$f: rotate ${rot:-4} ${period:-weekly} (~${days} days)"
    else result authlog logrotate Warning "$f: only ~${days} days kept (rotate ${rot:-?} ${period:-?}), want >= 7"; fi
}

# ------------------------------------------------------------------ Sysmon for Linux

SYSMON_CONFIG_XML='<Sysmon schemaversion="4.70">
  <!-- Managed by set-security-logging.sh. Events go to syslog (Linux-Sysmon/Operational). -->
  <EventFiltering>
    <!-- 1: process creation (all) -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude"/>
    </RuleGroup>
    <!-- 3: network connections, without loopback -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <DestinationIp condition="is">127.0.0.1</DestinationIp>
        <DestinationIp condition="is">::1</DestinationIp>
      </NetworkConnect>
    </RuleGroup>
    <!-- 5: process terminated - off -->
    <RuleGroup name="" groupRelation="or">
      <ProcessTerminate onmatch="include"/>
    </RuleGroup>
    <!-- 9: raw disk reads -->
    <RuleGroup name="" groupRelation="or">
      <RawAccessRead onmatch="exclude"/>
    </RuleGroup>
    <!-- 11: file creation in persistence / sensitive locations -->
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="begin with">/etc/cron</TargetFilename>
        <TargetFilename condition="begin with">/var/spool/cron</TargetFilename>
        <TargetFilename condition="begin with">/etc/systemd/system</TargetFilename>
        <TargetFilename condition="begin with">/etc/sudoers</TargetFilename>
        <TargetFilename condition="begin with">/etc/ld.so</TargetFilename>
        <TargetFilename condition="begin with">/etc/profile.d</TargetFilename>
        <TargetFilename condition="end with">/.ssh/authorized_keys</TargetFilename>
        <TargetFilename condition="end with">.bashrc</TargetFilename>
        <TargetFilename condition="begin with">/dev/shm</TargetFilename>
      </FileCreate>
    </RuleGroup>
    <!-- 23: file deletion - off -->
    <RuleGroup name="" groupRelation="or">
      <FileDelete onmatch="include"/>
    </RuleGroup>
  </EventFiltering>
</Sysmon>'

kernel_ge() { # kernel_ge 4.15
    local want="$1" cur; cur=$(printf '%s' "$KERNEL" | sed -E 's/^([0-9]+\.[0-9]+).*/\1/')
    [ "$(printf '%s\n%s\n' "$want" "$cur" | sort -V | head -1)" = "$want" ]
}

sysmon_repo_url() {
    local major="${OS_VER%%.*}"
    case "$OS_ID" in
        ubuntu) echo "https://packages.microsoft.com/config/ubuntu/$OS_VER/packages-microsoft-prod.deb" ;;
        debian) echo "https://packages.microsoft.com/config/debian/$major/packages-microsoft-prod.deb" ;;
        rhel|rocky|almalinux|centos|ol) echo "https://packages.microsoft.com/config/rhel/$major/packages-microsoft-prod.rpm" ;;
        fedora) echo "https://packages.microsoft.com/config/fedora/$major/packages-microsoft-prod.rpm" ;;
        sles|opensuse-leap) echo "https://packages.microsoft.com/config/sles/$major/packages-microsoft-prod.rpm" ;;
        *) echo "" ;;
    esac
}

install_sysmon_pkg() {
    if [ -n "$SYSMON_PKG_DIR" ]; then
        # offline: verify SHA256SUMS first
        [ -f "$SYSMON_PKG_DIR/SHA256SUMS" ] || { echo "SHA256SUMS missing in $SYSMON_PKG_DIR"; return 1; }
        (cd "$SYSMON_PKG_DIR" && sha256sum -c --quiet SHA256SUMS) || { echo "SHA256SUMS verification failed"; return 1; }
        case "$FAMILY" in
            deb) DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$SYSMON_PKG_DIR"/*.deb ;;
            rpm) $PKG install -y -q "$SYSMON_PKG_DIR"/*.rpm ;;
            suse) zypper --non-interactive install "$SYSMON_PKG_DIR"/*.rpm ;;
            *) return 1 ;;
        esac
        return $?
    fi
    # online: Microsoft repo (HTTPS bootstrap, then GPG-verified repository)
    local url tmp; url=$(sysmon_repo_url)
    [ -n "$url" ] || { echo "no packages.microsoft.com repo for $OS_ID $OS_VER"; return 1; }
    tmp=$(mktemp -d)
    have curl || have wget || pkg_install curl ca-certificates
    if have curl; then curl -fsSL -o "$tmp/pkg" "$url"; else wget -q -O "$tmp/pkg" "$url"; fi || { echo "download failed: $url"; rm -rf "$tmp"; return 1; }
    case "$FAMILY" in
        deb) mv "$tmp/pkg" "$tmp/pkg.deb"; dpkg -i "$tmp/pkg.deb" && apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q sysmonforlinux ;;
        rpm) mv "$tmp/pkg" "$tmp/pkg.rpm"; rpm -Uvh --replacepkgs "$tmp/pkg.rpm" && $PKG install -y -q sysmonforlinux ;;
        suse) mv "$tmp/pkg" "$tmp/pkg.rpm"; rpm -Uvh --replacepkgs "$tmp/pkg.rpm" && zypper --non-interactive install sysmonforlinux ;;
    esac
    local rc=$?; rm -rf "$tmp"; return $rc
}

do_sysmon() {
    if [ "$WITH_SYSMON" -eq 0 ]; then
        if have sysmon; then result sysmon sysmon OK "installed (not managed without --with-sysmon)"
        else result sysmon sysmon Skipped "not requested (--with-sysmon)"; fi
        return
    fi
    if [ "$IN_CONTAINER" -eq 1 ]; then result sysmon sysmon Skipped "container: eBPF sensor belongs to the host"; return; fi
    if ! kernel_ge 4.15; then result sysmon sysmon Warning "kernel $KERNEL < 4.15: Sysmon for Linux (eBPF) not supported"; return; fi

    local cfg_hash applied=""
    cfg_hash=$(printf '%s\n' "$SYSMON_CONFIG_XML" | sha256sum | awk '{print $1}')
    [ -f "$STATE_DIR/sysmon-config.sha256" ] && applied=$(cat "$STATE_DIR/sysmon-config.sha256")

    if ! have sysmon; then
        if [ "$CHECK" -eq 1 ]; then result sysmon sysmon WouldChange "install sysmonforlinux + config"; return; fi
        local out; out=$(install_sysmon_pkg 2>&1)
        if ! have sysmon; then result sysmon package Error "install failed: $(printf '%s' "$out" | tail -3)"; return; fi
        result sysmon package Changed "sysmonforlinux installed"
    else
        result sysmon package OK "$(dpkg-query -W -f='${Version}' sysmonforlinux 2>/dev/null || rpm -q sysmonforlinux 2>/dev/null)"
    fi

    local running=0; svc_active sysmon && running=1
    if [ "$running" -eq 1 ] && [ "$applied" = "$cfg_hash" ]; then result sysmon config OK "$cfg_hash"; return; fi
    if [ "$CHECK" -eq 1 ]; then result sysmon config WouldChange "apply $cfg_hash"; return; fi
    mkdir -p "$(dirname "$SYSMON_CFG")" "$STATE_DIR"
    printf '%s\n' "$SYSMON_CONFIG_XML" > "$SYSMON_CFG"
    local out
    if [ "$running" -eq 1 ]; then out=$(sysmon -c "$SYSMON_CFG" 2>&1); else out=$(sysmon -accepteula -i "$SYSMON_CFG" 2>&1); fi
    if svc_active sysmon; then
        echo "$cfg_hash" > "$STATE_DIR/sysmon-config.sha256"
        result sysmon config Changed "applied $cfg_hash, service running"
    else
        result sysmon config Error "sysmon not running: $(printf '%s' "$out" | tail -3)"
    fi
}

# ------------------------------------------------------------------ Wazuh

do_wazuh() {
    local conf=/var/ossec/etc/ossec.conf shared=/var/ossec/etc/shared/agent.conf
    if [ ! -f "$conf" ]; then result wazuh agent Warning "Wazuh agent not installed - logs stay local only"; return; fi
    local ver=""; [ -x /var/ossec/bin/wazuh-control ] && ver=$(/var/ossec/bin/wazuh-control info -v 2>/dev/null)
    if svc_active wazuh-agent; then result wazuh agent OK "running ${ver}"; else result wazuh agent Warning "installed ${ver} but not running"; fi

    # wanted: "format|location"
    local wanted=("audit|/var/log/audit/audit.log")
    if [ -n "$AUTH_LOG" ]; then wanted+=("syslog|$AUTH_LOG"); else wanted+=("journald|journald"); fi
    if [ "$WITH_SYSMON" -eq 1 ] && [ -n "$AUTH_LOG" ]; then
        if [ "$FAMILY" = "deb" ]; then wanted+=("syslog|/var/log/syslog"); else wanted+=("syslog|/var/log/messages"); fi
    fi
    local present missing=() w loc
    present=$(cat "$conf" "$shared" 2>/dev/null | grep -oE '<location>[^<]+</location>' | sed -E 's|</?location>||g')
    for w in "${wanted[@]}"; do
        loc="${w#*|}"
        printf '%s\n' "$present" | grep -qxF "$loc" || missing+=("$w")
    done
    if [ ${#missing[@]} -eq 0 ]; then result wazuh localfile OK "audit/auth logs collected"; return; fi
    local list; list=$(printf '%s ' "${missing[@]#*|}")
    if [ "$CONFIGURE_WAZUH" -eq 0 ]; then result wazuh localfile Warning "not collected: $list- use manager group agent.conf (wazuh/shared/linux) or --configure-wazuh"; return; fi
    if [ "$CHECK" -eq 1 ]; then result wazuh localfile WouldChange "add $list"; return; fi

    backup_once "$conf"
    # keep entries from a previous managed block, drop the block, append a new one
    local old=()
    while IFS= read -r w; do [ -n "$w" ] && old+=("$w"); done < <(awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
        index($0,b){f=1;next} index($0,e){f=0} f&&/<log_format>/{gsub(/.*<log_format>|<\/log_format>.*/,""); fmt=$0}
        f&&/<location>/{gsub(/.*<location>|<\/location>.*/,""); loc=$0} f&&/<\/localfile>/{print fmt "|" loc}' "$conf")
    local tmp; tmp=$(mktemp)
    awk -v b="$MARK_BEGIN" -v e="$MARK_END" 'index($0,b){f=1} !f{print} index($0,e){f=0}' "$conf" > "$tmp"
    {
        echo "$MARK_BEGIN"
        echo "<ossec_config>"
        printf '%s\n' "${old[@]}" "${missing[@]}" | awk 'NF && !seen[$0]++' | while IFS='|' read -r fmt loc; do
            printf '  <localfile>\n    <log_format>%s</log_format>\n    <location>%s</location>\n  </localfile>\n' "$fmt" "$loc"
        done
        echo "</ossec_config>"
        echo "$MARK_END"
    } >> "$tmp"
    cat "$tmp" > "$conf"; rm -f "$tmp"
    if [ "$IN_CONTAINER" -eq 0 ] && svc_restart wazuh-agent; then result wazuh localfile Changed "added $list; agent restarted"
    else result wazuh localfile Changed "added $list; restart wazuh-agent manually"; fi
}

# ------------------------------------------------------------------ main

main() {
    if [ "$(id -u)" -ne 0 ]; then echo "Run as root (sudo)." >&2; exit 3; fi
    local started; started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    detect_host
    if [ "$QUIET" -eq 0 ]; then
        echo
        echo "set-security-logging $VERSION  mode: $([ "$CHECK" -eq 1 ] && echo 'CHECK ONLY' || echo APPLY)"
        echo "$(hostname): $OS_NAME, family=$FAMILY, role=$ROLE, kernel=$KERNEL, $ARCH, systemd=$HAS_SYSTEMD, container=$IN_CONTAINER"
        echo
    fi
    result Host Role OK "$ROLE (family $FAMILY, pkg ${PKG:-none})"
    [ "$FAMILY" = "unknown" ] && result Host Distro Warning "unsupported distro '$OS_ID': package installs are skipped"
    set_profile
    AUDITD_RESTART=0; RULES_CHANGED=0
    do_auditd
    do_journald
    do_authlog
    do_sysmon
    do_wazuh

    local finished; finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local summary="OK=$N_OK Changed=$N_CHANGED WouldChange=$N_WOULD Warning=$N_WARN Error=$N_ERR Skipped=$N_SKIP"
    mkdir -p /var/log/seclogging
    [ -z "$REPORT" ] && REPORT="/var/log/seclogging/report-$(date +%Y%m%d-%H%M%S).json"
    {
        printf '{\n  "Tool": "set-security-logging", "Version": "%s", "Mode": "%s",\n' "$VERSION" "$([ "$CHECK" -eq 1 ] && echo Check || echo Apply)"
        printf '  "Started": "%s", "Finished": "%s",\n' "$started" "$finished"
        printf '  "Host": {"Name": "%s", "OS": "%s", "Family": "%s", "Role": "%s", "Kernel": "%s", "Arch": "%s", "Container": %s},\n' \
            "$(json_escape "$(hostname)")" "$(json_escape "$OS_NAME")" "$FAMILY" "$ROLE" "$KERNEL" "$ARCH" "$([ "$IN_CONTAINER" -eq 1 ] && echo true || echo false)"
        printf '  "Summary": {"OK": %d, "Changed": %d, "WouldChange": %d, "Warning": %d, "Error": %d, "Skipped": %d},\n' "$N_OK" "$N_CHANGED" "$N_WOULD" "$N_WARN" "$N_ERR" "$N_SKIP"
        printf '  "Results": [\n'
        local i
        for i in "${!RESULTS[@]}"; do
            printf '    %s' "${RESULTS[$i]}"; [ "$i" -lt $(( ${#RESULTS[@]} - 1 )) ] && printf ','; printf '\n'
        done
        printf '  ]\n}\n'
    } > "$REPORT"
    cp -f "$REPORT" /var/log/seclogging/last-report.json
    # summary line for the SIEM
    if [ "$CHECK" -eq 0 ] && have logger; then logger -t seclogging -p auth.notice "set-security-logging $VERSION role=$ROLE $summary"; fi
    echo
    echo "Summary: $summary"
    echo "Report:  $REPORT"
    [ "$N_ERR" -gt 0 ] && exit 2
    exit 0
}

main
