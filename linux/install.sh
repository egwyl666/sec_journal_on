#!/usr/bin/env bash
# install.sh - автоматизація "завантажити -> зібрати комплект -> встановити" для Linux.
#
# Одна команда (root, потрібен інтернет):
#   (curl -fsSL URL 2>/dev/null || wget -qO- URL) | sudo bash
#   де URL = https://raw.githubusercontent.com/egwyl666/sec_journal_on/v1.3.3/linux/install.sh
#   (працює і там, де є лише curl - мінімальні RHEL, і де лише wget - Ubuntu Desktop)
# Знімає стан "до" і "після" і записує, що змінилося: /var/log/seclogging/changes/<час>-changes.txt
#
# Використання:
#   sudo ./install.sh [install] [параметри] [параметри set-security-logging.sh]
#   sudo ./install.sh build [--out DIR] [--no-auditd]
#
# Команди:
#   install (за замовчуванням)  налаштувати цей хост (онлайн або з комплекту --from)
#   build                       зібрати офлайн-комплект для хостів без інтернету
#                               (той самий дистрибутив, версія та архітектура, що й тут;
#                               сімейства deb і rpm: Ubuntu/Debian/Mint/Astra, RHEL/CentOS/Rocky/Alma/Oracle/Fedora/Amazon)
# Параметри:
#   --from DIR       install: взяти комплект з DIR (перевіряється SHA256SUMS)
#   --out DIR        build: тека комплекту (типово ./seclogging-bundle-<os>-<версія>-<arch>)
#   --no-auditd      build: не додавати пакети auditd
#   --fetch          завантажити свіжий set-security-logging.sh з GitHub
#   --ref REF        гілка/тег/коміт для --fetch (типово закріплений реліз; HEAD - остання версія)
#   --no-wazuh       не дописувати збір журналів в ossec.conf агента Wazuh (типово дописує, якщо агент є)
#   -h|--help
# Усі інші параметри (--check, --configure-wazuh, --profile, --immutable, --quiet, ...)
# передаються в set-security-logging.sh без змін.

set -u
umask 022

REPO_RAW="https://raw.githubusercontent.com/egwyl666/sec_journal_on"
REF="v1.3.3"   # закріплений реліз; --ref HEAD - остання версія
CMD="install"
FROM=""
OUT=""
WITH_AUDITD=1
FETCH=0
WAZUH=1
# запуск через "curl ... | bash": поруч немає файлів - основний скрипт завантажуємо
[ -f "$0" ] || FETCH=1
PASS=()
SELF_DIR=$(cd "$(dirname "$0")" && pwd)

usage() { sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "ПОМИЛКА: $1" >&2; exit "${2:-2}"; }
info() { echo "==> $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

case "${1:-}" in install|build) CMD="$1"; shift ;; esac
while [ $# -gt 0 ]; do
    case "$1" in
        --from) FROM="${2:-}"; shift ;;
        --out) OUT="${2:-}"; shift ;;
        --with-sysmon) die "Sysmon for Linux більше не підтримується: достатньо auditd і journald" 64 ;;
        --no-auditd) WITH_AUDITD=0 ;;
        --fetch) FETCH=1 ;;
        --no-wazuh) WAZUH=0 ;;
        --ref) REF="${2:-}"; shift ;;
        -h|--help) usage; exit 0 ;;
        --) shift; PASS+=("$@"); break ;;
        *) PASS+=("$1") ;;
    esac
    shift
done

[ "$(id -u)" -eq 0 ] || die "запустіть від root (sudo)" 3

# ------------------------------------------------------------------ визначення ОС (без забруднення змінних)

# shellcheck disable=SC1091
HOST_ID=$(. /etc/os-release 2>/dev/null; echo "${ID:-unknown}")
# shellcheck disable=SC1091
HOST_LIKE=$(. /etc/os-release 2>/dev/null; echo "${ID_LIKE:-}")
# shellcheck disable=SC1091
HOST_VER=$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-}")
HOST_ARCH=$(uname -m)
FAMILY="unknown"
case " $HOST_ID $HOST_LIKE " in
    *" altlinux "*) FAMILY="alt" ;;
    *" debian "*|*" ubuntu "*) FAMILY="deb" ;;
    *" rhel "*|*" fedora "*|*" centos "*|*" amzn "*) FAMILY="rpm" ;;
    *" suse "*|*" sles "*|*" opensuse "*) FAMILY="suse" ;;
    *" arch "*|*" archlinux "*) FAMILY="arch" ;;
    *" alpine "*) FAMILY="alpine" ;;
esac
if [ "$FAMILY" = "unknown" ]; then
    if have apt-get && have dpkg; then FAMILY="deb"; elif have dnf || have yum; then FAMILY="rpm"
    elif have zypper; then FAMILY="suse"; elif have pacman; then FAMILY="arch"; elif have apk; then FAMILY="alpine"; fi
fi

download() { # download URL FILE
    if have curl; then curl -fsSL -o "$2" "$1"; elif have wget; then wget -q -O "$2" "$1"; else return 1; fi
}

# ------------------------------------------------------------------ скрипт

get_main_script() {
    # Друкує шлях до set-security-logging.sh: локальний поруч або завантажений (--fetch)
    local local_script="$SELF_DIR/set-security-logging.sh" tmp
    if [ "$FETCH" -eq 0 ] && [ -f "$local_script" ]; then echo "$local_script"; return 0; fi
    tmp=$(mktemp -d)/set-security-logging.sh
    download "$REPO_RAW/$REF/linux/set-security-logging.sh" "$tmp" || return 1
    bash -n "$tmp" || return 1
    chmod 0755 "$tmp"
    echo "$tmp"
}

# ------------------------------------------------------------------ build

deb_closure() { # deb_closure PACKAGE... -> імена всіх пакетів дерева залежностей (без віртуальних)
    apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts --no-breaks \
        --no-replaces --no-enhances "$@" 2>/dev/null | grep -E '^[a-z0-9]' | sort -u
}

pkg_download() { # pkg_download DIR PACKAGE... - пакети разом з усіма залежностями
    local dir="$1"; shift
    mkdir -p "$dir"
    case "$FAMILY" in
        deb)
            local all; all=$(deb_closure "$@")
            [ -n "$all" ] || return 1
            # shellcheck disable=SC2086
            (cd "$dir" && apt-get -o APT::Sandbox::User=root download $all >/dev/null) ;;
        rpm)
            if have dnf; then
                # dnf5 (Fedora 41+) не має -q у download; плагін download потрібен у dnf4
                dnf download --resolve --alldeps --destdir "$dir" "$@" >/dev/null 2>&1 \
                    || { dnf install -y -q 'dnf-command(download)' >/dev/null 2>&1 && dnf download --resolve --alldeps --destdir "$dir" "$@" >/dev/null 2>&1; }
            else
                # yum (CentOS 7): repotrack завантажує повне дерево залежностей, yumdownloader - лише відсутні тут
                have repotrack || yum install -y -q yum-utils >/dev/null 2>&1
                if have repotrack; then repotrack -a "$(uname -m)" -p "$dir" "$@" >/dev/null 2>&1
                elif have yumdownloader; then yumdownloader -q --resolve --destdir "$dir" "$@" >/dev/null
                else return 1; fi
                find "$dir" -name '*.i686.rpm' -delete 2>/dev/null
            fi
            ls "$dir"/*.rpm >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

write_sums() { # write_sums DIR -> DIR/SHA256SUMS для всіх файлів (рекурсивно, відносні шляхи)
    local tmp; tmp=$(mktemp)
    (cd "$1" && find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs -r -d '\n' sha256sum > "$tmp")
    mv "$tmp" "$1/SHA256SUMS"; chmod 0644 "$1/SHA256SUMS"
}

do_build() {
    [ "$FAMILY" = "deb" ] || [ "$FAMILY" = "rpm" ] \
        || die "офлайн-комплект підтримує сімейства deb і rpm (цей хост: $HOST_ID, сімейство $FAMILY). Онлайн-встановлення працює: sudo ./install.sh"
    [ -n "$OUT" ] || OUT="$PWD/seclogging-bundle-$HOST_ID-$HOST_VER-$HOST_ARCH"
    mkdir -p "$OUT" || die "не вдалося створити $OUT"
    OUT=$(cd "$OUT" && pwd)
    info "Комплект: $OUT ($HOST_ID $HOST_VER $HOST_ARCH)"

    local main; main=$(get_main_script) || die "не вдалося отримати set-security-logging.sh"
    install -m 0755 "$main" "$OUT/set-security-logging.sh"
    # сам install.sh: при запуску через "curl ... | bash" файлу $0 немає - завантажуємо ту саму версію
    if [ -f "$0" ]; then install -m 0755 "$0" "$OUT/install.sh" || die "не вдалося скопіювати install.sh"
    else
        if ! { download "$REPO_RAW/$REF/linux/install.sh" "$OUT/install.sh" && bash -n "$OUT/install.sh"; }; then
            die "не вдалося завантажити install.sh ($REPO_RAW/$REF/linux/install.sh)"
        fi
        chmod 0755 "$OUT/install.sh"
    fi
    if [ ! -s "$OUT/install.sh" ] || [ ! -s "$OUT/set-security-logging.sh" ]; then die "у комплекті бракує скриптів"; fi
    echo "    скрипти скопійовано"

    [ "$FAMILY" = "deb" ] && apt-get update -qq >/dev/null 2>&1
    if [ "$WITH_AUDITD" -eq 1 ]; then
        rm -rf "$OUT/auditd"
        if [ "$FAMILY" = "deb" ]; then
            pkg_download "$OUT/auditd" auditd || die "не вдалося завантажити пакети auditd"
        else
            pkg_download "$OUT/auditd" audit || die "не вдалося завантажити пакет audit"
        fi
        write_sums "$OUT/auditd"
        echo "    auditd: $(find "$OUT/auditd" -name '*.deb' -o -name '*.rpm' | wc -l) пакет(и)"
    fi
    printf 'OS_ID=%s\nOS_VERSION_ID=%s\nARCH=%s\nFAMILY=%s\nCREATED=%s\n' \
        "$HOST_ID" "$HOST_VER" "$HOST_ARCH" "$FAMILY" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$OUT/bundle.info"
    write_sums "$OUT"
    info "Готово. Скопіюйте теку на хост без інтернету і запустіть:"
    echo "    sudo $OUT/install.sh --from $OUT"
}

# ------------------------------------------------------------------ install

install_offline_pkgs() { # install_offline_pkgs DIR - ставить лише відсутні/старіші пакети, ніколи не відкочує версії
    local dir="$1" f pkg ver cur pass list=()
    : > /tmp/seclogging-offline.log
    case "$FAMILY" in
        deb)
            # кілька проходів: dpkg не впорядковує Pre-Depends усередині одного виклику
            for pass in 1 2 3 4; do
                list=()
                for f in "$dir"/*.deb; do
                    [ -f "$f" ] || continue
                    pkg=$(dpkg-deb -f "$f" Package); ver=$(dpkg-deb -f "$f" Version)
                    cur=$(dpkg-query -W -f='${Status}|${Version}' "$pkg" 2>/dev/null)
                    if [ "${cur%%|*}" = "install ok installed" ] && dpkg --compare-versions "${cur#*|}" ge "$ver"; then continue; fi
                    list+=("$f")
                done
                [ ${#list[@]} -eq 0 ] && return 0
                echo "--- прохід $pass: ${#list[@]} пакет(ів)" >> /tmp/seclogging-offline.log
                dpkg -i "${list[@]}" >> /tmp/seclogging-offline.log 2>&1 && return 0
            done
            return 1 ;;
        rpm)
            # відсутні пакети встановлюються, старіші - оновлюються, новіші на хості не чіпаються (без відкату)
            local upd=()
            for f in "$dir"/*.rpm; do
                [ -f "$f" ] || continue
                pkg=$(rpm -qp --qf '%{NAME}' "$f" 2>/dev/null)
                if rpm -q "$pkg" >/dev/null 2>&1; then
                    # "rpm -U --test --nodeps" без помилки = файл новіший за встановлений (залежності - з комплекту)
                    rpm -U --test --nodeps "$f" >/dev/null 2>&1 && upd+=("$f")
                else
                    list+=("$f")
                fi
            done
            list+=(${upd[@]+"${upd[@]}"})
            [ ${#list[@]} -eq 0 ] && return 0
            # одна транзакція: rpm сам впорядковує залежності
            rpm -Uvh "${list[@]}" >> /tmp/seclogging-offline.log 2>&1 ;;
        *) return 1 ;;
    esac
}

do_install() {
    local main args=(${PASS[@]+"${PASS[@]}"}) check=0 a
    for a in ${PASS[@]+"${PASS[@]}"}; do [ "$a" = "--check" ] && check=1; [ "$a" = "--configure-wazuh" ] && WAZUH=0; done
    [ "$WAZUH" -eq 1 ] && args+=(--configure-wazuh)
    local stamp snapdir before after changes
    stamp=$(date +%Y%m%d-%H%M%S); snapdir=/var/log/seclogging/changes
    before="$snapdir/$stamp-before.tsv"; after="$snapdir/$stamp-after.tsv"; changes="$snapdir/$stamp-changes.txt"
    if [ -n "$FROM" ]; then
        FROM=$(cd "$FROM" 2>/dev/null && pwd) || die "теку комплекту не знайдено"
        info "Перевірка комплекту $FROM"
        [ -f "$FROM/SHA256SUMS" ] || die "у комплекті немає SHA256SUMS"
        (cd "$FROM" && sha256sum -c --quiet --strict SHA256SUMS) || die "перевірка SHA256SUMS не пройдена - комплект пошкоджено або змінено"
        echo "    SHA256SUMS: OK"
        local b_id b_ver b_arch
        b_id=$(awk -F= '$1=="OS_ID"{print $2}' "$FROM/bundle.info" 2>/dev/null)
        b_ver=$(awk -F= '$1=="OS_VERSION_ID"{print $2}' "$FROM/bundle.info" 2>/dev/null)
        b_arch=$(awk -F= '$1=="ARCH"{print $2}' "$FROM/bundle.info" 2>/dev/null)
        if [ "$b_id/$b_ver/$b_arch" != "$HOST_ID/$HOST_VER/$HOST_ARCH" ]; then
            echo "    УВАГА: комплект зібрано для $b_id $b_ver $b_arch, а цей хост $HOST_ID $HOST_VER $HOST_ARCH - пакети можуть не встановитися"
        fi
        main="$FROM/set-security-logging.sh"
        info "Знімок стану \"до\""
        bash "$main" --snapshot "$before" >/dev/null || echo "    не вдалося"
        if ! have auditctl && [ -d "$FROM/auditd" ]; then
            info "Офлайн-встановлення auditd з комплекту"
            if install_offline_pkgs "$FROM/auditd"; then echo "    встановлено"
            else echo "    не вдалося (див. /tmp/seclogging-offline.log); set-security-logging.sh спробує через менеджер пакетів"; fi
        fi
    else
        main=$(get_main_script) || die "не вдалося отримати set-security-logging.sh (перевірте інтернет або використайте --from)"
        info "Знімок стану \"до\""
        bash "$main" --snapshot "$before" >/dev/null || echo "    не вдалося"
    fi
    info "Запуск $main ${args[*]:-}"
    local rc=0
    bash "$main" ${args[@]+"${args[@]}"} || rc=$?
    if [ "$check" -eq 0 ] && [ -f "$before" ]; then
        info "Знімок стану \"після\" і порівняння"
        if bash "$main" --snapshot "$after" >/dev/null; then
            bash "$main" --compare "$before" "$after" --compare-out "$changes"
        fi
    fi
    echo
    if [ "$rc" -eq 0 ]; then
        if [ "$check" -eq 1 ]; then echo "ГОТОВО: перевірку виконано, нічого не змінено."; else echo "ГОТОВО: журналювання безпеки налаштовано."; fi
    else
        echo "ЗАВЕРШЕНО З ПОМИЛКАМИ (код $rc). Надішліть файли звіту адміністратору."
    fi
    echo "Звіт:          /var/log/seclogging/last-report.json"
    [ -f "$changes" ] && echo "Що змінилося:  $changes"
    [ "$check" -eq 1 ] && [ -f "$before" ] && echo "Стан:          $before"
    return "$rc"
}

case "$CMD" in
    build) do_build ;;
    install) do_install; exit $? ;;
esac
