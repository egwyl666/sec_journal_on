#!/bin/sh
# Налаштування пакетного менеджера контейнера на HTTPS через проксі + CA (/ca.crt)
set +e

if command -v apt-get >/dev/null; then
  echo "Acquire::https::CAInfo \"/ca.crt\"; Acquire::https::Proxy \"${https_proxy:-}\"; Acquire::http::Proxy \"false\";" > /etc/apt/apt.conf.d/99proxy
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*; do [ -f "$f" ] && sed -i -E 's#http://(archive|security|ports)\.ubuntu\.com#https://\1.ubuntu.com#g; s#http://deb\.debian\.org#https://deb.debian.org#g' "$f"; done
  apt-get update -qq 2>&1 | tail -2
elif command -v apk >/dev/null; then
  cat /ca.crt >> /etc/ssl/certs/ca-certificates.crt; sed -i 's#http://#https://#' /etc/apk/repositories; apk update -q 2>&1 | tail -1
elif command -v pacman >/dev/null; then
  trust anchor /ca.crt 2>/dev/null || cat /ca.crt >> /etc/ssl/certs/ca-certificates.crt; pacman -Sy --noconfirm >/dev/null 2>&1; echo pacman $?
elif command -v zypper >/dev/null; then
  cp /ca.crt /etc/pki/trust/anchors/ && update-ca-certificates >/dev/null 2>&1; sed -i 's#http://#https://#' /etc/zypp/repos.d/*.repo; zypper -n --gpg-auto-import-keys ref >/dev/null 2>&1; echo zypper $?
else
  cp /ca.crt /etc/pki/ca-trust/source/anchors/ 2>/dev/null && update-ca-trust 2>/dev/null
  for f in /etc/yum.repos.d/*.repo; do sed -i 's#http://#https://#' "$f"; done
  if command -v dnf >/dev/null; then echo "proxy=${https_proxy:-}" >> /etc/dnf/dnf.conf; dnf -q makecache >/dev/null 2>&1; echo dnf $?
  else echo "proxy=${https_proxy:-}" >> /etc/yum.conf; yum -q makecache >/dev/null 2>&1; echo yum $?; fi
fi
