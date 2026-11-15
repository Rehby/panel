#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" != 0 ]; then
    echo "Запустите установщик от root: curl ... | sudo bash" >&2
    exit 1
fi
if [ "$(uname -s)" != Linux ] || ! command -v systemctl >/dev/null || ! systemctl show --property=Version --value >/dev/null 2>&1; then
    echo "Для установки нужен Linux с работающим systemd." >&2
    exit 1
fi

PATH="$PATH:/usr/sbin:/sbin"
export PATH
packages=()
add_package() {
    local package=$1 item
    for item in "${packages[@]+"${packages[@]}"}"; do
        [ "$item" = "$package" ] && return
    done
    packages+=("$package")
}
need_command() {
    command -v "$1" >/dev/null || add_package "$2"
}
if ! command -v python3 >/dev/null || ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))'; then
    add_package python3
fi
need_command curl curl
need_command docker docker.io
need_command nginx nginx
need_command certbot certbot
need_command sudo sudo
need_command visudo sudo
need_command useradd passwd
need_command usermod passwd
need_command runuser util-linux
need_command openssl openssl
need_command git git
need_command ip iproute2
need_command sha256sum coreutils
need_command update-ca-certificates ca-certificates

if [ "${packages[0]+set}" ]; then
    if ! command -v apt-get >/dev/null; then
        echo "Автоматическая установка зависимостей поддерживается через apt. Установите вручную: ${packages[*]}" >&2
        exit 1
    fi
    echo "Установка недостающих пакетов: ${packages[*]}"
    apt-get update </dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}" </dev/null
fi
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))'; then
    echo "Требуется Python 3.9 или новее." >&2
    exit 1
fi
for command in curl docker nginx certbot sudo visudo useradd usermod runuser openssl git ip sha256sum update-ca-certificates; do
    if ! command -v "$command" >/dev/null; then
        echo "Не найдена зависимость после установки: $command" >&2
        exit 1
    fi
done

if ! HOME=/nonexistent DOCKER_CONFIG=/nonexistent docker compose version >/dev/null 2>&1; then
    case "$(uname -m)" in
        x86_64) arch=x86_64; checksum=7af95166a730b87e172d4fc9aefea8725d3c6c7327d59149267b452114ddb7d4 ;;
        aarch64|arm64) arch=aarch64; checksum=49082844b87f03cdcd5f5bbef1ba8c9c897b7a2dfb80cea18d61ec8ca6117e0c ;;
        *) echo "Установите Docker Compose v2 вручную для этой архитектуры." >&2; exit 1 ;;
    esac
    plugin=/usr/local/lib/docker/cli-plugins/docker-compose
    if [ -e "$plugin" ] || [ -L "$plugin" ]; then
        echo "Существующий плагин Compose не работает: $plugin. Исправьте его вручную." >&2
        exit 1
    fi
    download=$(mktemp "${TMPDIR:-/tmp}/yptun-compose.XXXXXXXX")
    trap 'rm -f -- "$download"' EXIT
    curl -fsSL --connect-timeout 15 --max-time 180 \
        "https://github.com/docker/compose/releases/download/v2.39.4/docker-compose-linux-$arch" -o "$download"
    printf '%s  %s\n' "$checksum" "$download" | sha256sum -c -
    install -d -m 755 /usr/local/lib/docker/cli-plugins
    install -m 755 "$download" "$plugin"
    rm -f -- "$download"
    trap - EXIT
    HOME=/nonexistent DOCKER_CONFIG=/nonexistent docker compose version >/dev/null
fi

if ! nginx -V 2>&1 | grep -q -- '--with-http_v2_module'; then
    echo "Нужен nginx с модулем HTTP/2." >&2
    exit 1
fi
for unit in docker.service nginx.service certbot.timer; do
    if ! systemctl cat "$unit" >/dev/null 2>&1; then
        echo "Не найдена служба systemd: $unit" >&2
        exit 1
    fi
done

bootstrap=$(mktemp "${TMPDIR:-/tmp}/yptun-bootstrap.XXXXXXXX")
trap 'rm -f -- "$bootstrap"' EXIT
curl -fsSL --connect-timeout 15 --max-time 180 \
    https://raw.githubusercontent.com/Rehby/panel/main/deploy/bootstrap.py -o "$bootstrap"
python3 "$bootstrap"
