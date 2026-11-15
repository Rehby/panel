#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null || ! command -v curl >/dev/null; then
    echo "Для установки необходимы python3 и curl." >&2
    exit 1
fi

bootstrap=$(mktemp "${TMPDIR:-/tmp}/yptun-bootstrap.XXXXXXXX")
trap 'rm -f -- "$bootstrap"' EXIT
curl -fsSL --connect-timeout 15 --max-time 180 \
    https://raw.githubusercontent.com/Rehby/panel/main/deploy/bootstrap.py -o "$bootstrap"
python3 "$bootstrap"
