#!/bin/sh
# Keep tagged images and all container references, including stopped services.
# A grace period preserves recent builds for recovery and avoids active builds.
set -eu
docker image prune --force --filter until=24h
docker builder prune --force --filter until=168h --keep-storage 512MB
