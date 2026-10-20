#!/bin/bash
# update-crs.sh — pulls the latest tagged OWASP CRS release, tests config,
# reloads on success, auto-rolls-back on failure. No arguments.
set -euo pipefail

CRS_DIR="/usr/local/modsecurity-crs/"
LOG="/var/log/waf-admin/update-crs.log"

log() { echo "[$(date -Iseconds)] $1" >> "$LOG"; }

if [[ ! -d "$CRS_DIR/.git" ]]; then
    echo "ERROR: $CRS_DIR is not a git repository"
    log "FAILED: $CRS_DIR is not a git repo"
    exit 1
fi

cd "$CRS_DIR"

CURRENT_REF=$(git rev-parse HEAD)
CURRENT_TAG=$(git describe --tags "$CURRENT_REF" 2>/dev/null || echo "unknown")

git fetch --tags --quiet

LATEST_TAG=$(git tag -l 'v*' | sort -V | tail -n1)

if [[ -z "$LATEST_TAG" ]]; then
    echo "ERROR: no version tags found after fetch"
    log "FAILED: no tags found"
    exit 1
fi

if [[ "$CURRENT_TAG" == "$LATEST_TAG" ]]; then
    echo "ALREADY_UP_TO_DATE: $CURRENT_TAG"
    log "no-op, already on $CURRENT_TAG"
    exit 0
fi

git checkout --quiet "$LATEST_TAG"

# test config on whichever web server(s) are using this CRS
CONFIG_OK=true
TEST_MSG=""
RELOAD_CMD=""
if command -v nginx >/dev/null; then
    if ! TEST_MSG=$(nginx -t 2>&1); then
        CONFIG_OK=false
    else
        RELOAD_CMD="systemctl reload nginx"
    fi
elif command -v apache2ctl >/dev/null; then
    if ! TEST_MSG=$(apache2ctl configtest 2>&1); then
        CONFIG_OK=false
    else
        RELOAD_CMD="systemctl reload apache2"
    fi
fi

if [[ "$CONFIG_OK" == false ]]; then
    git checkout --quiet "$CURRENT_REF"
    echo "ROLLED_BACK: $LATEST_TAG failed config test, reverted to $CURRENT_TAG"
    echo "$TEST_MSG"
    log "FAILED update to $LATEST_TAG, rolled back to $CURRENT_TAG. output: $TEST_MSG"
    exit 1
fi

if [[ -n "$RELOAD_CMD" ]]; then
    $RELOAD_CMD
fi

echo "UPDATED: $CURRENT_TAG -> $LATEST_TAG"
log "SUCCESS updated $CURRENT_TAG -> $LATEST_TAG"
exit 0
