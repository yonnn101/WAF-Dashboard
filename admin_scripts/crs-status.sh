#!/bin/bash
# crs-status.sh — read-only. Reports the currently installed CRS tag and
# the latest tag available upstream, without changing anything.
set -euo pipefail

CRS_DIR="/usr/local/modsecurity-crs/"

if [[ ! -d "$CRS_DIR/.git" ]]; then
    echo "ERROR: $CRS_DIR is not a git repository"
    exit 1
fi

cd "$CRS_DIR"
CURRENT_TAG=$(git describe --tags HEAD 2>/dev/null || echo "unknown")
git fetch --tags --quiet
LATEST_TAG=$(git tag -l 'v*' | sort -V | tail -n1)

echo "current=${CURRENT_TAG}"
echo "latest=${LATEST_TAG}"
if [[ "$CURRENT_TAG" == "$LATEST_TAG" ]]; then
    echo "up_to_date=true"
else
    echo "up_to_date=false"
fi
exit 0
