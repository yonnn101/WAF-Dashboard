#!/bin/bash
# remove-rule.sh <rule_id> — appends a SecRuleRemoveById exclusion so the
# rule stops firing without touching CRS's own files. Idempotent.
set -euo pipefail

LOG="/var/log/waf-admin/remove-rule.log"
RULE_ID="${1:-}"
EXCLUSIONS_FILE="/usr/local/modsecurity-crs/rules/custom/rule-exclusions.conf"

log() { echo "[$(date -Iseconds)] $1" >> "$LOG"; }

if ! [[ "$RULE_ID" =~ ^[0-9]+$ ]]; then
    echo "ERROR: rule id must be numeric, got: '$RULE_ID'"
    log "REJECTED invalid rule id '$RULE_ID'"
    exit 1
fi

mkdir -p "$(dirname "$EXCLUSIONS_FILE")"
chmod 755 "$(dirname "$EXCLUSIONS_FILE")"
touch "$EXCLUSIONS_FILE"
chmod 644 "$EXCLUSIONS_FILE"

if grep -qE "SecRuleRemoveById[[:space:]]+$RULE_ID(\s|$)" "$EXCLUSIONS_FILE"; then
    echo "ALREADY_EXCLUDED: $RULE_ID"
    log "no-op, $RULE_ID already excluded"
    exit 0
fi

cp "$EXCLUSIONS_FILE" "$EXCLUSIONS_FILE.bak"
echo "SecRuleRemoveById $RULE_ID" >> "$EXCLUSIONS_FILE"

if command -v nginx >/dev/null && ! NGINX_MSG=$(nginx -t 2>&1); then
    mv "$EXCLUSIONS_FILE.bak" "$EXCLUSIONS_FILE"
    echo "ROLLED_BACK: adding exclusion for $RULE_ID broke config"
    echo "$NGINX_MSG"
    log "FAILED to exclude $RULE_ID, rolled back. nginx -t output: $NGINX_MSG"
    exit 1
fi
rm -f "$EXCLUSIONS_FILE.bak"

systemctl reload nginx

echo "EXCLUDED: $RULE_ID"
log "SUCCESS excluded rule $RULE_ID"
exit 0
