#!/bin/bash
# restore-rule.sh <rule_id> — removes a previously added SecRuleRemoveById
# exclusion, re-enabling that rule.
set -euo pipefail

LOG="/var/log/waf-admin/remove-rule.log"
RULE_ID="${1:-}"
EXCLUSIONS_FILE="/usr/local/modsecurity-crs/rules/custom/rule-exclusions.conf"

log() { echo "[$(date -Iseconds)] $1" >> "$LOG"; }

if ! [[ "$RULE_ID" =~ ^[0-9]+$ ]]; then
    echo "ERROR: rule id must be numeric, got: '$RULE_ID'"
    log "REJECTED invalid rule id '$RULE_ID' (restore)"
    exit 1
fi

if [[ ! -f "$EXCLUSIONS_FILE" ]] || ! grep -qE "SecRuleRemoveById[[:space:]]+$RULE_ID(\s|$)" "$EXCLUSIONS_FILE"; then
    echo "NOT_EXCLUDED: $RULE_ID"
    log "no-op, $RULE_ID was not excluded"
    exit 0
fi

cp "$EXCLUSIONS_FILE" "$EXCLUSIONS_FILE.bak"
grep -vE "SecRuleRemoveById[[:space:]]+$RULE_ID(\s|$)" "$EXCLUSIONS_FILE.bak" > "$EXCLUSIONS_FILE"

if command -v nginx >/dev/null && ! NGINX_MSG=$(nginx -t 2>&1); then
    mv "$EXCLUSIONS_FILE.bak" "$EXCLUSIONS_FILE"
    echo "ROLLED_BACK: removing exclusion for $RULE_ID broke config"
    echo "$NGINX_MSG"
    log "FAILED to restore $RULE_ID, rolled back. nginx -t output: $NGINX_MSG"
    exit 1
fi
rm -f "$EXCLUSIONS_FILE.bak"
chmod 644 "$EXCLUSIONS_FILE"

systemctl reload nginx

echo "RESTORED: $RULE_ID"
log "SUCCESS restored rule $RULE_ID"
exit 0
