#!/bin/bash
# add-custom-rule.sh <keyword> — generates and appends a ModSecurity rule
# blocking any request containing the given keyword, using an ID range
# reserved for dashboard-added rules (100001+) so it never collides with
# CRS's own IDs (900000s).
set -euo pipefail

LOG="/var/log/waf-admin/add-custom-rule.log"
KEYWORD="${1:-}"
RULES_FILE="/usr/local/modsecurity-crs/rules/custom/local-rules.conf"
COUNTER_FILE="/usr/local/modsecurity-crs/rules/custom/next_rule_id"
START_ID=100001

log() { echo "[$(date -Iseconds)] $1" >> "$LOG"; }

if [[ -z "$KEYWORD" ]]; then
    echo "ERROR: keyword cannot be empty"
    exit 1
fi

if ! [[ "$KEYWORD" =~ ^[A-Za-z0-9_.-]{1,100}$ ]]; then
    echo "ERROR: keyword contains disallowed characters. Only letters, numbers, '_', '-', '.' are permitted."
    log "REJECTED invalid keyword '$KEYWORD'"
    exit 1
fi

mkdir -p "$(dirname "$RULES_FILE")"
chmod 755 "$(dirname "$RULES_FILE")"
touch "$RULES_FILE"
chmod 644 "$RULES_FILE"

if [[ ! -f "$COUNTER_FILE" ]]; then
    echo "$START_ID" > "$COUNTER_FILE"
fi

NEW_ID=$(cat "$COUNTER_FILE")
if ! [[ "$NEW_ID" =~ ^[0-9]+$ ]]; then
    NEW_ID=$START_ID
fi

# refuse to add a duplicate rule for the same keyword
if grep -qF "Custom rule blocked keyword: $KEYWORD'" "$RULES_FILE" 2>/dev/null; then
    echo "ALREADY_EXISTS: a rule for '$KEYWORD' is already present"
    log "no-op, keyword '$KEYWORD' already has a rule"
    exit 0
fi

cp "$RULES_FILE" "$RULES_FILE.bak"

cat >> "$RULES_FILE" << EOF
SecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_BODY|REQUEST_HEADERS "@contains ${KEYWORD}" \\
    "id:${NEW_ID},phase:2,t:lowercase,deny,status:403,log,msg:'Custom rule blocked keyword: ${KEYWORD}'"
EOF

if command -v nginx >/dev/null; then
    if ! NGINX_MSG=$(nginx -t 2>&1); then
        mv "$RULES_FILE.bak" "$RULES_FILE"
        echo "ROLLED_BACK: new rule for '$KEYWORD' broke config"
        echo "$NGINX_MSG"
        log "FAILED to add rule for '$KEYWORD' (id $NEW_ID), rolled back. nginx -t output: $NGINX_MSG"
        exit 1
    fi
    systemctl reload nginx
elif command -v apache2ctl >/dev/null; then
    if ! APACHE_MSG=$(apache2ctl configtest 2>&1); then
        mv "$RULES_FILE.bak" "$RULES_FILE"
        echo "ROLLED_BACK: new rule for '$KEYWORD' broke config"
        echo "$APACHE_MSG"
        log "FAILED to add rule for '$KEYWORD' (id $NEW_ID), rolled back. apache2ctl output: $APACHE_MSG"
        exit 1
    fi
    systemctl reload apache2
fi
rm -f "$RULES_FILE.bak"
chmod 644 "$RULES_FILE"

echo $((NEW_ID + 1)) > "$COUNTER_FILE"

echo "ADDED: id=${NEW_ID} keyword=${KEYWORD}"
log "SUCCESS added rule id=$NEW_ID for keyword '$KEYWORD'"
exit 0
