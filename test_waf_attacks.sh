#!/bin/bash
# test_waf_attacks.sh — runs common cyberattack vectors against the local Apache WAF
# and displays whether ModSecurity blocked each attack (403 Forbidden).

TARGET="${1:-http://localhost}"

echo "========================================================"
echo "  🛡️  WAF ATTACK TEST SUITE (ModSecurity & Apache)"
echo "  Target: $TARGET"
echo "========================================================"
echo ""

run_test() {
    local name="$1"
    local method="$2"
    local url="$3"
    local data="${4:-}"
    local headers="${5:-}"

    printf "%-32s " "$name..."

    if [[ "$method" == "GET" ]]; then
        if [[ -n "$headers" ]]; then
            code=$(curl -s -o /dev/null -w "%{http_code}" -H "$headers" "$TARGET$url")
        else
            code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$url")
        fi
    elif [[ "$method" == "POST" ]]; then
        code=$(curl -s -o /dev/null -w "%{http_code}" -X POST -d "$data" "$TARGET$url")
    fi

    if [[ "$code" == "403" ]]; then
        echo -e "\033[1;32m[BLOCKED (HTTP 403)]\033[0m — Detected by WAF!"
    elif [[ "$code" == "200" ]]; then
        if [[ "$name" == *"Legitimate"* ]]; then
            echo -e "\033[1;34m[PASSED (HTTP 200)]\033[0m  — Benign traffic allowed"
        else
            echo -e "\033[1;31m[BYPASSED (HTTP 200)]\033[0m — Not blocked"
        fi
    else
        echo -e "\033[1;33m[STATUS $code]\033[0m"
    fi
}

# 1. Normal traffic
run_test "1. Legitimate Request" "GET" "/?search=shoes&cat=sport"

# 2. SQL Injection
run_test "2. SQL Injection (Auth Bypass)" "GET" "/?id=1'%20OR%20'1'='1"
run_test "3. SQL Injection (UNION SELECT)" "GET" "/?user=admin'%20UNION%20SELECT%20null,username,password%20FROM%20users--"

# 4. Path Traversal / LFI
run_test "4. Path Traversal (etc/passwd)" "GET" "/?file=../../../../etc/passwd"
run_test "5. Windows Traversal (win.ini)" "GET" "/?page=..\\..\\..\\windows\\win.ini"

# 6. Cross-Site Scripting (XSS)
run_test "6. Reflected XSS (<script>)" "GET" "/?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"
run_test "7. XSS (Image onerror)" "GET" "/?input=%3Cimg%20src=x%20onerror=alert(1)%3E"

# 8. Command Injection (RCE)
run_test "8. OS Command Injection (cat)" "POST" "/" "cmd=;cat%20/etc/passwd"
run_test "9. OS Command Injection (id)" "GET" "/?exec=|id"

# 10. Malicious Scanner User-Agent
run_test "10. Scanner Probe (Nikto)" "GET" "/" "" "User-Agent: Mozilla/5.0 (Nikto/2.1.6)"

echo ""
echo "========================================================"
echo "  ✅ Tests complete! Check your WAF Dashboard at:"
echo "     http://localhost:5000"
echo "  All 403 events are shipped in real-time to Supabase."
echo "========================================================"
