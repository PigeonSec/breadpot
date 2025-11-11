package server

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strings"

	"breadcrumb-pot/pkg/parser"
)

// handleInteractiveRequest processes requests with payload capture
func (s *HTTPServer) handleInteractiveRequest(endpoint parser.VulnerableEndpoint, w http.ResponseWriter, r *http.Request) {
	clientIP := s.getClientIP(r)

	// Read body
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(body)) // Reset for later use

	// Detect attack patterns and capture payloads
	s.detectAndCapture(endpoint, r, body, clientIP)

	// Check for file uploads
	if r.Method == "POST" && strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
		s.handleFileUpload(endpoint, r, clientIP)
	}

	// Check for command injection attempts
	s.detectCommandInjection(endpoint, r, string(body), clientIP)

	// Check for SQL injection
	s.detectSQLInjection(endpoint, r, string(body), clientIP)

	// Check for webshell uploads
	s.detectWebshellUpload(endpoint, body, clientIP)

	// Check for code execution attempts (Log4j, JNDI, etc.)
	s.detectCodeExecution(endpoint, r, string(body), clientIP)
}

// detectAndCapture detects various attack patterns
func (s *HTTPServer) detectAndCapture(endpoint parser.VulnerableEndpoint, r *http.Request, body []byte, clientIP string) {
	metadata := map[string]interface{}{
		"method":      r.Method,
		"path":        r.URL.Path,
		"query":       r.URL.RawQuery,
		"user_agent":  r.UserAgent(),
		"content_type": r.Header.Get("Content-Type"),
	}

	// Check for serialization attacks
	if s.detectSerialization(string(body)) {
		s.capture.CapturePayload(clientIP, endpoint.TemplateID, endpoint.CVE, "serialization", body, metadata)
	}

	// Check for XML/XXE attacks
	if strings.Contains(string(body), "<!ENTITY") || strings.Contains(string(body), "<!DOCTYPE") {
		s.capture.CapturePayload(clientIP, endpoint.TemplateID, endpoint.CVE, "xxe", body, metadata)
	}

	// Check for template injection
	if s.detectTemplateInjection(string(body)) {
		s.capture.CapturePayload(clientIP, endpoint.TemplateID, endpoint.CVE, "template_injection", body, metadata)
	}
}

// handleFileUpload handles multipart file uploads
func (s *HTTPServer) handleFileUpload(endpoint parser.VulnerableEndpoint, r *http.Request, clientIP string) {
	// Parse multipart form (limit to 32MB)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return
	}

	for _, fileHeaders := range r.MultipartForm.File {
		for _, fileHeader := range fileHeaders {
			file, err := fileHeader.Open()
			if err != nil {
				continue
			}
			defer file.Close()

			// Read file content
			data, err := io.ReadAll(file)
			if err != nil {
				continue
			}

			metadata := map[string]interface{}{
				"filename":     fileHeader.Filename,
				"size":         fileHeader.Size,
				"content_type": fileHeader.Header.Get("Content-Type"),
				"path":         r.URL.Path,
			}

			// Capture file
			s.capture.CaptureFile(clientIP, endpoint.TemplateID, endpoint.CVE, fileHeader.Filename, data, metadata)
		}
	}
}

// detectCommandInjection detects command injection attempts
func (s *HTTPServer) detectCommandInjection(endpoint parser.VulnerableEndpoint, r *http.Request, body, clientIP string) {
	commandPatterns := []string{
		// Shell commands
		`\|[\s]*\w+`,           // | command
		`&&[\s]*\w+`,           // && command
		`;[\s]*\w+`,            // ; command
		`\$\(.*?\)`,            // $(command)
		"`.*?`",                 // `command`

		// Common commands
		`\b(whoami|id|uname|cat|ls|dir|pwd|echo|wget|curl|nc|bash|sh|cmd|powershell)\b`,
	}

	// Check query params
	fullInput := r.URL.Query().Encode() + " " + body

	for _, pattern := range commandPatterns {
		if matched, _ := regexp.MatchString(pattern, fullInput); matched {
			// Extract the command
			re := regexp.MustCompile(pattern)
			matches := re.FindAllString(fullInput, -1)

			for _, match := range matches {
				metadata := map[string]interface{}{
					"method":     r.Method,
					"path":       r.URL.Path,
					"pattern":    pattern,
					"full_input": fullInput,
				}
				s.capture.CaptureCommand(clientIP, endpoint.TemplateID, endpoint.CVE, match, metadata)
			}
			break
		}
	}
}

// detectSQLInjection detects SQL injection attempts
func (s *HTTPServer) detectSQLInjection(endpoint parser.VulnerableEndpoint, r *http.Request, body, clientIP string) {
	sqlPatterns := []string{
		`(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)`,
		`(?i)(or|and)[\s]*[\d\w]+[\s]*(=|<|>)[\s]*[\d\w]+`,
		`(?i)['"][\s]*(or|and)[\s]*['"]?[\d\w]`,
		`(?i)(sleep|benchmark|waitfor)[\s]*\(`,
		`--[\s]*$`,
		`/\*.*?\*/`,
	}

	fullInput := r.URL.Query().Encode() + " " + body

	for _, pattern := range sqlPatterns {
		if matched, _ := regexp.MatchString(pattern, fullInput); matched {
			metadata := map[string]interface{}{
				"method": r.Method,
				"path":   r.URL.Path,
				"pattern": pattern,
			}
			s.capture.CaptureSQLInjection(clientIP, endpoint.TemplateID, endpoint.CVE, fullInput, metadata)
			break
		}
	}
}

// detectWebshellUpload detects webshell in uploaded content
func (s *HTTPServer) detectWebshellUpload(endpoint parser.VulnerableEndpoint, body []byte, clientIP string) {
	content := string(body)

	webshellIndicators := []string{
		"<?php",
		"eval(",
		"exec(",
		"system(",
		"passthru(",
		"shell_exec(",
		"base64_decode",
		"$_POST",
		"$_GET",
		"$_REQUEST",
	}

	indicatorCount := 0
	for _, indicator := range webshellIndicators {
		if strings.Contains(content, indicator) {
			indicatorCount++
		}
	}

	// If multiple indicators present, likely a webshell
	if indicatorCount >= 3 {
		metadata := map[string]interface{}{
			"indicators": indicatorCount,
			"size":       len(body),
		}
		s.capture.CaptureWebshell(clientIP, endpoint.TemplateID, endpoint.CVE, "uploaded", body, metadata)
	}
}

// detectCodeExecution detects code execution attempts (Log4j, JNDI, etc.)
func (s *HTTPServer) detectCodeExecution(endpoint parser.VulnerableEndpoint, r *http.Request, body, clientIP string) {
	codeExecPatterns := []string{
		// Log4Shell
		`\$\{jndi:`,
		`\$\{ldap:`,
		`\$\{rmi:`,
		`\$\{dns:`,

		// Template injection
		`\{\{.*?\}\}`,
		`\$\{.*?\}`,
		`<%.*?%>`,

		// Expression language
		`#\{.*?\}`,
		`@\{.*?\}`,
	}

	// Check all headers and body
	fullInput := body + " "
	for key, values := range r.Header {
		fullInput += key + ": " + strings.Join(values, " ") + " "
	}

	for _, pattern := range codeExecPatterns {
		if matched, _ := regexp.MatchString(pattern, fullInput); matched {
			re := regexp.MustCompile(pattern)
			matches := re.FindAllString(fullInput, -1)

			for _, match := range matches {
				metadata := map[string]interface{}{
					"method":     r.Method,
					"path":       r.URL.Path,
					"pattern":    pattern,
					"headers":    r.Header,
				}
				s.capture.CapturePayload(clientIP, endpoint.TemplateID, endpoint.CVE, "code_execution", []byte(match), metadata)
			}
			break
		}
	}
}

// detectSerialization detects serialized payloads
func (s *HTTPServer) detectSerialization(content string) bool {
	serializationIndicators := []string{
		"rO0",              // Java serialization (base64)
		"aced",             // Java serialization (hex)
		"O:",               // PHP serialization
		"__reduce__",       // Python pickle
		"ObjectInputStream",
	}

	for _, indicator := range serializationIndicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}
	return false
}

// detectTemplateInjection detects template injection attempts
func (s *HTTPServer) detectTemplateInjection(content string) bool {
	templatePatterns := []string{
		`\{\{.*?\}\}`,
		`\{\%.*?\%\}`,
		`\$\{.*?\}`,
		`#\{.*?\}`,
		`<%.*?%>`,
	}

	for _, pattern := range templatePatterns {
		if matched, _ := regexp.MatchString(pattern, content); matched {
			return true
		}
	}
	return false
}

// generateInteractiveResponse generates realistic interactive responses
func (s *HTTPServer) generateInteractiveResponse(endpoint parser.VulnerableEndpoint, r *http.Request) (int, map[string]string, string) {
	// For command injection, return command output
	if s.containsCommand(r.URL.Query().Encode()) {
		return 200, map[string]string{"Content-Type": "text/plain"}, s.simulateCommandOutput(r)
	}

	// For file upload, return success
	if r.Method == "POST" && strings.Contains(r.Header.Get("Content-Type"), "multipart") {
		return 200, map[string]string{"Content-Type": "application/json"}, `{"status":"success","message":"File uploaded successfully"}`
	}

	// For SQL injection, return fake DB data
	if s.containsSQLKeywords(r.URL.Query().Encode()) {
		return 200, map[string]string{"Content-Type": "text/html"}, s.simulateSQLOutput()
	}

	// Default response from generator
	resp := s.generator.GenerateHTTPResponse(endpoint)
	return resp.StatusCode, resp.Headers, resp.Body
}

// containsCommand checks if input contains command patterns
func (s *HTTPServer) containsCommand(input string) bool {
	patterns := []string{`whoami`, `id`, `uname`, `cat`, `ls`, `pwd`}
	for _, pattern := range patterns {
		if strings.Contains(input, pattern) {
			return true
		}
	}
	return false
}

// containsSQLKeywords checks for SQL keywords
func (s *HTTPServer) containsSQLKeywords(input string) bool {
	keywords := []string{"union", "select", "from", "where"}
	lowerInput := strings.ToLower(input)
	for _, keyword := range keywords {
		if strings.Contains(lowerInput, keyword) {
			return true
		}
	}
	return false
}

// simulateCommandOutput simulates command execution output
func (s *HTTPServer) simulateCommandOutput(r *http.Request) string {
	query := r.URL.Query().Encode()

	if strings.Contains(query, "whoami") {
		return "www-data\n"
	}
	if strings.Contains(query, "id") {
		return "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
	}
	if strings.Contains(query, "uname") {
		return "Linux webserver 4.15.0-112-generic #113-Ubuntu SMP x86_64 GNU/Linux\n"
	}
	if strings.Contains(query, "pwd") {
		return "/var/www/html\n"
	}
	if strings.Contains(query, "ls") {
		return "index.php\nconfig.php\nuploads\nimages\ncss\njs\n"
	}
	if strings.Contains(query, "cat") {
		return "<?php\n$db_host = 'localhost';\n$db_user = 'root';\n$db_pass = 'password123';\n?>\n"
	}

	return "Command executed successfully\n"
}

// simulateSQLOutput simulates SQL query results
func (s *HTTPServer) simulateSQLOutput() string {
	return `<table>
<tr><th>ID</th><th>Username</th><th>Email</th><th>Password</th></tr>
<tr><td>1</td><td>admin</td><td>admin@example.com</td><td>5f4dcc3b5aa765d61d8327deb882cf99</td></tr>
<tr><td>2</td><td>user</td><td>user@example.com</td><td>ee11cbb19052e40b07aac0ca060c23ee</td></tr>
<tr><td>3</td><td>test</td><td>test@example.com</td><td>098f6bcd4621d373cade4e832627b4f6</td></tr>
</table>`
}
