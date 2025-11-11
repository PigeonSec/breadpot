package response

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"breadcrumb-pot/pkg/parser"
	"breadcrumb-pot/pkg/types"
)

// Generator creates vulnerable responses based on templates
type Generator struct {
	interactionLevel string
	delays           types.DelayConfig
	customResponses  map[string]string
	rand             *rand.Rand
}

// NewGenerator creates a new response generator
func NewGenerator(config *types.ResponseConfig) *Generator {
	return &Generator{
		interactionLevel: config.Interaction,
		delays:           config.Delays,
		customResponses:  config.Custom,
		rand:             rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// HTTPResponse represents an HTTP response
type HTTPResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       string
	Delay      time.Duration
}

// GenerateHTTPResponse generates an HTTP response for a vulnerable endpoint
func (g *Generator) GenerateHTTPResponse(endpoint parser.VulnerableEndpoint) HTTPResponse {
	// Check for custom response
	if custom, ok := g.customResponses[endpoint.TemplateID]; ok {
		return HTTPResponse{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html"},
			Body:       custom,
			Delay:      g.calculateDelay(),
		}
	}

	// Generate response based on interaction level
	switch g.interactionLevel {
	case "high":
		return g.generateHighInteractionHTTP(endpoint)
	case "medium":
		return g.generateMediumInteractionHTTP(endpoint)
	default:
		return g.generateLowInteractionHTTP(endpoint)
	}
}

// generateHighInteractionHTTP creates realistic, stateful responses
func (g *Generator) generateHighInteractionHTTP(endpoint parser.VulnerableEndpoint) HTTPResponse {
	resp := HTTPResponse{
		StatusCode: 200,
		Headers:    make(map[string]string),
		Delay:      g.calculateDelay(),
	}

	// Analyze matchers to generate appropriate response
	for _, matcher := range endpoint.Matchers {
		switch matcher.Type {
		case "status":
			if len(matcher.Status) > 0 {
				resp.StatusCode = matcher.Status[0]
			}

		case "word":
			// Generate response containing expected words
			if len(matcher.Words) > 0 {
				resp.Body = g.buildResponseWithWords(matcher.Words, endpoint)
			}

		case "regex":
			// Generate response matching regex patterns
			if len(matcher.Regex) > 0 {
				resp.Body = g.buildResponseFromRegex(matcher.Regex, endpoint)
			}
		}
	}

	// Add realistic headers
	resp.Headers = g.generateRealisticHeaders(endpoint)

	// If no body was generated from matchers, create default vulnerable response
	if resp.Body == "" {
		resp.Body = g.generateDefaultVulnerableResponse(endpoint)
	}

	return resp
}

// generateMediumInteractionHTTP creates responses matching vulnerability signatures
func (g *Generator) generateMediumInteractionHTTP(endpoint parser.VulnerableEndpoint) HTTPResponse {
	resp := HTTPResponse{
		StatusCode: 200,
		Headers:    make(map[string]string),
		Delay:      g.calculateDelay(),
	}

	// Extract expected status code from matchers
	for _, matcher := range endpoint.Matchers {
		if matcher.Type == "status" && len(matcher.Status) > 0 {
			resp.StatusCode = matcher.Status[0]
		}
	}

	// Generate body with vulnerability indicators
	resp.Body = g.generateVulnerabilityIndicators(endpoint)
	resp.Headers = g.generateBasicHeaders(endpoint)

	return resp
}

// generateLowInteractionHTTP creates minimal responses
func (g *Generator) generateLowInteractionHTTP(endpoint parser.VulnerableEndpoint) HTTPResponse {
	return HTTPResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type": "text/html",
		},
		Body:  fmt.Sprintf("<html><body>%s</body></html>", endpoint.CVE),
		Delay: g.calculateDelay(),
	}
}

// buildResponseWithWords creates response containing expected words
func (g *Generator) buildResponseWithWords(words []string, endpoint parser.VulnerableEndpoint) string {
	var parts []string

	// Add HTML structure for web vulnerabilities
	if strings.Contains(endpoint.Path, "/") {
		parts = append(parts, "<html><head><title>Page</title></head><body>")
	}

	// Include each expected word in context
	for _, word := range words {
		// Try to make it look natural
		context := g.generateWordContext(word, endpoint)
		parts = append(parts, context)
	}

	if strings.Contains(endpoint.Path, "/") {
		parts = append(parts, "</body></html>")
	}

	return strings.Join(parts, "\n")
}

// generateWordContext creates natural-looking context around a word
func (g *Generator) generateWordContext(word string, endpoint parser.VulnerableEndpoint) string {
	contexts := []string{
		fmt.Sprintf("<div>%s</div>", word),
		fmt.Sprintf("<!-- %s -->", word),
		fmt.Sprintf("<meta name=\"generator\" content=\"%s\">", word),
		fmt.Sprintf("Server: %s", word),
		fmt.Sprintf("Version: %s", word),
		fmt.Sprintf("<input type=\"hidden\" name=\"%s\" value=\"%s\">", word, word),
	}

	return contexts[g.rand.Intn(len(contexts))]
}

// buildResponseFromRegex generates response matching regex patterns
func (g *Generator) buildResponseFromRegex(patterns []string, endpoint parser.VulnerableEndpoint) string {
	// For simplicity, generate common patterns
	// A full implementation would use regex-based generation libraries
	var parts []string

	for _, pattern := range patterns {
		generated := g.matchRegexPattern(pattern)
		if generated != "" {
			parts = append(parts, generated)
		}
	}

	if len(parts) == 0 {
		return g.generateDefaultVulnerableResponse(endpoint)
	}

	return strings.Join(parts, "\n")
}

// matchRegexPattern generates text matching common regex patterns
func (g *Generator) matchRegexPattern(pattern string) string {
	// Handle common patterns found in Nuclei templates
	switch {
	case strings.Contains(pattern, "version"):
		return "Version: 1.0.0"
	case strings.Contains(pattern, "admin"):
		return "<a href=\"/admin\">Admin Panel</a>"
	case strings.Contains(pattern, "error"):
		return "Error: Access denied"
	case strings.Contains(pattern, "root:"):
		return "root:x:0:0:root:/root:/bin/bash"
	case strings.Contains(pattern, "password"):
		return "<input type=\"password\" name=\"password\">"
	default:
		// Return pattern as literal for complex patterns
		return pattern
	}
}

// generateDefaultVulnerableResponse creates a default vulnerable response
func (g *Generator) generateDefaultVulnerableResponse(endpoint parser.VulnerableEndpoint) string {
	templates := map[string]string{
		// Path traversal
		"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",

		// Config files
		"/.env":         "DB_PASSWORD=secret123\nAPI_KEY=abc123xyz\n",
		"/config.php":   "<?php\n$dbpass = 'password123';\n$dbuser = 'root';\n?>",
		"/web.config":   "<?xml version=\"1.0\"?>\n<configuration>\n  <connectionStrings>\n    <add name=\"db\" connectionString=\"Server=localhost;Database=app;User=sa;Password=P@ssw0rd\"/>\n  </connectionStrings>\n</configuration>",

		// Admin panels
		"/admin":      "<html><head><title>Admin Panel</title></head><body><h1>Administration</h1><form><input name=\"username\"><input type=\"password\" name=\"password\"></form></body></html>",
		"/phpmyadmin": "<html><head><title>phpMyAdmin</title></head><body><h1>Welcome to phpMyAdmin</h1></body></html>",

		// Info disclosure
		"/phpinfo.php": "<html><body><h1>PHP Version 7.4.3</h1><table><tr><td>System</td><td>Linux server 4.15.0</td></tr></table></body></html>",

		// Default credentials
		"/api/v1/auth": `{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}`,
	}

	// Check for direct matches
	for pathPattern, response := range templates {
		if strings.Contains(endpoint.Path, pathPattern) {
			return response
		}
	}

	// Generate based on CVE or template info
	if endpoint.CVE != "" {
		return fmt.Sprintf(`<html>
<head><title>Vulnerable Service</title></head>
<body>
<h1>Service Information</h1>
<p>Version: 1.0.0 (Vulnerable to %s)</p>
<p>Status: Running</p>
<!-- %s -->
</body>
</html>`, endpoint.CVE, endpoint.Description)
	}

	// Generic vulnerable response
	return `<html>
<head><title>Application</title></head>
<body>
<h1>Welcome</h1>
<p>Server: Apache/2.4.29 (Ubuntu)</p>
<form action="/login" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="submit" value="Login">
</form>
</body>
</html>`
}

// generateVulnerabilityIndicators creates response with vulnerability markers
func (g *Generator) generateVulnerabilityIndicators(endpoint parser.VulnerableEndpoint) string {
	indicators := []string{
		fmt.Sprintf("<!-- Template: %s -->", endpoint.TemplateID),
	}

	if endpoint.CVE != "" {
		indicators = append(indicators, fmt.Sprintf("<!-- Vulnerable to: %s -->", endpoint.CVE))
	}

	// Add actual vulnerable content
	indicators = append(indicators, g.generateDefaultVulnerableResponse(endpoint))

	return strings.Join(indicators, "\n")
}

// generateRealisticHeaders creates realistic HTTP headers
func (g *Generator) generateRealisticHeaders(endpoint parser.VulnerableEndpoint) map[string]string {
	headers := map[string]string{
		"Content-Type": "text/html; charset=utf-8",
		"Connection":   "keep-alive",
		"Cache-Control": "no-cache",
	}

	// Add vulnerability-specific headers
	servers := []string{
		"Apache/2.4.29 (Ubuntu)",
		"nginx/1.14.0",
		"Microsoft-IIS/10.0",
		"Apache/2.4.41 (Unix)",
	}
	headers["Server"] = servers[g.rand.Intn(len(servers))]

	// Add powered-by headers for certain paths
	if strings.Contains(endpoint.Path, "php") {
		headers["X-Powered-By"] = "PHP/7.4.3"
	} else if strings.Contains(endpoint.Path, "asp") {
		headers["X-Powered-By"] = "ASP.NET"
	}

	return headers
}

// generateBasicHeaders creates basic HTTP headers
func (g *Generator) generateBasicHeaders(endpoint parser.VulnerableEndpoint) map[string]string {
	return map[string]string{
		"Content-Type": "text/html",
		"Server":       "Apache/2.4.29",
	}
}

// calculateDelay calculates response delay
func (g *Generator) calculateDelay() time.Duration {
	if !g.delays.Enabled {
		return 0
	}

	minDelay, _ := time.ParseDuration(g.delays.Min)
	maxDelay, _ := time.ParseDuration(g.delays.Max)

	if minDelay >= maxDelay {
		return minDelay
	}

	diff := maxDelay - minDelay
	delay := minDelay + time.Duration(g.rand.Int63n(int64(diff)))

	return delay
}

// DNSResponse represents a DNS response
type DNSResponse struct {
	Records []DNSRecord
	Delay   time.Duration
}

// DNSRecord represents a DNS record
type DNSRecord struct {
	Name  string
	Type  string
	Value string
	TTL   uint32
}

// GenerateDNSResponse generates a DNS response
func (g *Generator) GenerateDNSResponse(query parser.DNSQuery) DNSResponse {
	resp := DNSResponse{
		Delay: g.calculateDelay(),
	}

	// Generate records based on query type
	switch query.Type {
	case "A":
		resp.Records = append(resp.Records, DNSRecord{
			Name:  query.Name,
			Type:  "A",
			Value: "192.168.1.100",
			TTL:   300,
		})
	case "AAAA":
		resp.Records = append(resp.Records, DNSRecord{
			Name:  query.Name,
			Type:  "AAAA",
			Value: "::1",
			TTL:   300,
		})
	case "TXT":
		resp.Records = append(resp.Records, DNSRecord{
			Name:  query.Name,
			Type:  "TXT",
			Value: fmt.Sprintf("v=spf1 +all; %s", query.CVE),
			TTL:   300,
		})
	case "MX":
		resp.Records = append(resp.Records, DNSRecord{
			Name:  query.Name,
			Type:  "MX",
			Value: "10 mail.example.com",
			TTL:   300,
		})
	}

	return resp
}

// TCPResponse represents a TCP response
type TCPResponse struct {
	Data  []byte
	Delay time.Duration
}

// GenerateTCPResponse generates a TCP response
func (g *Generator) GenerateTCPResponse(service parser.TCPService, input []byte) TCPResponse {
	resp := TCPResponse{
		Delay: g.calculateDelay(),
	}

	// Generate response based on input patterns
	if len(service.Inputs) > 0 {
		// Use template's expected response
		for _, templateInput := range service.Inputs {
			if templateInput.Data != "" {
				resp.Data = []byte(templateInput.Data)
				break
			}
		}
	}

	// Generate common service banners if no specific response
	if len(resp.Data) == 0 {
		resp.Data = g.generateServiceBanner(service)
	}

	return resp
}

// generateServiceBanner generates common service banners
func (g *Generator) generateServiceBanner(service parser.TCPService) []byte {
	banners := map[string]string{
		"ssh":    "SSH-2.0-OpenSSH_7.4\r\n",
		"ftp":    "220 FTP Server ready\r\n",
		"smtp":   "220 mail.example.com ESMTP Postfix\r\n",
		"telnet": "Login: ",
		"http":   "HTTP/1.1 200 OK\r\nServer: Apache/2.4.29\r\n\r\n",
	}

	// Try to detect service type from CVE or description
	for serviceType, banner := range banners {
		if strings.Contains(strings.ToLower(service.Description), serviceType) {
			return []byte(banner)
		}
	}

	// Default banner
	return []byte("Service ready\r\n")
}
