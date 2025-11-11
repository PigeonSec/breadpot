package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"breadcrumb-pot/pkg/logger"
)

// Capture handles payload and file capture
type Capture struct {
	baseDir string
	logger  *logger.Logger
}

// CapturedPayload represents a captured attack payload
type CapturedPayload struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        string                 `json:"type"` // "command", "file", "webshell", "sql", "code"
	Content     string                 `json:"content"`
	ContentHash string                 `json:"content_hash"`
	SourceIP    string                 `json:"source_ip"`
	TemplateID  string                 `json:"template_id"`
	CVE         string                 `json:"cve"`
	FilePath    string                 `json:"file_path,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewCapture creates a new capture handler
func NewCapture(baseDir string, log *logger.Logger) (*Capture, error) {
	// Create directory structure
	dirs := []string{
		filepath.Join(baseDir, "commands"),
		filepath.Join(baseDir, "files"),
		filepath.Join(baseDir, "webshells"),
		filepath.Join(baseDir, "payloads"),
		filepath.Join(baseDir, "sql"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create capture directory %s: %w", dir, err)
		}
	}

	return &Capture{
		baseDir: baseDir,
		logger:  log,
	}, nil
}

// CaptureCommand captures command execution attempts
func (c *Capture) CaptureCommand(sourceIP, templateID, cve, command string, metadata map[string]interface{}) (*CapturedPayload, error) {
	payload := &CapturedPayload{
		ID:          c.generateID(),
		Timestamp:   time.Now(),
		Type:        "command",
		Content:     command,
		ContentHash: c.hash(command),
		SourceIP:    sourceIP,
		TemplateID:  templateID,
		CVE:         cve,
		Metadata:    metadata,
	}

	// Save to file
	filename := fmt.Sprintf("%s_%s.txt", payload.Timestamp.Format("20060102_150405"), payload.ID)
	filepath := filepath.Join(c.baseDir, "commands", filename)

	content := fmt.Sprintf(`Captured Command
================
ID:          %s
Timestamp:   %s
Source IP:   %s
Template:    %s
CVE:         %s
Hash:        %s

Command:
%s

Metadata:
%v
`, payload.ID, payload.Timestamp, sourceIP, templateID, cve, payload.ContentHash, command, metadata)

	if err := os.WriteFile(filepath, []byte(content), 0644); err != nil {
		return nil, err
	}

	payload.FilePath = filepath
	c.logger.Info(fmt.Sprintf("Captured command from %s: %s (saved to %s)", sourceIP, command, filename))

	return payload, nil
}

// CaptureFile captures uploaded files
func (c *Capture) CaptureFile(sourceIP, templateID, cve, filename string, data []byte, metadata map[string]interface{}) (*CapturedPayload, error) {
	payload := &CapturedPayload{
		ID:          c.generateID(),
		Timestamp:   time.Now(),
		Type:        "file",
		Content:     fmt.Sprintf("File: %s (%d bytes)", filename, len(data)),
		ContentHash: c.hashBytes(data),
		SourceIP:    sourceIP,
		TemplateID:  templateID,
		CVE:         cve,
		Metadata:    metadata,
	}

	// Save file with safe name
	safeName := c.sanitizeFilename(filename)
	savedPath := filepath.Join(c.baseDir, "files", fmt.Sprintf("%s_%s_%s",
		payload.Timestamp.Format("20060102_150405"), payload.ID, safeName))

	if err := os.WriteFile(savedPath, data, 0644); err != nil {
		return nil, err
	}

	// Save metadata
	metaPath := savedPath + ".meta"
	metaContent := fmt.Sprintf(`Captured File
=============
ID:          %s
Timestamp:   %s
Source IP:   %s
Template:    %s
CVE:         %s
Filename:    %s
Size:        %d bytes
Hash:        %s
Saved As:    %s

Metadata:
%v
`, payload.ID, payload.Timestamp, sourceIP, templateID, cve, filename, len(data), payload.ContentHash, safeName, metadata)

	os.WriteFile(metaPath, []byte(metaContent), 0644)

	payload.FilePath = savedPath
	c.logger.Info(fmt.Sprintf("Captured file from %s: %s (%d bytes, hash: %s)", sourceIP, filename, len(data), payload.ContentHash[:16]))

	return payload, nil
}

// CaptureWebshell captures webshell upload attempts
func (c *Capture) CaptureWebshell(sourceIP, templateID, cve, path string, data []byte, metadata map[string]interface{}) (*CapturedPayload, error) {
	payload := &CapturedPayload{
		ID:          c.generateID(),
		Timestamp:   time.Now(),
		Type:        "webshell",
		Content:     string(data),
		ContentHash: c.hashBytes(data),
		SourceIP:    sourceIP,
		TemplateID:  templateID,
		CVE:         cve,
		Metadata:    metadata,
	}

	// Save webshell
	filename := fmt.Sprintf("%s_%s_webshell.php", payload.Timestamp.Format("20060102_150405"), payload.ID)
	savedPath := filepath.Join(c.baseDir, "webshells", filename)

	if err := os.WriteFile(savedPath, data, 0644); err != nil {
		return nil, err
	}

	// Save analysis
	analysis := c.analyzeWebshell(string(data))
	analysisPath := savedPath + ".analysis"
	analysisContent := fmt.Sprintf(`Webshell Analysis
=================
ID:          %s
Timestamp:   %s
Source IP:   %s
Template:    %s
CVE:         %s
Path:        %s
Hash:        %s

Analysis:
%s

Content:
%s
`, payload.ID, payload.Timestamp, sourceIP, templateID, cve, path, payload.ContentHash, analysis, string(data))

	os.WriteFile(analysisPath, []byte(analysisContent), 0644)

	payload.FilePath = savedPath
	c.logger.Info(fmt.Sprintf("Captured webshell from %s: %s (hash: %s)", sourceIP, path, payload.ContentHash[:16]))

	return payload, nil
}

// CaptureSQLInjection captures SQL injection attempts
func (c *Capture) CaptureSQLInjection(sourceIP, templateID, cve, query string, metadata map[string]interface{}) (*CapturedPayload, error) {
	payload := &CapturedPayload{
		ID:          c.generateID(),
		Timestamp:   time.Now(),
		Type:        "sql",
		Content:     query,
		ContentHash: c.hash(query),
		SourceIP:    sourceIP,
		TemplateID:  templateID,
		CVE:         cve,
		Metadata:    metadata,
	}

	filename := fmt.Sprintf("%s_%s.sql", payload.Timestamp.Format("20060102_150405"), payload.ID)
	filepath := filepath.Join(c.baseDir, "sql", filename)

	content := fmt.Sprintf(`SQL Injection Attempt
====================
ID:          %s
Timestamp:   %s
Source IP:   %s
Template:    %s
CVE:         %s
Hash:        %s

SQL Query:
%s

Metadata:
%v
`, payload.ID, payload.Timestamp, sourceIP, templateID, cve, payload.ContentHash, query, metadata)

	if err := os.WriteFile(filepath, []byte(content), 0644); err != nil {
		return nil, err
	}

	payload.FilePath = filepath
	c.logger.Info(fmt.Sprintf("Captured SQL injection from %s: %s", sourceIP, query))

	return payload, nil
}

// CapturePayload captures generic payloads
func (c *Capture) CapturePayload(sourceIP, templateID, cve, payloadType string, data []byte, metadata map[string]interface{}) (*CapturedPayload, error) {
	payload := &CapturedPayload{
		ID:          c.generateID(),
		Timestamp:   time.Now(),
		Type:        payloadType,
		Content:     string(data),
		ContentHash: c.hashBytes(data),
		SourceIP:    sourceIP,
		TemplateID:  templateID,
		CVE:         cve,
		Metadata:    metadata,
	}

	filename := fmt.Sprintf("%s_%s_%s.bin", payload.Timestamp.Format("20060102_150405"), payload.ID, payloadType)
	savedPath := filepath.Join(c.baseDir, "payloads", filename)

	if err := os.WriteFile(savedPath, data, 0644); err != nil {
		return nil, err
	}

	// Save metadata
	metaPath := savedPath + ".meta"
	metaContent := fmt.Sprintf(`Payload Capture
===============
ID:          %s
Timestamp:   %s
Source IP:   %s
Template:    %s
CVE:         %s
Type:        %s
Size:        %d bytes
Hash:        %s

Metadata:
%v
`, payload.ID, payload.Timestamp, sourceIP, templateID, cve, payloadType, len(data), payload.ContentHash, metadata)

	os.WriteFile(metaPath, []byte(metaContent), 0644)

	payload.FilePath = savedPath
	c.logger.Info(fmt.Sprintf("Captured %s payload from %s (%d bytes)", payloadType, sourceIP, len(data)))

	return payload, nil
}

// generateID generates a unique ID
func (c *Capture) generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// hash generates SHA256 hash of string
func (c *Capture) hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// hashBytes generates SHA256 hash of bytes
func (c *Capture) hashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// sanitizeFilename removes dangerous characters from filename
func (c *Capture) sanitizeFilename(filename string) string {
	// Remove path separators and null bytes
	safe := filepath.Base(filename)
	safe = filepath.Clean(safe)
	if safe == "." || safe == ".." {
		safe = "unnamed"
	}
	return safe
}

// analyzeWebshell performs basic analysis of webshell content
func (c *Capture) analyzeWebshell(content string) string {
	indicators := []string{}

	// Check for common webshell indicators
	if containsAny(content, []string{"eval(", "exec(", "system(", "passthru(", "shell_exec("}) {
		indicators = append(indicators, "- Contains code execution functions")
	}
	if containsAny(content, []string{"base64_decode", "gzinflate", "str_rot13"}) {
		indicators = append(indicators, "- Contains obfuscation functions")
	}
	if containsAny(content, []string{"$_POST", "$_GET", "$_REQUEST", "$_COOKIE"}) {
		indicators = append(indicators, "- Accepts external input")
	}
	if containsAny(content, []string{"file_get_contents", "file_put_contents", "fopen", "fwrite"}) {
		indicators = append(indicators, "- File manipulation capabilities")
	}
	if containsAny(content, []string{"mysql_", "mysqli_", "pg_", "PDO"}) {
		indicators = append(indicators, "- Database access capabilities")
	}

	if len(indicators) == 0 {
		return "No obvious webshell indicators found"
	}

	result := "Webshell indicators detected:\n"
	for _, ind := range indicators {
		result += ind + "\n"
	}
	return result
}

// containsAny checks if string contains any of the patterns
func containsAny(s string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(s, pattern) {
			return true
		}
	}
	return false
}

// GetStats returns capture statistics
func (c *Capture) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})

	// Count files in each directory
	categories := []string{"commands", "files", "webshells", "sql", "payloads"}
	for _, cat := range categories {
		dir := filepath.Join(c.baseDir, cat)
		files, err := os.ReadDir(dir)
		if err == nil {
			count := 0
			for _, f := range files {
				if !f.IsDir() && filepath.Ext(f.Name()) != ".meta" {
					count++
				}
			}
			stats[cat] = count
		}
	}

	return stats
}
