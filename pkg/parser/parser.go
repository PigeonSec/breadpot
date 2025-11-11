package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"breadcrumb-pot/pkg/types"
	"gopkg.in/yaml.v3"
)

// Parser handles loading and parsing of Nuclei templates
type Parser struct {
	config *types.TemplatesConfig
}

// NewParser creates a new template parser
func NewParser(config *types.TemplatesConfig) *Parser {
	return &Parser{
		config: config,
	}
}

// LoadTemplates loads all templates from the configured directory
func (p *Parser) LoadTemplates() ([]*types.NucleiTemplate, error) {
	var templates []*types.NucleiTemplate

	// Walk through template directory
	err := filepath.Walk(p.config.Directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-YAML files
		if info.IsDir() || !isYAMLFile(path) {
			return nil
		}

		// Parse template
		template, err := p.parseTemplateFile(path)
		if err != nil {
			// Log error but continue processing other templates
			fmt.Printf("Warning: failed to parse template %s: %v\n", path, err)
			return nil
		}

		// Apply filters
		if p.shouldLoadTemplate(template) {
			templates = append(templates, template)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk template directory: %w", err)
	}

	return templates, nil
}

// parseTemplateFile parses a single template file
func (p *Parser) parseTemplateFile(path string) (*types.NucleiTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var template types.NucleiTemplate
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	// Validate template has required fields
	if template.ID == "" {
		return nil, fmt.Errorf("template missing ID")
	}

	return &template, nil
}

// ShouldLoadTemplate determines if a template should be loaded based on config (exported for database loader)
func (p *Parser) ShouldLoadTemplate(template *types.NucleiTemplate) bool {
	return p.shouldLoadTemplate(template)
}

// shouldLoadTemplate determines if a template should be loaded based on config
func (p *Parser) shouldLoadTemplate(template *types.NucleiTemplate) bool {
	// Check if explicitly disabled
	for _, disabled := range p.config.Disabled {
		if template.ID == disabled {
			return false
		}
	}

	// If enabled list exists, only load templates in that list
	if len(p.config.Enabled) > 0 {
		enabled := false
		for _, id := range p.config.Enabled {
			if template.ID == id {
				enabled = true
				break
			}
		}
		if !enabled {
			return false
		}
	}

	// Check severity filter
	if len(p.config.Severities) > 0 {
		severityMatch := false
		for _, sev := range p.config.Severities {
			if strings.EqualFold(template.Info.Severity, sev) {
				severityMatch = true
				break
			}
		}
		if !severityMatch {
			return false
		}
	}

	// Check tag filter
	if len(p.config.Tags) > 0 {
		tagMatch := false
		templateTags := getTags(template.Info.Tags)
		for _, configTag := range p.config.Tags {
			for _, templateTag := range templateTags {
				if strings.EqualFold(configTag, templateTag) {
					tagMatch = true
					break
				}
			}
			if tagMatch {
				break
			}
		}
		if !tagMatch {
			return false
		}
	}

	return true
}

// isYAMLFile checks if a file is a YAML file
func isYAMLFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

// ExtractVulnerableEndpoints extracts HTTP endpoints that should be exposed
func ExtractVulnerableEndpoints(template *types.NucleiTemplate) []VulnerableEndpoint {
	var endpoints []VulnerableEndpoint

	for _, req := range template.Requests {
		// Extract from path list
		for _, path := range req.Path {
			endpoint := VulnerableEndpoint{
				TemplateID:  template.ID,
				Method:      req.Method,
				Path:        path,
				Headers:     req.Headers,
				Body:        req.Body,
				Matchers:    req.Matchers,
				CVE:         template.Info.CVE,
				Severity:    template.Info.Severity,
				Description: template.Info.Description,
			}
			if endpoint.Method == "" {
				endpoint.Method = "GET"
			}
			endpoints = append(endpoints, endpoint)
		}

		// Extract from raw requests
		for _, raw := range req.Raw {
			endpoint := parseRawRequest(raw, template)
			if endpoint != nil {
				endpoints = append(endpoints, *endpoint)
			}
		}
	}

	return endpoints
}

// VulnerableEndpoint represents an HTTP endpoint that should be exposed
type VulnerableEndpoint struct {
	TemplateID  string
	Method      string
	Path        string
	Headers     map[string]string
	Body        string
	Matchers    []types.Matcher
	CVE         string
	Severity    string
	Description string
}

// parseRawRequest parses a raw HTTP request string
func parseRawRequest(raw string, template *types.NucleiTemplate) *VulnerableEndpoint {
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return nil
	}

	// Parse request line
	requestLine := strings.Fields(lines[0])
	if len(requestLine) < 2 {
		return nil
	}

	method := requestLine[0]
	path := requestLine[1]

	// Parse headers
	headers := make(map[string]string)
	bodyStart := 1
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			bodyStart = i + 1
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Parse body
	body := ""
	if bodyStart < len(lines) {
		body = strings.Join(lines[bodyStart:], "\n")
	}

	return &VulnerableEndpoint{
		TemplateID:  template.ID,
		Method:      method,
		Path:        path,
		Headers:     headers,
		Body:        body,
		CVE:         template.Info.CVE,
		Severity:    template.Info.Severity,
		Description: template.Info.Description,
	}
}

// ExtractDNSQueries extracts DNS queries that should be handled
func ExtractDNSQueries(template *types.NucleiTemplate) []DNSQuery {
	var queries []DNSQuery

	for _, req := range template.DNS {
		query := DNSQuery{
			TemplateID:  template.ID,
			Name:        req.Name,
			Type:        req.Type,
			Class:       req.Class,
			Matchers:    req.Matchers,
			CVE:         template.Info.CVE,
			Severity:    template.Info.Severity,
			Description: template.Info.Description,
		}
		if query.Type == "" {
			query.Type = "A"
		}
		if query.Class == "" {
			query.Class = "IN"
		}
		queries = append(queries, query)
	}

	return queries
}

// DNSQuery represents a DNS query pattern
type DNSQuery struct {
	TemplateID  string
	Name        string
	Type        string
	Class       string
	Matchers    []types.Matcher
	CVE         string
	Severity    string
	Description string
}

// ExtractTCPServices extracts TCP services that should be exposed
func ExtractTCPServices(template *types.NucleiTemplate) []TCPService {
	var services []TCPService

	// Process network requests
	for _, req := range template.Network {
		service := TCPService{
			TemplateID:  template.ID,
			Inputs:      req.Inputs,
			Matchers:    req.Matchers,
			CVE:         template.Info.CVE,
			Severity:    template.Info.Severity,
			Description: template.Info.Description,
		}
		services = append(services, service)
	}

	// Process TCP requests
	for _, req := range template.TCP {
		service := TCPService{
			TemplateID:  template.ID,
			Inputs:      req.Inputs,
			ReadSize:    req.ReadSize,
			Matchers:    req.Matchers,
			CVE:         template.Info.CVE,
			Severity:    template.Info.Severity,
			Description: template.Info.Description,
		}
		services = append(services, service)
	}

	return services
}

// TCPService represents a TCP service pattern
type TCPService struct {
	TemplateID  string
	Inputs      []types.Input
	ReadSize    int
	Matchers    []types.Matcher
	CVE         string
	Severity    string
	Description string
}

// getTags converts interface{} tags to []string
func getTags(tags interface{}) []string {
	if tags == nil {
		return []string{}
	}

	switch v := tags.(type) {
	case []string:
		return v
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, tag := range v {
			if s, ok := tag.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case string:
		// Handle comma-separated string
		if v == "" {
			return []string{}
		}
		parts := strings.Split(v, ",")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				result = append(result, trimmed)
			}
		}
		return result
	default:
		return []string{}
	}
}
