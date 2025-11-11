package types

import "time"

// NucleiTemplate represents a parsed Nuclei vulnerability template
type NucleiTemplate struct {
	ID       string                 `yaml:"id"`
	Info     TemplateInfo           `yaml:"info"`
	Requests []HTTPRequest          `yaml:"http,omitempty"`
	DNS      []DNSRequest           `yaml:"dns,omitempty"`
	Network  []NetworkRequest       `yaml:"network,omitempty"`
	TCP      []TCPRequest           `yaml:"tcp,omitempty"`
	Metadata map[string]interface{} `yaml:"metadata,omitempty"`
}

// TemplateInfo contains metadata about the vulnerability
type TemplateInfo struct {
	Name        string                 `yaml:"name"`
	Author      interface{}            `yaml:"author"`           // Can be string or array
	Severity    string                 `yaml:"severity"`
	Description string                 `yaml:"description"`
	Reference   interface{}            `yaml:"reference,omitempty"`     // Can be string or array
	Tags        interface{}            `yaml:"tags,omitempty"`          // Can be string or array
	CVE         string                 `yaml:"cve,omitempty"`
	Metadata    map[string]interface{} `yaml:"metadata,omitempty"`
	Classification map[string]interface{} `yaml:"classification,omitempty"`
}

// HTTPRequest represents an HTTP-based vulnerability check
type HTTPRequest struct {
	Method          string              `yaml:"method,omitempty"`
	Path            []string            `yaml:"path,omitempty"`
	Raw             []string            `yaml:"raw,omitempty"`
	Headers         map[string]string   `yaml:"headers,omitempty"`
	Body            string              `yaml:"body,omitempty"`
	Matchers        []Matcher           `yaml:"matchers,omitempty"`
	MatchersCondition string            `yaml:"matchers-condition,omitempty"`
	Extractors      []Extractor         `yaml:"extractors,omitempty"`
	ReqCondition    bool                `yaml:"req-condition,omitempty"`
	Redirects       bool                `yaml:"redirects,omitempty"`
	MaxRedirects    int                 `yaml:"max-redirects,omitempty"`
	CookieReuse     bool                `yaml:"cookie-reuse,omitempty"`
}

// DNSRequest represents a DNS-based vulnerability check
type DNSRequest struct {
	Name            string      `yaml:"name,omitempty"`
	Type            string      `yaml:"type,omitempty"`
	Class           string      `yaml:"class,omitempty"`
	Retries         int         `yaml:"retries,omitempty"`
	Matchers        []Matcher   `yaml:"matchers,omitempty"`
	Extractors      []Extractor `yaml:"extractors,omitempty"`
}

// NetworkRequest represents a network/TCP-based check
type NetworkRequest struct {
	Host       string      `yaml:"host,omitempty"`
	Inputs     []Input     `yaml:"inputs,omitempty"`
	Matchers   []Matcher   `yaml:"matchers,omitempty"`
	Extractors []Extractor `yaml:"extractors,omitempty"`
}

// TCPRequest represents a TCP-based check
type TCPRequest struct {
	Host       string      `yaml:"host,omitempty"`
	Inputs     []Input     `yaml:"inputs,omitempty"`
	ReadSize   int         `yaml:"read-size,omitempty"`
	Matchers   []Matcher   `yaml:"matchers,omitempty"`
	Extractors []Extractor `yaml:"extractors,omitempty"`
}

// Input represents input data for network/TCP requests
type Input struct {
	Data string `yaml:"data,omitempty"`
	Read int    `yaml:"read,omitempty"`
	Type string `yaml:"type,omitempty"`
}

// Matcher represents a condition to match against responses
type Matcher struct {
	Type      string   `yaml:"type"`
	Part      string   `yaml:"part,omitempty"`
	Words     []string `yaml:"words,omitempty"`
	Regex     []string `yaml:"regex,omitempty"`
	Status    []int    `yaml:"status,omitempty"`
	DSL       []string `yaml:"dsl,omitempty"`
	Condition string   `yaml:"condition,omitempty"`
	Negative  bool     `yaml:"negative,omitempty"`
}

// Extractor represents data extraction rules
type Extractor struct {
	Type      string            `yaml:"type"`
	Part      string            `yaml:"part,omitempty"`
	Name      string            `yaml:"name,omitempty"`
	Regex     []string          `yaml:"regex,omitempty"`
	Group     int               `yaml:"group,omitempty"`
	KVal      []string          `yaml:"kval,omitempty"`
	JSON      []string          `yaml:"json,omitempty"`
	Internal  bool              `yaml:"internal,omitempty"`
	Attribute map[string]string `yaml:"attribute,omitempty"`
}

// HoneypotConfig represents the configuration for the honeypot
type HoneypotConfig struct {
	Server    ServerConfig      `yaml:"server"`
	Templates TemplatesConfig   `yaml:"templates"`
	Logging   LoggingConfig     `yaml:"logging"`
	Responses ResponseConfig    `yaml:"responses"`
}

// ServerConfig contains server configuration
type ServerConfig struct {
	HTTP    HTTPServerConfig    `yaml:"http"`
	DNS     DNSServerConfig     `yaml:"dns"`
	TCP     TCPServerConfig     `yaml:"tcp"`
	UI      UIServerConfig      `yaml:"ui"`
}

// UIServerConfig contains UI server settings
type UIServerConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
}

// HTTPServerConfig contains HTTP server settings
type HTTPServerConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	TLS       bool   `yaml:"tls"`
	CertFile  string `yaml:"cert_file,omitempty"`
	KeyFile   string `yaml:"key_file,omitempty"`
}

// DNSServerConfig contains DNS server settings
type DNSServerConfig struct {
	Enabled bool   `yaml:"enabled"`
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	Network string `yaml:"network"` // "udp", "tcp", or "both"
}

// TCPServerConfig contains TCP server settings
type TCPServerConfig struct {
	Enabled bool          `yaml:"enabled"`
	Ports   []PortConfig  `yaml:"ports"`
}

// PortConfig represents a TCP port configuration
type PortConfig struct {
	Port     int    `yaml:"port"`
	Protocol string `yaml:"protocol,omitempty"` // e.g., "ssh", "telnet", "custom"
}

// TemplatesConfig contains template loading configuration
type TemplatesConfig struct {
	Directory  string   `yaml:"directory"`
	Enabled    []string `yaml:"enabled,omitempty"`    // List of template IDs to enable
	Disabled   []string `yaml:"disabled,omitempty"`   // List of template IDs to disable
	Tags       []string `yaml:"tags,omitempty"`       // Enable templates with these tags
	Severities []string `yaml:"severities,omitempty"` // Enable templates with these severities
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level      string `yaml:"level"`       // debug, info, warn, error
	File       string `yaml:"file"`        // Log file path
	Format     string `yaml:"format"`      // json or text
	MaxSize    int    `yaml:"max_size"`    // Max size in MB
	MaxBackups int    `yaml:"max_backups"` // Max number of old log files
	MaxAge     int    `yaml:"max_age"`     // Max age in days
}

// ResponseConfig contains response generation settings
type ResponseConfig struct {
	Interaction string            `yaml:"interaction"` // "low", "medium", "high"
	Delays      DelayConfig       `yaml:"delays"`
	Custom      map[string]string `yaml:"custom,omitempty"` // Custom responses per template ID
}

// DelayConfig contains response delay settings
type DelayConfig struct {
	Enabled bool   `yaml:"enabled"`
	Min     string `yaml:"min"` // e.g., "100ms"
	Max     string `yaml:"max"` // e.g., "2s"
}

// InteractionLog represents a logged interaction
type InteractionLog struct {
	Timestamp   time.Time              `json:"timestamp"`
	Protocol    string                 `json:"protocol"`
	SourceIP    string                 `json:"source_ip"`
	SourcePort  int                    `json:"source_port"`
	DestPort    int                    `json:"dest_port"`
	TemplateID  string                 `json:"template_id,omitempty"`
	CVE         string                 `json:"cve,omitempty"`
	Severity    string                 `json:"severity,omitempty"`
	Method      string                 `json:"method,omitempty"`
	Path        string                 `json:"path,omitempty"`
	Headers     map[string][]string    `json:"headers,omitempty"`
	Body        string                 `json:"body,omitempty"`
	Query       string                 `json:"query,omitempty"`
	Response    string                 `json:"response,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}
