package config

import (
	"fmt"
	"os"

	"breadcrumb-pot/pkg/types"
	"gopkg.in/yaml.v3"
)

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*types.HoneypotConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config types.HoneypotConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate configuration
	if err := ValidateConfig(&config); err != nil {
		return nil, err
	}

	// Apply defaults
	ApplyDefaults(&config)

	return &config, nil
}

// ValidateConfig validates the configuration
func ValidateConfig(config *types.HoneypotConfig) error {
	// Check at least one server is enabled
	if !config.Server.HTTP.Enabled && !config.Server.DNS.Enabled && !config.Server.TCP.Enabled {
		return fmt.Errorf("at least one server (HTTP, DNS, or TCP) must be enabled")
	}

	// Validate HTTP config
	if config.Server.HTTP.Enabled {
		if config.Server.HTTP.Port <= 0 || config.Server.HTTP.Port > 65535 {
			return fmt.Errorf("invalid HTTP port: %d", config.Server.HTTP.Port)
		}
		if config.Server.HTTP.TLS {
			if config.Server.HTTP.CertFile == "" || config.Server.HTTP.KeyFile == "" {
				return fmt.Errorf("TLS enabled but cert_file or key_file not specified")
			}
		}
	}

	// Validate DNS config
	if config.Server.DNS.Enabled {
		if config.Server.DNS.Port <= 0 || config.Server.DNS.Port > 65535 {
			return fmt.Errorf("invalid DNS port: %d", config.Server.DNS.Port)
		}
		if config.Server.DNS.Network != "udp" && config.Server.DNS.Network != "tcp" && config.Server.DNS.Network != "both" {
			return fmt.Errorf("invalid DNS network: %s (must be udp, tcp, or both)", config.Server.DNS.Network)
		}
	}

	// Validate TCP config
	if config.Server.TCP.Enabled {
		if len(config.Server.TCP.Ports) == 0 {
			return fmt.Errorf("TCP server enabled but no ports configured")
		}
		for _, portConfig := range config.Server.TCP.Ports {
			if portConfig.Port <= 0 || portConfig.Port > 65535 {
				return fmt.Errorf("invalid TCP port: %d", portConfig.Port)
			}
		}
	}

	// Validate templates config
	if config.Templates.Directory == "" {
		return fmt.Errorf("templates directory not specified")
	}

	// Validate logging config
	if config.Logging.Level == "" {
		config.Logging.Level = "info"
	}

	// Validate response config
	if config.Responses.Interaction != "low" && config.Responses.Interaction != "medium" && config.Responses.Interaction != "high" {
		return fmt.Errorf("invalid interaction level: %s (must be low, medium, or high)", config.Responses.Interaction)
	}

	return nil
}

// ApplyDefaults applies default values to configuration
func ApplyDefaults(config *types.HoneypotConfig) {
	// HTTP defaults
	if config.Server.HTTP.Host == "" {
		config.Server.HTTP.Host = "0.0.0.0"
	}
	if config.Server.HTTP.Port == 0 {
		config.Server.HTTP.Port = 8080
	}

	// DNS defaults
	if config.Server.DNS.Host == "" {
		config.Server.DNS.Host = "0.0.0.0"
	}
	if config.Server.DNS.Port == 0 {
		config.Server.DNS.Port = 53
	}
	if config.Server.DNS.Network == "" {
		config.Server.DNS.Network = "both"
	}

	// Logging defaults
	if config.Logging.Level == "" {
		config.Logging.Level = "info"
	}
	if config.Logging.Format == "" {
		config.Logging.Format = "text"
	}
	if config.Logging.File == "" {
		config.Logging.File = "logs/honeypot.log"
	}
	if config.Logging.MaxSize == 0 {
		config.Logging.MaxSize = 100 // 100 MB
	}
	if config.Logging.MaxBackups == 0 {
		config.Logging.MaxBackups = 10
	}
	if config.Logging.MaxAge == 0 {
		config.Logging.MaxAge = 30 // 30 days
	}

	// Response defaults
	if config.Responses.Interaction == "" {
		config.Responses.Interaction = "medium"
	}
	if config.Responses.Delays.Min == "" {
		config.Responses.Delays.Min = "100ms"
	}
	if config.Responses.Delays.Max == "" {
		config.Responses.Delays.Max = "1s"
	}
}

// SaveConfig saves configuration to a YAML file
func SaveConfig(config *types.HoneypotConfig, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GenerateDefaultConfig generates a default configuration
func GenerateDefaultConfig() *types.HoneypotConfig {
	return &types.HoneypotConfig{
		Server: types.ServerConfig{
			HTTP: types.HTTPServerConfig{
				Enabled: true,
				Host:    "0.0.0.0",
				Port:    8080,
				TLS:     false,
			},
			DNS: types.DNSServerConfig{
				Enabled: false,
				Host:    "0.0.0.0",
				Port:    53,
				Network: "both",
			},
			TCP: types.TCPServerConfig{
				Enabled: false,
				Ports: []types.PortConfig{
					{Port: 22, Protocol: "ssh"},
					{Port: 23, Protocol: "telnet"},
					{Port: 21, Protocol: "ftp"},
				},
			},
		},
		Templates: types.TemplatesConfig{
			Directory:  "templates",
			Severities: []string{"critical", "high", "medium"},
		},
		Logging: types.LoggingConfig{
			Level:      "info",
			File:       "logs/honeypot.log",
			Format:     "text",
			MaxSize:    100,
			MaxBackups: 10,
			MaxAge:     30,
		},
		Responses: types.ResponseConfig{
			Interaction: "medium",
			Delays: types.DelayConfig{
				Enabled: true,
				Min:     "100ms",
				Max:     "1s",
			},
		},
	}
}
