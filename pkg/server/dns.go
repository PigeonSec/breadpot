package server

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"breadcrumb-pot/pkg/logger"
	"breadcrumb-pot/pkg/parser"
	"breadcrumb-pot/pkg/response"
	"breadcrumb-pot/pkg/types"

	"github.com/miekg/dns"
)

// DNSServer handles DNS honeypot requests
type DNSServer struct {
	config    *types.DNSServerConfig
	generator *response.Generator
	logger    *logger.Logger
	queries   map[string]parser.DNSQuery
	udpServer *dns.Server
	tcpServer *dns.Server
}

// NewDNSServer creates a new DNS server
func NewDNSServer(
	config *types.DNSServerConfig,
	generator *response.Generator,
	log *logger.Logger,
) *DNSServer {
	return &DNSServer{
		config:    config,
		generator: generator,
		logger:    log,
		queries:   make(map[string]parser.DNSQuery),
	}
}

// RegisterQueries registers DNS queries to handle
func (s *DNSServer) RegisterQueries(queries []parser.DNSQuery) {
	for _, query := range queries {
		key := fmt.Sprintf("%s:%s:%s", query.Name, query.Type, query.Class)
		s.queries[key] = query

		s.logger.Debug(fmt.Sprintf("Registered DNS query: %s %s %s (Template: %s, CVE: %s)",
			query.Name, query.Type, query.Class, query.TemplateID, query.CVE))
	}
}

// Start starts the DNS server
func (s *DNSServer) Start() error {
	if !s.config.Enabled {
		s.logger.Info("DNS server disabled")
		return nil
	}

	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	// Create DNS handler
	dns.HandleFunc(".", s.handleDNSRequest)

	s.logger.Info(fmt.Sprintf("Starting DNS server on %s (network: %s)", addr, s.config.Network))

	// Start servers based on network config
	errChan := make(chan error, 2)

	if s.config.Network == "udp" || s.config.Network == "both" {
		s.udpServer = &dns.Server{
			Addr: addr,
			Net:  "udp",
		}
		go func() {
			errChan <- s.udpServer.ListenAndServe()
		}()
		s.logger.Info(fmt.Sprintf("DNS server listening on UDP %s", addr))
	}

	if s.config.Network == "tcp" || s.config.Network == "both" {
		s.tcpServer = &dns.Server{
			Addr: addr,
			Net:  "tcp",
		}
		go func() {
			errChan <- s.tcpServer.ListenAndServe()
		}()
		s.logger.Info(fmt.Sprintf("DNS server listening on TCP %s", addr))
	}

	// Return first error
	return <-errChan
}

// Stop stops the DNS server
func (s *DNSServer) Stop(ctx context.Context) error {
	s.logger.Info("Stopping DNS server")

	if s.udpServer != nil {
		if err := s.udpServer.ShutdownContext(ctx); err != nil {
			return err
		}
	}

	if s.tcpServer != nil {
		if err := s.tcpServer.ShutdownContext(ctx); err != nil {
			return err
		}
	}

	return nil
}

// handleDNSRequest handles incoming DNS requests
func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	startTime := time.Now()
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	// Get client IP
	clientIP := s.getClientIP(w.RemoteAddr())

	// Process each question
	for _, q := range r.Question {
		s.logger.Debug(fmt.Sprintf("DNS query from %s: %s %s %s",
			clientIP, q.Name, dns.TypeToString[q.Qtype], dns.ClassToString[q.Qclass]))

		// Log interaction
		interaction := types.InteractionLog{
			Timestamp:  startTime,
			Protocol:   "DNS",
			SourceIP:   clientIP,
			SourcePort: 0,
			DestPort:   s.config.Port,
			Query:      fmt.Sprintf("%s %s %s", q.Name, dns.TypeToString[q.Qtype], dns.ClassToString[q.Qclass]),
			Metadata: map[string]interface{}{
				"question": q.Name,
				"type":     dns.TypeToString[q.Qtype],
				"class":    dns.ClassToString[q.Qclass],
			},
		}

		// Check if query matches a registered template
		matched := false
		for _, query := range s.queries {
			if s.matchesQuery(q, query) {
				matched = true
				interaction.TemplateID = query.TemplateID
				interaction.CVE = query.CVE
				interaction.Severity = query.Severity

				// Generate response
				resp := s.generator.GenerateDNSResponse(query)

				// Apply delay
				if resp.Delay > 0 {
					time.Sleep(resp.Delay)
				}

				// Add records to response
				for _, record := range resp.Records {
					rr := s.createDNSRecord(record, q)
					if rr != nil {
						m.Answer = append(m.Answer, rr)
					}
				}

				interaction.Response = fmt.Sprintf("%d records", len(resp.Records))

				s.logger.Info(fmt.Sprintf("DNS query matched template %s (CVE: %s) from %s: %s %s - %d records, Duration: %v",
					query.TemplateID, query.CVE, clientIP, q.Name, dns.TypeToString[q.Qtype], len(resp.Records), time.Since(startTime)))

				break
			}
		}

		// If no match, provide default response
		if !matched {
			interaction.TemplateID = "unmatched"
			rr := s.createDefaultDNSRecord(q)
			if rr != nil {
				m.Answer = append(m.Answer, rr)
			}
			interaction.Response = "default response"

			s.logger.Debug(fmt.Sprintf("DNS query (unmatched) from %s: %s %s - Duration: %v",
				clientIP, q.Name, dns.TypeToString[q.Qtype], time.Since(startTime)))
		}

		// Log interaction
		s.logger.LogInteraction(interaction)
	}

	// Send response
	w.WriteMsg(m)
}

// matchesQuery checks if a DNS question matches a template query
func (s *DNSServer) matchesQuery(q dns.Question, query parser.DNSQuery) bool {
	// Normalize names
	qName := strings.TrimSuffix(q.Name, ".")
	queryName := strings.TrimSuffix(query.Name, ".")

	// Support wildcards
	if strings.HasPrefix(queryName, "*.") {
		suffix := strings.TrimPrefix(queryName, "*.")
		if !strings.HasSuffix(qName, suffix) {
			return false
		}
	} else if qName != queryName {
		return false
	}

	// Check type
	qType := dns.TypeToString[q.Qtype]
	if query.Type != "" && query.Type != qType {
		return false
	}

	// Check class
	qClass := dns.ClassToString[q.Qclass]
	if query.Class != "" && query.Class != qClass {
		return false
	}

	return true
}

// createDNSRecord creates a DNS resource record
func (s *DNSServer) createDNSRecord(record response.DNSRecord, q dns.Question) dns.RR {
	header := dns.RR_Header{
		Name:   q.Name,
		Rrtype: s.stringToType(record.Type),
		Class:  q.Qclass,
		Ttl:    record.TTL,
	}

	switch record.Type {
	case "A":
		return &dns.A{
			Hdr: header,
			A:   net.ParseIP(record.Value),
		}
	case "AAAA":
		return &dns.AAAA{
			Hdr:  header,
			AAAA: net.ParseIP(record.Value),
		}
	case "TXT":
		return &dns.TXT{
			Hdr: header,
			Txt: []string{record.Value},
		}
	case "CNAME":
		return &dns.CNAME{
			Hdr:    header,
			Target: record.Value,
		}
	case "MX":
		// Parse MX format: "priority hostname"
		var priority uint16
		var hostname string
		fmt.Sscanf(record.Value, "%d %s", &priority, &hostname)
		return &dns.MX{
			Hdr:        header,
			Preference: priority,
			Mx:         hostname,
		}
	case "NS":
		return &dns.NS{
			Hdr: header,
			Ns:  record.Value,
		}
	case "PTR":
		return &dns.PTR{
			Hdr: header,
			Ptr: record.Value,
		}
	default:
		return nil
	}
}

// createDefaultDNSRecord creates a default DNS record
func (s *DNSServer) createDefaultDNSRecord(q dns.Question) dns.RR {
	switch q.Qtype {
	case dns.TypeA:
		return &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  q.Qclass,
				Ttl:    300,
			},
			A: net.ParseIP("127.0.0.1"),
		}
	case dns.TypeAAAA:
		return &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeAAAA,
				Class:  q.Qclass,
				Ttl:    300,
			},
			AAAA: net.ParseIP("::1"),
		}
	case dns.TypeTXT:
		return &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  q.Qclass,
				Ttl:    300,
			},
			Txt: []string{"v=spf1 -all"},
		}
	default:
		return nil
	}
}

// stringToType converts type string to dns.Type
func (s *DNSServer) stringToType(typeStr string) uint16 {
	typeMap := map[string]uint16{
		"A":     dns.TypeA,
		"AAAA":  dns.TypeAAAA,
		"TXT":   dns.TypeTXT,
		"CNAME": dns.TypeCNAME,
		"MX":    dns.TypeMX,
		"NS":    dns.TypeNS,
		"PTR":   dns.TypePTR,
		"SOA":   dns.TypeSOA,
		"SRV":   dns.TypeSRV,
	}

	if t, ok := typeMap[typeStr]; ok {
		return t
	}
	return dns.TypeA
}

// getClientIP extracts client IP from address
func (s *DNSServer) getClientIP(addr net.Addr) string {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		return udpAddr.IP.String()
	}
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP.String()
	}
	return addr.String()
}

// GetStats returns server statistics
func (s *DNSServer) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"queries_registered": len(s.queries),
		"network":            s.config.Network,
		"address":            fmt.Sprintf("%s:%d", s.config.Host, s.config.Port),
	}
}
