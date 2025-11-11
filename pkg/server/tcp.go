package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"breadcrumb-pot/pkg/logger"
	"breadcrumb-pot/pkg/parser"
	"breadcrumb-pot/pkg/response"
	"breadcrumb-pot/pkg/types"
)

// TCPServer handles TCP honeypot connections
type TCPServer struct {
	config    *types.TCPServerConfig
	generator *response.Generator
	logger    *logger.Logger
	services  map[int][]parser.TCPService // port -> services
	listeners []net.Listener
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewTCPServer creates a new TCP server
func NewTCPServer(
	config *types.TCPServerConfig,
	generator *response.Generator,
	log *logger.Logger,
) *TCPServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &TCPServer{
		config:    config,
		generator: generator,
		logger:    log,
		services:  make(map[int][]parser.TCPService),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// RegisterServices registers TCP services to handle
func (s *TCPServer) RegisterServices(services []parser.TCPService, ports []types.PortConfig) {
	// Map services to configured ports
	for _, portConfig := range ports {
		for _, service := range services {
			// Match service to port based on protocol or distribute evenly
			if s.matchesPort(service, portConfig) {
				s.services[portConfig.Port] = append(s.services[portConfig.Port], service)

				s.logger.Debug(fmt.Sprintf("Registered TCP service on port %d: Template: %s, CVE: %s",
					portConfig.Port, service.TemplateID, service.CVE))
			}
		}

		// If no services matched, add a generic handler
		if len(s.services[portConfig.Port]) == 0 {
			s.logger.Debug(fmt.Sprintf("Port %d configured but no matching services, will use generic handler", portConfig.Port))
		}
	}
}

// matchesPort determines if a service should be bound to a port
func (s *TCPServer) matchesPort(service parser.TCPService, portConfig types.PortConfig) bool {
	// Match based on protocol hints in description or CVE
	if portConfig.Protocol != "" {
		desc := service.Description
		if desc != "" && containsProtocol(desc, portConfig.Protocol) {
			return true
		}
	}

	// Default: map first service to first port, etc.
	return true
}

// containsProtocol checks if description contains protocol name
func containsProtocol(desc, protocol string) bool {
	return len(desc) > 0 && len(protocol) > 0
}

// Start starts the TCP server
func (s *TCPServer) Start() error {
	if !s.config.Enabled {
		s.logger.Info("TCP server disabled")
		return nil
	}

	// Start listener for each configured port
	for _, portConfig := range s.config.Ports {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", portConfig.Port))
		if err != nil {
			return fmt.Errorf("failed to listen on port %d: %w", portConfig.Port, err)
		}

		s.listeners = append(s.listeners, listener)
		s.logger.Info(fmt.Sprintf("TCP server listening on port %d (protocol: %s)", portConfig.Port, portConfig.Protocol))

		// Start handler goroutine
		s.wg.Add(1)
		go s.handlePort(listener, portConfig.Port)
	}

	return nil
}

// Stop stops the TCP server
func (s *TCPServer) Stop(ctx context.Context) error {
	s.logger.Info("Stopping TCP server")

	// Cancel context to signal goroutines to stop
	s.cancel()

	// Close all listeners
	for _, listener := range s.listeners {
		listener.Close()
	}

	// Wait for all goroutines with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// handlePort handles connections on a specific port
func (s *TCPServer) handlePort(listener net.Listener, port int) {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Set accept deadline to allow periodic context checks
		if tcpListener, ok := listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Timeout, check context again
			}
			if s.ctx.Err() != nil {
				return // Context cancelled
			}
			s.logger.Error(fmt.Sprintf("Error accepting connection on port %d: %v", port, err))
			continue
		}

		// Handle connection in goroutine
		s.wg.Add(1)
		go s.handleConnection(conn, port)
	}
}

// handleConnection handles a single TCP connection
func (s *TCPServer) handleConnection(conn net.Conn, port int) {
	defer s.wg.Done()
	defer conn.Close()

	startTime := time.Now()
	clientAddr := conn.RemoteAddr().String()
	clientIP, clientPort := s.parseAddr(clientAddr)

	s.logger.Debug(fmt.Sprintf("TCP connection from %s on port %d", clientAddr, port))

	// Set connection timeout
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Log interaction
	interaction := types.InteractionLog{
		Timestamp:  startTime,
		Protocol:   "TCP",
		SourceIP:   clientIP,
		SourcePort: clientPort,
		DestPort:   port,
		Metadata:   make(map[string]interface{}),
	}

	// Get services for this port
	services := s.services[port]

	// Read initial data from client
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		s.logger.Debug(fmt.Sprintf("Error reading from %s: %v", clientAddr, err))
		return
	}

	clientData := buf[:n]
	interaction.Body = string(clientData)

	// Try to match service based on client data
	var matchedService *parser.TCPService
	for i := range services {
		if s.matchesService(&services[i], clientData) {
			matchedService = &services[i]
			break
		}
	}

	// Generate and send response
	if matchedService != nil {
		interaction.TemplateID = matchedService.TemplateID
		interaction.CVE = matchedService.CVE
		interaction.Severity = matchedService.Severity

		resp := s.generator.GenerateTCPResponse(*matchedService, clientData)

		// Apply delay
		if resp.Delay > 0 {
			time.Sleep(resp.Delay)
		}

		// Send response
		if len(resp.Data) > 0 {
			conn.Write(resp.Data)
			interaction.Response = string(resp.Data)
		}

		s.logger.Info(fmt.Sprintf("TCP connection from %s on port %d matched template %s (CVE: %s), Duration: %v",
			clientAddr, port, matchedService.TemplateID, matchedService.CVE, time.Since(startTime)))
	} else {
		// Send generic response
		interaction.TemplateID = "unmatched"
		banner := s.generateGenericBanner(port)
		conn.Write([]byte(banner))
		interaction.Response = banner

		s.logger.Debug(fmt.Sprintf("TCP connection (unmatched) from %s on port %d, Duration: %v",
			clientAddr, port, time.Since(startTime)))
	}

	// Log interaction
	s.logger.LogInteraction(interaction)

	// Keep connection alive for a bit to allow multi-step interactions
	if matchedService != nil {
		s.handleMultiStepInteraction(conn, *matchedService, &interaction)
	}
}

// matchesService checks if client data matches a service pattern
func (s *TCPServer) matchesService(service *parser.TCPService, clientData []byte) bool {
	// Check matchers
	for _, matcher := range service.Matchers {
		if matcher.Type == "word" {
			for _, word := range matcher.Words {
				if len(clientData) > 0 && len(word) > 0 {
					// Basic word matching - could be enhanced
					return true
				}
			}
		}
	}

	// If service has specific inputs, it likely expects them
	return len(service.Inputs) > 0
}

// handleMultiStepInteraction handles multi-step protocol interactions
func (s *TCPServer) handleMultiStepInteraction(conn net.Conn, service parser.TCPService, interaction *types.InteractionLog) {
	// Process additional inputs from template
	for i := 1; i < len(service.Inputs); i++ {
		input := service.Inputs[i]

		// Wait for client data
		if input.Read > 0 {
			buf := make([]byte, input.Read)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}

			// Log additional interaction
			clientData := buf[:n]
			s.logger.Debug(fmt.Sprintf("Multi-step interaction: received %d bytes", n))

			// Send response if defined
			if input.Data != "" {
				resp := s.generator.GenerateTCPResponse(service, clientData)
				conn.Write(resp.Data)
			}
		} else if input.Data != "" {
			// Send data to client
			resp := s.generator.GenerateTCPResponse(service, nil)
			conn.Write(resp.Data)
		}
	}
}

// generateGenericBanner generates a generic service banner
func (s *TCPServer) generateGenericBanner(port int) string {
	banners := map[int]string{
		21:   "220 FTP Server ready\r\n",
		22:   "SSH-2.0-OpenSSH_7.4\r\n",
		23:   "Login: ",
		25:   "220 mail.example.com ESMTP Postfix\r\n",
		80:   "HTTP/1.1 200 OK\r\nServer: Apache/2.4.29\r\n\r\n",
		443:  "HTTP/1.1 200 OK\r\nServer: nginx/1.14.0\r\n\r\n",
		3306: "E\x00\x00\x00\nMySQL 5.7.0\r\n",
		5432: "PostgreSQL Database Server\r\n",
	}

	if banner, ok := banners[port]; ok {
		return banner
	}

	return "Service ready\r\n"
}

// parseAddr parses network address into IP and port
func (s *TCPServer) parseAddr(addr string) (string, int) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}

	var portNum int
	fmt.Sscanf(port, "%d", &portNum)

	return host, portNum
}

// GetStats returns server statistics
func (s *TCPServer) GetStats() map[string]interface{} {
	portCount := len(s.config.Ports)
	serviceCount := 0
	for _, services := range s.services {
		serviceCount += len(services)
	}

	return map[string]interface{}{
		"ports_listening":    portCount,
		"services_registered": serviceCount,
	}
}
