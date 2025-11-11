package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"breadcrumb-pot/pkg/capture"
	"breadcrumb-pot/pkg/logger"
	"breadcrumb-pot/pkg/parser"
	"breadcrumb-pot/pkg/response"
	"breadcrumb-pot/pkg/types"

	"github.com/gorilla/mux"
)

// HTTPServer handles HTTP/HTTPS honeypot requests
type HTTPServer struct {
	config    *types.HTTPServerConfig
	generator *response.Generator
	logger    *logger.Logger
	capture   *capture.Capture
	router    *mux.Router
	server    *http.Server
	endpoints map[string]parser.VulnerableEndpoint
}

// NewHTTPServer creates a new HTTP server
func NewHTTPServer(
	config *types.HTTPServerConfig,
	generator *response.Generator,
	log *logger.Logger,
	cap *capture.Capture,
) *HTTPServer {
	return &HTTPServer{
		config:    config,
		generator: generator,
		logger:    log,
		capture:   cap,
		router:    mux.NewRouter(),
		endpoints: make(map[string]parser.VulnerableEndpoint),
	}
}

// RegisterEndpoints registers vulnerable endpoints
func (s *HTTPServer) RegisterEndpoints(endpoints []parser.VulnerableEndpoint) {
	for _, endpoint := range endpoints {
		s.registerEndpoint(endpoint)
	}

	// Add catch-all handler for unmatched requests
	s.router.PathPrefix("/").HandlerFunc(s.handleCatchAll)
}

// registerEndpoint registers a single vulnerable endpoint
func (s *HTTPServer) registerEndpoint(endpoint parser.VulnerableEndpoint) {
	// Clean and normalize path
	path := s.normalizePath(endpoint.Path)
	key := fmt.Sprintf("%s:%s", endpoint.Method, path)

	// Store endpoint
	s.endpoints[key] = endpoint

	// Register route
	route := s.router.HandleFunc(path, s.createHandler(endpoint))

	// Set method constraint
	if endpoint.Method != "" {
		route.Methods(endpoint.Method)
	} else {
		route.Methods("GET")
	}

	s.logger.Debug(fmt.Sprintf("Registered endpoint: %s %s (Template: %s, CVE: %s)",
		endpoint.Method, path, endpoint.TemplateID, endpoint.CVE))
}

// normalizePath normalizes URL paths and handles Nuclei template variables
func (s *HTTPServer) normalizePath(path string) string {
	// Remove common Nuclei template variables
	path = strings.ReplaceAll(path, "{{BaseURL}}", "")
	path = strings.ReplaceAll(path, "{{Hostname}}", "")
	path = strings.ReplaceAll(path, "{{Host}}", "")
	path = strings.ReplaceAll(path, "{{RootURL}}", "")
	path = strings.ReplaceAll(path, "{{Path}}", "")

	// Remove any remaining template variables (basic approach)
	// More sophisticated variable handling could be added
	path = strings.TrimSpace(path)

	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return path
}

// createHandler creates a handler for a vulnerable endpoint
func (s *HTTPServer) createHandler(endpoint parser.VulnerableEndpoint) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		// Read request body
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(body)) // Reset for handler

		// Log interaction
		interaction := types.InteractionLog{
			Timestamp:  startTime,
			Protocol:   "HTTP",
			SourceIP:   s.getClientIP(r),
			SourcePort: 0, // Not easily available
			DestPort:   s.config.Port,
			TemplateID: endpoint.TemplateID,
			CVE:        endpoint.CVE,
			Severity:   endpoint.Severity,
			Method:     r.Method,
			Path:       r.URL.Path,
			Headers:    r.Header,
			Body:       string(body),
			Query:      r.URL.RawQuery,
			Metadata: map[string]interface{}{
				"user_agent": r.UserAgent(),
				"referer":    r.Referer(),
			},
		}

		// Handle interactive requests (payload capture)
		s.handleInteractiveRequest(endpoint, w, r)

		// Generate response
		status, headers, responseBody := s.generateInteractiveResponse(endpoint, r)

		// Set headers
		for key, value := range headers {
			w.Header().Set(key, value)
		}

		// Write response
		w.WriteHeader(status)
		w.Write([]byte(responseBody))

		// Update interaction log with response
		interaction.Response = responseBody

		// Log interaction
		s.logger.LogInteraction(interaction)

		s.logger.Info(fmt.Sprintf("HTTP %s %s from %s - Template: %s, CVE: %s, Status: %d, Duration: %v",
			r.Method, r.URL.Path, s.getClientIP(r), endpoint.TemplateID, endpoint.CVE, status, time.Since(startTime)))
	}
}

// handleCatchAll handles unmatched requests
func (s *HTTPServer) handleCatchAll(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Read request body
	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	// Log interaction even for unmatched requests
	interaction := types.InteractionLog{
		Timestamp:  startTime,
		Protocol:   "HTTP",
		SourceIP:   s.getClientIP(r),
		SourcePort: 0,
		DestPort:   s.config.Port,
		TemplateID: "unmatched",
		Method:     r.Method,
		Path:       r.URL.Path,
		Headers:    r.Header,
		Body:       string(body),
		Query:      r.URL.RawQuery,
		Metadata: map[string]interface{}{
			"user_agent": r.UserAgent(),
			"referer":    r.Referer(),
		},
	}

	// Return generic 404 response
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("<html><body><h1>404 Not Found</h1></body></html>"))

	interaction.Response = "404 Not Found"

	// Log interaction
	s.logger.LogInteraction(interaction)

	s.logger.Debug(fmt.Sprintf("HTTP %s %s from %s - Unmatched request, Duration: %v",
		r.Method, r.URL.Path, s.getClientIP(r), time.Since(startTime)))
}

// getClientIP extracts client IP from request
func (s *HTTPServer) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Use RemoteAddr
	parts := strings.Split(r.RemoteAddr, ":")
	if len(parts) > 0 {
		return parts[0]
	}

	return r.RemoteAddr
}

// Start starts the HTTP server
func (s *HTTPServer) Start() error {
	if !s.config.Enabled {
		s.logger.Info("HTTP server disabled")
		return nil
	}

	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	s.logger.Info(fmt.Sprintf("Starting HTTP server on %s (TLS: %v)", addr, s.config.TLS))

	if s.config.TLS {
		if s.config.CertFile == "" || s.config.KeyFile == "" {
			return fmt.Errorf("TLS enabled but cert_file or key_file not specified")
		}
		return s.server.ListenAndServeTLS(s.config.CertFile, s.config.KeyFile)
	}

	return s.server.ListenAndServe()
}

// Stop stops the HTTP server
func (s *HTTPServer) Stop(ctx context.Context) error {
	if s.server == nil {
		return nil
	}

	s.logger.Info("Stopping HTTP server")
	return s.server.Shutdown(ctx)
}

// GetStats returns server statistics
func (s *HTTPServer) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"endpoints_registered": len(s.endpoints),
		"tls_enabled":          s.config.TLS,
		"address":              fmt.Sprintf("%s:%d", s.config.Host, s.config.Port),
	}
}

// GetEndpoints returns a list of registered endpoints
func (s *HTTPServer) GetEndpoints() []map[string]string {
	var endpoints []map[string]string
	for key, endpoint := range s.endpoints {
		endpoints = append(endpoints, map[string]string{
			"key":         key,
			"method":      endpoint.Method,
			"path":        endpoint.Path,
			"template_id": endpoint.TemplateID,
			"cve":         endpoint.CVE,
			"severity":    endpoint.Severity,
		})
	}
	return endpoints
}

// ServeHTTP implements http.Handler for middleware support
func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// AddHealthCheck adds a health check endpoint
func (s *HTTPServer) AddHealthCheck() {
	s.router.HandleFunc("/_health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "healthy",
			"stats":  s.GetStats(),
		})
	}).Methods("GET")

	s.logger.Debug("Added health check endpoint: /_health")
}

// AddStatsEndpoint adds an endpoint to view statistics
func (s *HTTPServer) AddStatsEndpoint() {
	s.router.HandleFunc("/_stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"stats":     s.GetStats(),
			"endpoints": s.GetEndpoints(),
		})
	}).Methods("GET")

	s.logger.Debug("Added stats endpoint: /_stats")
}
