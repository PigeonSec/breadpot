package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"breadcrumb-pot/pkg/types"

	"github.com/sirupsen/logrus"
)

// Logger handles logging for the honeypot
type Logger struct {
	log              *logrus.Logger
	config           *types.LoggingConfig
	interactionFile  *os.File
	interactionMutex sync.Mutex
	stats            *Statistics
}

// Statistics tracks honeypot statistics
type Statistics struct {
	mu                  sync.RWMutex
	TotalInteractions   int64
	HTTPInteractions    int64
	DNSInteractions     int64
	TCPInteractions     int64
	UniqueIPs           map[string]bool
	CVEsTriggered       map[string]int64
	TemplatesTriggered  map[string]int64
	TopPaths            map[string]int64
	StartTime           time.Time
}

// NewLogger creates a new logger
func NewLogger(config *types.LoggingConfig) (*Logger, error) {
	log := logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	log.SetLevel(level)

	// Set log format
	if config.Format == "json" {
		log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
		})
	} else {
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
		})
	}

	// Set output
	if config.File != "" {
		// Create log directory if needed
		logDir := filepath.Dir(config.File)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}

		// Open log file
		file, err := os.OpenFile(config.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		log.SetOutput(file)
	} else {
		log.SetOutput(os.Stdout)
	}

	// Open interaction log file
	var interactionFile *os.File
	if config.File != "" {
		interactionPath := getInteractionLogPath(config.File)

		// Ensure captures directory exists
		capturesDir := filepath.Dir(interactionPath)
		if err := os.MkdirAll(capturesDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create captures directory: %w", err)
		}

		interactionFile, err = os.OpenFile(interactionPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open interaction log file: %w", err)
		}
	}

	return &Logger{
		log:             log,
		config:          config,
		interactionFile: interactionFile,
		stats: &Statistics{
			UniqueIPs:          make(map[string]bool),
			CVEsTriggered:      make(map[string]int64),
			TemplatesTriggered: make(map[string]int64),
			TopPaths:           make(map[string]int64),
			StartTime:          time.Now(),
		},
	}, nil
}

// getInteractionLogPath generates the interaction log file path
func getInteractionLogPath(logFile string) string {
	// Store all interactions under captures/ directory for better organization
	return "captures/interactions.jsonl"
}

// LogInteraction logs an interaction to the interaction file
func (l *Logger) LogInteraction(interaction types.InteractionLog) {
	// Update statistics
	l.updateStats(interaction)

	// Write to interaction log file
	if l.interactionFile != nil {
		l.interactionMutex.Lock()
		defer l.interactionMutex.Unlock()

		data, err := json.Marshal(interaction)
		if err != nil {
			l.Error(fmt.Sprintf("Failed to marshal interaction: %v", err))
			return
		}

		l.interactionFile.Write(data)
		l.interactionFile.Write([]byte("\n"))
		l.interactionFile.Sync()
	}
}

// updateStats updates statistics based on interaction
func (l *Logger) updateStats(interaction types.InteractionLog) {
	l.stats.mu.Lock()
	defer l.stats.mu.Unlock()

	l.stats.TotalInteractions++

	switch interaction.Protocol {
	case "HTTP":
		l.stats.HTTPInteractions++
		if interaction.Path != "" {
			l.stats.TopPaths[interaction.Path]++
		}
	case "DNS":
		l.stats.DNSInteractions++
	case "TCP":
		l.stats.TCPInteractions++
	}

	if interaction.SourceIP != "" {
		l.stats.UniqueIPs[interaction.SourceIP] = true
	}

	if interaction.CVE != "" {
		l.stats.CVEsTriggered[interaction.CVE]++
	}

	if interaction.TemplateID != "" && interaction.TemplateID != "unmatched" {
		l.stats.TemplatesTriggered[interaction.TemplateID]++
	}
}

// GetStats returns current statistics
func (l *Logger) GetStats() map[string]interface{} {
	l.stats.mu.RLock()
	defer l.stats.mu.RUnlock()

	uptime := time.Since(l.stats.StartTime)

	return map[string]interface{}{
		"total_interactions":  l.stats.TotalInteractions,
		"http_interactions":   l.stats.HTTPInteractions,
		"dns_interactions":    l.stats.DNSInteractions,
		"tcp_interactions":    l.stats.TCPInteractions,
		"unique_ips":          len(l.stats.UniqueIPs),
		"cves_triggered":      l.stats.CVEsTriggered,
		"templates_triggered": l.stats.TemplatesTriggered,
		"top_paths":           l.getTopN(l.stats.TopPaths, 10),
		"uptime_seconds":      uptime.Seconds(),
		"start_time":          l.stats.StartTime,
	}
}

// getTopN returns top N items from a map
func (l *Logger) getTopN(m map[string]int64, n int) map[string]int64 {
	result := make(map[string]int64)

	// Simple implementation - could be optimized with heap
	for i := 0; i < n; i++ {
		var maxKey string
		var maxVal int64

		for k, v := range m {
			if _, exists := result[k]; !exists && v > maxVal {
				maxKey = k
				maxVal = v
			}
		}

		if maxKey == "" {
			break
		}

		result[maxKey] = maxVal
	}

	return result
}

// Debug logs a debug message
func (l *Logger) Debug(msg string) {
	l.log.Debug(msg)
}

// Info logs an info message
func (l *Logger) Info(msg string) {
	l.log.Info(msg)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string) {
	l.log.Warn(msg)
}

// Error logs an error message
func (l *Logger) Error(msg string) {
	l.log.Error(msg)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string) {
	l.log.Fatal(msg)
}

// WithFields returns a logger with fields
func (l *Logger) WithFields(fields map[string]interface{}) *logrus.Entry {
	return l.log.WithFields(logrus.Fields(fields))
}

// Close closes the logger and any open files
func (l *Logger) Close() error {
	if l.interactionFile != nil {
		return l.interactionFile.Close()
	}
	return nil
}

// PrintStats prints statistics to console
func (l *Logger) PrintStats() {
	stats := l.GetStats()

	fmt.Println("\n===== Honeypot Statistics =====")
	fmt.Printf("Uptime: %.2f seconds\n", stats["uptime_seconds"])
	fmt.Printf("Total Interactions: %d\n", stats["total_interactions"])
	fmt.Printf("  HTTP: %d\n", stats["http_interactions"])
	fmt.Printf("  DNS:  %d\n", stats["dns_interactions"])
	fmt.Printf("  TCP:  %d\n", stats["tcp_interactions"])
	fmt.Printf("Unique IPs: %d\n", stats["unique_ips"])

	if cves, ok := stats["cves_triggered"].(map[string]int64); ok && len(cves) > 0 {
		fmt.Println("\nCVEs Triggered:")
		for cve, count := range cves {
			fmt.Printf("  %s: %d\n", cve, count)
		}
	}

	if templates, ok := stats["templates_triggered"].(map[string]int64); ok && len(templates) > 0 {
		fmt.Println("\nTop Templates Triggered:")
		for template, count := range templates {
			fmt.Printf("  %s: %d\n", template, count)
		}
	}

	if paths, ok := stats["top_paths"].(map[string]int64); ok && len(paths) > 0 {
		fmt.Println("\nTop Paths Accessed:")
		for path, count := range paths {
			fmt.Printf("  %s: %d\n", path, count)
		}
	}

	fmt.Println("===============================\n")
}

// RotateLogs rotates log files based on configuration
func (l *Logger) RotateLogs() error {
	// This is a simplified version
	// In production, you might want to use a proper log rotation library
	if l.config.MaxSize <= 0 {
		return nil
	}

	// Check file size
	if l.interactionFile != nil {
		info, err := l.interactionFile.Stat()
		if err != nil {
			return err
		}

		maxSize := int64(l.config.MaxSize) * 1024 * 1024 // Convert MB to bytes
		if info.Size() > maxSize {
			l.Info("Rotating interaction log file")

			// Close current file
			l.interactionFile.Close()

			// Rename current file
			oldPath := l.interactionFile.Name()
			newPath := fmt.Sprintf("%s.%d", oldPath, time.Now().Unix())
			os.Rename(oldPath, newPath)

			// Open new file
			file, err := os.OpenFile(oldPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				return err
			}
			l.interactionFile = file

			// Clean up old files
			l.cleanupOldLogs(oldPath)
		}
	}

	return nil
}

// cleanupOldLogs removes old log files based on max_backups config
func (l *Logger) cleanupOldLogs(basePath string) {
	if l.config.MaxBackups <= 0 {
		return
	}

	// List backup files
	dir := filepath.Dir(basePath)
	pattern := filepath.Base(basePath) + ".*"

	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return
	}

	// Remove oldest files if exceeding max_backups
	if len(matches) > l.config.MaxBackups {
		// Sort by modification time and remove oldest
		for i := 0; i < len(matches)-l.config.MaxBackups; i++ {
			os.Remove(matches[i])
		}
	}
}
