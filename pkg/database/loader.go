package database

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"breadcrumb-pot/pkg/parser"
	"breadcrumb-pot/pkg/types"

	"gopkg.in/yaml.v3"
)

// BatchLoader loads templates into database in batches
type BatchLoader struct {
	db         *DB
	parser     *parser.Parser
	batchSize  int
	workers    int
	verbose    bool
	stats      *LoadStats
	mu         sync.Mutex
}

// LoadStats tracks loading progress
type LoadStats struct {
	TotalFiles      int
	ProcessedFiles  int
	SuccessFiles    int
	FailedFiles     int
	TotalTemplates  int
	TotalEndpoints  int
	StartTime       time.Time
	EndTime         time.Time
	Errors          []string
}

// NewBatchLoader creates a new batch loader
func NewBatchLoader(db *DB, config *types.TemplatesConfig, verbose bool) *BatchLoader {
	return &BatchLoader{
		db:         db,
		parser:     parser.NewParser(config),
		batchSize:  100,  // Process 100 files at a time
		workers:    4,    // Use 4 parallel workers
		verbose:    verbose,
		stats:      &LoadStats{StartTime: time.Now()},
	}
}

// LoadAllTemplates loads all templates from directory into database
func (bl *BatchLoader) LoadAllTemplates(directory string) error {
	bl.log("Scanning directory: %s", directory)

	// Collect all YAML files
	var files []string
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && isYAMLFile(path) {
			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to scan directory: %w", err)
	}

	bl.stats.TotalFiles = len(files)
	bl.log("Found %d template files", bl.stats.TotalFiles)

	// Process files in batches with multiple workers
	return bl.processBatches(files)
}

// processBatches processes files in parallel batches
func (bl *BatchLoader) processBatches(files []string) error {
	// Create work channel
	workChan := make(chan string, bl.batchSize)
	resultChan := make(chan *processResult, bl.batchSize)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < bl.workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for file := range workChan {
				result := bl.processFile(file)
				resultChan <- result
			}
		}(i)
	}

	// Start result collector
	done := make(chan bool)
	go func() {
		for result := range resultChan {
			bl.collectResult(result)

			// Progress indicator
			if bl.verbose && bl.stats.ProcessedFiles%100 == 0 {
				bl.log("Progress: %d/%d files (%.1f%%) - %d templates, %d endpoints",
					bl.stats.ProcessedFiles,
					bl.stats.TotalFiles,
					float64(bl.stats.ProcessedFiles)/float64(bl.stats.TotalFiles)*100,
					bl.stats.TotalTemplates,
					bl.stats.TotalEndpoints,
				)
			}
		}
		done <- true
	}()

	// Send work
	for _, file := range files {
		workChan <- file
	}
	close(workChan)

	// Wait for workers
	wg.Wait()
	close(resultChan)

	// Wait for collector
	<-done

	bl.stats.EndTime = time.Now()
	bl.printSummary()

	return nil
}

type processResult struct {
	File      string
	Success   bool
	Template  *types.NucleiTemplate
	Endpoints int
	Error     string
}

// processFile processes a single template file
func (bl *BatchLoader) processFile(path string) *processResult {
	result := &processResult{
		File: path,
	}

	// Parse template file
	data, err := os.ReadFile(path)
	if err != nil {
		result.Error = fmt.Sprintf("read error: %v", err)
		return result
	}

	var template types.NucleiTemplate
	if err := yaml.Unmarshal(data, &template); err != nil {
		result.Error = fmt.Sprintf("parse error: %v", err)
		return result
	}

	// Validate
	if template.ID == "" {
		result.Error = "missing template ID"
		return result
	}

	// Check if should load based on filters
	if !bl.parser.ShouldLoadTemplate(&template) {
		result.Error = "filtered out"
		return result
	}

	result.Template = &template

	// Store template
	if err := bl.db.StoreTemplate(&template); err != nil {
		result.Error = fmt.Sprintf("db store error: %v", err)
		return result
	}

	// Extract and store endpoints
	endpoints := parser.ExtractVulnerableEndpoints(&template)
	for _, endpoint := range endpoints {
		dbEndpoint := &HTTPEndpointDB{
			TemplateID:  endpoint.TemplateID,
			Method:      endpoint.Method,
			Path:        endpoint.Path,
			Headers:     endpoint.Headers,
			Body:        endpoint.Body,
			Matchers:    endpoint.Matchers,
			CVE:         endpoint.CVE,
			Severity:    endpoint.Severity,
			Description: endpoint.Description,
		}

		if err := bl.db.StoreHTTPEndpoint(dbEndpoint); err != nil {
			// Log but continue
			if bl.verbose {
				bl.log("Warning: failed to store endpoint %s:%s - %v", endpoint.Method, endpoint.Path, err)
			}
		} else {
			result.Endpoints++
		}
	}

	result.Success = true
	return result
}

// collectResult collects processing results
func (bl *BatchLoader) collectResult(result *processResult) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	bl.stats.ProcessedFiles++

	if result.Success {
		bl.stats.SuccessFiles++
		bl.stats.TotalTemplates++
		bl.stats.TotalEndpoints += result.Endpoints
	} else {
		bl.stats.FailedFiles++
		if result.Error != "filtered out" {
			bl.stats.Errors = append(bl.stats.Errors, fmt.Sprintf("%s: %s", result.File, result.Error))
		}
	}
}

// printSummary prints loading summary
func (bl *BatchLoader) printSummary() {
	duration := bl.stats.EndTime.Sub(bl.stats.StartTime)

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Template Loading Complete")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Duration:           %v\n", duration.Round(time.Second))
	fmt.Printf("Total Files:        %d\n", bl.stats.TotalFiles)
	fmt.Printf("Processed:          %d\n", bl.stats.ProcessedFiles)
	fmt.Printf("Success:            %d\n", bl.stats.SuccessFiles)
	fmt.Printf("Failed:             %d\n", bl.stats.FailedFiles)
	fmt.Printf("Templates Loaded:   %d\n", bl.stats.TotalTemplates)
	fmt.Printf("Endpoints Created:  %d\n", bl.stats.TotalEndpoints)
	fmt.Printf("Rate:               %.0f files/sec\n", float64(bl.stats.ProcessedFiles)/duration.Seconds())

	if len(bl.stats.Errors) > 0 {
		fmt.Printf("\nErrors: %d (showing first 10)\n", len(bl.stats.Errors))
		for i, err := range bl.stats.Errors {
			if i >= 10 {
				fmt.Printf("... and %d more errors\n", len(bl.stats.Errors)-10)
				break
			}
			fmt.Printf("  - %s\n", err)
		}
	}
	fmt.Println(strings.Repeat("=", 60))
}

// log prints a log message
func (bl *BatchLoader) log(format string, args ...interface{}) {
	if bl.verbose {
		fmt.Printf("[LOADER] "+format+"\n", args...)
	}
}

// isYAMLFile checks if file is YAML
func isYAMLFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}
