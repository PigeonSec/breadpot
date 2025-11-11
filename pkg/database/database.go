package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"breadcrumb-pot/pkg/types"

	_ "modernc.org/sqlite"
)

// DB wraps the database connection with caching
type DB struct {
	conn          *sql.DB
	cache         *EndpointCache
	templateCount int64
	endpointCount int64
	mu            sync.RWMutex
}

// EndpointCache provides fast in-memory lookup
type EndpointCache struct {
	endpoints map[string]*CachedEndpoint // key: method:path
	mu        sync.RWMutex
	maxSize   int
}

// CachedEndpoint is an in-memory representation
type CachedEndpoint struct {
	ID          int64
	Method      string
	Path        string
	TemplateID  string
	CVE         string
	Severity    string
	Description string
	Headers     map[string]string
	LastUsed    time.Time
}

// NewDB creates a new database connection
func NewDB(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable WAL mode for better concurrency
	if _, err := conn.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("failed to enable WAL: %w", err)
	}

	if _, err := conn.Exec("PRAGMA synchronous=NORMAL"); err != nil {
		return nil, fmt.Errorf("failed to set synchronous mode: %w", err)
	}

	db := &DB{
		conn: conn,
		cache: &EndpointCache{
			endpoints: make(map[string]*CachedEndpoint),
			maxSize:   10000, // Cache up to 10k endpoints
		},
	}

	if err := db.createSchema(); err != nil {
		return nil, err
	}

	return db, nil
}

// createSchema creates database tables
func (db *DB) createSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS templates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		template_id TEXT UNIQUE NOT NULL,
		name TEXT,
		author TEXT,
		severity TEXT,
		description TEXT,
		cve TEXT,
		tags TEXT,
		metadata TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		INDEX idx_template_id (template_id),
		INDEX idx_cve (cve),
		INDEX idx_severity (severity)
	);

	CREATE TABLE IF NOT EXISTS http_endpoints (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		template_id TEXT NOT NULL,
		method TEXT NOT NULL,
		path TEXT NOT NULL,
		headers TEXT,
		body TEXT,
		matchers TEXT,
		cve TEXT,
		severity TEXT,
		description TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (template_id) REFERENCES templates(template_id),
		INDEX idx_method_path (method, path),
		INDEX idx_template (template_id),
		INDEX idx_cve_endpoint (cve)
	);

	CREATE TABLE IF NOT EXISTS dns_queries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		template_id TEXT NOT NULL,
		name TEXT,
		type TEXT,
		class TEXT,
		matchers TEXT,
		cve TEXT,
		severity TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (template_id) REFERENCES templates(template_id)
	);

	CREATE TABLE IF NOT EXISTS tcp_services (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		template_id TEXT NOT NULL,
		inputs TEXT,
		read_size INTEGER,
		matchers TEXT,
		cve TEXT,
		severity TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (template_id) REFERENCES templates(template_id)
	);

	CREATE TABLE IF NOT EXISTS load_stats (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		load_time DATETIME DEFAULT CURRENT_TIMESTAMP,
		templates_loaded INTEGER,
		endpoints_created INTEGER,
		duration_ms INTEGER
	);
	`

	_, err := db.conn.Exec(schema)
	return err
}

// StoreTemplate stores a template in the database
func (db *DB) StoreTemplate(template *types.NucleiTemplate) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Serialize complex fields
	tags, _ := json.Marshal(template.Info.Tags)
	metadata, _ := json.Marshal(template.Metadata)

	_, err := db.conn.Exec(`
		INSERT OR REPLACE INTO templates (template_id, name, author, severity, description, cve, tags, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		template.ID,
		template.Info.Name,
		fmt.Sprint(template.Info.Author),
		template.Info.Severity,
		template.Info.Description,
		template.Info.CVE,
		string(tags),
		string(metadata),
	)

	if err == nil {
		db.templateCount++
	}

	return err
}

// StoreHTTPEndpoint stores an HTTP endpoint
func (db *DB) StoreHTTPEndpoint(endpoint *HTTPEndpointDB) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	headers, _ := json.Marshal(endpoint.Headers)
	matchers, _ := json.Marshal(endpoint.Matchers)

	_, err := db.conn.Exec(`
		INSERT INTO http_endpoints (template_id, method, path, headers, body, matchers, cve, severity, description)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		endpoint.TemplateID,
		endpoint.Method,
		endpoint.Path,
		string(headers),
		endpoint.Body,
		string(matchers),
		endpoint.CVE,
		endpoint.Severity,
		endpoint.Description,
	)

	if err == nil {
		db.endpointCount++
	}

	return err
}

// HTTPEndpointDB represents an endpoint in the database
type HTTPEndpointDB struct {
	ID          int64
	TemplateID  string
	Method      string
	Path        string
	Headers     map[string]string
	Body        string
	Matchers    interface{}
	CVE         string
	Severity    string
	Description string
}

// LookupEndpoint finds an endpoint by method and path
func (db *DB) LookupEndpoint(method, path string) (*CachedEndpoint, error) {
	key := fmt.Sprintf("%s:%s", method, path)

	// Check cache first
	if endpoint := db.cache.Get(key); endpoint != nil {
		return endpoint, nil
	}

	// Query database
	var ep CachedEndpoint
	var headersJSON string

	err := db.conn.QueryRow(`
		SELECT id, method, path, template_id, cve, severity, description, COALESCE(headers, '{}')
		FROM http_endpoints
		WHERE method = ? AND path = ?
		LIMIT 1`,
		method, path,
	).Scan(&ep.ID, &ep.Method, &ep.Path, &ep.TemplateID, &ep.CVE, &ep.Severity, &ep.Description, &headersJSON)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Parse headers
	json.Unmarshal([]byte(headersJSON), &ep.Headers)
	ep.LastUsed = time.Now()

	// Add to cache
	db.cache.Set(key, &ep)

	return &ep, nil
}

// GetAllEndpoints returns all endpoints (for initial loading)
func (db *DB) GetAllEndpoints() ([]*CachedEndpoint, error) {
	rows, err := db.conn.Query(`
		SELECT id, method, path, template_id, cve, severity, description, COALESCE(headers, '{}')
		FROM http_endpoints
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var endpoints []*CachedEndpoint

	for rows.Next() {
		var ep CachedEndpoint
		var headersJSON string

		if err := rows.Scan(&ep.ID, &ep.Method, &ep.Path, &ep.TemplateID, &ep.CVE, &ep.Severity, &ep.Description, &headersJSON); err != nil {
			continue
		}

		json.Unmarshal([]byte(headersJSON), &ep.Headers)
		ep.LastUsed = time.Now()

		endpoints = append(endpoints, &ep)
	}

	return endpoints, nil
}

// GetStats returns database statistics
func (db *DB) GetStats() map[string]interface{} {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return map[string]interface{}{
		"templates_count":   db.templateCount,
		"endpoints_count":   db.endpointCount,
		"cached_endpoints":  len(db.cache.endpoints),
		"cache_max_size":    db.cache.maxSize,
	}
}

// ClearDatabase drops all data (for fresh reload)
func (db *DB) ClearDatabase() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, err := db.conn.Exec(`
		DELETE FROM http_endpoints;
		DELETE FROM dns_queries;
		DELETE FROM tcp_services;
		DELETE FROM templates;
		DELETE FROM load_stats;
		VACUUM;
	`)

	if err == nil {
		db.templateCount = 0
		db.endpointCount = 0
		db.cache.Clear()
	}

	return err
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.conn.Close()
}

// Cache methods

// Get retrieves from cache
func (c *EndpointCache) Get(key string) *CachedEndpoint {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if ep, ok := c.endpoints[key]; ok {
		ep.LastUsed = time.Now()
		return ep
	}
	return nil
}

// Set adds to cache
func (c *EndpointCache) Set(key string, endpoint *CachedEndpoint) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction if cache is full
	if len(c.endpoints) >= c.maxSize {
		// Remove oldest
		var oldestKey string
		var oldestTime time.Time
		for k, v := range c.endpoints {
			if oldestTime.IsZero() || v.LastUsed.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.LastUsed
			}
		}
		delete(c.endpoints, oldestKey)
	}

	c.endpoints[key] = endpoint
}

// Clear clears the cache
func (c *EndpointCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.endpoints = make(map[string]*CachedEndpoint)
}

// WarmCache preloads frequently used endpoints
func (db *DB) WarmCache(limit int) error {
	rows, err := db.conn.Query(`
		SELECT id, method, path, template_id, cve, severity, description, COALESCE(headers, '{}')
		FROM http_endpoints
		ORDER BY RANDOM()
		LIMIT ?`, limit)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var ep CachedEndpoint
		var headersJSON string

		if err := rows.Scan(&ep.ID, &ep.Method, &ep.Path, &ep.TemplateID, &ep.CVE, &ep.Severity, &ep.Description, &headersJSON); err != nil {
			continue
		}

		json.Unmarshal([]byte(headersJSON), &ep.Headers)
		ep.LastUsed = time.Now()

		key := fmt.Sprintf("%s:%s", ep.Method, ep.Path)
		db.cache.Set(key, &ep)
	}

	return nil
}
