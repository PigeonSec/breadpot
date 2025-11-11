package ui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// UIServer serves the real-time capture viewer
type UIServer struct {
	router       *mux.Router
	log          *logrus.Logger
	capturesDir  string
	clients      map[chan []byte]bool
	clientsMutex sync.RWMutex
	stats        *Stats
	statsMutex   sync.RWMutex
}

// Stats holds real-time statistics
type Stats struct {
	TotalInteractions int64                 `json:"total_interactions"`
	CommandCaptures   int64                 `json:"command_captures"`
	FileUploads       int64                 `json:"file_uploads"`
	WebshellDetects   int64                 `json:"webshell_detects"`
	SQLInjections     int64                 `json:"sql_injections"`
	PayloadCaptures   int64                 `json:"payload_captures"`
	TopCVEs           map[string]int        `json:"top_cves"`
	TopIPs            map[string]int        `json:"top_ips"`
	LastUpdate        time.Time             `json:"last_update"`
}

// NewUIServer creates a new UI server
func NewUIServer(capturesDir string, log *logrus.Logger) *UIServer {
	ui := &UIServer{
		router:      mux.NewRouter(),
		log:         log,
		capturesDir: capturesDir,
		clients:     make(map[chan []byte]bool),
		stats: &Stats{
			TopCVEs: make(map[string]int),
			TopIPs:  make(map[string]int),
		},
	}

	ui.setupRoutes()
	return ui
}

// setupRoutes configures HTTP routes
func (ui *UIServer) setupRoutes() {
	ui.router.HandleFunc("/", ui.handleIndex).Methods("GET")
	ui.router.HandleFunc("/api/stats", ui.handleStats).Methods("GET")
	ui.router.HandleFunc("/api/interactions", ui.handleInteractions).Methods("GET")
	ui.router.HandleFunc("/api/captures/{type}", ui.handleCaptures).Methods("GET")
	ui.router.HandleFunc("/api/captures/{type}/{file}", ui.handleCaptureFile).Methods("GET")
	ui.router.HandleFunc("/api/stream", ui.handleSSE).Methods("GET")
}

// Start starts the UI server
func (ui *UIServer) Start(port int) error {
	ui.log.Infof("Starting UI server on :%d", port)

	// Start background stats updater
	go ui.updateStatsLoop()

	// Start interaction watcher
	go ui.watchInteractions()

	return http.ListenAndServe(fmt.Sprintf(":%d", port), ui.router)
}

// handleIndex serves the main UI
func (ui *UIServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>breadcrumb-pot</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'SF Mono', Monaco, 'Courier New', monospace;
            background: #000;
            color: #0f0;
            padding: 20px;
            font-size: 13px;
            line-height: 1.6;
        }
        .terminal {
            max-width: 1400px;
            margin: 0 auto;
        }
        .prompt { color: #0f0; }
        .prompt:before { content: '$ '; color: #0f0; }
        h1 {
            font-size: 14px;
            font-weight: normal;
            margin-bottom: 20px;
            color: #0f0;
        }
        .stats {
            margin: 20px 0;
            border-top: 1px solid #333;
            border-bottom: 1px solid #333;
            padding: 10px 0;
        }
        .stat-line {
            display: flex;
            gap: 30px;
            margin: 5px 0;
            font-size: 12px;
        }
        .stat-label { color: #666; min-width: 120px; }
        .stat-value { color: #0f0; }
        .tabs {
            margin: 20px 0;
            display: flex;
            gap: 15px;
            border-bottom: 1px solid #333;
            padding-bottom: 10px;
        }
        .tab {
            cursor: pointer;
            color: #666;
            padding: 5px 10px;
            border: 1px solid transparent;
        }
        .tab:hover { color: #0f0; }
        .tab.active {
            color: #0f0;
            border: 1px solid #333;
        }
        .feed {
            margin-top: 20px;
            max-height: calc(100vh - 350px);
            overflow-y: auto;
        }
        .entry {
            margin: 10px 0;
            padding: 8px 0;
            border-bottom: 1px solid #111;
            font-size: 12px;
        }
        .entry.new { animation: flash 0.5s; }
        @keyframes flash { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .timestamp { color: #666; margin-right: 10px; }
        .method { color: #ff0; margin-right: 10px; }
        .path { color: #0ff; margin-right: 10px; }
        .ip { color: #f0f; }
        .cve { color: #f00; margin-left: 10px; }
        .severity-critical { color: #f00; }
        .severity-high { color: #f80; }
        .severity-medium { color: #ff0; }
        .severity-low { color: #0f0; }
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #000; }
        ::-webkit-scrollbar-thumb { background: #333; }
        ::-webkit-scrollbar-thumb:hover { background: #555; }
        .blink { animation: blink 1s infinite; }
        @keyframes blink { 0%, 50% { opacity: 1; } 51%, 100% { opacity: 0; } }
        .capture-list { list-style: none; }
        .capture-list li {
            padding: 5px 0;
            border-bottom: 1px solid #111;
            cursor: pointer;
        }
        .capture-list li:hover { color: #ff0; }
        pre {
            background: #111;
            padding: 15px;
            overflow-x: auto;
            margin: 10px 0;
            border: 1px solid #333;
        }
        button {
            background: #000;
            color: #0f0;
            border: 1px solid #333;
            padding: 5px 15px;
            cursor: pointer;
            font-family: inherit;
            font-size: 12px;
        }
        button:hover { border-color: #0f0; }
    </style>
</head>
<body>
    <div class="terminal">
        <div class="prompt">breadcrumb-pot --monitor</div>
        <h1>[LIVE CAPTURE FEED] <span class="blink">●</span></h1>

        <div class="stats">
            <div class="stat-line">
                <span class="stat-label">interactions</span><span class="stat-value" id="total">0</span>
                <span class="stat-label">commands</span><span class="stat-value" id="commands">0</span>
                <span class="stat-label">files</span><span class="stat-value" id="files">0</span>
                <span class="stat-label">webshells</span><span class="stat-value" id="webshells">0</span>
                <span class="stat-label">sql</span><span class="stat-value" id="sql">0</span>
                <span class="stat-label">payloads</span><span class="stat-value" id="payloads">0</span>
            </div>
        </div>

        <div class="tabs">
            <div class="tab active" onclick="switchTab('interactions')">live</div>
            <div class="tab" onclick="switchTab('commands')">commands</div>
            <div class="tab" onclick="switchTab('files')">files</div>
            <div class="tab" onclick="switchTab('webshells')">webshells</div>
            <div class="tab" onclick="switchTab('sql')">sql</div>
            <div class="tab" onclick="switchTab('payloads')">payloads</div>
        </div>

        <div class="feed" id="content"></div>
    </div>

    <script>
        let currentTab = 'interactions';
        let eventSource = null;

        function connectSSE() {
            eventSource = new EventSource('/api/stream');
            eventSource.addEventListener('stats', (e) => updateStats(JSON.parse(e.data)));
            eventSource.addEventListener('interaction', (e) => {
                if (currentTab === 'interactions') addInteraction(JSON.parse(e.data));
            });
            eventSource.onerror = () => setTimeout(connectSSE, 5000);
        }

        function updateStats(stats) {
            document.getElementById('total').textContent = stats.total_interactions || 0;
            document.getElementById('commands').textContent = stats.command_captures || 0;
            document.getElementById('files').textContent = stats.file_uploads || 0;
            document.getElementById('webshells').textContent = stats.webshell_detects || 0;
            document.getElementById('sql').textContent = stats.sql_injections || 0;
            document.getElementById('payloads').textContent = stats.payload_captures || 0;
        }

        function addInteraction(int) {
            const content = document.getElementById('content');
            const div = document.createElement('div');
            div.className = 'entry new';
            
            const time = (int.timestamp || '').split('T')[1]?.split('+')[0] || 'unknown';
            const method = int.method || 'GET';
            const path = int.path || '/';
            const ip = int.source_ip || 'unknown';
            const cve = int.cve || int.template_id || '';
            const severity = int.severity || '';

            let html = '<span class="timestamp">' + time + '</span>';
            html += '<span class="method">' + method + '</span>';
            html += '<span class="path">' + path + '</span>';
            html += '<span class="ip">' + ip + '</span>';
            
            if (cve && cve !== 'unknown' && cve !== 'unmatched') {
                html += '<span class="cve">[' + cve + ']</span>';
            }
            if (severity && severity !== 'unknown') {
                html += '<span class="severity-' + severity + '">[' + severity + ']</span>';
            }

            div.innerHTML = html;
            content.insertBefore(div, content.firstChild);
            
            setTimeout(() => div.classList.remove('new'), 500);
            while (content.children.length > 100) content.removeChild(content.lastChild);
        }

        async function switchTab(tab) {
            currentTab = tab;
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            event.target.classList.add('active');

            const content = document.getElementById('content');

            if (tab === 'interactions') {
                await loadInteractions();
            } else {
                await loadCaptures(tab);
            }
        }

        async function loadInteractions() {
            const content = document.getElementById('content');
            content.innerHTML = '<div class="entry">loading...</div>';

            try {
                const response = await fetch('/api/interactions?limit=100');
                const interactions = await response.json();
                content.innerHTML = '';
                interactions.forEach(int => addInteraction(int));
                if (interactions.length === 0) {
                    content.innerHTML = '<div class="entry">no interactions yet</div>';
                }
            } catch (e) {
                content.innerHTML = '<div class="entry">error: ' + e.message + '</div>';
            }
        }

        async function loadCaptures(type) {
            const content = document.getElementById('content');
            content.innerHTML = '<div class="entry">loading...</div>';

            try {
                const response = await fetch('/api/captures/' + type);
                const captures = await response.json();
                content.innerHTML = '';

                if (captures.length === 0) {
                    content.innerHTML = '<div class="entry">no ' + type + ' captured</div>';
                    return;
                }

                const ul = document.createElement('ul');
                ul.className = 'capture-list';
                captures.forEach(cap => {
                    const li = document.createElement('li');
                    li.textContent = cap.name + ' (' + cap.size + ')';
                    li.onclick = () => viewCapture(type, cap.name);
                    ul.appendChild(li);
                });
                content.appendChild(ul);
            } catch (e) {
                content.innerHTML = '<div class="entry">error: ' + e.message + '</div>';
            }
        }

        async function viewCapture(type, file) {
            const content = document.getElementById('content');
            content.innerHTML = '<div class="entry">loading...</div>';

            try {
                const response = await fetch('/api/captures/' + type + '/' + file);
                const text = await response.text();

                content.innerHTML = '<button onclick="switchTab(\'' + type + '\')">back</button>' +
                    '<h2 style="margin: 15px 0; font-size: 13px; color: #0f0;">' + file + '</h2>' +
                    '<pre>' + escapeHtml(text) + '</pre>';
            } catch (e) {
                content.innerHTML = '<div class="entry">error: ' + e.message + '</div>';
            }
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Init
        connectSSE();
        loadInteractions();
        setInterval(() => fetch('/api/stats').then(r => r.json()).then(updateStats), 2000);
    </script>
</body>
</html>
`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleStats returns current statistics
func (ui *UIServer) handleStats(w http.ResponseWriter, r *http.Request) {
	ui.statsMutex.RLock()
	defer ui.statsMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ui.stats)
}

// handleInteractions returns recent interactions
func (ui *UIServer) handleInteractions(w http.ResponseWriter, r *http.Request) {
	interactionsFile := filepath.Join(ui.capturesDir, "interactions.jsonl")

	file, err := os.Open(interactionsFile)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}
	defer file.Close()

	// Initialize as empty array
	interactions := []map[string]interface{}{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		var interaction map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &interaction); err == nil {
			interactions = append(interactions, interaction)
		}
	}

	// Return last 50 interactions
	if len(interactions) > 50 {
		interactions = interactions[len(interactions)-50:]
	}

	// Reverse order (newest first)
	for i, j := 0, len(interactions)-1; i < j; i, j = i+1, j-1 {
		interactions[i], interactions[j] = interactions[j], interactions[i]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(interactions)
}

// handleCaptures lists captures of a specific type
func (ui *UIServer) handleCaptures(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	captureType := vars["type"]

	captureDir := filepath.Join(ui.capturesDir, captureType)

	// Initialize as empty array, not nil
	files := []map[string]string{}

	filepath.WalkDir(captureDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}

		// Skip metadata files
		if filepath.Ext(path) == ".meta" || filepath.Ext(path) == ".analysis" {
			return nil
		}

		info, _ := d.Info()
		files = append(files, map[string]string{
			"name":     d.Name(),
			"size":     fmt.Sprintf("%d bytes", info.Size()),
			"modified": info.ModTime().Format("2006-01-02 15:04:05"),
		})

		return nil
	})

	// Sort by modification time (newest first)
	sort.Slice(files, func(i, j int) bool {
		return files[i]["modified"] > files[j]["modified"]
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}

// handleCaptureFile serves a specific capture file
func (ui *UIServer) handleCaptureFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	captureType := vars["type"]
	fileName := vars["file"]

	filePath := filepath.Join(ui.capturesDir, captureType, fileName)

	// Security check
	if !filepath.HasPrefix(filePath, ui.capturesDir) {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(data)
}

// handleSSE handles Server-Sent Events for live updates
func (ui *UIServer) handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Create channel for this client
	messageChan := make(chan []byte, 10)

	ui.clientsMutex.Lock()
	ui.clients[messageChan] = true
	ui.clientsMutex.Unlock()

	// Remove client on disconnect
	defer func() {
		ui.clientsMutex.Lock()
		delete(ui.clients, messageChan)
		ui.clientsMutex.Unlock()
		close(messageChan)
	}()

	// Send initial stats
	ui.statsMutex.RLock()
	statsData, _ := json.Marshal(ui.stats)
	ui.statsMutex.RUnlock()
	fmt.Fprintf(w, "event: stats\ndata: %s\n\n", statsData)
	w.(http.Flusher).Flush()

	// Listen for messages or client disconnect
	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case msg := <-messageChan:
			fmt.Fprintf(w, "%s\n\n", msg)
			w.(http.Flusher).Flush()
		}
	}
}

// broadcastToClients sends message to all connected clients
func (ui *UIServer) broadcastToClients(eventType string, data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return
	}

	message := []byte(fmt.Sprintf("event: %s\ndata: %s", eventType, jsonData))

	ui.clientsMutex.RLock()
	defer ui.clientsMutex.RUnlock()

	for client := range ui.clients {
		select {
		case client <- message:
		default:
			// Client buffer full, skip
		}
	}
}

// updateStatsLoop periodically updates statistics
func (ui *UIServer) updateStatsLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ui.updateStats()

		// Broadcast to clients
		ui.statsMutex.RLock()
		ui.broadcastToClients("stats", ui.stats)
		ui.statsMutex.RUnlock()
	}
}

// updateStats recalculates statistics from captures
func (ui *UIServer) updateStats() {
	ui.statsMutex.Lock()
	defer ui.statsMutex.Unlock()

	// Count files in each directory
	ui.stats.CommandCaptures = ui.countFiles("commands")
	ui.stats.FileUploads = ui.countFiles("files")
	ui.stats.WebshellDetects = ui.countFiles("webshells")
	ui.stats.SQLInjections = ui.countFiles("sql")
	ui.stats.PayloadCaptures = ui.countFiles("payloads")

	// Parse interactions.jsonl for stats
	interactionsFile := filepath.Join(ui.capturesDir, "interactions.jsonl")
	file, err := os.Open(interactionsFile)
	if err != nil {
		return
	}
	defer file.Close()

	topCVEs := make(map[string]int)
	topIPs := make(map[string]int)
	var count int64

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var interaction map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &interaction); err == nil {
			count++

			if cve, ok := interaction["cve"].(string); ok && cve != "" && cve != "unknown" {
				topCVEs[cve]++
			}

			if ip, ok := interaction["source_ip"].(string); ok && ip != "" {
				topIPs[ip]++
			}
		}
	}

	ui.stats.TotalInteractions = count
	ui.stats.TopCVEs = topCVEs
	ui.stats.TopIPs = topIPs
	ui.stats.LastUpdate = time.Now()
}

// countFiles counts non-metadata files in a directory
func (ui *UIServer) countFiles(subdir string) int64 {
	var count int64
	dir := filepath.Join(ui.capturesDir, subdir)

	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}

		// Skip metadata files
		ext := filepath.Ext(path)
		if ext != ".meta" && ext != ".analysis" {
			count++
		}

		return nil
	})

	return count
}

// watchInteractions watches for new interactions and broadcasts them
func (ui *UIServer) watchInteractions() {
	interactionsFile := filepath.Join(ui.capturesDir, "interactions.jsonl")

	var lastSize int64
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		info, err := os.Stat(interactionsFile)
		if err != nil {
			continue
		}

		if info.Size() > lastSize {
			// File has grown, read new lines
			file, err := os.Open(interactionsFile)
			if err != nil {
				continue
			}

			file.Seek(lastSize, 0)
			scanner := bufio.NewScanner(file)

			for scanner.Scan() {
				var interaction map[string]interface{}
				if err := json.Unmarshal(scanner.Bytes(), &interaction); err == nil {
					ui.broadcastToClients("interaction", interaction)
				}
			}

			lastSize = info.Size()
			file.Close()
		}
	}
}
