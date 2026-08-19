package dashboard

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/ghostguard/ghostguard/internal/model"
)

type Metrics struct {
	mu                sync.RWMutex
	TotalRequests     int64            `json:"total_requests"`
	TotalToolCalls    int64            `json:"total_tool_calls"`
	DeniedCalls       int64            `json:"denied_calls"`
	AllowedCalls      int64            `json:"allowed_calls"`
	AnomaliesDetected int64            `json:"anomalies_detected"`
	ToolCounts        map[string]int64 `json:"tool_counts"`
	PolicyDecisions   map[string]int64 `json:"policy_decisions"`
	LastActivity      time.Time        `json:"last_activity"`
	StartTime         time.Time        `json:"start_time"`
}

type Dashboard struct {
	metrics  *Metrics
	clients  map[chan model.InterceptionEvent]bool
	mu       sync.RWMutex
}

func NewDashboard() *Dashboard {
	return &Dashboard{
		metrics: &Metrics{
			ToolCounts:      make(map[string]int64),
			PolicyDecisions: make(map[string]int64),
			StartTime:       time.Now().UTC(),
		},
		clients: make(map[chan model.InterceptionEvent]bool),
	}
}

func (d *Dashboard) RecordEvent(event *model.InterceptionEvent) {
	d.metrics.mu.Lock()
	defer d.metrics.mu.Unlock()

	d.metrics.TotalRequests++
	d.metrics.TotalToolCalls += int64(len(event.ToolCalls))
	d.metrics.AnomaliesDetected += int64(len(event.Anomalies))
	d.metrics.LastActivity = time.Now().UTC()

	for _, tc := range event.ToolCalls {
		d.metrics.ToolCounts[tc.Name]++
	}

	for _, dec := range event.Decisions {
		d.metrics.PolicyDecisions[string(dec.Action)]++
		switch dec.Action {
		case model.DecisionDeny:
			d.metrics.DeniedCalls++
		case model.DecisionAllow:
			d.metrics.AllowedCalls++
		}
	}

	d.mu.RLock()
	for ch := range d.clients {
		select {
		case ch <- *event:
		default:
		}
	}
	d.mu.RUnlock()
}

type MetricsSnapshot struct {
	TotalRequests     int64            `json:"total_requests"`
	TotalToolCalls    int64            `json:"total_tool_calls"`
	DeniedCalls       int64            `json:"denied_calls"`
	AllowedCalls      int64            `json:"allowed_calls"`
	AnomaliesDetected int64            `json:"anomalies_detected"`
	ToolCounts        map[string]int64 `json:"tool_counts"`
	PolicyDecisions   map[string]int64 `json:"policy_decisions"`
	LastActivity      time.Time        `json:"last_activity"`
	StartTime         time.Time        `json:"start_time"`
}

func (d *Dashboard) GetMetrics() MetricsSnapshot {
	d.metrics.mu.RLock()
	defer d.metrics.mu.RUnlock()
	toolCounts := make(map[string]int64, len(d.metrics.ToolCounts))
	for k, v := range d.metrics.ToolCounts {
		toolCounts[k] = v
	}
	decisions := make(map[string]int64, len(d.metrics.PolicyDecisions))
	for k, v := range d.metrics.PolicyDecisions {
		decisions[k] = v
	}
	return MetricsSnapshot{
		TotalRequests:     d.metrics.TotalRequests,
		TotalToolCalls:    d.metrics.TotalToolCalls,
		DeniedCalls:       d.metrics.DeniedCalls,
		AllowedCalls:      d.metrics.AllowedCalls,
		AnomaliesDetected: d.metrics.AnomaliesDetected,
		ToolCounts:        toolCounts,
		PolicyDecisions:   decisions,
		LastActivity:      d.metrics.LastActivity,
		StartTime:         d.metrics.StartTime,
	}
}

func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/metrics":
		d.handleMetrics(w, r)
	case "/prometheus":
		d.handlePrometheus(w, r)
	case "/events":
		d.handleSSE(w, r)
	case "/health":
		d.handleHealth(w, r)
	case "/", "/index.html":
		d.handleIndex(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (d *Dashboard) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(d.GetMetrics())
}

func (d *Dashboard) handlePrometheus(w http.ResponseWriter, r *http.Request) {
	metrics := d.GetMetrics()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Header().Set("Content-Type", "text/plain")

	lines := []string{
		"# HELP ghostguard_requests_total Total number of requests",
		"# TYPE ghostguard_requests_total counter",
		"ghostguard_requests_total " + formatInt64(metrics.TotalRequests),
		"# HELP ghostguard_tool_calls_total Total number of tool calls",
		"# TYPE ghostguard_tool_calls_total counter",
		"ghostguard_tool_calls_total " + formatInt64(metrics.TotalToolCalls),
		"# HELP ghostguard_denied_total Total number of denied calls",
		"# TYPE ghostguard_denied_total counter",
		"ghostguard_denied_total " + formatInt64(metrics.DeniedCalls),
		"# HELP ghostguard_allowed_total Total number of allowed calls",
		"# TYPE ghostguard_allowed_total counter",
		"ghostguard_allowed_total " + formatInt64(metrics.AllowedCalls),
		"# HELP ghostguard_anomalies_total Total number of anomalies detected",
		"# TYPE ghostguard_anomalies_total counter",
		"ghostguard_anomalies_total " + formatInt64(metrics.AnomaliesDetected),
	}
	for tool, count := range metrics.ToolCounts {
		lines = append(lines,
			"# HELP ghostguard_tool_calls_by_name Tool calls by tool name",
			"# TYPE ghostguard_tool_calls_by_name counter",
			`ghostguard_tool_calls_by_name{tool="`+tool+`"} `+formatInt64(count),
		)
	}
	for action, count := range metrics.PolicyDecisions {
		lines = append(lines,
			"# HELP ghostguard_policy_decisions_total Policy decisions by action",
			"# TYPE ghostguard_policy_decisions_total counter",
			`ghostguard_policy_decisions_total{action="`+action+`"} `+formatInt64(count),
		)
	}

	for _, line := range lines {
		w.Write([]byte(line + "\n"))
	}
}

func formatInt64(v int64) string {
	return fmt.Sprintf("%d", v)
}

func (d *Dashboard) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	eventCh := make(chan model.InterceptionEvent, 100)

	d.mu.Lock()
	d.clients[eventCh] = true
	d.mu.Unlock()

	defer func() {
		d.mu.Lock()
		delete(d.clients, eventCh)
		d.mu.Unlock()
	}()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-eventCh:
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (d *Dashboard) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	io.WriteString(w, dashboardHTML)
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GhostGuard Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff41; padding: 20px; }
        h1 { text-align: center; margin-bottom: 20px; text-shadow: 0 0 10px #00ff41; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .card { background: #111; border: 1px solid #00ff41; border-radius: 8px; padding: 15px; }
        .card h3 { color: #00cc33; font-size: 12px; margin-bottom: 5px; text-transform: uppercase; }
        .card .value { font-size: 28px; font-weight: bold; }
        .card .value.danger { color: #ff0040; }
        .card .value.safe { color: #00ff41; }
        .events { background: #111; border: 1px solid #333; border-radius: 8px; padding: 15px; max-height: 400px; overflow-y: auto; }
        .events h3 { color: #00cc33; margin-bottom: 10px; }
        .event { border-bottom: 1px solid #222; padding: 8px 0; font-size: 13px; }
        .event:last-child { border-bottom: none; }
        .denied { color: #ff0040; }
        .allowed { color: #00ff41; }
        .anomaly { color: #ffaa00; }
        .time { color: #666; }
        .status { text-align: center; margin-bottom: 15px; color: #666; }
    </style>
</head>
<body>
    <h1>GhostGuard Dashboard</h1>
    <div class="status" id="status">Connecting...</div>
    <div class="grid">
        <div class="card"><h3>Total Requests</h3><div class="value" id="total">0</div></div>
        <div class="card"><h3>Tool Calls</h3><div class="value" id="tools">0</div></div>
        <div class="card"><h3>Denied</h3><div class="value danger" id="denied">0</div></div>
        <div class="card"><h3>Allowed</h3><div class="value safe" id="allowed">0</div></div>
        <div class="card"><h3>Anomalies</h3><div class="value anomaly" id="anomalies">0</div></div>
    </div>
    <div class="events">
        <h3>Live Events</h3>
        <div id="event-list"></div>
    </div>
    <script>
        const evtSource = new EventSource('/events');
        const eventList = document.getElementById('event-list');
        const status = document.getElementById('status');
        
        evtSource.onopen = () => { status.textContent = 'Connected'; status.style.color = '#00ff41'; };
        evtSource.onerror = () => { status.textContent = 'Disconnected'; status.style.color = '#ff0040'; };
        
        fetch('/metrics').then(r => r.json()).then(updateMetrics);
        
        evtSource.onmessage = (e) => {
            const event = JSON.parse(e.data);
            const div = document.createElement('div');
            div.className = 'event';
            
            let cls = '';
            let detail = '';
            if (event.decisions && event.decisions.length > 0) {
                const d = event.decisions[0];
                cls = d.action === 'deny' ? 'denied' : d.action === 'allow' ? 'allowed' : '';
                detail = ' [' + d.action + ': ' + d.reason + ']';
            }
            
            div.innerHTML = '<span class="time">' + new Date(event.timestamp).toLocaleTimeString() + '</span> ' +
                event.method + ' ' + event.host + event.path + '<span class="' + cls + '">' + detail + '</span>';
            eventList.insertBefore(div, eventList.firstChild);
            
            if (eventList.children.length > 50) eventList.removeChild(eventList.lastChild);
            
            fetch('/metrics').then(r => r.json()).then(updateMetrics);
        };
        
        function updateMetrics(m) {
            document.getElementById('total').textContent = m.total_requests;
            document.getElementById('tools').textContent = m.total_tool_calls;
            document.getElementById('denied').textContent = m.denied_calls;
            document.getElementById('allowed').textContent = m.allowed_calls;
            document.getElementById('anomalies').textContent = m.anomalies_detected;
        }
    </script>
</body>
</html>`
