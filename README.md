# GhostGuard

A lightweight Go sidecar proxy that intercepts AI agent calls (OpenAI, Anthropic, MCP) and applies real-time security: policies, anomaly detection, and alerting.

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   AI Agent      │────▶│   GhostGuard     │────▶│  OpenAI/Anthropic│
│  (your code)    │     │   (sidecar)      │     │     API          │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                              │
                              ├─ Policy Engine (OPA/Rego)
                              ├─ Anomaly Detector (Z-score)
                              ├─ Rate Limiter
                              ├─ Dashboard (SSE)
                              ├─ Audit Logger
                              └─ Alert Webhooks
```

## Quick Start

```bash
# Install
go install github.com/ghostguard/ghostguard/cmd/ghostguard@latest

# Generate default config
ghostguard config init

# Run with default policies
ghostguard serve --port 8081 --policies ./policies

# Point your AI agent to the proxy
export OPENAI_BASE_URL=http://localhost:8081/v1
```

## Features

- **HTTP Proxy MITM** — Framework-agnostic, works with any HTTP client
- **OPA/Rego Policies** — Block, allow, or log tool calls based on rules
- **Anomaly Detection** — Z-score rate analysis, entropy detection, sequence analysis
- **Rate Limiting** — Per-host throttling with configurable limits
- **Dry-Run Mode** — Evaluate policies without enforcing (for testing)
- **MCP Server** — stdio transport for AI agents
- **Dashboard** — Real-time SSE dashboard with metrics
- **Alerting** — Webhook, Slack, stdout JSON alerts
- **Audit Logging** — Structured JSON logs for compliance

## Commands

```bash
ghostguard serve [flags]        # Start proxy
ghostguard policy test [flags]  # Test a policy
ghostguard policy lint [flags]  # Lint .rego files
ghostguard config init          # Generate default config.yaml
ghostguard mcp                  # Run as MCP stdio server
ghostguard version              # Print version
```

## Flags (serve)

```
--port              Listen port (default: 8081)
--dash-port         Dashboard port (default: 9090, empty to disable)
--policies          Policy directory (default: ./policies)
--audit-log         Audit log file path
--webhook           Alert webhook URL
--slack             Slack webhook URL
--dry-run           Dry-run mode: evaluate but don't enforce
--rate-limit        Max calls per minute per host (default: 60)
--rate-window       Rate limit window (default: 1m)
--rate-threshold    Rate anomaly Z-score threshold (default: 3.0)
--entropy-threshold Entropy anomaly threshold (default: 4.0)
```

## TLS / CA Trust

GhostGuard generates a self-signed CA on first run. For HTTPS interception to work, your client must trust the GhostGuard CA.

### Option 1: Skip TLS verification (development only)

```bash
export OPENAI_BASE_URL=http://localhost:8081/v1
# Use HTTP, not HTTPS — no TLS issues
```

### Option 2: Trust the CA (production)

GhostGuard logs the CA certificate path on startup. Add it to your trust:

```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ghostguard-ca.pem

# Linux
sudo cp ghostguard-ca.pem /usr/local/share/ca-certificates/ghostguard-ca.crt
sudo update-ca-certificates

# Go programs
export SSL_CERT_FILE=/path/to/ghostguard-ca.pem
export REQUESTS_CA_BUNDLE=/path/to/ghostguard-ca.pem

# Python requests
pip install certifi
export REQUESTS_CA_BUNDLE=$(python -c "import certifi; print(certifi.where())")
```

### Option 3: Export CA for manual trust

```bash
ghostguard serve --port 8081
# CA cert is written to ./ghostguard-ca.pem on startup
```

## Policy Example

```rego
package ghostguard

default allow = false

# Block dangerous tools
deny if {
    input.tool_name == "exec"
}

# Allow safe tools
allow if {
    input.tool_name == "search_web"
}

# Audit mode — log but don't block
log if {
    input.tool_name == "query_database"
}
```

## Testing Policies

```bash
# Quick test
ghostguard policy test --policy policies/default.rego --tool exec --args '{"command":"ls"}'

# Test from JSON file
ghostguard policy test --policy policies/default.rego --input tool_call.json

# Lint all policies
ghostguard policy lint --dir ./policies
```

## Dry-Run Mode

Test policies in production without blocking traffic:

```bash
ghostguard serve --dry-run --port 8081
# All policy violations are logged but requests pass through
```

## Rate Limiting

GhostGuard throttles per-host tool calls:

```bash
ghostguard serve --rate-limit 30 --rate-window 1m
# Max 30 calls per minute per host
```

## MCP Server

Run GhostGuard as an MCP stdio server for direct agent integration:

```bash
ghostguard mcp
```

Provides tools:
- `ghostguard_status` — Get proxy status
- `ghostguard_test_tool` — Test a tool call against policies

## Dashboard

Real-time dashboard at `http://localhost:9090`:
- Total requests, tool calls, denied/allowed counts
- Anomaly detections
- Live event stream (SSE)
- Policy decisions breakdown

## Docker

```bash
docker compose up
```

## Configuration

```bash
ghostguard config init  # Creates config.yaml with defaults
```

```yaml
listen_addr: ":8081"
dash_addr: ":9090"
policy_dir: "./policies"
target_hosts:
  - api.openai.com
  - api.anthropic.com
alert_webhook: "https://hooks.example.com/alerts"
audit_log_path: "./audit.log"
dry_run: false
rate_limit: 60
rate_window: "1m"
detector:
  rate_threshold: 3.0
  entropy_threshold: 4.0
```

## Anomaly Detection

| Anomaly | Description |
|---------|-------------|
| High rate | Tool call rate >3σ above baseline |
| High entropy | Suspiciously random arguments (possible exfiltration) |
| Unknown tool | Tool not seen in baseline period |
| Suspicious sequence | `exec` after `read_file`, etc. |

## License

MIT
