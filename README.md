# GhostGuard

A lightweight security proxy for AI agents. Intercepta llamadas HTTP entre tus agentes AI y los proveedores LLM (OpenAI, Anthropic, Gemini), aplica políticas OPA/Rego en tiempo real, detecta anomalías y genera alertas.

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   AI Agent      │────▶│   GhostGuard     │────▶│  OpenAI/        │
│  (your code)    │◀────│   Proxy :8888    │◀────│  Anthropic/     │
└─────────────────┘     └──────────────────┘     │  Gemini API     │
                               │                 └─────────────────┘
                               ├─ Policy Engine (OPA/Rego)
                               ├─ Anomaly Detector (Z-score)
                               ├─ Rate Limiter
                               ├─ Dashboard (SSE)
                               ├─ Audit Logger
                               └─ Alert Webhooks (Slack)
```

## Quick Start

```bash
# Clone and build
git clone git@github.com-z4d3s:Z4D3S/GhostGuard.git
cd ghostguard
go build -o ghostguard ./cmd/ghostguard

# Run with default policies
./ghostguard serve --port 8888 --policies ./policies

# Point your AI agent to the proxy
export OPENAI_BASE_URL=http://localhost:8888
```

## How It Works

GhostGuard sits between your AI agent and the LLM API. When the agent makes a tool call, GhostGuard evaluates it against your Rego policies before forwarding.

**With a real agent:**
```python
from openai import OpenAI

# Point to GhostGuard instead of OpenAI directly
client = OpenAI(base_url="http://localhost:8888")

# Agent tries exec("rm -rf /")
# GhostGuard → DENY → 403 policy_violation
# Agent tries search_web("golang docs")
# GhostGuard → ALLOW → forwarded to OpenAI
```

**With Docker:**
```yaml
services:
  ghostguard:
    build: .
    ports: ["8888:8888"]
    volumes: ["./policies:/policies"]

  my-agent:
    image: my-agent
    environment:
      - OPENAI_BASE_URL=http://ghostguard:8888
```

## Features

| Feature | Description |
|---------|-------------|
| **OPA/Rego Policies** | Block, allow, or log tool calls with custom rules |
| **Anomaly Detection** | Z-score rate analysis, entropy detection, sequence analysis |
| **Rate Limiting** | Per-host throttling with configurable limits |
| **Dry-Run Mode** | Evaluate policies without enforcing (for testing) |
| **Dashboard** | Real-time SSE dashboard with metrics |
| **Alerting** | Webhook, Slack, stdout JSON alerts |
| **Audit Logging** | Structured JSON logs for compliance |
| **Multi-provider** | OpenAI, Anthropic, Gemini support |

## Commands

```bash
ghostguard serve [flags]    # Start proxy
ghostguard mcp              # Run as MCP stdio server
ghostguard version          # Print version
```

## Flags (serve)

```
--port              Listen port (default: 8888)
--dash-port         Dashboard port (default: 9999, empty to disable)
--policies          Policy directory (default: ./policies)
--config            Config file (default: config.yaml)
--dry-run           Evaluate but don't enforce
--rate-limit        Max calls per minute per host (default: 60)
--rate-window       Rate limit window (default: 1m)
--rate-threshold    Rate anomaly Z-score threshold (default: 3.0)
--entropy-threshold Entropy anomaly threshold (default: 4.0)
--slack             Slack webhook URL
--webhook           Alert webhook URL
--audit-log         Audit log file path
```

## Policy Example

```rego
package ghostguard

default allow = false

# Allow safe tools
allow {
    input.name == "search_web"
}

allow {
    input.name == "get_weather"
}

# Log but allow database queries
allow {
    input.name == "query_database"
}

# Deny everything else (exec, shell, write_file, etc.)
# → default allow = false handles this
```

## Anomaly Detection

| Anomaly | Description |
|---------|-------------|
| High rate | Tool call rate >3σ above baseline |
| High entropy | Suspiciously random arguments (possible exfiltration) |
| Unknown tool | Tool not seen in baseline period |
| Suspicious sequence | `exec` after `read_file`, etc. |

## Dashboard

Real-time dashboard at `http://localhost:9999`:
- Total requests, tool calls, denied/allowed counts
- Anomaly detections
- Live event stream (SSE)
- Policy decisions breakdown

## License

MIT — see [LICENSE](LICENSE)
