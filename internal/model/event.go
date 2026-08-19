package model

import (
	"encoding/json"
	"time"
)

type ToolCall struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
	RawArgs   string                 `json:"raw_args,omitempty"`
}

type ToolResult struct {
	ToolCallID string `json:"tool_call_id"`
	Content    string `json:"content"`
	IsError    bool   `json:"is_error"`
}

type DecisionAction string

const (
	DecisionAllow DecisionAction = "allow"
	DecisionDeny  DecisionAction = "deny"
	DecisionLog   DecisionAction = "log"
)

type PolicyDecision struct {
	Action     DecisionAction `json:"action"`
	PolicyName string         `json:"policy_name"`
	Reason     string         `json:"reason"`
	Timestamp  time.Time      `json:"timestamp"`
}

type AnomalyType string

const (
	AnomalyHighRate      AnomalyType = "high_rate"
	AnomalyHighEntropy   AnomalyType = "high_entropy"
	AnomalyUnknownTool   AnomalyType = "unknown_tool"
	AnomalySuspiciousSeq AnomalyType = "suspicious_sequence"
)

type Anomaly struct {
	Type        AnomalyType     `json:"type"`
	ToolCall    *ToolCall       `json:"tool_call,omitempty"`
	Score       float64         `json:"score"`
	Threshold   float64         `json:"threshold"`
	Description string          `json:"description"`
	Timestamp   time.Time       `json:"timestamp"`
	Details     json.RawMessage `json:"details,omitempty"`
}

type AlertSeverity string

const (
	AlertInfo     AlertSeverity = "info"
	AlertWarning  AlertSeverity = "warning"
	AlertCritical AlertSeverity = "critical"
)

type Alert struct {
	ID         string        `json:"id"`
	Severity   AlertSeverity `json:"severity"`
	Source     string        `json:"source"`
	Title      string        `json:"title"`
	Message    string        `json:"message"`
	Anomaly    *Anomaly      `json:"anomaly,omitempty"`
	Decision   *PolicyDecision `json:"decision,omitempty"`
	Timestamp  time.Time     `json:"timestamp"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type InterceptionEvent struct {
	ID           string          `json:"id"`
	Method       string          `json:"method"`
	Path         string          `json:"path"`
	Host         string          `json:"host"`
	ToolCalls    []ToolCall      `json:"tool_calls,omitempty"`
	ToolResults  []ToolResult    `json:"tool_results,omitempty"`
	Decisions    []PolicyDecision `json:"decisions,omitempty"`
	Anomalies    []Anomaly       `json:"anomalies,omitempty"`
	Alerts       []Alert         `json:"alerts,omitempty"`
	RequestSize  int             `json:"request_size"`
	ResponseSize int             `json:"response_size"`
	Duration     time.Duration   `json:"duration"`
	Timestamp    time.Time       `json:"timestamp"`
	UpstreamStatus int           `json:"upstream_status,omitempty"`
}

type OpenAIRequest struct {
	Model    string          `json:"model"`
	Messages json.RawMessage `json:"messages"`
	Tools    json.RawMessage `json:"tools,omitempty"`
}

type OpenAIResponse struct {
	ID      string `json:"id"`
	Choices []struct {
		Message struct {
			Content   string        `json:"content"`
			ToolCalls []interface{} `json:"tool_calls,omitempty"`
		} `json:"message"`
	} `json:"choices"`
}

type AnthropicRequest struct {
	Model     string          `json:"model"`
	Messages  json.RawMessage `json:"messages"`
	Tools     json.RawMessage `json:"tools,omitempty"`
	MaxTokens int             `json:"max_tokens"`
}

type AnthropicResponse struct {
	ID    string `json:"id"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text,omitempty"`
	} `json:"content"`
}
