package audit

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ghostguard/ghostguard/internal/model"
)

func TestLogMessage(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf)

	err := l.LogMessage("info", "test message")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log entry: %v", err)
	}

	if entry.Level != "info" {
		t.Errorf("expected level 'info', got '%s'", entry.Level)
	}
	if entry.Message != "test message" {
		t.Errorf("expected message 'test message', got '%s'", entry.Message)
	}
	if entry.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
}

func TestLogDecision(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf)

	decision := &model.PolicyDecision{
		Action:     model.DecisionDeny,
		PolicyName: "test",
		Reason:     "dangerous",
	}

	err := l.LogDecision(decision)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log entry: %v", err)
	}

	if entry.Level != "deny" {
		t.Errorf("expected level 'deny', got '%s'", entry.Level)
	}
}

func TestLogAlert(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf)

	alert := &model.Alert{
		ID:       "alert-1",
		Severity: model.AlertCritical,
		Source:   "detector",
		Title:    "Anomaly",
		Message:  "high rate",
	}

	err := l.LogAlert(alert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log entry: %v", err)
	}

	if entry.Level != "critical" {
		t.Errorf("expected level 'critical', got '%s'", entry.Level)
	}
	if entry.Alert == nil {
		t.Error("expected alert in entry")
	}
}

func TestLogEvent(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf)

	event := &model.InterceptionEvent{
		ID:     "event-1",
		Method: "POST",
		Path:   "/v1/chat/completions",
		Host:   "api.openai.com",
	}

	err := l.LogEvent(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log entry: %v", err)
	}

	if entry.Level != "info" {
		t.Errorf("expected level 'info', got '%s'", entry.Level)
	}
	if entry.Event == nil {
		t.Error("expected event in entry")
	}
}

func TestConcurrentLogging(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf)

	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func() {
			l.LogMessage("info", "concurrent")
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 100 {
		t.Errorf("expected 100 log lines, got %d", len(lines))
	}
}
