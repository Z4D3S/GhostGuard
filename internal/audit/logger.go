package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/ghostguard/ghostguard/internal/model"
)

type Logger struct {
	mu      sync.Mutex
	writer  io.Writer
	encoder *json.Encoder
}

type LogEntry struct {
	Timestamp string              `json:"timestamp"`
	Level     string              `json:"level"`
	Event     *model.InterceptionEvent `json:"event,omitempty"`
	Alert     *model.Alert        `json:"alert,omitempty"`
	Message   string              `json:"message"`
}

func NewLogger(writer io.Writer) *Logger {
	return &Logger{
		writer:  writer,
		encoder: json.NewEncoder(writer),
	}
}

func NewFileLogger(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening audit log file: %w", err)
	}
	return NewLogger(f), nil
}

func (l *Logger) LogEvent(event *model.InterceptionEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     "info",
		Event:     event,
		Message:   fmt.Sprintf("intercepted %s %s on %s", event.Method, event.Path, event.Host),
	}
	return l.encoder.Encode(entry)
}

func (l *Logger) LogAlert(alert *model.Alert) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     string(alert.Severity),
		Alert:     alert,
		Message:   alert.Message,
	}
	return l.encoder.Encode(entry)
}

func (l *Logger) LogDecision(decision *model.PolicyDecision) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     string(decision.Action),
		Message:   fmt.Sprintf("policy %s: %s - %s", decision.PolicyName, decision.Action, decision.Reason),
	}
	return l.encoder.Encode(entry)
}

func (l *Logger) LogMessage(level, msg string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level,
		Message:   msg,
	}
	return l.encoder.Encode(entry)
}
