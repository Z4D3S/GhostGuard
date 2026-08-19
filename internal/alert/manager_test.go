package alert

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/ghostguard/ghostguard/internal/model"
)

func TestStdoutSinkSend(t *testing.T) {
	var buf bytes.Buffer
	sink := NewStdoutSink(&buf)

	alert := &model.Alert{
		ID:       "test-1",
		Severity: model.AlertWarning,
		Source:   "test",
		Title:    "Test Alert",
		Message:  "test message",
		Timestamp: time.Now().UTC(),
	}

	if err := sink.Send(alert); err != nil {
		t.Fatalf("send: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Error("expected output from stdout sink")
	}

	// Output format: [ALERT][severity] <json>\n
	// Find the JSON part after the prefix
	jsonStart := 0
	for i, ch := range output {
		if ch == '{' {
			jsonStart = i
			break
		}
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(output[jsonStart:]), &parsed); err != nil {
		t.Errorf("invalid JSON output: %v", err)
	}

	if !bytes.Contains([]byte(output), []byte("test-1")) {
		t.Error("output should contain alert ID")
	}
}

func TestManagerAlert(t *testing.T) {
	var buf bytes.Buffer
	sink := NewStdoutSink(&buf)
	mgr := NewManager(sink)

	alert := &model.Alert{
		ID:        "mgr-1",
		Severity:  model.AlertCritical,
		Source:    "test",
		Title:     "Critical",
		Message:   "something bad",
		Timestamp: time.Now().UTC(),
	}

	if err := mgr.Alert(alert); err != nil {
		t.Fatalf("alert: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("expected output from manager")
	}
}

func TestManagerAlertAnomaly(t *testing.T) {
	var buf bytes.Buffer
	sink := NewStdoutSink(&buf)
	mgr := NewManager(sink)

	anomaly := &model.Anomaly{
		Type:        model.AnomalyHighRate,
		Score:       5.0,
		Threshold:   3.0,
		Description: "high rate detected",
		Timestamp:   time.Now().UTC(),
	}

	if err := mgr.AlertAnomaly(anomaly); err != nil {
		t.Fatalf("alert anomaly: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("expected output")
	}
}

func TestManagerAlertDecisionDeny(t *testing.T) {
	var buf bytes.Buffer
	sink := NewStdoutSink(&buf)
	mgr := NewManager(sink)

	decision := &model.PolicyDecision{
		Action:     model.DecisionDeny,
		PolicyName: "test",
		Reason:     "blocked",
		Timestamp:  time.Now().UTC(),
	}

	if err := mgr.AlertDecision(decision); err != nil {
		t.Fatalf("alert decision: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("expected output for deny decision")
	}
}

func TestManagerAlertDecisionAllowNoAlert(t *testing.T) {
	var buf bytes.Buffer
	sink := NewStdoutSink(&buf)
	mgr := NewManager(sink)

	decision := &model.PolicyDecision{
		Action:     model.DecisionAllow,
		PolicyName: "test",
		Reason:     "allowed",
		Timestamp:  time.Now().UTC(),
	}

	if err := mgr.AlertDecision(decision); err != nil {
		t.Fatalf("alert decision: %v", err)
	}

	if buf.Len() != 0 {
		t.Error("expected no output for allow decision")
	}
}
