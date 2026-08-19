package dashboard

import (
	"testing"
	"time"

	"github.com/ghostguard/ghostguard/internal/model"
)

func TestRecordEvent(t *testing.T) {
	d := NewDashboard()

	event := &model.InterceptionEvent{
		ID:     "test-1",
		Method: "POST",
		Path:   "/v1/chat/completions",
		Host:   "api.openai.com",
		ToolCalls: []model.ToolCall{
			{Name: "exec"},
			{Name: "search_web"},
		},
		Decisions: []model.PolicyDecision{
			{Action: model.DecisionDeny},
			{Action: model.DecisionAllow},
		},
		Anomalies: []model.Anomaly{
			{Type: model.AnomalyHighRate},
		},
	}

	d.RecordEvent(event)

	metrics := d.GetMetrics()

	if metrics.TotalRequests != 1 {
		t.Errorf("expected 1 total request, got %d", metrics.TotalRequests)
	}
	if metrics.TotalToolCalls != 2 {
		t.Errorf("expected 2 tool calls, got %d", metrics.TotalToolCalls)
	}
	if metrics.DeniedCalls != 1 {
		t.Errorf("expected 1 denied call, got %d", metrics.DeniedCalls)
	}
	if metrics.AllowedCalls != 1 {
		t.Errorf("expected 1 allowed call, got %d", metrics.AllowedCalls)
	}
	if metrics.AnomaliesDetected != 1 {
		t.Errorf("expected 1 anomaly, got %d", metrics.AnomaliesDetected)
	}
	if metrics.ToolCounts["exec"] != 1 {
		t.Errorf("expected 1 exec call, got %d", metrics.ToolCounts["exec"])
	}
	if metrics.ToolCounts["search_web"] != 1 {
		t.Errorf("expected 1 search_web call, got %d", metrics.ToolCounts["search_web"])
	}
	if metrics.PolicyDecisions["deny"] != 1 {
		t.Errorf("expected 1 deny decision, got %d", metrics.PolicyDecisions["deny"])
	}
	if metrics.PolicyDecisions["allow"] != 1 {
		t.Errorf("expected 1 allow decision, got %d", metrics.PolicyDecisions["allow"])
	}
}

func TestGetMetricsCopies(t *testing.T) {
	d := NewDashboard()

	event := &model.InterceptionEvent{
		ToolCalls: []model.ToolCall{{Name: "exec"}},
		Decisions: []model.PolicyDecision{{Action: model.DecisionDeny}},
	}
	d.RecordEvent(event)

	m1 := d.GetMetrics()
	m2 := d.GetMetrics()

	m1.ToolCounts["exec"] = 999
	if m2.ToolCounts["exec"] != 1 {
		t.Error("expected metrics copy to be independent")
	}
}

func TestGetMetricsEmpty(t *testing.T) {
	d := NewDashboard()

	metrics := d.GetMetrics()

	if metrics.TotalRequests != 0 {
		t.Errorf("expected 0 total requests, got %d", metrics.TotalRequests)
	}
	if metrics.StartTime.IsZero() {
		t.Error("expected non-zero start time")
	}
}

func TestMultipleEvents(t *testing.T) {
	d := NewDashboard()

	for i := 0; i < 10; i++ {
		event := &model.InterceptionEvent{
			ToolCalls: []model.ToolCall{{Name: "exec"}},
			Decisions: []model.PolicyDecision{{Action: model.DecisionDeny}},
		}
		d.RecordEvent(event)
	}

	metrics := d.GetMetrics()

	if metrics.TotalRequests != 10 {
		t.Errorf("expected 10 total requests, got %d", metrics.TotalRequests)
	}
	if metrics.TotalToolCalls != 10 {
		t.Errorf("expected 10 tool calls, got %d", metrics.TotalToolCalls)
	}
	if metrics.DeniedCalls != 10 {
		t.Errorf("expected 10 denied calls, got %d", metrics.DeniedCalls)
	}
	if metrics.ToolCounts["exec"] != 10 {
		t.Errorf("expected 10 exec calls, got %d", metrics.ToolCounts["exec"])
	}
}

func TestLastActivity(t *testing.T) {
	d := NewDashboard()
	before := time.Now().UTC()

	event := &model.InterceptionEvent{
		ToolCalls: []model.ToolCall{{Name: "exec"}},
		Decisions: []model.PolicyDecision{{Action: model.DecisionDeny}},
	}
	d.RecordEvent(event)

	after := time.Now().UTC()
	metrics := d.GetMetrics()

	if metrics.LastActivity.Before(before) || metrics.LastActivity.After(after) {
		t.Error("expected LastActivity to be between before and after")
	}
}
