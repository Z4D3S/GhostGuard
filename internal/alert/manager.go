package alert

import (
	"fmt"
	"time"

	"github.com/ghostguard/ghostguard/internal/model"
)

type Sink interface {
	Send(alert *model.Alert) error
}

type Manager struct {
	sinks []Sink
}

func NewManager(sinks ...Sink) *Manager {
	return &Manager{ sinks: sinks }
}

func (m *Manager) Alert(alert *model.Alert) error {
	var lastErr error
	for _, sink := range m.sinks {
		if err := sink.Send(alert); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func (m *Manager) AlertAnomaly(anomaly *model.Anomaly) error {
	severity := model.AlertWarning
	if anomaly.Score > anomaly.Threshold*2 {
		severity = model.AlertCritical
	}

	alert := &model.Alert{
		ID:        fmt.Sprintf("anomaly-%d", time.Now().UnixNano()),
		Severity:  severity,
		Source:    "detector",
		Title:     fmt.Sprintf("Anomaly: %s", anomaly.Type),
		Message:   anomaly.Description,
		Anomaly:   anomaly,
		Timestamp: time.Now().UTC(),
	}
	return m.Alert(alert)
}

func (m *Manager) AlertDecision(decision *model.PolicyDecision) error {
	if decision.Action != model.DecisionDeny {
		return nil
	}

	alert := &model.Alert{
		ID:        fmt.Sprintf("policy-deny-%d", time.Now().UnixNano()),
		Severity:  model.AlertWarning,
		Source:    "policy",
		Title:     fmt.Sprintf("Policy Deny: %s", decision.PolicyName),
		Message:   decision.Reason,
		Decision:  decision,
		Timestamp: time.Now().UTC(),
	}
	return m.Alert(alert)
}
