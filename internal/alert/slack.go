package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ghostguard/ghostguard/internal/model"
)

type SlackSink struct {
	WebhookURL string
	Channel    string
	HTTPClient *http.Client
}

type slackMessage struct {
	Channel string       `json:"channel,omitempty"`
	Text    string       `json:"text"`
	Blocks  []slackBlock `json:"blocks,omitempty"`
}

type slackBlock struct {
	Type string      `json:"type"`
	Text *slackText  `json:"text,omitempty"`
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func NewSlackSink(webhookURL, channel string) *SlackSink {
	return &SlackSink{
		WebhookURL: webhookURL,
		Channel:    channel,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (s *SlackSink) Send(alert *model.Alert) error {
	blocks := []slackBlock{
		{
			Type: "section",
			Text: &slackText{
				Type: "mrkdwn",
				Text: fmt.Sprintf("*%s*\n%s\nSeverity: %s | Source: %s",
					alert.Title, alert.Message, alert.Severity, alert.Source),
			},
		},
	}

	msg := slackMessage{
		Channel: s.Channel,
		Text:    fmt.Sprintf("[%s] %s: %s", alert.Severity, alert.Title, alert.Message),
		Blocks:  blocks,
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshaling slack message: %w", err)
	}

	resp, err := s.HTTPClient.Post(s.WebhookURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("sending slack message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("slack webhook returned status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
