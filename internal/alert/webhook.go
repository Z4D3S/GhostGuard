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

type WebhookSink struct {
	URL        string
	HTTPClient *http.Client
}

func NewWebhookSink(url string) *WebhookSink {
	return &WebhookSink{
		URL: url,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (w *WebhookSink) Send(alert *model.Alert) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("marshaling alert: %w", err)
	}

	resp, err := w.HTTPClient.Post(w.URL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("sending webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
