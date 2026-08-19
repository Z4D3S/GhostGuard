package alert

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ghostguard/ghostguard/internal/model"
)

type StdoutSink struct {
	Writer io.Writer
}

func NewStdoutSink(writer io.Writer) *StdoutSink {
	return &StdoutSink{ Writer: writer }
}

func (s *StdoutSink) Send(alert *model.Alert) error {
	data, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("marshaling alert: %w", err)
	}

	_, err = fmt.Fprintf(s.Writer, "[ALERT][%s] %s\n", alert.Severity, string(data))
	return err
}
