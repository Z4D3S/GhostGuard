package detector

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ghostguard/ghostguard/internal/model"
)

type Detector struct {
	mu             sync.RWMutex
	rateBaseline   *Baseline
	window         *SlidingWindow
	knownTools     map[string]bool
	previousTools  []string
	config         DetectorConfig
}

type DetectorConfig struct {
	RateThreshold     float64 `yaml:"rate_threshold"`
	EntropyThreshold  float64 `yaml:"entropy_threshold"`
	WindowInterval    time.Duration `yaml:"window_interval"`
	WindowMaxAge      time.Duration `yaml:"window_max_age"`
	MaxPrevTools      int     `yaml:"max_prev_tools"`
}

func DefaultConfig() DetectorConfig {
	return DetectorConfig{
		RateThreshold:    3.0,
		EntropyThreshold: 4.0,
		WindowInterval:   time.Minute,
		WindowMaxAge:     5 * time.Minute,
		MaxPrevTools:     10,
	}
}

func NewDetector(config DetectorConfig) *Detector {
	return &Detector{
		rateBaseline: NewBaseline(),
		window:       NewSlidingWindow(config.WindowInterval, config.WindowMaxAge),
		knownTools:   make(map[string]bool),
		config:       config,
	}
}

func (d *Detector) Analyze(toolCall *model.ToolCall) []model.Anomaly {
	var anomalies []model.Anomaly

	if a := d.checkRate(toolCall); a != nil {
		anomalies = append(anomalies, *a)
	}
	if a := d.checkEntropy(toolCall); a != nil {
		anomalies = append(anomalies, *a)
	}
	if a := d.checkUnknownTool(toolCall); a != nil {
		anomalies = append(anomalies, *a)
	}
	if a := d.checkSuspiciousSequence(toolCall); a != nil {
		anomalies = append(anomalies, *a)
	}

	d.recordTool(toolCall)
	return anomalies
}

func (d *Detector) checkRate(toolCall *model.ToolCall) *model.Anomaly {
	count := d.window.Record(toolCall.Name)
	d.rateBaseline.Update(float64(count))

	zscore := d.rateBaseline.ZScore(float64(count))
	if d.rateBaseline.Count() < 10 {
		return nil
	}

	if zscore > d.config.RateThreshold {
		details, _ := json.Marshal(map[string]interface{}{
			"count":  count,
			"zscore": zscore,
			"mean":   d.rateBaseline.Mean(),
		})
		return &model.Anomaly{
			Type:        model.AnomalyHighRate,
			ToolCall:    toolCall,
			Score:       zscore,
			Threshold:   d.config.RateThreshold,
			Description: fmt.Sprintf("unusual call rate for tool '%s': %.1fσ above baseline", toolCall.Name, zscore),
			Timestamp:   time.Now().UTC(),
			Details:     details,
		}
	}
	return nil
}

func (d *Detector) checkEntropy(toolCall *model.ToolCall) *model.Anomaly {
	argsStr := fmt.Sprintf("%v", toolCall.Arguments)
	entropy := ShannonEntropy(argsStr)

	if entropy > d.config.EntropyThreshold {
		details, _ := json.Marshal(map[string]interface{}{
			"entropy": entropy,
			"level":   SuspiciousEntropyLevel(argsStr),
		})
		return &model.Anomaly{
			Type:        model.AnomalyHighEntropy,
			ToolCall:    toolCall,
			Score:       entropy,
			Threshold:   d.config.EntropyThreshold,
			Description: fmt.Sprintf("high entropy in arguments for tool '%s': %.2f (possible exfiltration)", toolCall.Name, entropy),
			Timestamp:   time.Now().UTC(),
			Details:     details,
		}
	}
	return nil
}

func (d *Detector) checkUnknownTool(toolCall *model.ToolCall) *model.Anomaly {
	d.mu.RLock()
	known := d.knownTools[toolCall.Name]
	d.mu.RUnlock()

	if !known && d.rateBaseline.Count() > 5 {
		return &model.Anomaly{
			Type:        model.AnomalyUnknownTool,
			ToolCall:    toolCall,
			Score:       1.0,
			Threshold:   0.0,
			Description: fmt.Sprintf("unknown tool detected: '%s'", toolCall.Name),
			Timestamp:   time.Now().UTC(),
		}
	}
	return nil
}

func (d *Detector) checkSuspiciousSequence(toolCall *model.ToolCall) *model.Anomaly {
	d.mu.RLock()
	prev := make([]string, len(d.previousTools))
	copy(prev, d.previousTools)
	d.mu.RUnlock()

	dangerousSequences := map[string][]string{
		"exec":        {"read_file", "get_config", "list_files"},
		"file_write":  {"read_file", "list_files"},
		"shell":       {"read_file", "get_config"},
		"bash":        {"read_file", "get_config"},
		"http_request": {"read_file"},
	}

	if dangerousPrev, ok := dangerousSequences[toolCall.Name]; ok {
		for _, p := range prev {
			for _, dp := range dangerousPrev {
				if p == dp {
					return &model.Anomaly{
						Type:        model.AnomalySuspiciousSeq,
						ToolCall:    toolCall,
						Score:       1.0,
						Threshold:   0.0,
						Description: fmt.Sprintf("suspicious sequence: '%s' after '%s'", toolCall.Name, p),
						Timestamp:   time.Now().UTC(),
					}
				}
			}
		}
	}
	return nil
}

func (d *Detector) recordTool(toolCall *model.ToolCall) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.knownTools[toolCall.Name] = true
	d.previousTools = append(d.previousTools, toolCall.Name)
	if len(d.previousTools) > d.config.MaxPrevTools {
		d.previousTools = d.previousTools[1:]
	}
}
