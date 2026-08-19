package detector

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type PersistentBaseline struct {
	*Baseline
	mu       sync.Mutex
	filePath string
}

type baselineData struct {
	Count int64   `json:"count"`
	Mean  float64 `json:"mean"`
	M2    float64 `json:"m2"`
	Min   float64 `json:"min"`
	Max   float64 `json:"max"`
	SavedAt time.Time `json:"saved_at"`
}

func NewPersistentBaseline(filePath string) (*PersistentBaseline, error) {
	pb := &PersistentBaseline{
		Baseline: NewBaseline(),
		filePath: filePath,
	}

	if err := pb.load(); err != nil {
		return nil, fmt.Errorf("loading baseline: %w", err)
	}

	return pb, nil
}

func (pb *PersistentBaseline) load() error {
	data, err := os.ReadFile(pb.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading baseline file: %w", err)
	}

	var saved baselineData
	if err := json.Unmarshal(data, &saved); err != nil {
		return fmt.Errorf("parsing baseline file: %w", err)
	}

	if time.Since(saved.SavedAt) > 24*time.Hour {
		return nil
	}

	pb.count = saved.Count
	pb.mean = saved.Mean
	pb.m2 = saved.M2
	pb.min = saved.Min
	pb.max = saved.Max

	return nil
}

func (pb *PersistentBaseline) Save() error {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	data := baselineData{
		Count:   pb.count,
		Mean:    pb.mean,
		M2:      pb.m2,
		Min:     pb.min,
		Max:     pb.max,
		SavedAt: time.Now().UTC(),
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling baseline: %w", err)
	}

	if err := os.WriteFile(pb.filePath, jsonData, 0644); err != nil {
		return fmt.Errorf("writing baseline file: %w", err)
	}

	return nil
}
