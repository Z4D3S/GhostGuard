package detector

import (
	"testing"
	"time"
)

func TestBaselineWelford(t *testing.T) {
	b := NewBaseline()

	values := []float64{10, 12, 11, 13, 10, 12, 14, 11, 13, 15}
	for _, v := range values {
		b.Update(v)
	}

	if b.Count() != 10 {
		t.Errorf("expected count 10, got %d", b.Count())
	}

	mean := b.Mean()
	if mean < 11.5 || mean > 12.5 {
		t.Errorf("expected mean ~12, got %f", mean)
	}

	std := b.StdDev()
	if std < 1.0 || std > 2.0 {
		t.Errorf("expected std ~1.5, got %f", std)
	}
}

func TestBaselineZScore(t *testing.T) {
	b := NewBaseline()

	// Use varied values so we have a non-zero std deviation
	values := []float64{10, 11, 12, 13, 14, 10, 11, 12, 13, 14, 10, 11, 12, 13, 14, 10, 11, 12, 13, 14}
	for _, v := range values {
		b.Update(v)
	}

	// Outlier should have high z-score
	z := b.ZScore(30.0)
	if z < 5.0 {
		t.Errorf("expected high z-score for outlier, got %f", z)
	}

	// Mean-ish value should have low z-score
	z = b.ZScore(12.0)
	if z > 1.0 {
		t.Errorf("expected low z-score for mean value, got %f", z)
	}
}

func TestBaselineMinMax(t *testing.T) {
	b := NewBaseline()
	b.Update(5.0)
	b.Update(15.0)
	b.Update(3.0)
	b.Update(20.0)

	if b.Min() != 3.0 {
		t.Errorf("expected min 3, got %f", b.Min())
	}
	if b.Max() != 20.0 {
		t.Errorf("expected max 20, got %f", b.Max())
	}
}

func TestSlidingWindowRecord(t *testing.T) {
	sw := NewSlidingWindow(time.Second, 5*time.Second)

	count := sw.Record("tool_a")
	if count != 1 {
		t.Errorf("expected count 1, got %d", count)
	}

	count = sw.Record("tool_a")
	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}

	count = sw.Record("tool_b")
	if count != 1 {
		t.Errorf("expected count 1 for tool_b, got %d", count)
	}
}

func TestSlidingWindowCount(t *testing.T) {
	sw := NewSlidingWindow(time.Second, 5*time.Second)

	sw.Record("test")
	sw.Record("test")
	sw.Record("test")

	count := sw.Count("test")
	if count != 3 {
		t.Errorf("expected count 3, got %d", count)
	}

	count = sw.Count("other")
	if count != 0 {
		t.Errorf("expected count 0, got %d", count)
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input    string
		min, max float64
	}{
		{"aaaa", 0.0, 0.1},
		{"abcdefgh", 2.5, 3.5},
		{"a1b2c3d4", 2.5, 3.5},
		{"", 0.0, 0.0},
	}

	for _, tt := range tests {
		e := ShannonEntropy(tt.input)
		if e < tt.min || e > tt.max {
			t.Errorf("ShannonEntropy(%q) = %f, want [%f, %f]", tt.input, e, tt.min, tt.max)
		}
	}
}

func TestSuspiciousEntropyLevel(t *testing.T) {
	if SuspiciousEntropyLevel("aaaa") != "low" {
		t.Error("expected low entropy for repeated chars")
	}
	if SuspiciousEntropyLevel("abcdefghij1234567890!@#$%^&*") != "very_high" {
		t.Error("expected very_high entropy for random string")
	}
}

func TestIsHighEntropy(t *testing.T) {
	if IsHighEntropy("aaaa", 3.0) {
		t.Error("expected low entropy for 'aaaa'")
	}
	if !IsHighEntropy("abcdefghij1234567890!@#$%^&*()", 3.0) {
		t.Error("expected high entropy for random string")
	}
}
