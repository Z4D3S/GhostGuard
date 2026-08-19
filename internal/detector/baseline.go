package detector

import (
	"math"
	"sync"
	"time"
)

type Baseline struct {
	mu       sync.RWMutex
	count    int64
	mean     float64
	m2       float64
	min      float64
	max      float64
	lastSeen time.Time
}

func NewBaseline() *Baseline {
	return &Baseline{
		min: math.MaxFloat64,
		max: -math.MaxFloat64,
	}
}

func (b *Baseline) Update(value float64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.count++
	b.lastSeen = time.Now()

	delta := value - b.mean
	b.mean += delta / float64(b.count)
	delta2 := value - b.mean
	b.m2 += delta * delta2

	if value < b.min {
		b.min = value
	}
	if value > b.max {
		b.max = value
	}
}

func (b *Baseline) Mean() float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.mean
}

func (b *Baseline) Variance() float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.count < 2 {
		return 0
	}
	return b.m2 / float64(b.count-1)
}

func (b *Baseline) StdDev() float64 {
	return math.Sqrt(b.Variance())
}

func (b *Baseline) ZScore(value float64) float64 {
	std := b.StdDev()
	if std == 0 {
		return 0
	}
	return (value - b.mean) / std
}

func (b *Baseline) Count() int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.count
}

func (b *Baseline) Min() float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.min
}

func (b *Baseline) Max() float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.max
}
