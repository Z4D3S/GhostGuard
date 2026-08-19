package detector

import "math"

func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	length := float64(len([]rune(s)))
	entropy := 0.0

	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

func IsHighEntropy(s string, threshold float64) bool {
	return ShannonEntropy(s) > threshold
}

func SuspiciousEntropyLevel(s string) string {
	e := ShannonEntropy(s)
	switch {
	case e > 4.5:
		return "very_high"
	case e > 3.5:
		return "high"
	case e > 2.5:
		return "medium"
	default:
		return "low"
	}
}
