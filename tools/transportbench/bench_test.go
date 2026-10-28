package main

import (
	"testing"
	"time"
)

func TestSpreadOf(t *testing.T) {
	tests := []struct {
		name string
		in   []float64
		want spread[float64]
	}{
		{"empty", nil, spread[float64]{}},
		{"odd count", []float64{3, 1, 2}, spread[float64]{median: 2, min: 1, max: 3}},
		{"even count takes lower middle", []float64{4, 1, 3, 2}, spread[float64]{median: 2, min: 1, max: 4}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := spreadOf(tt.in); got != tt.want {
				t.Fatalf("spreadOf(%v) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestPercentile(t *testing.T) {
	ten := make([]time.Duration, 10)
	for i := range ten {
		ten[i] = time.Duration(i+1) * time.Millisecond
	}
	tests := []struct {
		name   string
		sorted []time.Duration
		p      float64
		want   time.Duration
	}{
		{"empty", nil, 0.5, 0},
		{"single", []time.Duration{7}, 0.95, 7},
		{"p50 of 10", ten, 0.50, 5 * time.Millisecond},
		{"p95 of 10", ten, 0.95, 10 * time.Millisecond},
		{"p0 clamps to first", ten, 0, 1 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := percentile(tt.sorted, tt.p); got != tt.want {
				t.Fatalf("percentile(%v) = %v, want %v", tt.p, got, tt.want)
			}
		})
	}
}
