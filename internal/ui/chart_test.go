package ui

import (
	"strings"
	"testing"
)

func TestNiceCeil(t *testing.T) {
	for in, want := range map[float64]float64{37: 50, 130: 200, 10: 10, 11: 20, 0.4: 0.5, 999: 1000, 0: 1} {
		if got := NiceCeil(in); got != want {
			t.Errorf("NiceCeil(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestLatencyChart(t *testing.T) {
	ms := []float64{12, 14, 11, 35, 18, -1, 9, 37}
	lines := LatencyChart(ms, 5, 40)
	if len(lines) != 5 {
		t.Fatalf("want 5 rows, got %d", len(lines))
	}
	for i, l := range lines {
		// "  " margin + label column + " ┤" + one column per sample.
		if w := visWidth(l); w != 2+len("50 ms")+2+len(ms) {
			t.Errorf("row %d is %d wide: %q", i, w, l)
		}
	}
	if !strings.Contains(lines[0], "50 ms") || !strings.Contains(lines[4], "0 ms") {
		t.Errorf("scale labels: %q / %q", lines[0], lines[4])
	}
	if !strings.Contains(lines[4], "×") {
		t.Errorf("a lost sample is marked on the bottom row: %q", lines[4])
	}
	// More samples than fit: the newest are kept.
	many := make([]float64, 100)
	for i := range many {
		many[i] = float64(i)
	}
	if w := visWidth(LatencyChart(many, 3, 30)[0]); w != 32 {
		t.Errorf("a full chart fills the width: %d", w)
	}
}

func TestSignalChartScale(t *testing.T) {
	lines := SignalChart([]float64{-55, -80, 0}, 4, 30)
	if len(lines) != 4 || !strings.Contains(lines[0], "-40 dBm") || !strings.Contains(lines[3], "-90 dBm") || !strings.Contains(lines[3], "×") {
		t.Errorf("got %q", lines)
	}
}

func TestGaugeWidth(t *testing.T) {
	for _, f := range []float64{-1, 0, 0.01, 0.33, 0.5, 0.99, 1, 2} {
		if w := visWidth(Gauge(f, 14)); w != 14 {
			t.Errorf("Gauge(%v) is %d wide", f, w)
		}
		if w := visWidth(Meter(f, 10, Warn)); w != 10 {
			t.Errorf("Meter(%v) is %d wide", f, w)
		}
	}
	if g := Gauge(1, 4); strings.Contains(g, "░") {
		t.Errorf("a full gauge has no empty part: %q", g)
	}
}

func TestRowMovesDetailsInNarrowPanel(t *testing.T) {
	panels(t, 60)
	r := Row("Wi-Fi", OK, "TP-Link", "-62 dBm", "good · 2.4 GHz · ch 1 · quiet channel")
	parts := strings.Split(r, "\n")
	if len(parts) != 2 || !strings.Contains(parts[1], "good · 2.4 GHz") {
		t.Fatalf("details should move to their own line: %q", r)
	}
	if visWidth(frameLine(parts[1])) != inner()+6 {
		t.Errorf("the second line fits the panel")
	}
	if r := Row("DNS", OK, "System", "18 ms", "fast"); strings.Contains(r, "\n") {
		t.Errorf("a row that fits stays on one line: %q", r)
	}
}
