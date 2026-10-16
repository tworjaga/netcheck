package ui

import (
	"fmt"
	"math"
	"strings"
)

// Charts: several rows tall, one column per sample, newest on the right.
// Each row holds eight steps (▁ to █), so a five-row chart has forty levels.

// chartSpec says how to scale and colour one kind of chart.
type chartSpec struct {
	lo, hi  float64
	missing func(v float64) bool
	colour  func(v float64) color
	label   func(v float64) string
}

// NiceCeil rounds v up to 1, 2 or 5 times a power of ten, for a scale that
// reads well: 37 ms becomes 50, 130 becomes 200.
func NiceCeil(v float64) float64 {
	if v <= 0 {
		return 1
	}
	p := math.Pow(10, math.Floor(math.Log10(v)))
	for _, m := range []float64{1, 2, 5, 10} {
		if v <= m*p {
			return m * p
		}
	}
	return 10 * p
}

// LatencyChart draws latency samples (ms; negative = lost) from 0 to a
// rounded maximum, coloured green, amber or red like Spark.
func LatencyChart(ms []float64, height, width int) []string {
	top := 0.0
	for _, v := range ms {
		top = max(top, v)
	}
	return chart(ms, height, width, chartSpec{
		lo: 0, hi: NiceCeil(math.Max(top, 10)),
		missing: func(v float64) bool { return v < 0 },
		colour:  latencyColor,
		label:   func(v float64) string { return fmt.Sprintf("%.0f ms", v) },
	})
}

// SignalChart draws Wi-Fi signal readings (dBm; 0 = not connected) on a
// fixed -90 to -40 dBm scale, coloured by quality like SignalBars.
func SignalChart(dbm []float64, height, width int) []string {
	return chart(dbm, height, width, chartSpec{
		lo: -90, hi: -40,
		missing: func(v float64) bool { return v == 0 || v <= -150 },
		colour:  signalColor,
		label:   func(v float64) string { return fmt.Sprintf("%.0f dBm", v) },
	})
}

func signalColor(v float64) color {
	switch {
	case v < -75:
		return cBad
	case v < -67:
		return cWarn
	}
	return cGood
}

// chart renders the newest samples that fit in width (axis included).
func chart(vals []float64, height, width int, s chartSpec) []string {
	height = max(height, 2)
	hiL, midL, loL := s.label(s.hi), s.label((s.hi+s.lo)/2), s.label(s.lo)
	lw := max(visWidth(hiL), visWidth(midL), visWidth(loL))
	cols := max(1, width-lw-2)
	if len(vals) > cols {
		vals = vals[len(vals)-cols:]
	}
	steps := []rune(" ▁▂▃▄▅▆▇█")
	if asciiOnly {
		steps = []rune(" .:-=+*#@")
	}
	mid := height / 2
	lines := make([]string, height)
	for r := 0; r < height; r++ {
		label, tick := "", pick("│", "|")
		switch r {
		case 0:
			label, tick = hiL, pick("┤", "+")
		case mid:
			label, tick = midL, pick("┤", "+")
		case height - 1:
			label, tick = loL, pick("┤", "+")
		}
		var c cells
		for _, v := range vals {
			if s.missing(v) {
				if r == height-1 {
					c.add(cBad, []rune(pick("×", "x"))[0])
				} else {
					c.add(cDim, ' ')
				}
				continue
			}
			frac := (v - s.lo) / (s.hi - s.lo)
			eighths := int(math.Round(math.Max(0, math.Min(1, frac)) * float64(height*8)))
			if eighths == 0 && r == height-1 {
				eighths = 1 // a sample always leaves a mark
			}
			fill := max(0, min(8, eighths-(height-1-r)*8))
			c.add(s.colour(v), steps[fill])
		}
		lines[r] = "  " + Dim(padL(label, lw)+" "+tick) + c.String()
	}
	return lines
}

// Gauge is a bar filled to frac (0 to 1) over width columns, with eighth
// steps for a smooth fill: ████████▌░░░░.
func Gauge(frac float64, width int) string {
	return gauge(frac, width, cAccent)
}

// Meter is a Gauge coloured by status: a signal or quality reading.
func Meter(frac float64, width int, st Status) string {
	col := map[Status]color{OK: cGood, Warn: cWarn, Bad: cBad}[st]
	if st == Skip {
		col = cDim
	}
	return gauge(frac, width, col)
}

func gauge(frac float64, width int, col color) string {
	frac = math.Max(0, math.Min(1, frac))
	eighths := int(math.Round(frac * float64(width*8)))
	full, part := eighths/8, eighths%8
	partials := []string{"", "▏", "▎", "▍", "▌", "▋", "▊", "▉"}
	bar, rest := strings.Repeat(pick("█", "#"), full), width-full
	if part > 0 && full < width {
		if asciiOnly {
			bar += "#"
		} else {
			bar += partials[part]
		}
		rest--
	}
	return paint(col, bar) + Dim(strings.Repeat(pick("░", "-"), max(0, rest)))
}
