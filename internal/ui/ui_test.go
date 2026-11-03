package ui

import (
	"strings"
	"testing"
)

func TestSparkSteadyStaysLow(t *testing.T) {
	got := Spark([]float64{14, 14.2, 13.9, 14.1})
	if strings.ContainsAny(got, "▅▆▇█") {
		t.Fatalf("steady latency should render as low bars, got %q", got)
	}
}

func TestSparkShowsSpikesAndLoss(t *testing.T) {
	got := []rune(Spark([]float64{10, 10, 80, -1, 10}))
	if len(got) != 5 {
		t.Fatalf("want 5 glyphs, got %q", string(got))
	}
	if got[2] != '█' {
		t.Errorf("spike should be the tallest bar, got %q", string(got[2]))
	}
	if got[3] != '×' {
		t.Errorf("lost probe should render as ×, got %q", string(got[3]))
	}
}

func TestRowAlignsWithoutColor(t *testing.T) {
	a := Row("Gateway", OK, "192.168.1.1", "2.0 ms", "")
	b := Row("Cloudflare", Warn, "1.1.1.1", "180 ms", "")
	// The metric column must end at the same rune offset in both rows.
	if width(a) != width(b) {
		t.Fatalf("rows misaligned:\n%q\n%q", a, b)
	}
}

func TestBarsFixedScale(t *testing.T) {
	got := []rune(Bars([]float64{0, 50, 100, -1}, 0, 100, -1))
	if len(got) != 4 || got[0] != '▁' || got[2] != '█' || got[3] != '×' {
		t.Fatalf("got %q", string(got))
	}
	// A steady strong signal must stay tall even though it barely varies.
	steady := []rune(Bars([]float64{90, 91, 90}, 0, 100, -1))
	if steady[0] < '▆' {
		t.Fatalf("steady strong signal should render tall, got %q", string(steady))
	}
}

func TestGroupOffTerminalPrintsFinalLinesInOrder(t *testing.T) {
	// Tests don't run on a terminal, so the group is quiet until End.
	g := NewGroup("A", "B")
	c := g.Add("C")
	g.Progress(0, "working")
	g.Finish(1, "line B")
	g.Finish(0, "line A")
	g.Finish(c, "") // hidden row
	if got := g.lines(); len(got) != 2 || got[0] != "line A" || got[1] != "line B" {
		t.Fatalf("got %q", got)
	}
	g.End()
}
