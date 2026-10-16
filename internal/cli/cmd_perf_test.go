package cli

import (
	"strings"
	"testing"

	"github.com/tworjaga/netcheck/internal/perf"
	"github.com/tworjaga/netcheck/internal/ui"
)

func TestParseRate(t *testing.T) {
	for in, want := range map[string]int64{"50M": 50e6, "1G": 1e9, "500k": 500e3, "1.5g": 1.5e9, "100Mbps": 100e6, "2000": 2000} {
		if got, err := parseRate(in); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "fast", "-5M", "0"} {
		if _, err := parseRate(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestSwing(t *testing.T) {
	if s := swing([]float64{10, 100, 100, 100, 100}); s != 0 {
		t.Errorf("steady after ramp-up: %v", s)
	}
	if s := swing([]float64{0, 100, 10, 100, 10}); s < 0.5 {
		t.Errorf("swinging: %v", s)
	}
}

func TestPerfVerdict(t *testing.T) {
	steady := []float64{100, 900, 920, 910, 905}
	rs := []perf.Result{{Test: perf.TCPDown, Mbps: 910, Streams: 4, Samples: steady}, {Test: perf.TCPUp, Mbps: 905, Streams: 4, Samples: steady}}
	st, msg, notes := perfVerdict("box", rs, 0)
	if st != ui.OK || msg != "Download 910 Mbps, upload 905 Mbps, between here and box." || len(notes) != 0 {
		t.Errorf("%v %q %v", st, msg, notes)
	}
	rs[1].Mbps = 40
	if _, _, notes := perfVerdict("box", rs, 0); len(notes) != 1 || !strings.HasPrefix(notes[0], "Upload is much slower") {
		t.Errorf("asymmetric: %v", notes)
	}
	rs[0].Samples = []float64{0, 900, 50, 900, 40, 880}
	if _, _, notes := perfVerdict("box", rs[:1], 0); len(notes) != 1 || !strings.Contains(notes[0], "swings") {
		t.Errorf("swinging: %v", notes)
	}
	udp := []perf.Result{{Test: perf.UDP, Mbps: 47, UDP: &perf.UDPStats{Sent: 1000, Received: 950, Lost: 50, LossPct: 5, JitterMs: 40, OutOfOrder: 3}}}
	st, msg, notes = perfVerdict("box", udp, 50e6)
	all := strings.Join(notes, " ")
	if st != ui.Warn || !strings.HasPrefix(msg, "UDP at 50.0 Mbps: 5.0% lost, jitter 40.0 ms") || !strings.Contains(all, "can't keep up") || !strings.Contains(all, "Jitter of 40 ms") || !strings.Contains(all, "out of order") {
		t.Errorf("udp: %v %q %v", st, msg, notes)
	}
	slow := []perf.Result{{Test: perf.UDP, Mbps: 780, UDP: &perf.UDPStats{Sent: 1000, Received: 993, LossPct: 0.7}}}
	if st, _, notes := perfVerdict("box", slow, 5e9); st != ui.OK || !strings.Contains(strings.Join(notes, " "), "couldn't send faster") {
		t.Errorf("sender limit: %v %v", st, notes)
	}
	if st, msg, _ := perfVerdict("box", []perf.Result{{Test: perf.TCPDown, Error: "nothing listens on box:5205"}}, 0); st != ui.Bad || !strings.Contains(msg, "download test failed: nothing listens") {
		t.Errorf("error: %q", msg)
	}
	for _, l := range perfTable(udp, 50e6).Lines(78) {
		if ui.VisWidth(l) > 78 {
			t.Errorf("too wide: %q", l)
		}
	}
}
