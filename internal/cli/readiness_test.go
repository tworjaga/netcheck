package cli

import (
	"strings"
	"testing"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

func TestReadiness(t *testing.T) {
	fibre := link{PingKnown: true, LatencyMs: 12, JitterMs: 2, LossKnown: true, DownMbps: 300, UpMbps: 50, LoadedMs: 30}
	cases := []struct {
		name             string
		in               link
		calls, games, tv ui.Status
		reasonHas        string // in the first non-OK use's reason
	}{
		{"fibre", fibre, ui.OK, ui.OK, ui.OK, ""},
		{"satellite", link{PingKnown: true, LatencyMs: 600, JitterMs: 40, LossKnown: true, LossPct: 0, DownMbps: 100, UpMbps: 10}, ui.Bad, ui.Bad, ui.OK, "latency is 600 ms"},
		{"lossy wifi", link{PingKnown: true, LatencyMs: 20, JitterMs: 8, LossKnown: true, LossPct: 5, DownMbps: 80, UpMbps: 20}, ui.Bad, ui.Bad, ui.Warn, "packet loss is 5.0%"},
		{"slow dsl", link{PingKnown: true, LatencyMs: 30, JitterMs: 3, LossKnown: true, DownMbps: 8, UpMbps: 0.8}, ui.Bad, ui.Warn, ui.Bad, "upload is 0.80 Mbps"},
		{"mobile, jittery", link{PingKnown: true, LatencyMs: 45, JitterMs: 22, LossKnown: true, DownMbps: 40, UpMbps: 10}, ui.OK, ui.Warn, ui.OK, "jitter is 22 ms"},
		{"bufferbloat", link{PingKnown: true, LatencyMs: 15, JitterMs: 2, LossKnown: true, DownMbps: 200, UpMbps: 20, LoadedMs: 450}, ui.Bad, ui.Bad, ui.OK, "latency under load is 450 ms"},
		{"4K borderline", link{PingKnown: true, LatencyMs: 15, JitterMs: 2, LossKnown: true, DownMbps: 20, UpMbps: 5}, ui.OK, ui.OK, ui.Warn, "4K wants 25 Mbps"},
		{"ping only (doctor --fast)", link{PingKnown: true, LatencyMs: 15, JitterMs: 2, LossKnown: true}, ui.OK, ui.OK, ui.Skip, ""},
		{"nothing known", link{}, ui.Skip, ui.Skip, ui.Skip, ""},
	}
	for _, c := range cases {
		us := readiness(c.in)
		if us[0].Status != c.calls || us[1].Status != c.games || us[2].Status != c.tv {
			t.Errorf("%s: got calls=%v games=%v 4k=%v (%+v)", c.name, us[0].Status, us[1].Status, us[2].Status, us)
			continue
		}
		if c.reasonHas != "" {
			found := false
			for _, u := range us {
				if u.Status != ui.OK && strings.Contains(u.Reason, c.reasonHas) {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: no reason mentions %q: %+v", c.name, c.reasonHas, us)
			}
		}
	}
}

func TestReadinessSaysWhatWasNotMeasured(t *testing.T) {
	us := readiness(link{PingKnown: true, LatencyMs: 15, JitterMs: 2, LossKnown: true})
	if us[0].Reason != "steady, low latency (bandwidth not measured)" {
		t.Fatalf("calls reason should admit bandwidth wasn't tested: %q", us[0].Reason)
	}
	if us[2].Reason != "needs a speed test" {
		t.Fatalf("4K: %+v", us[2])
	}
}

func TestReadinessFromSpeedTestAdmitsNoLoss(t *testing.T) {
	us := readiness(link{PingKnown: true, LatencyMs: 15, JitterMs: 2, DownMbps: 300, UpMbps: 50, LoadedMs: 40})
	if us[0].Reason != "steady, low latency (packet loss not measured)" {
		t.Fatalf("got %q", us[0].Reason)
	}
}

func TestReadinessLine(t *testing.T) {
	cases := []struct {
		in   link
		want string
	}{
		{link{PingKnown: true, LatencyMs: 12, JitterMs: 2, LossKnown: true, DownMbps: 300, UpMbps: 50},
			"Good for video calls, gaming and 4K streaming."},
		{link{PingKnown: true, LatencyMs: 45, JitterMs: 22, LossKnown: true, DownMbps: 40, UpMbps: 10},
			"Good for video calls and 4K streaming; borderline for gaming: jitter is 22 ms; games want under 10 ms."},
		{link{PingKnown: true, LatencyMs: 600, JitterMs: 5, LossKnown: true, DownMbps: 100, UpMbps: 10},
			"Good for 4K streaming; not good for video calls and gaming: latency is 600 ms; calls want under 150 ms."},
		{link{}, ""},
	}
	for _, c := range cases {
		if got := readinessLine(readiness(c.in)); got != c.want {
			t.Errorf("got  %q\nwant %q", got, c.want)
		}
	}
}

func TestJoinAnd(t *testing.T) {
	if joinAnd([]string{"a"}) != "a" || joinAnd([]string{"a", "b"}) != "a and b" || joinAnd([]string{"a", "b", "c"}) != "a, b and c" {
		t.Fatal("joinAnd")
	}
}

func TestSpeedLink(t *testing.T) {
	l := speedLink(probe.SpeedResult{IdleMs: 14, IdleJitterMs: 3, DownMbps: 20, UpMbps: 4, DownLoadedMs: 120, UpLoadedMs: 260})
	if !l.PingKnown || l.LossKnown || l.LoadedMs != 260 {
		t.Fatalf("got %+v", l)
	}
	us := readiness(l)
	// 260 ms under load: borderline for calls (bad from 400), poor for games (bad from 250).
	if us[0].Status != ui.Warn || us[1].Status != ui.Bad || us[2].Status != ui.Warn {
		t.Fatalf("got %+v", us)
	}
}

// From a real `netcheck speed` on Windows: 50 ms idle, jitter just over
// 10 ms, 15 Mbps down, 221 ms while downloading. Gaming must blame the
// latency under load (2.2x its limit), not jitter a hair over 10 ms, and no
// value may round onto the limit it's compared with.
func TestReadinessRealWindowsRun(t *testing.T) {
	us := readiness(link{PingKnown: true, LatencyMs: 50, JitterMs: 10.4, DownMbps: 15.0, UpMbps: 11.8, LoadedMs: 221})
	if us[1].Status != ui.Warn || us[1].Reason != "latency under load is 221 ms; games lag while others download" {
		t.Errorf("gaming: %+v", us[1])
	}
	if us[0].Reason != "latency under load is 221 ms; calls stutter while others download" {
		t.Errorf("calls: %+v", us[0])
	}
	us = readiness(link{PingKnown: true, LatencyMs: 20, JitterMs: 10.4, LossKnown: true, DownMbps: 300, UpMbps: 50, LoadedMs: 40})
	if us[1].Reason != "jitter is 10.4 ms; games want under 10 ms" {
		t.Errorf("rounding: %q", us[1].Reason)
	}
}
