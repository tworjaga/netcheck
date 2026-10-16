package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/history"
	"github.com/tworjaga/netcheck/internal/ui"
)

// fakeClock only moves when the watcher sleeps (or a probe "takes time").
// Probes run in parallel, so it locks.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	slept  []time.Duration
	perOne time.Duration // time each tick's probes "take"
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() == nil && d > 0 {
		c.slept = append(c.slept, d)
		c.now = c.now.Add(d)
	}
}

// scripted returns a probe that plays back vals, then repeats the last one.
func scripted(c *fakeClock, vals ...float64) func(context.Context, time.Duration) float64 {
	i := 0
	return func(context.Context, time.Duration) float64 {
		c.mu.Lock()
		defer c.mu.Unlock()
		v := vals[min(i, len(vals)-1)]
		i++
		c.now = c.now.Add(c.perOne)
		return v
	}
}

var t0 = time.Date(2026, 10, 13, 19, 0, 0, 0, time.UTC)

func TestWatcherTicksOnTheIntervalAndLogs(t *testing.T) {
	c := &fakeClock{now: t0}
	path := filepath.Join(t.TempDir(), "history.jsonl")
	log, err := history.Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	w := watcher{
		clock: c, interval: 5 * time.Second, until: 30 * time.Second,
		targets: []watchTarget{
			{t: history.Gateway, probe: scripted(c, 2)},
			{t: history.Internet, probe: scripted(c, 14, -1, -1, 15)},
			{t: history.DNS, probe: scripted(c, 9)},
		},
		record: func(s history.Sample) { _ = log.Append(s) },
	}
	got := w.run(context.Background())
	log.Close()
	if len(got) != 6 {
		t.Fatalf("30 s at 5 s should be 6 samples, got %d", len(got))
	}
	for i, s := range got {
		if want := t0.Add(time.Duration(i) * 5 * time.Second); !s.T.Equal(want) {
			t.Fatalf("sample %d at %v, want %v (drift)", i, s.T, want)
		}
	}
	read, _ := history.Read(path)
	if len(read.Samples) != 6 || read.Skipped != 0 {
		t.Fatalf("log has %d samples", len(read.Samples))
	}
	if v, _ := read.Samples[1].Get(history.Internet); v != -1 {
		t.Fatalf("lost probe should be logged as -1, got %v", v)
	}
	r := history.Analyze(read.Samples, time.UTC)
	if len(r.Outages) != 1 || r.Outages[0].Cause != "isp" || r.Outages[0].Seconds != 10 {
		t.Fatalf("outages: %+v", r.Outages)
	}
}

func TestWatcherSubtractsProbeTimeFromSleep(t *testing.T) {
	c := &fakeClock{now: t0, perOne: 300 * time.Millisecond}
	w := watcher{clock: c, interval: 5 * time.Second, until: 10 * time.Second,
		targets: []watchTarget{{t: history.Internet, probe: scripted(c, 10)}}}
	w.run(context.Background())
	if len(c.slept) == 0 || c.slept[0] != 4700*time.Millisecond {
		t.Fatalf("slept %v", c.slept)
	}
}

func TestWatcherStopsOnCtrlCWithoutCountingTheCutProbe(t *testing.T) {
	c := &fakeClock{now: t0}
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	w := watcher{clock: c, interval: time.Second,
		targets: []watchTarget{{t: history.Internet, probe: func(context.Context, time.Duration) float64 {
			if n++; n == 4 {
				cancel() // Ctrl-C arrives while the 4th probe is in flight
				return -1
			}
			return 10
		}}}}
	done := make(chan []history.Sample)
	go func() { done <- w.run(ctx) }()
	select {
	case got := <-done:
		if len(got) != 3 {
			t.Fatalf("want the 3 completed samples, got %d", len(got))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher didn't stop on cancel")
	}
}

func TestProbeTimeoutFitsInterval(t *testing.T) {
	if probeTimeout(5*time.Second) != 2*time.Second || probeTimeout(time.Second) != 800*time.Millisecond {
		t.Fatal("probe timeout must stay below the interval")
	}
}

func samplesFrom(netVals []float64, gw float64) []history.Sample {
	var out []history.Sample
	for i, v := range netVals {
		out = append(out, history.Sample{V: 1, T: t0.Add(time.Duration(i) * 5 * time.Second), GW: history.Ms(gw), Net: history.Ms(v), DNS: history.Ms(8)})
	}
	return out
}

func repeat(v float64, n int) []float64 {
	out := make([]float64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func TestWatchVerdict(t *testing.T) {
	steady := repeat(14, 100)
	withDrop := append(append(repeat(14, 50), -1, -1, -1), repeat(14, 47)...)
	lossy := append([]float64(nil), steady...)
	for i := 0; i < 100; i += 20 {
		lossy[i] = -1
	}
	spiky := append([]float64(nil), steady...)
	for i := 0; i < 100; i += 10 {
		spiky[i] = 200
	}
	cases := []struct {
		name string
		in   []history.Sample
		want ui.Status
		has  string
	}{
		{"steady", samplesFrom(steady, 2), ui.OK, "Stable"},
		{"one drop, router fine", samplesFrom(withDrop, 2), ui.Warn, "ISP"},
		{"scattered loss", samplesFrom(lossy, 2), ui.Warn, "were lost"},
		{"spikes", samplesFrom(spiky, 2), ui.Warn, "spikes"},
		{"never answered", samplesFrom(repeat(-1, 10), 2), ui.Bad, "never answered"},
		{"nothing", nil, ui.Skip, "Nothing"},
	}
	for _, c := range cases {
		r := history.Analyze(c.in, time.UTC)
		st, head, _ := watchVerdict(r, 500*time.Second)
		if st != c.want || !strings.Contains(head, c.has) {
			t.Errorf("%s: got (%v, %q)", c.name, st, head)
		}
	}
	// A long outage relative to the session is serious.
	long := append(append(repeat(14, 20), repeat(-1, 40)...), repeat(14, 20)...)
	if st, _, _ := watchVerdict(history.Analyze(samplesFrom(long, -1), time.UTC), 400*time.Second); st != ui.Bad {
		t.Errorf("long outage should be bad, got %v", st)
	}
}

func TestLiveLines(t *testing.T) {
	tg := []watchTarget{{label: "Gateway", addr: "192.168.1.1"}, {label: "Internet", addr: "1.1.1.1"}}
	lines := liveLines(tg, [][]float64{{2, 2, 3}, {14, -1}}, 3, 15*time.Second, 1, 5*time.Second)
	if len(lines) != 4 || !strings.Contains(lines[1], "lost") || !strings.Contains(lines[3], "1 drop") {
		t.Fatalf("got %q", lines)
	}
}

func TestPlainSample(t *testing.T) {
	s := history.Sample{T: t0, Net: history.Ms(14.25), DNS: history.Ms(-1)}
	if got := plainSample(s); !strings.Contains(got, "internet 14.3") || !strings.Contains(got, "dns lost") || strings.Contains(got, "gateway") {
		t.Fatalf("got %q", got)
	}
}

func TestFmtDur(t *testing.T) {
	cases := map[time.Duration]string{
		45 * time.Second:                               "45 s",
		90 * time.Second:                               "1 min 30 s",
		12 * time.Minute:                               "12 min",
		2*time.Hour + 5*time.Minute:                    "2 h 5 min",
		3 * time.Hour:                                  "3 h",
		50*time.Hour + 10*time.Minute:                  "2 d 2 h",
		23*time.Hour + 59*time.Minute + 50*time.Second: "1 d",
	}
	for d, want := range cases {
		if got := fmtDur(d); got != want {
			t.Errorf("fmtDur(%v) = %q, want %q", d, got, want)
		}
	}
}

// hourly builds days of samples, 30 per hour, with latency and loss from f.
func hourly(days int, loc *time.Location, f func(h, i int) (net, gw float64)) []history.Sample {
	var out []history.Sample
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, loc)
	for d := 0; d < days; d++ {
		for h := 0; h < 24; h++ {
			for i := 0; i < 30; i++ {
				nv, gw := f(h, i)
				out = append(out, history.Sample{V: 1, T: start.AddDate(0, 0, d).Add(time.Duration(h)*time.Hour + time.Duration(i)*2*time.Minute), Net: history.Ms(nv), GW: history.Ms(gw)})
			}
		}
	}
	return out
}

func TestHistoryVerdict(t *testing.T) {
	loc := time.FixedZone("local", 3600)
	cases := []struct {
		name string
		f    func(h, i int) (float64, float64)
		want ui.Status
		has  string
	}{
		{"steady", func(h, i int) (float64, float64) { return 15, 2 }, ui.OK, "no time of day stands out"},
		{"evening slowdown", func(h, i int) (float64, float64) {
			if h == 20 {
				return 60, 2
			}
			return 15, 2
		}, ui.Warn, "slows down around 8pm"},
		{"evening packet loss", func(h, i int) (float64, float64) {
			if h == 21 && i%10 == 0 {
				return -1, 2
			}
			return 15, 2
		}, ui.Warn, "unreliable around 9pm"},
		{"outages at 8pm every day, router fine", func(h, i int) (float64, float64) {
			if h == 20 && i < 3 {
				return -1, 2
			}
			return 15, 2
		}, ui.Bad, "drops around 8pm"},
		{"outages with the router down", func(h, i int) (float64, float64) {
			if h == 3 && i < 2 {
				return -1, -1
			}
			return 15, 2
		}, ui.Bad, "Wi-Fi, cable or router"},
	}
	for _, c := range cases {
		r := history.Analyze(hourly(4, loc, c.f), loc)
		st, head, _ := historyVerdict(r, loc)
		if st != c.want || !strings.Contains(head, c.has) {
			t.Errorf("%s: got (%v, %q)", c.name, st, head)
		}
	}
	if st, head, _ := historyVerdict(history.Analyze(nil, loc), loc); st != ui.Skip || !strings.Contains(head, "netcheck watch") {
		t.Errorf("empty: got (%v, %q)", st, head)
	}
}

func TestBadHoursNeedsEnoughOfTheDay(t *testing.T) {
	// Two hours of data can't show a time-of-day pattern.
	loc := time.UTC
	var ss []history.Sample
	for i := 0; i < 60; i++ {
		v := 15.0
		if i >= 30 {
			v = 80
		}
		ss = append(ss, history.Sample{V: 1, T: time.Date(2026, 10, 1, 19, 0, 0, 0, loc).Add(time.Duration(i) * 2 * time.Minute), Net: history.Ms(v)})
	}
	if b := badHours(history.Analyze(ss, loc)); len(b) != 0 {
		t.Fatalf("got %+v", b)
	}
}

func TestHourName(t *testing.T) {
	for h, want := range map[int]string{0: "midnight", 9: "9am", 12: "noon", 20: "8pm"} {
		if hourName(h) != want {
			t.Errorf("hourName(%d) = %q", h, hourName(h))
		}
	}
}

func TestDayStrip(t *testing.T) {
	d := history.Day{HourMs: repeat(-1, 24), HourLoss: repeat(-1, 24)}
	d.HourMs[8], d.HourLoss[8] = 20, 0
	d.HourLoss[9] = 100
	os.Setenv("NO_COLOR", "1")
	s := dayStrip(d, 10, 40)
	if n := len([]rune(stripANSI(s))); n != 24 {
		t.Fatalf("strip should be 24 cells, got %d: %q", n, s)
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case r == 0x1b:
			esc = true
		case esc && r == 'm':
			esc = false
		case !esc:
			b.WriteRune(r)
		}
	}
	return b.String()
}
