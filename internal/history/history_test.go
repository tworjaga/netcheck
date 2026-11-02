package history

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var base = time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)

// series builds samples every 5 s from start; f returns gw, net, dns for
// sample i (NaN-free: use -1 for lost, and -2 for "not measured").
func series(start time.Time, n int, f func(i int) (gw, net, dns float64)) []Sample {
	box := func(v float64) *float64 {
		if v == -2 {
			return nil
		}
		return Ms(v)
	}
	out := make([]Sample, n)
	for i := range out {
		g, nt, d := f(i)
		out[i] = Sample{V: Version, T: start.Add(time.Duration(i) * 5 * time.Second), GW: box(g), Net: box(nt), DNS: box(d)}
	}
	return out
}

func TestWriterRoundTripAndVersioning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "history.jsonl")
	w, err := Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range series(base, 3, func(i int) (float64, float64, float64) { return 2, 14.26, -1 }) {
		if err := w.Append(s); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	b, _ := os.ReadFile(path)
	first := strings.SplitN(string(b), "\n", 2)[0]
	if first != `{"v":1,"t":"2026-10-05T00:00:00Z","gw":2,"net":14.3,"dns":-1}` {
		t.Fatalf("line format changed: %s", first)
	}
	// A newer format, garbage, and a torn last line are skipped, not fatal.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"v":2,"t":"2026-10-05T00:01:00Z","net":3}` + "\nnot json\n" + `{"v":1,"t":"2026-10-05T00:0`)
	f.Close()
	res, err := Read(path)
	if err != nil || len(res.Samples) != 3 || res.Skipped != 3 {
		t.Fatalf("got %d samples, %d skipped, %v", len(res.Samples), res.Skipped, err)
	}
	if v, ok := res.Samples[0].Get(DNS); !ok || v != -1 {
		t.Fatalf("lost DNS should read back as -1, got %v %v", v, ok)
	}
}

func TestReadMissingLog(t *testing.T) {
	res, err := Read(filepath.Join(t.TempDir(), "nope.jsonl"))
	if err != nil || len(res.Samples) != 0 {
		t.Fatalf("got %+v, %v", res, err)
	}
}

func TestWriterRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	w, err := Open(path, 200) // ~3 lines per file
	if err != nil {
		t.Fatal(err)
	}
	ss := series(base, 10, func(i int) (float64, float64, float64) { return 1, 10, 5 })
	for _, s := range ss {
		if err := w.Append(s); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	cur, _ := os.Stat(path)
	old, err := os.Stat(path + ".1")
	if err != nil || cur.Size() > 200 || old.Size() > 200 {
		t.Fatalf("rotation didn't bound the files: %v", err)
	}
	res, _ := Read(path)
	if len(res.Samples) == 0 || len(res.Samples) >= 10 {
		t.Fatalf("expected only the newest samples to survive, got %d", len(res.Samples))
	}
	last := res.Samples[len(res.Samples)-1]
	if !last.T.Equal(ss[9].T) {
		t.Fatalf("newest sample missing after rotation")
	}
	for i := 1; i < len(res.Samples); i++ {
		if res.Samples[i].T.Before(res.Samples[i-1].T) {
			t.Fatal("samples out of order across rotated files")
		}
	}
}

func TestOutagesAndCause(t *testing.T) {
	ss := series(base, 40, func(i int) (float64, float64, float64) {
		switch {
		case i == 3: // one lost probe: packet loss, not an outage
			return 2, -1, 10
		case i >= 10 && i < 16: // 30 s down, router fine: ISP
			return 2, -1, -1
		case i >= 25 && i < 28: // router down too: local
			return -1, -1, -1
		}
		return 2, 15, 10
	})
	r := Analyze(ss, time.UTC)
	if len(r.Outages) != 2 {
		t.Fatalf("want 2 outages, got %+v", r.Outages)
	}
	if o := r.Outages[0]; o.Cause != "isp" || o.Seconds != 30 || o.Ongoing {
		t.Fatalf("first outage: %+v", o)
	}
	if o := r.Outages[1]; o.Cause != "local" || o.Seconds != 15 {
		t.Fatalf("second outage: %+v", o)
	}
	if r.OutageSeconds != 45 || r.Internet.Lost != 10 || r.Internet.MedianMs != 15 {
		t.Fatalf("report: %+v %+v", r, r.Internet)
	}
}

func TestOutageDoesNotSpanGapsAndOngoing(t *testing.T) {
	a := series(base, 5, func(i int) (float64, float64, float64) {
		if i >= 3 {
			return -2, -1, -2
		}
		return -2, 10, -2
	})
	// The watcher stopped for an hour, then came back to a dead link.
	b := series(base.Add(time.Hour), 4, func(i int) (float64, float64, float64) { return -2, -1, -2 })
	r := Analyze(append(a, b...), time.UTC)
	if len(r.Outages) != 2 {
		t.Fatalf("want 2 outages, got %+v", r.Outages)
	}
	if r.Outages[0].Seconds != 10 || r.Outages[0].Cause != "unknown" || r.Outages[0].Ongoing {
		t.Fatalf("an hour of not watching must not count as downtime: %+v", r.Outages[0])
	}
	if !r.Outages[1].Ongoing || r.Outages[1].Seconds != 20 {
		t.Fatalf("second outage: %+v", r.Outages[1])
	}
	if r.Gateway != nil {
		t.Fatal("unmeasured gateway should have no stats")
	}
}

func TestDaysAndHours(t *testing.T) {
	loc := time.FixedZone("CEST", 2*3600)
	// 23:59:50 UTC is 01:59:50 the next day in CEST.
	start := time.Date(2026, 10, 5, 23, 59, 50, 0, time.UTC)
	ss := series(start, 4, func(i int) (float64, float64, float64) { return 1, float64(10 + i), 5 })
	r := Analyze(ss, loc)
	if len(r.Days) != 1 || r.Days[0].Date != "2026-10-06" {
		t.Fatalf("days: %+v", r.Days)
	}
	d := r.Days[0]
	if d.HourLoss[1] != 0 || d.HourLoss[2] != 0 || d.HourLoss[3] != -1 || d.HourMs[3] != -1 {
		t.Fatalf("hour buckets: %v %v", d.HourMs, d.HourLoss)
	}
	if len(r.Hours) != 2 || r.Hours[0].Hour != 1 || r.Hours[1].Hour != 2 {
		t.Fatalf("hours: %+v", r.Hours)
	}
}

func TestSince(t *testing.T) {
	ss := series(base, 10, func(int) (float64, float64, float64) { return 1, 1, 1 })
	if got := Since(ss, base.Add(20*time.Second)); len(got) != 6 {
		t.Fatalf("got %d", len(got))
	}
}

func TestEmpty(t *testing.T) {
	r := Analyze(nil, time.UTC)
	if r.Samples != 0 || r.Outages == nil || r.Days == nil {
		t.Fatalf("empty report should have empty, non-nil lists: %+v", r)
	}
}
