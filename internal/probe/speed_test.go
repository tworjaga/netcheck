package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRate paces each fake transfer like a ~100 Mbps line. Unpaced, it pushed
// gigabits over loopback, which on Windows starved the latency probes and
// left the "under load" numbers empty.
const fakeRate = 100e6 / 8 // bytes per second

// pace sleeps until n bytes are due at fakeRate since start.
func pace(start time.Time, n int) {
	if due := start.Add(time.Duration(float64(n) / fakeRate * float64(time.Second))); time.Until(due) > 0 {
		time.Sleep(time.Until(due))
	}
}

// fakeSpeedServer mimics Cloudflare's __down and __up. While a transfer is
// in flight, tiny latency requests are delayed by bloat, which simulates a
// saturated link with a deep buffer.
func fakeSpeedServer(t *testing.T, bloat time.Duration) *httptest.Server {
	t.Helper()
	var busy atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/__down":
			n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
			w.Header().Set("Cf-Meta-Colo", "VIE")
			if n == 0 {
				// A real line's idle latency. Loopback alone can round to 0 ms
				// on Windows, whose monotonic clock ticks too coarsely.
				time.Sleep(2 * time.Millisecond)
				if busy.Load() > 0 {
					time.Sleep(bloat)
				}
				return
			}
			busy.Add(1)
			defer busy.Add(-1)
			chunk := make([]byte, 32<<10)
			start := time.Now()
			for sent := 0; sent < n; sent += len(chunk) {
				if _, err := w.Write(chunk); err != nil {
					return
				}
				pace(start, sent+len(chunk))
			}
		case "/__up":
			busy.Add(1)
			defer busy.Add(-1)
			buf := make([]byte, 32<<10)
			start, got := time.Now(), 0
			for {
				n, err := r.Body.Read(buf)
				got += n
				if err != nil {
					break
				}
				pace(start, got)
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func quickCfg(url string) SpeedConfig {
	return SpeedConfig{BaseURL: url, DownStreams: 2, UpStreams: 2, Duration: 900 * time.Millisecond, Warmup: 200 * time.Millisecond, IdleProbes: 4}
}

func TestRunSpeedMeasuresBothDirections(t *testing.T) {
	srv := fakeSpeedServer(t, 0)
	phases := map[string]bool{}
	res := RunSpeed(context.Background(), quickCfg(srv.URL), func(p SpeedProgress) { phases[p.Phase] = true })
	if res.Error != "" || res.Partial != "" {
		t.Fatalf("unexpected error: %+v", res)
	}
	if res.DownMbps <= 0 || res.UpMbps <= 0 {
		t.Fatalf("expected throughput in both directions, got %+v", res)
	}
	if res.Server != "Cloudflare VIE" || res.IdleMs <= 0 || res.Grade == "" {
		t.Fatalf("missing details: %+v", res)
	}
	for _, p := range []string{"latency", "download", "upload"} {
		if !phases[p] {
			t.Errorf("no progress reported for %s", p)
		}
	}
}

func TestRunSpeedDetectsBufferbloat(t *testing.T) {
	srv := fakeSpeedServer(t, 400*time.Millisecond)
	res := RunSpeed(context.Background(), quickCfg(srv.URL), nil)
	if res.Error != "" {
		t.Fatalf("%+v", res)
	}
	if res.BloatMs < 250 || res.Grade != "F" {
		t.Fatalf("a 400 ms queue under load should grade F, got %.0f ms grade %q", res.BloatMs, res.Grade)
	}
}

func TestRunSpeedOffline(t *testing.T) {
	start := time.Now()
	res := RunSpeed(context.Background(), quickCfg("http://127.0.0.1:1"), nil)
	if res.Error == "" {
		t.Fatalf("offline must report an error, got %+v", res)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("offline speed test took too long")
	}
}

func TestRunSpeedCancel(t *testing.T) {
	srv := fakeSpeedServer(t, 0)
	cfg := quickCfg(srv.URL)
	cfg.Duration = 20 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(700 * time.Millisecond); cancel() }()
	start := time.Now()
	res := RunSpeed(ctx, cfg, nil)
	if res.Error != "interrupted" {
		t.Fatalf("got %+v", res)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("Ctrl-C should stop the test promptly")
	}
}

func TestBloatGrade(t *testing.T) {
	cases := map[float64]string{0: "A", 29: "A", 30: "B", 59: "B", 60: "C", 119: "C", 120: "D", 249: "D", 250: "F", 900: "F"}
	for ms, want := range cases {
		if got := BloatGrade(ms); got != want {
			t.Errorf("BloatGrade(%v) = %s, want %s", ms, got, want)
		}
	}
}

func TestRayColo(t *testing.T) {
	for ray, want := range map[string]string{
		"a4a53e03f8885ba7-VIE":  "VIE", // a real header, 2026-10-14
		"8c1f00aa11bb22cc-FRA":  "FRA",
		"a4a53e03f8885ba7":      "",
		"a4a53e03f8885ba7-vie":  "",
		"a4a53e03f8885ba7-VIEN": "",
		"":                      "",
	} {
		if got := rayColo(ray); got != want {
			t.Errorf("rayColo(%q) = %q, want %q", ray, got, want)
		}
	}
}

func TestLatencyProbeFallsBackToRay(t *testing.T) {
	// Today's speed.cloudflare.com: no Cf-Meta-Colo, only CF-Ray.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-RAY", "a4a53e03f8885ba7-VIE")
	}))
	defer srv.Close()
	_, colo, err := latencyProbe(context.Background(), srv.Client(), srv.URL)
	if err != nil || colo != "VIE" {
		t.Fatalf("got %q %v", colo, err)
	}
}
