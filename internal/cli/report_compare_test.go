package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
)

// sample builds a report with the numbers that comparisons use.
func sample(at time.Time, gwMs, netMs, jitter, dnsMs float64, dbm int, down, up, idle, bloat float64, grade, verdictMsg string) reportData {
	return reportData{
		Generated: at,
		Verdict:   verdict{"warn", verdictMsg},
		Checks: doctorReport{
			Gateway:  &probe.PingResult{Sent: 10, Received: 10, AvgMs: gwMs},
			Internet: &probe.PingResult{Sent: 10, Received: 10, AvgMs: netMs, JitterMs: jitter},
			DNS:      []probe.DNSResult{{Label: "System", Answered: 3, Lookups: 3, MedianMs: dnsMs}},
			Wifi:     &probe.WifiInfo{Connected: true, SignalDBm: dbm},
			Speed:    &probe.SpeedResult{DownMbps: down, UpMbps: up, IdleMs: idle, BloatMs: bloat, Grade: grade},
		},
	}
}

func TestCompareReports(t *testing.T) {
	// Before: the real report from the test machine (grade C). After: the
	// same line with SQM on, shaped a little below the measured speed.
	t0 := time.Date(2026, 10, 13, 23, 57, 0, 0, time.UTC)
	before := sample(t0, 15, 26, 16, 28, -53, 19.8, 15.3, 53, 112, "C", "Latency rises by 112 ms when the connection is busy (grade C).")
	after := sample(t0.Add(26*time.Hour), 14, 20, 15, 27, -55, 17.5, 13.5, 51, 9, "A", "Your connection looks healthy.")
	c := compareReports(before, after)
	got := map[string]string{}
	for _, r := range c.Rows {
		got[r.Metric] = r.Change
	}
	want := map[string]string{
		"Router latency": "same", "Router loss": "same",
		"Internet latency": "better", "Internet jitter": "same", "Internet loss": "same",
		"Your DNS": "same", "Wi-Fi signal": "same",
		"Download": "worse", "Upload": "worse", "Idle latency": "same", "Bufferbloat": "better",
	}
	for m, w := range want {
		if got[m] != w {
			t.Errorf("%s: got %q, want %q", m, got[m], w)
		}
	}
	if len(c.Rows) != len(want) || !c.Since.Equal(t0) {
		t.Fatalf("rows %+v since %v", c.Rows, c.Since)
	}
	if s := compareSummary(c); s != "Compared with Tue Oct 13 23:57: 2 better, 2 worse, 7 about the same." {
		t.Errorf("summary: %q", s)
	}

	after.Compared = &c
	md := renderMarkdown(after)
	for _, want := range []string{
		"## Compared with Tue 13 Oct 2026 23:57 UTC",
		"| Bufferbloat | 112 ms | 9.0 ms | better |",
		"| Download | 19.8 Mbps | 17.5 Mbps | worse |",
		"| Wi-Fi signal | -53 dBm | -55 dBm | about the same |",
		"Before: Latency rises by 112 ms",
		"Now: Your connection looks healthy.",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
}

func TestCompareSkipsWhatWasntMeasured(t *testing.T) {
	before := sample(time.Now(), 15, 26, 16, 28, -53, 19.8, 15.3, 53, 112, "C", "x")
	fast := sample(time.Now(), 15, 26, 16, 28, -53, 0, 0, 0, 0, "", "y")
	fast.Checks.Speed = nil // report --fast
	fast.Checks.Wifi = &probe.WifiInfo{}
	for _, r := range compareReports(before, fast).Rows {
		switch r.Metric {
		case "Download", "Upload", "Idle latency", "Bufferbloat", "Wi-Fi signal":
			t.Errorf("%s wasn't measured this time, so it can't be compared", r.Metric)
		}
	}
}

func TestLastReportRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netcheck", "last-report.json")
	t.Setenv("NETCHECK_LAST_REPORT", path)
	if _, err := loadReport("last"); !errors.Is(err, errNoLastReport) {
		t.Fatalf("before any report: %v", err)
	}
	r := sample(time.Date(2026, 10, 13, 23, 57, 0, 0, time.UTC), 15, 26, 16, 28, -53, 19.8, 15.3, 53, 112, "C", "grade C")
	if err := saveLastReport(r); err != nil {
		t.Fatal(err)
	}
	back, err := loadReport("last")
	if err != nil || !back.Generated.Equal(r.Generated) || back.Checks.Speed.DownMbps != 19.8 {
		t.Fatalf("got %+v %v", back, err)
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Error("temp file left behind")
	}
	junk := filepath.Join(t.TempDir(), "notes.md")
	_ = os.WriteFile(junk, []byte("# Network report\n"), 0o600)
	if _, err := loadReport(junk); err == nil || !strings.Contains(err.Error(), "--format json") {
		t.Errorf("a Markdown report can't be compared, and the error should say how to make one: %v", err)
	}
}
