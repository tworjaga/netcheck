package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/ui"
	"github.com/tworjaga/netcheck/internal/uptime"
)

func TestUptimeDashFits(t *testing.T) {
	var ts []uptime.Target
	for _, s := range []string{"https://a-rather-long-name.example.com/health/check/endpoint", "tcp://db.internal:5432", "ping://192.168.0.1"} {
		x, _ := uptime.ParseTarget(s)
		ts = append(ts, x)
	}
	m := uptime.NewMonitor(ts, 1, 14)
	now := time.Now()
	m.Add(uptime.Sample{Time: now, ID: ts[0].ID, OK: true, Ms: 120, Detail: "200", CertDays: 9})
	m.Add(uptime.Sample{Time: now, ID: ts[1].ID, OK: false, Detail: "connection refused"})
	d := &uptimeDash{m: m, every: 30 * time.Second, logPath: `C:\Users\x\AppData\Roaming\netcheck\uptime.jsonl`, start: now.Add(-time.Hour)}
	d.addEvents([]uptime.Event{{Time: now, Kind: "down", Text: "db.internal:5432 is down: connection refused"}})
	for _, size := range [][2]int{{80, 24}, {120, 30}, {200, 50}} {
		lines := d.render(size[0], size[1], now)
		text := strings.Join(lines, "\n")
		for _, l := range lines {
			if ui.VisWidth(l) > size[0]-1 {
				t.Errorf("%dx%d: too wide (%d): %q", size[0], size[1], ui.VisWidth(l), l)
			}
		}
		if !strings.Contains(text, "1 down") || !strings.Contains(text, "is down: connection refused") || !strings.Contains(text, "9 d") {
			t.Errorf("%dx%d:\n%s", size[0], size[1], text)
		}
	}
}

func TestUptimeReport(t *testing.T) {
	if prettyID("https://example.com/") != "example.com" || prettyID("tcp://db:5432") != "db:5432" || prettyID("ping://h") != "ping h" {
		t.Error("prettyID")
	}
	rows := []uptimeRow{
		{Target: "https://shop.test", Sum: &uptime.Summary{Checks: 100, Good: 97, Uptime: 97, Outages: []uptime.Outage{{Start: time.Now(), Length: time.Hour, Ended: true}}}},
		{Target: "tcp://db:5432", Sum: &uptime.Summary{Checks: 100, Good: 90, Uptime: 90, Outages: []uptime.Outage{{Start: time.Date(2026, 10, 14, 9, 30, 0, 0, time.Local), Detail: "refused"}}}},
	}
	st, msg, notes := reportVerdict(rows, 7)
	if st != ui.Bad || !strings.Contains(msg, "2 targets, 2 outages") || !strings.Contains(msg, "db:5432 at 90.00%") || !strings.Contains(notes[0], "db:5432 has been down since Oct 14 09:30") {
		t.Errorf("%v %q %v", st, msg, notes)
	}
	if st, _, _ := reportVerdict(nil, 7); st != ui.Skip {
		t.Error("empty")
	}
	for _, l := range reportTable(rows).Lines(78) {
		if ui.VisWidth(l) > 78 {
			t.Errorf("too wide: %q", l)
		}
	}
}

func TestUptimeAlertLinesInFile(t *testing.T) {
	got := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
	}))
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "servers.txt")
	os.WriteFile(file, []byte("# my servers\nhttps://shop.test name=Shop\nalert webhook "+srv.URL+"/hook\n"), 0o644)
	if code := cmdUptime([]string{"-f", file, "--test-alert", "--json"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	select {
	case b := <-got:
		if !strings.Contains(b, "test alert from netcheck uptime") {
			t.Errorf("body %q", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the webhook from the file wasn't called")
	}
	os.WriteFile(file, []byte("alert pager 555\n"), 0o644)
	if code := cmdUptime([]string{"-f", file, "--test-alert"}); code != 2 {
		t.Errorf("a bad alert line: exit %d", code)
	}
}
