package cli

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/history"
	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

func dashSession(t *testing.T) (*dashboard, time.Time) {
	t.Helper()
	t0 := time.Date(2026, 10, 14, 18, 0, 0, 0, time.UTC)
	targets := []watchTarget{
		{t: history.Gateway, label: "Gateway", addr: "192.168.0.1"},
		{t: history.Internet, label: "Internet", addr: "1.1.1.1"},
		{t: history.DNS, label: "DNS", addr: "System"},
	}
	d := newDashboard(targets, t0, 5*time.Second, "192.168.0.123 → 192.168.0.1 → 1.1.1.1", "saving to history", nil)
	at := t0
	add := func(gw, net, dns float64) {
		at = at.Add(5 * time.Second)
		d.add(history.Sample{V: history.Version, T: at, GW: history.Ms(gw), Net: history.Ms(net), DNS: history.Ms(dns)})
	}
	for i := 0; i < 10; i++ {
		add(6, 18, 21)
	}
	add(6, 400, 21) // a spike
	add(6, 19, 21)
	add(5, -1, -1) // the internet drops, the router keeps answering
	add(6, -1, 22)
	add(6, -1, 21)
	add(6, 17, 20) // back
	return d, at
}

func TestDashboardEvents(t *testing.T) {
	d, _ := dashSession(t)
	var texts []string
	for _, e := range d.events {
		texts = append(texts, e.text)
	}
	all := strings.Join(texts, " | ")
	for _, want := range []string{"watch started", "spike 400 ms (usually 18 ms)", "internet down", "internet back after 15 s", "dns missed a probe"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing event %q in %s", want, all)
		}
	}
	if d.drops != 1 || !d.downAt.IsZero() {
		t.Errorf("drops %d, down %v", d.drops, d.downAt)
	}
	if strings.Contains(all, "router missed") || strings.Contains(all, "gateway missed") {
		t.Errorf("the router never missed a probe: %s", all)
	}
}

func TestDashboardFitsTheWindow(t *testing.T) {
	d, now := dashSession(t)
	for _, size := range [][2]int{{120, 32}, {dashMinW, dashMinH}, {200, 50}} {
		w, h := size[0], size[1]
		lines := d.render(w, h, now)
		if len(lines) > h {
			t.Errorf("%dx%d: %d lines", w, h, len(lines))
		}
		for i, l := range lines {
			if ui.VisWidth(l) > w-1 {
				t.Errorf("%dx%d: line %d is %d wide: %q", w, h, i, ui.VisWidth(l), l)
			}
		}
		screen := strings.Join(lines, "\n")
		for _, want := range []string{"q quit", "Internet 1.1.1.1", "Now", "Router", "192.168.0.1", "DNS", "System", "Events", "Drops", "internet back after 15 s"} {
			if !strings.Contains(screen, want) {
				t.Errorf("%dx%d: missing %q", w, h, want)
			}
		}
	}
}

func TestDashboardShowsAnOutage(t *testing.T) {
	d, now := dashSession(t)
	d.add(history.Sample{V: history.Version, T: now.Add(5 * time.Second), GW: history.Ms(6), Net: history.Ms(-1), DNS: history.Ms(21)})
	d.add(history.Sample{V: history.Version, T: now.Add(10 * time.Second), GW: history.Ms(6), Net: history.Ms(-1), DNS: history.Ms(21)})
	screen := strings.Join(d.render(100, 30, now.Add(12*time.Second)), "\n")
	if !strings.Contains(screen, "down") || !strings.Contains(screen, "for 7 s") {
		t.Errorf("the internet panel should say it's down and for how long:\n%s", screen)
	}
}

func TestDashboardPanelsLineUp(t *testing.T) {
	d, now := dashSession(t)
	for _, h := range []int{dashMinH, 30, 45} {
		lines := d.render(110, h, now)
		// The chart and Now panels close on the same row.
		for i, l := range lines {
			if strings.Contains(l, "╰") && strings.Count(l, "╰") == 1 && !strings.Contains(l, "Events") {
				if i+1 < len(lines) && !strings.Contains(lines[i+1], "Router") {
					t.Errorf("h=%d: one panel ends early at row %d: %q", h, i, l)
				}
			}
		}
		if len(lines) > h {
			t.Errorf("h=%d: %d lines", h, len(lines))
		}
	}
}

func TestUnknownDevicesForWatch(t *testing.T) {
	known := &knownNetwork{Subnet: "192.168.0.0/24", Devices: map[string]*knownDevice{
		"02:00:00:00:00:01": {IP: "192.168.0.1"},
		"ea:00:00:00:00:74": {IP: "192.168.0.74"},
	}}
	_, subnet, _ := net.ParseCIDR(known.Subnet)
	arp := []probe.ARPEntry{
		{IP: net.ParseIP("192.168.0.1"), MAC: "02:00:00:00:00:01"},
		{IP: net.ParseIP("192.168.0.74"), MAC: "ea:00:00:00:00:74"},
		{IP: net.ParseIP("192.168.0.73"), MAC: "02:00:00:00:00:73"},  // joined
		{IP: net.ParseIP("172.21.26.153"), MAC: "00:15:5d:19:5c:e6"}, // WSL, another subnet
	}
	seen := map[string]bool{}
	got := unknownDevices(arp, known, subnet, seen)
	if len(got) != 1 || got[0].IP.String() != "192.168.0.73" {
		t.Fatalf("got %+v", got)
	}
	if again := unknownDevices(arp, known, subnet, seen); len(again) != 0 {
		t.Errorf("each newcomer is reported once: %+v", again)
	}
}
