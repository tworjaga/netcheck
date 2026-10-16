package cli

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/lanwatch"
	"github.com/tworjaga/netcheck/internal/ui"
)

func TestLanDashFits(t *testing.T) {
	start := time.Now().Add(-time.Hour)
	s := lanwatch.Snapshot{Time: start, Gateway: "192.168.0.1", GatewayMAC: "54:67:51:79:25:c9", Devices: map[string]lanwatch.Device{},
		DNS: []string{"198.51.100.21", "198.51.100.123"}, PublicIP: "198.51.100.41", UPnP: true}
	for i := 0; i < 40; i++ {
		mac := fmt.Sprintf("aa:bb:cc:00:00:%02x", i)
		s.Devices[mac] = lanwatch.Device{IP: fmt.Sprintf("192.168.0.%d", 10+i), MAC: mac, Name: "a-device-with-a-rather-long-name"}
	}
	d := &lanDash{first: map[string]time.Time{}, every: 2 * time.Minute, start: start}
	d.update(s, []lanwatch.Event{{Time: time.Now(), Kind: "spoof", Level: "bad", Text: "The router's hardware address changed"}}, time.Now().Add(time.Minute))
	for _, size := range [][2]int{{80, 24}, {120, 40}, {200, 60}} {
		lines := d.render(size[0], size[1], time.Now())
		text := strings.Join(lines, "\n")
		if len(lines) > size[1] {
			t.Errorf("%dx%d: %d lines", size[0], size[1], len(lines))
		}
		for _, l := range lines {
			if ui.VisWidth(l) > size[0]-1 {
				t.Errorf("%dx%d too wide: %q", size[0], size[1], l)
			}
		}
		if !strings.Contains(text, "1 alarm") || !strings.Contains(text, "more") || !strings.Contains(text, "hardware address changed") {
			t.Errorf("%dx%d:\n%s", size[0], size[1], text)
		}
	}
}
