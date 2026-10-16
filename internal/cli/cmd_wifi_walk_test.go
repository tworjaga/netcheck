package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

// scriptedWifi returns readings in order, then keeps repeating the last.
func scriptedWifi(rs ...probe.WifiInfo) func(context.Context) probe.WifiInfo {
	i := 0
	return func(context.Context) probe.WifiInfo {
		r := rs[min(i, len(rs)-1)]
		i++
		return r
	}
}

func at(dbm int, bssid string) probe.WifiInfo {
	return probe.WifiInfo{Connected: true, SignalDBm: dbm, BSSID: bssid, Band: "2.4 GHz", Channel: 1}
}

func lines(ls ...string) <-chan string {
	ch := make(chan string, len(ls))
	for _, l := range ls {
		ch <- l
	}
	close(ch)
	return ch
}

func TestWalkSpots(t *testing.T) {
	router, extender := "02:00:00:00:00:01", "02:00:00:00:01:51"
	read := scriptedWifi(
		at(-52, router), at(-55, router), at(-50, router), at(-53, router), at(-90, router), // living room: one bad blip
		at(-71, extender), at(-69, extender), at(-70, extender), at(-72, extender), at(-70, extender), // kitchen, roamed to the extender
		probe.WifiInfo{}, probe.WifiInfo{}, probe.WifiInfo{}, probe.WifiInfo{}, probe.WifiInfo{}, // garden: no Wi-Fi
	)
	prompts, samples := 0, 0
	spots := walkSpots(context.Background(), lines("living room", "  kitchen ", "garden", "", "never read"),
		func() { prompts++ }, read, 0, func(string, []int) { samples++ })
	if len(spots) != 3 || prompts != 4 || samples != 15 {
		t.Fatalf("spots=%d prompts=%d samples=%d", len(spots), prompts, samples)
	}
	if s := spots[0]; s.Name != "living room" || s.DBm != -53 || s.Quality != "excellent" || s.BSSID != router {
		t.Errorf("living room: %+v", s) // the median ignores the -90 blip
	}
	if s := spots[1]; s.Name != "kitchen" || s.DBm != -70 || s.Quality != "fair" || s.BSSID != extender || s.Channel != 1 {
		t.Errorf("kitchen: %+v", s)
	}
	if s := spots[2]; s.DBm != 0 || s.Quality != "no Wi-Fi" || s.BSSID != "" {
		t.Errorf("garden: %+v", s)
	}
}

func TestWalkSpotsStopsOnCtrlC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	read := func(context.Context) probe.WifiInfo {
		if n++; n == 7 { // two readings into the second spot
			cancel()
		}
		return at(-60, "x")
	}
	spots := walkSpots(ctx, lines("hall", "attic", "cellar"), func() {}, read, 0, nil)
	if len(spots) != 1 || spots[0].Name != "hall" {
		t.Fatalf("the interrupted spot must be dropped, the finished one kept: %+v", spots)
	}
}

func TestWalkVerdict(t *testing.T) {
	sp := func(name string, dbm int) walkSpot { return walkSpot{Name: name, DBm: dbm} }
	run := func(name string, spots []walkSpot, want ui.Status, has string) vcase {
		st, msg := walkVerdict(spots)
		return vcase{name, st, msg, want, has}
	}
	checkCases(t, []vcase{
		run("nothing", nil, ui.Skip, "No spots"),
		run("good", []walkSpot{sp("hall", -50), sp("bedroom", -62)}, ui.OK, "Good signal everywhere you checked; weakest in bedroom (-62 dBm)."),
		run("fair", []walkSpot{sp("hall", -50), sp("kitchen", -70)}, ui.OK, "weakest in kitchen (-70 dBm, fair)"),
		run("weak", []walkSpot{sp("hall", -50), sp("bedroom", -80), sp("attic", -84)}, ui.Warn, "weak in bedroom (-80 dBm) and attic (-84 dBm)"),
		run("none", []walkSpot{sp("hall", -50), sp("garden", 0)}, ui.Warn, "No Wi-Fi in garden"),
	})
}

func TestWalkRows(t *testing.T) {
	spots := []walkSpot{
		{Name: "kitchen", DBm: -70, Quality: "fair", BSSID: "b", Band: "2.4 GHz", Channel: 1},
		{Name: "garden", Quality: "no Wi-Fi"},
		{Name: "living room", DBm: -53, Quality: "excellent", BSSID: "a", Band: "2.4 GHz", Channel: 1},
	}
	rows := walkRows(spots)
	if len(rows) != 3 || !strings.Contains(rows[0], "living room") || !strings.Contains(rows[1], "kitchen") || !strings.Contains(rows[2], "garden") {
		t.Fatalf("strongest first, no Wi-Fi last: %q", rows)
	}
	// Two access points: each row says which one; kitchen met AP "b" first.
	if !strings.Contains(rows[1], "AP 1") || !strings.Contains(rows[0], "AP 2") {
		t.Errorf("AP labels: %q", rows)
	}
	one := walkRows([]walkSpot{{Name: "hall", DBm: -50, Quality: "excellent", BSSID: "a"}, {Name: "bed", DBm: -60, Quality: "excellent", BSSID: "a"}})
	if strings.Contains(strings.Join(one, ""), "AP 1") {
		t.Errorf("a single access point needs no label: %q", one)
	}
	if long := walkRows([]walkSpot{{Name: "upstairs bathroom", DBm: -60, Quality: "excellent"}}); !strings.Contains(long[0], "upstairs b…") {
		t.Errorf("long names are shortened: %q", long)
	}
}

func TestMedianDBm(t *testing.T) {
	if got := medianDBm([]int{-60, 0, -70, -65, 0}); got != -65 {
		t.Errorf("got %d", got)
	}
	if got := medianDBm([]int{0, 0}); got != 0 {
		t.Errorf("got %d", got)
	}
}
