package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
)

// homeScan is shaped like a real scan of a home network (MACs replaced):
// the router, an extender, a phone with a private address, this computer
// (no MAC of its own in the ARP table).
func homeScan() []probe.Device {
	return []probe.Device{
		{IP: "192.168.0.1", MAC: "02:00:00:00:00:01", Gateway: true, Kind: "router"},
		{IP: "192.168.0.250", MAC: "02:00:00:00:01:51"},
		{IP: "192.168.0.74", MAC: "ea:00:00:00:00:74", RandomMAC: true},
		{IP: "192.168.0.200", Name: "laptop", Self: true},
	}
}

func TestRememberMarksNewDevices(t *testing.T) {
	s := &deviceStore{V: 1, Networks: map[string]*knownNetwork{}}
	t0 := time.Date(2026, 10, 13, 23, 57, 0, 0, time.UTC)
	devs := homeScan()
	key := networkKey(devs, "192.168.0.0/24")
	if key != "router 02:00:00:00:00:01" {
		t.Fatalf("key %q", key)
	}

	d := s.remember(key, "192.168.0.0/24", devs, t0)
	if !d.First || len(d.New) != 0 {
		t.Fatalf("first scan: %+v", d)
	}
	if got := diffLine(d, devs); !strings.Contains(got, "Remembered 4 devices on this network") {
		t.Errorf("first line: %q", got)
	}

	// Same devices an hour later: nothing new.
	d = s.remember(key, "192.168.0.0/24", devs, t0.Add(time.Hour))
	if d.First || len(d.New) != 0 || !d.Since.Equal(t0) {
		t.Fatalf("repeat: %+v", d)
	}
	if got := diffLine(d, devs); !strings.Contains(got, "No new devices since Tue Oct 13 23:57.") {
		t.Errorf("repeat line: %q", got)
	}

	// A stranger joins, and the phone shows up with a new private address.
	more := append(homeScan(),
		probe.Device{IP: "192.168.0.77", MAC: "02:00:00:00:00:77"},
		probe.Device{IP: "192.168.0.80", MAC: "ea:00:00:00:00:80", RandomMAC: true})
	d = s.remember(key, "192.168.0.0/24", more, t0.Add(2*time.Hour))
	if len(d.New) != 2 || !d.New["02:00:00:00:00:77"] || !d.New["ea:00:00:00:00:80"] {
		t.Fatalf("new: %+v", d.New)
	}
	got := diffLine(d, more)
	if !strings.Contains(got, "2 new devices since Wed Oct 14 00:57: 192.168.0.77, 192.168.0.80.") || !strings.Contains(got, "private Wi-Fi addresses") {
		t.Errorf("new line: %q", got)
	}
}

func TestRememberKeepsNetworksApart(t *testing.T) {
	s := &deviceStore{V: 1, Networks: map[string]*knownNetwork{}}
	now := time.Now()
	home := homeScan()
	s.remember(networkKey(home, "192.168.0.0/24"), "192.168.0.0/24", home, now)
	// Another network with the same subnet but a different router.
	school := []probe.Device{{IP: "192.168.0.1", MAC: "02:00:00:00:99:01", Gateway: true}, {IP: "192.168.0.5", MAC: "02:00:00:00:99:05"}}
	d := s.remember(networkKey(school, "192.168.0.0/24"), "192.168.0.0/24", school, now)
	if !d.First || len(d.New) != 0 {
		t.Fatalf("a different router is a different network: %+v", d)
	}
	if networkKey([]probe.Device{{IP: "10.0.0.5"}}, "10.0.0.0/24") != "subnet 10.0.0.0/24" {
		t.Error("without a router MAC the subnet identifies the network")
	}
}

func TestRememberForgetsOldDevices(t *testing.T) {
	s := &deviceStore{V: 1, Networks: map[string]*knownNetwork{}}
	t0 := time.Now()
	devs := homeScan()
	key := networkKey(devs, "192.168.0.0/24")
	s.remember(key, "192.168.0.0/24", devs, t0)
	s.remember(key, "192.168.0.0/24", devs[:1], t0.Add(forgetAfter+time.Hour)) // only the router answers
	if n := len(s.Networks[key].Devices); n != 1 {
		t.Fatalf("devices unseen for %v should be forgotten, %d left", forgetAfter, n)
	}
	// A forgotten device that comes back counts as new again.
	d := s.remember(key, "192.168.0.0/24", devs, t0.Add(forgetAfter+2*time.Hour))
	if len(d.New) != 3 {
		t.Fatalf("got %+v", d.New)
	}
}

func TestDevicesFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "devices.json")
	t.Setenv("NETCHECK_DEVICES", path)
	devs := homeScan()
	if d := rememberDevices(devs, "192.168.0.0/24", time.Now()); d == nil || !d.First {
		t.Fatalf("first: %+v", d)
	}
	d := rememberDevices(append(devs, probe.Device{IP: "192.168.0.77", MAC: "02:00:00:00:00:77"}), "192.168.0.0/24", time.Now())
	if d == nil || d.First || len(d.New) != 1 {
		t.Fatalf("second: %+v", d)
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Error("temp file left behind")
	}
}

func TestDevicesFileUnreadableIsLeftAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	t.Setenv("NETCHECK_DEVICES", path)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if d := rememberDevices(homeScan(), "192.168.0.0/24", time.Now()); d != nil {
		t.Fatalf("got %+v", d)
	}
	if b, _ := os.ReadFile(path); string(b) != "{not json" {
		t.Fatal("a file netcheck can't read must not be overwritten")
	}
}
