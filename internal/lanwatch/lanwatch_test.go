package lanwatch

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
)

const (
	routerMAC = "54:67:51:79:25:c9"
	evilMAC   = "de:ad:be:ef:00:01"
)

var t0 = time.Date(2026, 10, 15, 20, 0, 0, 0, time.UTC)

func snap(at time.Duration, devs ...Device) Snapshot {
	s := Snapshot{Time: t0.Add(at), Gateway: "192.168.0.1", GatewayMAC: routerMAC, Devices: map[string]Device{}, DNS: []string{"192.168.0.1"}, PublicIP: "198.51.100.41", UPnP: true}
	for _, d := range devs {
		s.Devices[d.MAC] = d
	}
	return s
}

var (
	router = Device{IP: "192.168.0.1", MAC: routerMAC}
	phone  = Device{IP: "192.168.0.31", MAC: "80:9f:9b:39:62:8c", Name: "Pixel"}
	tv     = Device{IP: "192.168.0.38", MAC: "6c:c2:42:87:e9:a5", Vendor: "LG"}
	plug   = Device{IP: "192.168.0.99", MAC: "aa:bb:cc:00:00:99", Vendor: "Espressif"}
)

func kinds(evs []Event) string {
	var k []string
	for _, e := range evs {
		k = append(k, e.Kind+"/"+e.Level)
	}
	return strings.Join(k, " ")
}

func TestDiffDevices(t *testing.T) {
	known := map[string]bool{phone.MAC: true, tv.MAC: true, routerMAC: true}
	gone := map[string]time.Time{}
	prev := snap(0, router, phone, tv)
	evs := Diff(prev, snap(2*time.Minute, router, phone, tv, plug), known, gone, 15*time.Minute)
	if kinds(evs) != "joined/warn" || !strings.Contains(evs[0].Text, "New device: Espressif (192.168.0.99)") || !known[plug.MAC] {
		t.Errorf("new: %v", evs)
	}
	// A known device coming back is only information.
	known2 := map[string]bool{phone.MAC: true, tv.MAC: true, routerMAC: true, plug.MAC: true}
	if evs := Diff(prev, snap(2*time.Minute, router, phone, tv, plug), known2, map[string]time.Time{}, time.Minute); kinds(evs) != "joined/info" {
		t.Errorf("known joined: %v", evs)
	}
	// Leaving: the phone is missing, but not for long enough yet.
	cur := snap(4*time.Minute, router, tv)
	if evs := Diff(prev, cur, known, gone, 15*time.Minute); len(evs) != 0 {
		t.Errorf("missing a moment isn't leaving: %v", evs)
	}
	if _, kept := cur.Devices[phone.MAC]; !kept {
		t.Error("a missing device is kept until it has really left")
	}
	later := snap(20*time.Minute, router, tv)
	if evs := Diff(cur, later, known, gone, 15*time.Minute); kinds(evs) != "left/info" || !strings.Contains(evs[0].Text, "Pixel") {
		t.Errorf("left: %v", evs)
	}
	// Back within the grace time: no event at all.
	gone2 := map[string]time.Time{}
	a := snap(0, router, phone)
	b := snap(time.Minute, router)
	Diff(a, b, known, gone2, 15*time.Minute)
	if evs := Diff(b, snap(2*time.Minute, router, phone), known, gone2, 15*time.Minute); len(evs) != 0 {
		t.Errorf("came back in time: %v", evs)
	}
	// Without a devices history, joining is never "new".
	if evs := Diff(snap(0, router), snap(time.Minute, router, plug), nil, map[string]time.Time{}, time.Minute); kinds(evs) != "joined/info" {
		t.Errorf("no history: %v", evs)
	}
}

func TestDiffSpoofingAndSettings(t *testing.T) {
	gone := map[string]time.Time{}
	prev := snap(0, router, phone)
	cur := snap(time.Minute, Device{IP: "192.168.0.1", MAC: evilMAC}, phone)
	cur.GatewayMAC = evilMAC
	evs := Diff(prev, cur, nil, gone, time.Minute)
	if len(evs) == 0 || evs[0].Kind != "spoof" || evs[0].Level != "bad" || !strings.Contains(evs[0].Text, evilMAC) {
		t.Fatalf("router MAC changed: %v", evs)
	}
	// Another address claiming the router's MAC.
	cur = snap(time.Minute, router, phone, Device{IP: "192.168.0.66", MAC: routerMAC})
	cur.Devices["x"] = Device{IP: "192.168.0.66", MAC: routerMAC}
	if evs := Diff(prev, cur, nil, map[string]time.Time{}, time.Minute); !strings.Contains(kinds(evs), "spoof/warn") {
		t.Errorf("second address with the router's MAC: %v", evs)
	}
	cur = snap(time.Minute, router, phone)
	cur.Gateway = "192.168.1.1"
	if evs := Diff(prev, cur, nil, map[string]time.Time{}, time.Minute); !strings.Contains(kinds(evs), "gateway/warn") {
		t.Errorf("gateway: %v", evs)
	}
	cur = snap(time.Minute, router, phone)
	cur.DNS, cur.PublicIP = []string{"203.0.113.53"}, "198.51.100.99"
	cur.DHCP, prev.DHCP = []string{"192.168.0.1", "192.168.0.66"}, []string{"192.168.0.1"}
	cur.Mappings = []probe.PortMapping{{Protocol: "TCP", ExternalPort: 3074, Client: "192.168.0.38", Description: "Xbox"}}
	evs = Diff(prev, cur, nil, map[string]time.Time{}, time.Minute)
	if got := kinds(evs); got != "dhcp/bad dns/warn upnp-open/warn public-ip/info" {
		t.Errorf("settings: %s", got)
	}
	// A forward going away.
	prev2 := cur
	cur2 := snap(2*time.Minute, router, phone)
	cur2.DNS, cur2.PublicIP, cur2.DHCP = cur.DNS, cur.PublicIP, cur.DHCP
	if evs := Diff(prev2, cur2, nil, map[string]time.Time{}, time.Minute); kinds(evs) != "upnp-closed/info" {
		t.Errorf("closed: %v", kinds(evs))
	}
	// The same two DHCP servers again: not a new alarm.
	if evs := Diff(cur, cur, nil, map[string]time.Time{}, time.Minute); len(evs) != 0 {
		t.Errorf("nothing changed: %v", evs)
	}
}

func TestTake(t *testing.T) {
	oldG, oldL, oldS, oldD, oldA, oldN, oldP, oldM, oldH := gatewayIP, localIP, subnetOf, discover, arpTable, dnsList, publicIP, mappings, findDHCP
	defer func() {
		gatewayIP, localIP, subnetOf, discover, arpTable, dnsList, publicIP, mappings, findDHCP = oldG, oldL, oldS, oldD, oldA, oldN, oldP, oldM, oldH
	}()
	gatewayIP = func() (net.IP, error) { return net.ParseIP("192.168.0.1"), nil }
	localIP = func() net.IP { return net.ParseIP("192.168.0.200") }
	subnetOf = func(net.IP) (*net.IPNet, error) { _, n, _ := net.ParseCIDR("192.168.0.0/24"); return n, nil }
	discover = func(context.Context, net.IP, net.IP, *net.IPNet, probe.ScanOptions) probe.DevicesResult {
		return probe.DevicesResult{Devices: []probe.Device{
			{IP: "192.168.0.1", MAC: "54:67:51:79:25:C9", Gateway: true}, {IP: "192.168.0.31", MAC: "80:9f:9b:39:62:8c", Name: "Pixel"},
			{IP: "192.168.0.200", MAC: "11:11:11:11:11:11", Self: true}, {IP: "192.168.0.50"},
		}}
	}
	arpTable = func(context.Context) []probe.ARPEntry {
		return []probe.ARPEntry{{IP: net.ParseIP("192.168.0.1"), MAC: "54:67:51:79:25:c9"}}
	}
	dnsList = func(context.Context) []string { return []string{"198.51.100.21", "198.51.100.123"} }
	publicIP = func(context.Context) (net.IP, error) { return net.ParseIP("198.51.100.41"), nil }
	mappings = func(context.Context, net.IP) ([]probe.PortMapping, error) { return nil, probe.ErrNoUPnP }
	findDHCP = func(context.Context, time.Duration) probe.DHCPResult {
		return probe.DHCPResult{Servers: []probe.DHCPServer{{ServerID: "192.168.0.250"}}}
	}
	s, err := Take(context.Background(), true)
	if err != nil || s.Gateway != "192.168.0.1" || s.GatewayMAC != routerMAC || len(s.Devices) != 2 || s.Devices["80:9f:9b:39:62:8c"].Name != "Pixel" {
		t.Fatalf("%+v %v", s, err)
	}
	if strings.Join(s.DNS, ",") != "198.51.100.123,198.51.100.21" || s.PublicIP != "198.51.100.41" || s.UPnP || strings.Join(s.DHCP, ",") != "192.168.0.250" {
		t.Errorf("settings: %+v", s)
	}
	if s, _ := Take(context.Background(), false); s.DHCP != nil {
		t.Error("DHCP only when asked")
	}
	if !Own(net.ParseIP("192.168.0.1")) || Own(net.ParseIP("198.51.100.41")) || Own(nil) {
		t.Error("Own")
	}
}
