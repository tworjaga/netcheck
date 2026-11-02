package lanaudit

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/domain"
	"github.com/tworjaga/netcheck/internal/probe"
)

func TestWifiCheck(t *testing.T) {
	cases := []struct {
		sec, cipher string
		st          domain.Status
		title       string
	}{
		{"WPA3-Personal", "GCMP", domain.OK, "uses WPA3"},
		{"WPA2-Personal", "CCMP", domain.OK, "uses WPA2"},
		{"WPA2-Personal", "TKIP", domain.Warn, "TKIP"},
		{"WPA-Personal", "TKIP", domain.Warn, "first WPA"},
		{"WEP", "WEP", domain.Bad, "uses WEP"},
		{"Open", "None", domain.Bad, "is open"},
		{"Offen", "Keine", domain.Bad, "is open"},
		{"WPA1 WPA2", "", domain.OK, "uses WPA2"},
		{"", "", domain.Info, "Couldn't read"},
	}
	for _, c := range cases {
		cs := WifiCheck(probe.WifiInfo{Connected: true, SSID: "Home", Security: c.sec, Cipher: c.cipher})
		if len(cs) != 1 || cs[0].Status != c.st || !strings.Contains(cs[0].Title, c.title) {
			t.Errorf("%s/%s: %+v", c.sec, c.cipher, cs)
		}
		if (cs[0].Status == domain.Bad || cs[0].Status == domain.Warn) && cs[0].Fix == "" {
			t.Errorf("%s: no fix", c.sec)
		}
	}
	if WifiCheck(probe.WifiInfo{}) != nil {
		t.Error("not on Wi-Fi: nothing to say")
	}
}

func find(cs []domain.Check, part string) *domain.Check {
	for i := range cs {
		if strings.Contains(cs[i].Title, part) {
			return &cs[i]
		}
	}
	return nil
}

func TestRouterChecks(t *testing.T) {
	old := adminRedirects
	defer func() { adminRedirects = old }()
	redirects := false
	adminRedirects = func(context.Context, string) bool { return redirects }
	one := probe.DHCPResult{Servers: []probe.DHCPServer{{ServerID: "192.168.0.1", DNS: []string{"192.168.0.1"}}}}

	cs := RouterChecks(context.Background(), "192.168.0.1", []Open{{Port: 80}, {Port: 23}}, nil, probe.ErrNoUPnP, one)
	for title, st := range map[string]domain.Status{"only on plain HTTP": domain.Warn, "answers Telnet": domain.Bad, "UPnP is off": domain.OK, "the router": domain.OK} {
		if c := find(cs, title); c == nil || c.Status != st {
			t.Errorf("%q: %+v", title, c)
		}
	}
	redirects = true
	if c := find(RouterChecks(context.Background(), "192.168.0.1", []Open{{Port: 80}}, nil, probe.ErrNoUPnP, one), "HTTPS"); c == nil || c.Status != domain.OK {
		t.Errorf("http that redirects to https: %+v", c)
	}
	maps := []probe.PortMapping{{Protocol: "TCP", ExternalPort: 3074, InternalPort: 3074, Client: "192.168.0.50", Description: "Xbox"}}
	if c := find(RouterChecks(context.Background(), "192.168.0.1", nil, maps, nil, one), "opened 1"); c == nil || c.Status != domain.Warn || !strings.Contains(c.Detail, "Xbox") {
		t.Errorf("forwards: %+v", c)
	}
	if c := find(RouterChecks(context.Background(), "192.168.0.1", nil, nil, nil, one), "no ports forwarded"); c == nil || c.Status != domain.Info {
		t.Errorf("upnp on, empty: %+v", c)
	}
	two := probe.DHCPResult{Servers: []probe.DHCPServer{{ServerID: "192.168.0.1"}, {ServerID: "192.168.0.66"}}}
	if c := find(RouterChecks(context.Background(), "192.168.0.1", nil, nil, probe.ErrNoUPnP, two), "2 DHCP servers"); c == nil || c.Status != domain.Bad {
		t.Errorf("rogue dhcp: %+v", c)
	}
	other := probe.DHCPResult{Servers: []probe.DHCPServer{{ServerID: "192.168.0.250"}}}
	if c := find(RouterChecks(context.Background(), "192.168.0.1", nil, nil, probe.ErrNoUPnP, other), "not the router"); c == nil || c.Status != domain.Info {
		t.Errorf("dhcp elsewhere: %+v", c)
	}
	if c := find(RouterChecks(context.Background(), "192.168.0.1", nil, nil, probe.ErrNoUPnP, probe.DHCPResult{Unavailable: "needs admin"}), "not checked"); c == nil {
		t.Error("dhcp unavailable")
	}
}

func TestDeviceChecks(t *testing.T) {
	devs := []DeviceReport{
		{Device: probe.Device{IP: "192.168.0.1", Gateway: true}, Open: []Open{{80, "web page (HTTP)"}, {23, "Telnet"}}},
		{Device: probe.Device{IP: "192.168.0.20", Name: "nas"}, Open: []Open{{445, "file sharing (SMB)"}, {22, "SSH"}, {6379, "Redis"}}},
		{Device: probe.Device{IP: "192.168.0.30", Vendor: "Hikvision"}, Open: []Open{{554, "camera stream (RTSP)"}, {23, "Telnet"}}},
		{Device: probe.Device{IP: "192.168.0.40"}, Open: []Open{{9100, "printer (raw)"}, {80, "web page (HTTP)"}}},
		{Device: probe.Device{IP: "192.168.0.200", Self: true}, Open: []Open{{6379, "Redis"}}},
	}
	cs := DeviceChecks(devs)
	want := map[string]domain.Status{
		"192.168.0.20 (nas): Redis": domain.Bad, "192.168.0.20 (nas): file sharing": domain.Info,
		"192.168.0.30 (Hikvision): Telnet": domain.Bad, "192.168.0.30 (Hikvision): camera": domain.Info,
		"2 of 4 devices show nothing risky": domain.OK,
	}
	for title, st := range want {
		if c := find(cs, title); c == nil || c.Status != st {
			t.Errorf("%q: %+v", title, c)
		}
	}
	for _, c := range cs {
		if strings.Contains(c.Title, "192.168.0.1 ") || strings.Contains(c.Title, "SSH") || strings.Contains(c.Title, "printer") || strings.Contains(c.Title, "192.168.0.200") {
			t.Errorf("shouldn't be a finding: %q", c.Title)
		}
	}
	fresh := NewDeviceChecks([]DeviceReport{{Device: probe.Device{IP: "192.168.0.9", MAC: "aa:bb:cc:dd:ee:ff", Vendor: "Espressif"}}, {Device: probe.Device{IP: "192.168.0.10", MAC: "11:22:33:44:55:66"}, Known: true}})
	if len(fresh) != 1 || fresh[0].Status != domain.Info || !strings.Contains(fresh[0].Detail, "192.168.0.9 (Espressif)") {
		t.Errorf("new: %+v", fresh)
	}
}

func TestAudit(t *testing.T) {
	saved := []any{readWifi, gateway, localIP, subnetOf, discover, mappings, findDHCP, dialPort, adminRedirects}
	defer func() {
		readWifi = saved[0].(func(context.Context) probe.WifiInfo)
		gateway = saved[1].(func() (net.IP, error))
		localIP = saved[2].(func() net.IP)
		subnetOf = saved[3].(func(net.IP) (*net.IPNet, error))
		discover = saved[4].(func(context.Context, net.IP, net.IP, *net.IPNet, probe.ScanOptions) probe.DevicesResult)
		mappings = saved[5].(func(context.Context, net.IP) ([]probe.PortMapping, error))
		findDHCP = saved[6].(func(context.Context, time.Duration) probe.DHCPResult)
		dialPort = saved[7].(func(context.Context, string) bool)
		adminRedirects = saved[8].(func(context.Context, string) bool)
	}()
	readWifi = func(context.Context) probe.WifiInfo {
		return probe.WifiInfo{Connected: true, SSID: "Home", Security: "WPA3-Personal", Cipher: "GCMP"}
	}
	gateway = func() (net.IP, error) { return net.ParseIP("192.168.0.1"), nil }
	localIP = func() net.IP { return net.ParseIP("192.168.0.200") }
	subnetOf = func(net.IP) (*net.IPNet, error) {
		_, n, _ := net.ParseCIDR("192.168.0.0/24")
		return n, nil
	}
	discover = func(context.Context, net.IP, net.IP, *net.IPNet, probe.ScanOptions) probe.DevicesResult {
		return probe.DevicesResult{Devices: []probe.Device{
			{IP: "192.168.0.200", Self: true}, {IP: "192.168.0.1", Gateway: true, MAC: "aa:aa:aa:aa:aa:01"}, {IP: "192.168.0.50", MAC: "aa:aa:aa:aa:aa:50"},
		}}
	}
	calls := 0
	mappings = func(context.Context, net.IP) ([]probe.PortMapping, error) {
		calls++
		return nil, probe.ErrNoUPnP
	}
	findDHCP = func(context.Context, time.Duration) probe.DHCPResult {
		return probe.DHCPResult{Servers: []probe.DHCPServer{{ServerID: "192.168.0.1"}}}
	}
	dialed := map[string]bool{}
	var mu sync.Mutex
	dialPort = func(_ context.Context, addr string) bool {
		mu.Lock()
		dialed[addr] = true
		mu.Unlock()
		return addr == "192.168.0.1:443" || addr == "192.168.0.50:22"
	}
	adminRedirects = func(context.Context, string) bool { return false }

	r := Audit(context.Background(), Options{Known: map[string]bool{"aa:aa:aa:aa:aa:01": true, "aa:aa:aa:aa:aa:50": true}})
	_, warn, bad := domain.Report{Checks: r.Checks}.Count()
	if r.Error != "" || r.Grade != "A+" || warn+bad != 0 || len(r.Devices) != 3 || calls != 2 || *r.UPnP {
		for _, c := range r.Checks {
			t.Logf("%s %s: %s", c.Status, c.Area, c.Title)
		}
		t.Fatalf("grade %s, upnp tried %d times, %+v", r.Grade, calls, r.Error)
	}
	if dialed["192.168.0.200:23"] {
		t.Error("this machine isn't port-checked (listen covers it)")
	}
	if r.Devices[0].IP != "192.168.0.1" || r.Devices[2].IP != "192.168.0.200" || len(r.Devices[2].Open) != 0 || r.Devices[1].Open[0].Port != 22 {
		t.Errorf("devices: %+v", r.Devices)
	}
	subnetOf = func(net.IP) (*net.IPNet, error) {
		_, n, _ := net.ParseCIDR("203.0.113.0/24")
		return n, nil
	}
	if r := Audit(context.Background(), Options{}); !strings.Contains(r.Error, "private networks") {
		t.Errorf("public network: %q", r.Error)
	}
	gateway = func() (net.IP, error) { return nil, errors.New("none") }
	if r := Audit(context.Background(), Options{}); !strings.Contains(r.Error, "no router") {
		t.Errorf("no router: %q", r.Error)
	}
}
