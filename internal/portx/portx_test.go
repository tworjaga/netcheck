package portx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/sockets"
)

func sp(s string) *string { return &s }

// fwState is a firewall with the Public profile in use, blocking by default.
func fwState(rules ...WinRule) WinFirewall {
	f := WinFirewall{Current: 4, Rules: rules}
	f.Profiles = append(f.Profiles,
		struct {
			Type    int  `json:"t"`
			Enabled bool `json:"e"`
			Inbound int  `json:"i"`
		}{1, true, 0},
		struct {
			Type    int  `json:"t"`
			Enabled bool `json:"e"`
			Inbound int  `json:"i"`
		}{2, true, 0},
		struct {
			Type    int  `json:"t"`
			Enabled bool `json:"e"`
			Inbound int  `json:"i"`
		}{4, true, 0})
	return f
}

func TestPortMatch(t *testing.T) {
	for spec, want := range map[string]bool{"*": true, "": true, "8080": true, "80,8080": true, "8000-8100": true, "80": false, "RPC": false, "9000-9100,443": false} {
		if portMatch(spec, 8080) != want {
			t.Errorf("%q: want %v", spec, want)
		}
	}
}

func TestEvalWindows(t *testing.T) {
	allow := WinRule{Name: "Web 8080", Protocol: 6, Ports: sp("8080"), Profiles: 7, Action: 1, Remote: sp("*")}
	cases := []struct {
		name    string
		f       WinFirewall
		program string
		st      Status
		title   string
	}{
		{"no rule", fwState(), "node.exe", Bad, "No Windows Firewall rule"},
		{"port rule", fwState(allow), "node.exe", OK, "allows TCP 8080"},
		{"program rule, any port", fwState(WinRule{Name: "Node", Protocol: 256, Ports: sp("*"), App: sp(`C:\Program Files\nodejs\node.exe`), Profiles: 7, Action: 1}), "node.exe", OK, "allows"},
		{"another program's rule", fwState(WinRule{Name: "Py", Protocol: 6, App: sp(`C:\Python\python.exe`), Profiles: 7, Action: 1}), "node.exe", Bad, "No Windows Firewall rule"},
		{"block wins", fwState(allow, WinRule{Name: "Block it", Protocol: 6, Ports: sp("8080"), Profiles: 7, Action: 0}), "node.exe", Bad, "blocks TCP 8080"},
		{"private only", fwState(WinRule{Name: "Web priv", Protocol: 6, Ports: sp("8080"), Profiles: 2, Action: 1}), "node.exe", Bad, "only on Private networks"},
		{"local subnet only", fwState(WinRule{Name: "Web lan", Protocol: 6, Ports: sp("8080"), Profiles: 7, Action: 1, Remote: sp("LocalSubnet")}), "node.exe", Warn, "local network only"},
		{"store app", fwState(WinRule{Name: "Game Bar", Protocol: 256, Profiles: 7, Action: 1, Owner: sp("S-1-5-21-1")}), "node.exe", Bad, "No Windows Firewall rule"},
		{"service rule", fwState(WinRule{Name: "Svc", Protocol: 6, Ports: sp("8080"), Profiles: 7, Action: 1, Service: sp("w3svc")}), "node.exe", Bad, "No Windows Firewall rule"},
		{"System any-port rule", fwState(WinRule{Name: "WFD", Protocol: 6, Ports: sp("*"), App: sp("System"), Profiles: 7, Action: 1}), "System", Bad, "No Windows Firewall rule"},
		{"System port rule", fwState(WinRule{Name: "SMB", Protocol: 6, Ports: sp("8080"), App: sp("System"), Profiles: 7, Action: 1}), "System", OK, "allows"},
		{"udp rule for tcp", fwState(WinRule{Name: "U", Protocol: 17, Ports: sp("8080"), Profiles: 7, Action: 1}), "node.exe", Bad, "No Windows Firewall rule"},
	}
	for _, c := range cases {
		v := EvalWindows(c.f, 8080, "tcp", c.program)
		if v.Status != c.st || !strings.Contains(v.Title, c.title) {
			t.Errorf("%s: %s %q", c.name, v.Status, v.Title)
		}
		if (v.Status == Bad || v.Status == Warn) && v.Fix == "" {
			t.Errorf("%s: no fix", c.name)
		}
	}
	off := fwState()
	off.Profiles[2].Enabled = false
	if v := EvalWindows(off, 8080, "tcp", ""); v.Status != OK || !strings.Contains(v.Title, "off") {
		t.Errorf("firewall off: %+v", v)
	}
	open := fwState()
	open.Profiles[2].Inbound = 1
	if v := EvalWindows(open, 8080, "tcp", ""); v.Status != OK || !strings.Contains(v.Title, "lets everything in") {
		t.Errorf("default allow: %+v", v)
	}
	if v := EvalWindows(fwState(), 8080, "tcp", "System"); strings.Contains(v.Fix, "Allow an app") {
		t.Errorf("no 'allow an app' for Windows itself: %s", v.Fix)
	}
}

func TestParseWinFirewall(t *testing.T) {
	f, err := ParseWinFirewall([]byte(`{"current":4,"profiles":[{"t":1,"e":true,"i":0},{"t":2,"e":true,"i":0},{"t":4,"e":true,"i":0}],
		"rules":[{"n":"Web","p":6,"l":"8080","a":null,"pr":2147483647,"ac":1,"r":"*","k":null,"s":null,"o":null}]}`))
	if err != nil || f.Current != 4 || len(f.Profiles) != 3 || len(f.Rules) != 1 || str(f.Rules[0].Ports) != "8080" || f.Rules[0].App != nil {
		t.Fatalf("%+v %v", f, err)
	}
	if v := EvalWindows(f, 8080, "tcp", "x.exe"); v.Status != OK {
		t.Errorf("parsed rule applies: %+v", v)
	}
}

func TestParseRule(t *testing.T) {
	for in, want := range map[string]Rule{
		"db.internal:5432":         {Host: "db.internal", Port: 5432},
		"10.0.0.5:22 deny":         {Host: "10.0.0.5", Port: 22, Expect: "deny"},
		"[2001:db8::1]:443 ALLOW":  {Host: "2001:db8::1", Port: 443, Expect: "allow"},
		"example.com:25   blocked": {Host: "example.com", Port: 25, Expect: "deny"},
	} {
		got, err := ParseRule(in)
		if err != nil || got != want {
			t.Errorf("%q: %+v %v", in, got, err)
		}
	}
	for _, bad := range []string{"example.com", "example.com:0", "a:1 maybe", "a:1 allow extra", ""} {
		if _, err := ParseRule(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestReach(t *testing.T) {
	old := dialReach
	defer func() { dialReach = old }()
	dialReach = func(_ context.Context, addr string, _ time.Duration) (time.Duration, error) {
		switch addr {
		case "10.0.0.1:80":
			return 12 * time.Millisecond, nil
		case "10.0.0.1:23":
			return 0, &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
		case "10.0.0.1:3306":
			return 0, &net.OpError{Op: "dial", Err: timeoutErr{}}
		}
		return 0, &net.DNSError{Name: "nope.test", IsNotFound: true}
	}
	rules := []Rule{{Host: "10.0.0.1", Port: 80, Expect: "allow"}, {Host: "10.0.0.1", Port: 23, Expect: "deny"},
		{Host: "10.0.0.1", Port: 3306, Expect: "allow"}, {Host: "nope.test", Port: 1, Expect: "allow"}, {Host: "10.0.0.1", Port: 80}}
	waited := 0
	rs := Reach(context.Background(), rules, time.Second, func(context.Context) error { waited++; return nil })
	want := []struct {
		result string
		holds  string
	}{{Open, "true"}, {Refused, "true"}, {Filtered, "false"}, {Failed, "nil"}, {Open, "nil"}}
	for i, w := range want {
		h := "nil"
		if rs[i].Holds != nil {
			h = fmt.Sprint(*rs[i].Holds)
		}
		if rs[i].Result != w.result || h != w.holds {
			t.Errorf("%s: %s holds=%s, want %s %s", rs[i].Rule, rs[i].Result, h, w.result, w.holds)
		}
	}
	if rs[0].RTT != 12*time.Millisecond || waited != 5 || rs[3].Error != "the name doesn't resolve" {
		t.Errorf("rtt %v waited %d err %q", rs[0].RTT, waited, rs[3].Error)
	}
}

// layered fakes every layer of Diagnose.
func layered(t *testing.T, ss []sockets.Socket, fw FirewallVerdict, ms []probe.PortMapping, wan, pub string) {
	t.Helper()
	oL, oF, oG, oI, oM, oW, oP, oE, o6 := listSockets, firewall, gateway, localIP, mappings, routerWAN, publicIP, external, ipv6Global
	listSockets = func() (sockets.Snapshot, error) { return sockets.Snapshot{Sockets: ss}, nil }
	firewall = func(context.Context, int, string, string) FirewallVerdict { return fw }
	gateway = func() (net.IP, error) { return net.ParseIP("192.168.0.1"), nil }
	localIP = func() net.IP { return net.ParseIP("192.168.0.200") }
	mappings = func(context.Context, net.IP) ([]probe.PortMapping, error) {
		if ms == nil {
			return nil, errors.New("no UPnP")
		}
		return ms, nil
	}
	routerWAN = func(context.Context, net.IP) (net.IP, error) { return net.ParseIP(wan), nil }
	publicIP = func(context.Context) (net.IP, error) { return net.ParseIP(pub), nil }
	external = func(_ context.Context, _ string, port int) probe.ExternalResult {
		return probe.ExternalResult{IP: pub, Port: port, Open: true}
	}
	ipv6Global = func() []string { return []string{"2a02:8388::5"} }
	t.Cleanup(func() {
		listSockets, firewall, gateway, localIP, mappings, routerWAN, publicIP, external, ipv6Global = oL, oF, oG, oI, oM, oW, oP, oE, o6
	})
}

func TestDiagnose(t *testing.T) {
	srv := []sockets.Socket{{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 8080, State: "LISTEN", Process: "node.exe"}}
	fwOK := FirewallVerdict{Status: OK, Title: "Windows Firewall allows TCP 8080"}
	fwd := []probe.PortMapping{{Protocol: "TCP", ExternalPort: 8080, InternalPort: 8080, Client: "192.168.0.200", Enabled: true, Description: "node"}}

	layered(t, srv, fwOK, fwd, "198.51.100.41", "198.51.100.41")
	r := Diagnose(context.Background(), 8080, "tcp", Options{Helper: "https://helper.test"})
	if r.Blocking() != nil || r.Program != "node.exe" || len(r.Layers) != 5 {
		t.Fatalf("all good: %+v", r.Layers)
	}
	for _, l := range r.Layers {
		if l.Status != OK {
			t.Errorf("%s: %s %s", l.Name, l.Status, l.Title)
		}
	}
	if !strings.Contains(r.Layers[3].Detail, "2a02:8388::5") {
		t.Errorf("IPv6 note: %q", r.Layers[3].Detail)
	}

	cases := []struct {
		name      string
		ss        []sockets.Socket
		fw        FirewallVerdict
		ms        []probe.PortMapping
		wan       string
		layer     string
		titlePart string
	}{
		{"nothing listens", nil, fwOK, fwd, "198.51.100.41", LayerListen, "Nothing listens"},
		{"loopback only", []sockets.Socket{{Proto: "tcp", LocalIP: "127.0.0.1", LocalPort: 8080, State: "LISTEN", Process: "node.exe"}}, fwOK, fwd, "198.51.100.41", LayerListen, "only for this machine"},
		{"firewall", srv, FirewallVerdict{Status: Bad, Title: "No Windows Firewall rule lets TCP 8080 in"}, fwd, "198.51.100.41", LayerFirewall, "No Windows Firewall rule"},
		{"forwarded elsewhere", srv, fwOK, []probe.PortMapping{{Protocol: "TCP", ExternalPort: 8080, InternalPort: 8080, Client: "192.168.0.38", Enabled: true}}, "198.51.100.41", LayerRouter, "another device"},
		{"wrong inner port", srv, fwOK, []probe.PortMapping{{Protocol: "TCP", ExternalPort: 80, InternalPort: 8080, Client: "192.168.0.200", Enabled: true}, {Protocol: "TCP", ExternalPort: 8080, InternalPort: 9090, Client: "192.168.0.200", Enabled: true}}, "198.51.100.41", "", ""},
		{"cgnat", srv, fwOK, fwd, "100.70.1.2", LayerInternet, "carrier-grade NAT"},
	}
	for _, c := range cases {
		layered(t, c.ss, c.fw, c.ms, c.wan, "198.51.100.41")
		r := Diagnose(context.Background(), 8080, "tcp", Options{})
		b := r.Blocking()
		if c.layer == "" {
			continue
		}
		if b == nil || b.Name != c.layer || !strings.Contains(b.Title, c.titlePart) {
			t.Errorf("%s: blocking %+v", c.name, b)
		}
	}
	// No UPnP: the router layer can't tell; nothing is blocking, the outside isn't tested.
	layered(t, srv, fwOK, nil, "", "198.51.100.41")
	r = Diagnose(context.Background(), 8080, "tcp", Options{})
	if r.Blocking() != nil || r.Layers[2].Status != Unknown || !strings.Contains(r.Layers[2].Fix, "http://192.168.0.1") || r.Layers[4].Status != Unknown {
		t.Errorf("unknowns: %+v", r.Layers)
	}
	if r := Diagnose(context.Background(), 5353, "udp", Options{Helper: "https://h"}); !strings.Contains(r.Layers[4].Title, "UDP can't be tested") {
		t.Errorf("udp outside: %+v", r.Layers[4])
	}
}
