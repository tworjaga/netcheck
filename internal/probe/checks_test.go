package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func swap[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

// ---- ipv6

func TestCheckIPv6Works(t *testing.T) {
	swap(t, &globalV6, func() net.IP { return net.ParseIP("2001:db8::5") })
	swap(t, &tcpConnect, func(ctx context.Context, addr string, _ time.Duration) (float64, bool) {
		if strings.HasPrefix(addr, "[") {
			return 12, true
		}
		return 10, true
	})
	swap(t, &lookupIPAddr, func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("2606:4700::1")}, {IP: net.ParseIP("104.16.1.1")}}, nil
	})
	r := CheckIPv6(context.Background())
	if !r.Reachable || r.V6Ms != 12 || r.V4Ms != 10 || !r.DNSAAAA || !r.Preferred || r.Address != "2001:db8::5" {
		t.Fatalf("got %+v", r)
	}
}

func TestCheckIPv6Broken(t *testing.T) {
	swap(t, &globalV6, func() net.IP { return net.ParseIP("2001:db8::5") })
	calls := 0
	swap(t, &tcpConnect, func(ctx context.Context, addr string, _ time.Duration) (float64, bool) {
		if strings.HasPrefix(addr, "[") {
			calls++
			return 0, false
		}
		return 10, true
	})
	swap(t, &lookupIPAddr, func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("104.16.1.1")}, {IP: net.ParseIP("2606:4700::1")}}, nil
	})
	r := CheckIPv6(context.Background())
	if r.Reachable || r.Preferred || !r.DNSAAAA || r.V4Ms != 10 {
		t.Fatalf("got %+v", r)
	}
	if calls != len(v6Targets) {
		t.Fatalf("a dead path should cost one try per target, took %d", calls)
	}
}

func TestULA(t *testing.T) {
	if !isULA(net.ParseIP("fd12::1")) || isULA(net.ParseIP("2001:db8::1")) {
		t.Fatal("ULA detection")
	}
}

// ---- captive portal

func TestCaptive(t *testing.T) {
	cases := []struct {
		name    string
		h       http.HandlerFunc
		intact  bool
		redirTo string
	}{
		{"clean 204", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }, true, ""},
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://login.hotelwifi.example/portal", http.StatusFound)
		}, false, "login.hotelwifi.example"},
		{"login page with 200", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<html><meta http-equiv="refresh" content="0;url=https://wifi.cafe.example/?x=1"></html>`)
		}, false, "wifi.cafe.example"},
	}
	for _, c := range cases {
		srv := httptest.NewServer(c.h)
		swap(t, &captiveChecks, []CaptiveCheck{{URL: srv.URL, Status: 204}})
		r := CheckCaptive(context.Background())
		srv.Close()
		p := r.Probes[0]
		if p.Intact != c.intact || p.Redirect != c.redirTo || p.Error != "" {
			t.Errorf("%s: got %+v", c.name, p)
		}
	}
	swap(t, &captiveChecks, []CaptiveCheck{{URL: "http://127.0.0.1:1/", Status: 204}})
	if p := CheckCaptive(context.Background()).Probes[0]; p.Error == "" || p.Intact {
		t.Errorf("offline: got %+v", p)
	}
}

func TestCaptiveBodyMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>")
	}))
	defer srv.Close()
	swap(t, &captiveChecks, []CaptiveCheck{{URL: srv.URL, Status: 200, Body: "Success"}})
	if p := CheckCaptive(context.Background()).Probes[0]; !p.Intact {
		t.Fatalf("got %+v", p)
	}
}

// ---- TLS and clock

func tlsServer(t *testing.T) (*httptest.Server, *x509.CertPool) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // handshake failures are the point
	srv.StartTLS()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool
}

func dialTo(srv *httptest.Server) func(context.Context, string, *tls.Config) (*tls.Conn, error) {
	return func(ctx context.Context, host string, cfg *tls.Config) (*tls.Conn, error) {
		cfg = cfg.Clone()
		cfg.ServerName = "example.com" // the httptest certificate's name
		d := tls.Dialer{Config: cfg}
		c, err := d.DialContext(ctx, "tcp", srv.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return c.(*tls.Conn), nil
	}
}

func TestTLSTrusted(t *testing.T) {
	srv, pool := tlsServer(t)
	defer srv.Close()
	swap(t, &tlsDial, dialTo(srv))
	p := probeTLS(context.Background(), "www.example.com", pool)
	if !p.OK || p.Version != "TLS 1.3" || p.Problem != "" {
		t.Fatalf("got %+v", p)
	}
	// httptest signs with its own "Acme Co" CA: trusted here, but not a
	// public CA, which is exactly what HTTPS inspection looks like.
	if p.Inspector != "Acme Co" {
		t.Fatalf("local CA should be flagged, got %q", p.Inspector)
	}
}

func TestTLSUntrustedIsNamed(t *testing.T) {
	srv, _ := tlsServer(t)
	defer srv.Close()
	swap(t, &tlsDial, dialTo(srv))
	p := probeTLS(context.Background(), "www.example.com", x509.NewCertPool())
	if p.OK || p.Problem != "untrusted" || p.Issuer == "" {
		t.Fatalf("got %+v", p)
	}
}

func TestTLSNetworkError(t *testing.T) {
	swap(t, &tlsDial, func(context.Context, string, *tls.Config) (*tls.Conn, error) {
		return nil, errors.New("connection refused")
	})
	if p := probeTLS(context.Background(), "x", nil); p.Problem != "network" {
		t.Fatalf("got %+v", p)
	}
}

func TestInspectorDetection(t *testing.T) {
	c := &x509.Certificate{}
	c.Issuer.CommonName = "Avast Web/Mail Shield Root"
	if got := inspectorIn([]*x509.Certificate{c}); got != "Avast Web/Mail Shield Root" {
		t.Fatalf("got %q", got)
	}
	c.Issuer.CommonName = "R11"
	c.Issuer.Organization = []string{"Let's Encrypt"}
	if got := inspectorIn([]*x509.Certificate{c}); got != "" {
		t.Fatalf("false positive %q", got)
	}
}

func TestClockSkew(t *testing.T) {
	base := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	swap(t, &now, func() time.Time { return base.Add(90 * time.Second) })
	swap(t, &dateHeader, func(ctx context.Context, url string) (time.Time, time.Duration, error) {
		if strings.Contains(url, "microsoft") {
			return time.Time{}, 0, errors.New("blocked")
		}
		return base, 0, nil
	})
	skew, ok := clockSkew(context.Background())
	if !ok || skew != 89.5 {
		t.Fatalf("got %v %v", skew, ok)
	}
	swap(t, &dateHeader, func(context.Context, string) (time.Time, time.Duration, error) {
		return time.Time{}, 0, errors.New("offline")
	})
	if _, ok := clockSkew(context.Background()); ok {
		t.Fatal("offline must not report a skew")
	}
}

// ---- DNS leak

func TestCheckLeak(t *testing.T) {
	swap(t, &listInterfaces, func() []NetIf { return []NetIf{{Name: "eth0"}, {Name: "wg0"}} })
	swap(t, &lookupHostIPs, func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("74.125.0.9")}, nil })
	fakeTXT(t, map[string]string{
		whoamiGoogle:                       "172.253.0.4",
		"9.0.125.74.origin.asn.cymru.com":  "15169 | 74.125.0.0/16 | US | arin | 2007-03-13",
		"4.0.253.172.origin.asn.cymru.com": "15169 | 172.253.0.0/16 | US | arin | 2007-03-13",
		"7.113.0.203.origin.asn.cymru.com": "64500 | 203.0.113.0/24 | NL | ripencc | 2001-01-01",
		"AS15169.asn.cymru.com":            "15169 | US | arin | 2000-03-30 | GOOGLE, US",
		"AS64500.asn.cymru.com":            "64500 | NL | ripencc | 2001-01-01 | VPNCO, NL",
	})
	ipsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "203.0.113.7") }))
	defer ipsrv.Close()
	swap(t, &publicIPEndpoints, []string{ipsrv.URL})
	r := CheckLeak(context.Background())
	if len(r.VPN) != 1 || r.VPN[0] != "wg0" {
		t.Fatalf("vpn: %+v", r.VPN)
	}
	if len(r.Resolvers) != 2 || r.Resolvers[0].ASN != "AS15169" || r.Resolvers[0].Org != "GOOGLE" {
		t.Fatalf("resolvers: %+v", r.Resolvers)
	}
	if r.Public.ASN != "AS64500" {
		t.Fatalf("public: %+v", r.Public)
	}
}

func TestVPNNames(t *testing.T) {
	for name, want := range map[string]bool{
		"utun4": true, "wg0": true, "tun0": true, "NordLynx": true, "OpenVPN TAP-Windows6": true,
		"ProtonVPN": true, "eth0": false, "Wi-Fi": false, "en0": false, "tailscale0": false, "docker0": false,
	} {
		if vpnName.MatchString(name) != want {
			t.Errorf("%s: want %v", name, want)
		}
	}
}

// ---- DNSSEC

// fakeResolver answers like a DNS server: validating or not.
func fakeResolver(validating bool) func(context.Context, string, []byte, time.Duration) ([]byte, error) {
	return func(_ context.Context, _ string, q []byte, _ time.Duration) ([]byte, error) {
		m, _ := ParseMsg(q)
		name := m.Questions[0]
		flags := uint16(0x8180) // response, RD, RA
		rcode, answer := 0, true
		switch {
		case name == dnssecSigned && validating:
			flags |= flagAD
		case strings.Contains(name, "fail") && validating:
			rcode, answer = rcodeServFail, false
		}
		b := append([]byte(nil), q[:2]...)
		b = binary.BigEndian.AppendUint16(b, flags|uint16(rcode))
		an := uint16(0)
		if answer {
			an = 1
		}
		b = append(b, 0, 1, byte(an>>8), byte(an), 0, 0, 0, 0)
		b = appendName(b, name)
		b = append(b, 0, TypeA, 0, 1)
		if answer {
			b = append(b, 0xC0, 12, 0, TypeA, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1)
		}
		return b, nil
	}
}

func TestDNSSECValidating(t *testing.T) {
	swap(t, &dnsExchange, fakeResolver(true))
	r := CheckDNSSEC(context.Background(), "192.0.2.53")
	if !r.Answered || !r.AD || !r.Rejects || !r.RejectKnown {
		t.Fatalf("got %+v", r)
	}
}

func TestDNSSECNotValidating(t *testing.T) {
	swap(t, &dnsExchange, fakeResolver(false))
	r := CheckDNSSEC(context.Background(), "192.0.2.53")
	if !r.Answered || r.AD || r.Rejects || !r.RejectKnown {
		t.Fatalf("got %+v", r)
	}
}

func TestDNSSECDead(t *testing.T) {
	swap(t, &dnsExchange, func(context.Context, string, []byte, time.Duration) ([]byte, error) {
		return nil, errors.New("i/o timeout")
	})
	if r := CheckDNSSEC(context.Background(), "192.0.2.53"); r.Answered || r.Error == "" {
		t.Fatalf("got %+v", r)
	}
}

func TestDNSExchangeRealSocket(t *testing.T) {
	port, stop := fakeDNS(t, false)
	defer stop()
	q := BuildQuery(0x4242, "example.com.", TypeA, true, true)
	b, err := dnsExchange(context.Background(), "127.0.0.1:"+port, q, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := ParseMsg(b); m == nil || m.ID != 0x4242 || len(m.Answers) != 1 {
		t.Fatalf("got %+v", m)
	}
}

func TestParseNetshDNS(t *testing.T) {
	out := "\r\nConfiguration for interface \"Wi-Fi\"\r\n" +
		"    DNS servers configured through DHCP:  192.168.1.1\r\n" +
		"                                          8.8.8.8\r\n" +
		"    Register with which suffix:           Primary only\r\n\r\n" +
		"Configuration for interface \"Ethernet\"\r\n" +
		"    DNS servers configured through DHCP:  None\r\n\r\n" +
		"Configuration for interface \"Loopback Pseudo-Interface 1\"\r\n" +
		"    Statically Configured DNS Servers:    None\r\n" +
		"    Über DHCP konfigurierte DNS-Server:   192.168.1.1\r\n"
	got := parseNetshDNS(out)
	if len(got) != 2 || got[0] != "192.168.1.1" || got[1] != "8.8.8.8" {
		t.Fatalf("got %v", got)
	}
}

// ---- MTU

// mtuPath answers DF pings that fit in mtu; bigger ones are refused with
// "too big" when signal is set, or silently dropped (a black hole).
type mtuPath struct {
	mtu    int
	signal bool
	sent   int
}

func (p *mtuPath) Echo(dst net.IP, o EchoOpts) (EchoReply, error) {
	p.sent++
	if o.Size+mtuHeaders <= p.mtu {
		return EchoReply{Kind: EchoOK, From: dst, RTT: time.Millisecond}, nil
	}
	if p.signal {
		return EchoReply{Kind: EchoTooBig}, nil
	}
	return EchoReply{Kind: EchoTimeout}, nil
}

func TestProbeMTU(t *testing.T) {
	for _, c := range []struct {
		mtu    int
		signal bool
	}{{1500, true}, {1492, true}, {1420, false}, {1280, true}} {
		withEchoer(t, &mtuPath{mtu: c.mtu, signal: c.signal}, nil)
		r := ProbeMTU(context.Background(), "192.0.2.1")
		if r.MTU != c.mtu || r.Error != "" || (c.mtu < 1500 && r.Signalled != c.signal) {
			t.Errorf("mtu %d signal %v: got %+v", c.mtu, c.signal, r)
		}
	}
}

func TestProbeMTUNoICMP(t *testing.T) {
	withEchoer(t, nil, ErrNoICMP)
	if r := ProbeMTU(context.Background(), "192.0.2.1"); r.MTU != 0 || r.Error == "" {
		t.Fatalf("got %+v", r)
	}
	withEchoer(t, &fakeEcho{script: []float64{-1}}, nil)
	if r := ProbeMTU(context.Background(), "192.0.2.1"); r.Error != ErrICMPBlocked.Error() {
		t.Fatalf("got %+v", r)
	}
}

// ---- DHCP

func offer(xid uint32, server, offered string, dns ...string) []byte {
	p := make([]byte, 240)
	p[0] = 2
	binary.BigEndian.PutUint32(p[4:], xid)
	copy(p[16:20], net.ParseIP(offered).To4())
	copy(p[236:], dhcpMagic)
	p = append(p, 53, 1, 2)
	p = append(p, 54, 4)
	p = append(p, net.ParseIP(server).To4()...)
	p = append(p, 3, 4)
	p = append(p, net.ParseIP(server).To4()...)
	p = append(p, 6, byte(4*len(dns)))
	for _, d := range dns {
		p = append(p, net.ParseIP(d).To4()...)
	}
	return append(p, 255)
}

func TestDiscoverIsWellFormed(t *testing.T) {
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	p := buildDiscover(0xAABBCCDD, mac)
	if p[0] != 1 || binary.BigEndian.Uint32(p[4:]) != 0xAABBCCDD || p[10]&0x80 == 0 || string(p[28:34]) != string(mac) || string(p[236:240]) != string(dhcpMagic) || p[240] != 53 || p[len(p)-1] != 255 {
		t.Fatalf("bad packet % x", p)
	}
}

func TestFindDHCPServersCountsDistinct(t *testing.T) {
	swap(t, &dhcpExchange, func(_ context.Context, pkt []byte, _ time.Duration) ([]dhcpReply, error) {
		xid := binary.BigEndian.Uint32(pkt[4:])
		return []dhcpReply{
			{offer(xid, "192.168.1.1", "192.168.1.50", "192.168.1.1"), nil},
			{offer(xid, "192.168.1.1", "192.168.1.50", "192.168.1.1"), nil}, // a retransmit
			{offer(xid, "10.0.0.1", "10.0.0.23", "10.0.0.1"), nil},          // a second router
			{offer(xid^1, "172.16.0.1", "172.16.0.9"), nil},                 // someone else's xid
			{[]byte("junk"), nil},
		}, nil
	})
	r := FindDHCPServers(context.Background(), time.Millisecond)
	if len(r.Servers) != 2 || r.Servers[1].ServerID != "10.0.0.1" || r.Servers[1].Offered != "10.0.0.23" || r.Servers[0].DNS[0] != "192.168.1.1" {
		t.Fatalf("got %+v", r)
	}
}

func TestFindDHCPServersNeedsElevation(t *testing.T) {
	swap(t, &dhcpExchange, func(context.Context, []byte, time.Duration) ([]dhcpReply, error) {
		return nil, errNeedsElevation
	})
	if r := FindDHCPServers(context.Background(), time.Millisecond); r.Unavailable == "" {
		t.Fatalf("got %+v", r)
	}
}

func TestPublicCA(t *testing.T) {
	for name, want := range map[string]bool{
		"Google Trust Services": true, "Let's Encrypt": true, "DigiCert Inc": true, "Microsoft Corporation": true,
		"Anthropic": false, "Contoso Corp Inspection CA": false,
	} {
		if publicCA(name) != want {
			t.Errorf("%s: want %v", name, want)
		}
	}
}

func TestCheckResolverSystemSkipsOSCache(t *testing.T) {
	// Where the OS offers a cache-free lookup (Windows), the system resolver
	// uses it for every name and for the NXDOMAIN check.
	var asked []string
	swap(t, &systemLookup, func(_ context.Context, name string) (bool, error) {
		asked = append(asked, name)
		if strings.HasPrefix(name, "nx") {
			return false, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		}
		return true, nil
	})
	r := CheckResolver(context.Background(), Resolver{Label: "System"}, DefaultNames)
	if r.Answered != 3 || r.RewritesNX || r.Error != "" || len(asked) != 4 {
		t.Fatalf("got %+v after %v", r, asked)
	}
}
