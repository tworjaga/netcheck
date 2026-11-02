package tracex

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
)

// pathProber is a pretend route: routers at TTL 1..len(path), then the
// destination. "" in the path is a silent router.
type pathProber struct {
	path  []string
	dst   net.IP
	state string // TCP: what the destination says
	block int    // past this TTL nothing answers (0: no block)
	quiet bool   // the destination answers only at full distance
}

func (p *pathProber) probe(_ context.Context, ttl int) reply {
	if p.block > 0 && ttl > p.block {
		return reply{}
	}
	if ttl <= len(p.path) {
		if p.path[ttl-1] == "" {
			return reply{}
		}
		return reply{from: net.ParseIP(p.path[ttl-1]), rtt: time.Duration(ttl) * 10 * time.Millisecond, ok: true}
	}
	if p.quiet && ttl != 64 {
		return reply{}
	}
	return reply{from: p.dst, rtt: 50 * time.Millisecond, reached: true, state: p.state, ok: true}
}

func (p *pathProber) close() {}

func usePath(t *testing.T, p *pathProber) {
	t.Helper()
	oldNew, oldRes := newProber, resolveHost
	newProber = func(string, net.IP, int, time.Duration) (prober, string, error) { return p, "raw", nil }
	resolveHost = func(context.Context, string) (net.IP, error) { return p.dst, nil }
	t.Cleanup(func() { newProber, resolveHost = oldNew, oldRes })
}

func TestWalk(t *testing.T) {
	dst := net.ParseIP("203.0.113.9")
	usePath(t, &pathProber{path: []string{"192.168.0.1", "", "198.51.100.1"}, dst: dst, state: "open"})
	r := Trace(context.Background(), "example.com", Options{Proto: "tcp", NoNames: true, Probes: 2})
	if r.Error != "" || !r.Reached || r.PortState != "open" || r.Port != 443 || len(r.Hops) != 4 {
		t.Fatalf("got %+v", r)
	}
	if r.Hops[1].IP != "" || r.Hops[1].Answered() != 0 || r.Hops[3].IP != dst.String() || !r.Hops[3].Reached || r.Hops[0].Best() != 10 {
		t.Errorf("hops %+v", r.Hops)
	}

	usePath(t, &pathProber{path: []string{"192.168.0.1", "198.51.100.1"}, dst: dst, block: 2})
	r = Trace(context.Background(), "example.com", Options{Proto: "udp", NoNames: true, Probes: 1, MaxHops: 20})
	if r.Reached || len(r.Hops) != 3 || !strings.Contains(r.Note, "stopped after 6 silent hops") {
		t.Errorf("blocked: %d hops, note %q", len(r.Hops), r.Note)
	}

	usePath(t, &pathProber{path: []string{"192.168.0.1"}, dst: dst, quiet: true, state: "closed"})
	r = Trace(context.Background(), "example.com", Options{Proto: "tcp", NoNames: true, Probes: 1})
	last := r.Hops[len(r.Hops)-1]
	if !r.Reached || last.TTL != 0 || r.PortState != "closed" || !strings.Contains(r.Note, "destination did") {
		t.Errorf("quiet routers, reached at full distance: %+v %q", last, r.Note)
	}
}

func TestTraceErrors(t *testing.T) {
	oldNew, oldRes := newProber, resolveHost
	defer func() { newProber, resolveHost = oldNew, oldRes }()
	resolveHost = func(context.Context, string) (net.IP, error) { return net.ParseIP("192.0.2.1"), nil }
	newProber = func(string, net.IP, int, time.Duration) (prober, string, error) { return nil, "", ErrPrivileged }
	if r := Trace(context.Background(), "x", Options{Proto: "tcp"}); !strings.Contains(r.Error, "TCP traces need") {
		t.Errorf("privileges: %q", r.Error)
	}
	resolveHost = func(context.Context, string) (net.IP, error) {
		return nil, &net.DNSError{Name: "nope.test", IsNotFound: true}
	}
	if r := Trace(context.Background(), "nope.test", Options{}); r.Error != "nope.test doesn't exist" {
		t.Errorf("missing: %q", r.Error)
	}
	resolveHost = func(context.Context, string) (net.IP, error) { return net.ParseIP("2001:db8::1"), nil }
	if r := Trace(context.Background(), "v6", Options{}); !strings.Contains(r.Error, "IPv4") {
		t.Errorf("v6: %q", r.Error)
	}
}

func TestICMPTraceAndOwners(t *testing.T) {
	oldICMP, oldRes, oldTXT, oldAddr := icmpTrace, resolveHost, lookupTXT, lookupAddr
	defer func() { icmpTrace, resolveHost, lookupTXT, lookupAddr = oldICMP, oldRes, oldTXT, oldAddr }()
	resolveHost = func(context.Context, string) (net.IP, error) { return net.ParseIP("1.1.1.1"), nil }
	icmpTrace = func(_ context.Context, host string, o probe.RouteOpts) probe.RouteResult {
		return probe.RouteResult{Target: host, Addr: host, Method: "icmp", Reached: true, Hops: []probe.Hop{
			{TTL: 1, IP: "192.168.0.1", SamplesMs: []float64{1, 2, 1}},
			{TTL: 2, IP: "100.64.0.1", SamplesMs: []float64{8, -1, 9}},
			{TTL: 3, IP: "198.51.100.121", SamplesMs: []float64{10, 11, 12}},
			{TTL: 4, IP: "1.1.1.1", SamplesMs: []float64{60, 61, 62}},
		}}
	}
	lookupAddr = func(_ context.Context, ip string) ([]string, error) {
		if ip == "1.1.1.1" {
			return []string{"one.one.one.one."}, nil
		}
		return nil, errors.New("none")
	}
	lookupTXT = func(_ context.Context, name string) ([]string, error) {
		switch name {
		case "1.1.1.1.origin.asn.cymru.com":
			return []string{"13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"}, nil
		case "121.100.51.198.origin.asn.cymru.com":
			return []string{"64496 | 198.51.100.0/24 | AT | ripencc | 1996-01-01"}, nil
		case "AS13335.asn.cymru.com":
			return []string{"13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"}, nil
		case "AS64496.asn.cymru.com":
			return []string{"64496 | AT | ripencc | 1996-01-01 | EXAMPLE-AS - Example Telecom GmbH, AT"}, nil
		}
		return nil, errors.New("none")
	}
	r := Trace(context.Background(), "1.1.1.1", Options{})
	if r.Method != "icmp" || !r.Reached || len(r.Hops) != 4 || !r.Hops[3].Reached || r.Hops[3].Name != "one.one.one.one" {
		t.Fatalf("got %+v", r)
	}
	if r.Hops[0].Owner != "private network" || !strings.Contains(r.Hops[1].Owner, "carrier-grade") || r.Hops[2].ASN != 64496 || r.Hops[3].Owner != "Cloudflare, Inc." {
		t.Errorf("owners: %+v", r.Hops)
	}
	if got := strings.Join(Owners(r.Hops), " | "); got != "private network | carrier-grade NAT (your ISP) | Example Telecom GmbH | Cloudflare, Inc." {
		t.Errorf("owners in order: %s", got)
	}
	if j := BiggestJump(r.Hops); j.From != 3 || j.To != 4 || j.AddMs != 50 {
		t.Errorf("jump %+v", j)
	}
	if r.Hops[1].Avg() != 8.5 || r.Hops[1].Answered() != 2 {
		t.Errorf("stats %+v", r.Hops[1])
	}
}

// icmpError builds an ICMP error quoting a probe's IPv4 and UDP/TCP header,
// optionally behind an IPv4 header of its own.
func icmpError(typ byte, proto byte, dst net.IP, sport int, withIP bool) []byte {
	inner := make([]byte, 20+8)
	inner[0], inner[9] = 0x45, proto
	copy(inner[16:20], dst.To4())
	binary.BigEndian.PutUint16(inner[20:], uint16(sport))
	b := append([]byte{typ, 0, 0, 0, 0, 0, 0, 0}, inner...)
	if withIP {
		outer := make([]byte, 20)
		outer[0] = 0x45
		b = append(outer, b...)
	}
	return b
}

func TestParseICMP(t *testing.T) {
	dst := net.ParseIP("203.0.113.9")
	for _, withIP := range []bool{false, true} {
		typ, _, proto, d, sport, ok := parseICMP(icmpError(11, 6, dst, 40001, withIP))
		if !ok || typ != 11 || proto != 6 || !d.Equal(dst) || sport != 40001 {
			t.Errorf("withIP=%v: %d %d %v %d %v", withIP, typ, proto, d, sport, ok)
		}
	}
	if _, _, _, _, _, ok := parseICMP([]byte{0, 0, 0, 0, 0, 0, 0, 0}); ok {
		t.Error("an echo reply isn't an error about a probe")
	}
}

func TestRawProberMatchesReplies(t *testing.T) {
	dst := net.ParseIP("203.0.113.9")
	p := &rawProber{proto: "udp", dst: dst.To4(), waiters: map[int]chan icmpHit{}}
	port, ch := p.register()
	pc := &fakePacketConn{packets: [][]byte{
		icmpError(11, 6, dst, port, false),                      // TCP: not ours
		icmpError(11, 17, net.ParseIP("192.0.2.1"), port, true), // another destination
		icmpError(11, 17, dst, port, true),                      // ours
	}, from: net.ParseIP("198.51.100.1")}
	p.conn = pc
	go p.read()
	select {
	case h := <-ch:
		if h.typ != 11 || !h.from.Equal(net.ParseIP("198.51.100.1")) {
			t.Errorf("hit %+v", h)
		}
	case <-time.After(time.Second):
		t.Fatal("no hit")
	}
	select {
	case h := <-ch:
		t.Errorf("only one hit is ours: %+v", h)
	default:
	}
}

type fakePacketConn struct {
	net.PacketConn
	packets [][]byte
	from    net.IP
}

func (f *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if len(f.packets) == 0 {
		time.Sleep(50 * time.Millisecond)
		return 0, nil, errors.New("closed")
	}
	p := f.packets[0]
	f.packets = f.packets[1:]
	return copy(b, p), &net.IPAddr{IP: f.from}, nil
}
