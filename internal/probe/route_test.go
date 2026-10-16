package probe

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// pathEcho is a fake network path. Probes with TTL n are answered by
// routers[n-1]; the destination answers once TTL reaches len(routers)+1.
// An empty router string is a hop that never answers. lossAt makes every
// other probe to that TTL vanish.
type pathEcho struct {
	mu      sync.Mutex
	routers []string
	dst     string
	lossAt  map[int]bool
	n       map[int]int
	direct  map[string]bool // addresses that answer plain pings (TTL 0)
}

func (p *pathEcho) Echo(dst net.IP, o EchoOpts) (EchoReply, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.n == nil {
		p.n = map[int]int{}
	}
	if o.TTL == 0 { // a plain ping
		if p.direct[dst.String()] {
			return EchoReply{Kind: EchoOK, From: dst, RTT: 5 * time.Millisecond}, nil
		}
		return EchoReply{Kind: EchoTimeout}, nil
	}
	p.n[o.TTL]++
	if p.lossAt[o.TTL] && p.n[o.TTL]%2 == 0 {
		return EchoReply{Kind: EchoTimeout}, nil
	}
	ms := time.Duration(o.TTL*3) * time.Millisecond
	if o.TTL > len(p.routers) {
		return EchoReply{Kind: EchoOK, From: net.ParseIP(p.dst), RTT: ms}, nil
	}
	if r := p.routers[o.TTL-1]; r != "" {
		return EchoReply{Kind: EchoTTLExceeded, From: net.ParseIP(r), RTT: ms}, nil
	}
	return EchoReply{Kind: EchoTimeout}, nil
}

func TestTraceDiscoversPathAndStats(t *testing.T) {
	withEchoer(t, &pathEcho{routers: []string{"192.168.1.1", "100.64.0.1", "84.1.1.1"}, dst: "127.0.0.1", lossAt: map[int]bool{2: true}}, nil)
	updates := 0
	r := Trace(context.Background(), "127.0.0.1", RouteOpts{Rounds: 4, Interval: time.Millisecond, OnUpdate: func(RouteResult) { updates++ }})
	if r.Method != "icmp" || !r.Reached || len(r.Hops) != 4 {
		t.Fatalf("got %+v", r)
	}
	if r.Hops[0].IP != "192.168.1.1" || r.Hops[3].IP != "127.0.0.1" {
		t.Fatalf("hops: %+v", r.Hops)
	}
	for _, h := range r.Hops {
		if h.Sent != 4 {
			t.Errorf("hop %d probed %d times, want 4", h.TTL, h.Sent)
		}
	}
	if r.Hops[1].LossPct != 25 && r.Hops[1].LossPct != 50 {
		t.Errorf("hop 2 should show the scripted loss, got %.0f%%", r.Hops[1].LossPct)
	}
	if r.Hops[0].LossPct != 0 || r.Hops[0].AvgMs <= 0 {
		t.Errorf("hop 1: %+v", r.Hops[0])
	}
	if updates < 4 {
		t.Errorf("expected live updates, got %d", updates)
	}
}

func TestTraceKeepsSilentMiddleHop(t *testing.T) {
	withEchoer(t, &pathEcho{routers: []string{"192.168.1.1", "", "84.1.1.1"}, dst: "127.0.0.1"}, nil)
	r := Trace(context.Background(), "127.0.0.1", RouteOpts{Rounds: 1})
	if len(r.Hops) != 4 || r.Hops[1].IP != "" || r.Hops[1].Received != 0 || !r.Reached {
		t.Fatalf("a hop that never answers must stay in the path: %+v", r.Hops)
	}
}

func TestTraceStopsWhenCancelled(t *testing.T) {
	withEchoer(t, &pathEcho{routers: []string{"192.168.1.1"}, dst: "127.0.0.1"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(60 * time.Millisecond); cancel() }()
	done := make(chan RouteResult, 1)
	go func() { done <- Trace(ctx, "127.0.0.1", RouteOpts{Rounds: 0, Interval: 5 * time.Millisecond}) }()
	select {
	case r := <-done:
		if len(r.Hops) == 0 {
			t.Fatalf("got %+v", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Trace ignored Ctrl-C")
	}
}

func TestTraceFallsBackToSystemTool(t *testing.T) {
	// ICMP works for direct pings but TTL-exceeded replies are unreadable
	// (every TTL probe times out), as with unprivileged Linux ping sockets.
	withEchoer(t, &pathEcho{routers: []string{"", "", "", "", "", "", "", "", ""}, dst: "203.0.113.9", direct: map[string]bool{"192.168.1.1": true, "203.0.113.9": true}}, nil)
	old := Run
	Run = func(ctx context.Context, d time.Duration, name string, args ...string) (string, error) {
		return "traceroute to 203.0.113.9, 30 hops max\n 1  192.168.1.1  0.9 ms\n 2  * \n 3  203.0.113.9  11.2 ms\n", nil
	}
	defer func() { Run = old }()
	r := Trace(context.Background(), "203.0.113.9", RouteOpts{Rounds: 3, Interval: time.Millisecond})
	if r.Method != "icmp+system" || !r.Reached || len(r.Hops) != 3 || r.Note == "" {
		t.Fatalf("got %+v", r)
	}
	if r.Hops[0].Sent != 3 || r.Hops[0].LossPct != 0 {
		t.Errorf("hop 1 should be pinged directly each round: %+v", r.Hops[0])
	}
	if r.Hops[1].Sent != 1 || r.Hops[1].IP != "" {
		t.Errorf("silent hop should not be probed again: %+v", r.Hops[1])
	}
}

func TestTraceWithoutICMPUsesSingleSystemPass(t *testing.T) {
	withEchoer(t, nil, ErrNoICMP)
	old := Run
	Run = func(ctx context.Context, d time.Duration, name string, args ...string) (string, error) {
		return "  1    <1 ms    <1 ms    <1 ms  192.168.1.1\r\n  2     *        *        *     Request timed out.\r\n  3    12 ms    11 ms    13 ms  203.0.113.9\r\n\r\nTrace complete.\r\n", nil
	}
	defer func() { Run = old }()
	r := Trace(context.Background(), "203.0.113.9", RouteOpts{Rounds: 5})
	if r.Method != "system" || len(r.Hops) != 3 || r.Hops[0].LastMs != 0.5 || r.Note == "" {
		t.Fatalf("got %+v", r)
	}
}

func TestTraceNothingWorks(t *testing.T) {
	withEchoer(t, nil, ErrNoICMP)
	old := Run
	Run = func(ctx context.Context, d time.Duration, name string, args ...string) (string, error) {
		return "", context.DeadlineExceeded
	}
	defer func() { Run = old }()
	if r := Trace(context.Background(), "203.0.113.9", RouteOpts{Rounds: 1}); r.Error == "" {
		t.Fatalf("expected a clear error, got %+v", r)
	}
}

func TestFirstHops(t *testing.T) {
	withEchoer(t, &pathEcho{routers: []string{"192.168.1.1", "100.64.0.1", "84.1.1.1"}, dst: "127.0.0.1"}, nil)
	got := FirstHops(context.Background(), "127.0.0.1", 2)
	if len(got) != 2 || got[0].String() != "192.168.1.1" || got[1].String() != "100.64.0.1" {
		t.Fatalf("got %v", got)
	}
	if n := NATFromHops(ip("192.168.1.1"), got); n.Kind != "cgnat" {
		t.Fatalf("route hops should feed NAT detection, got %+v", n)
	}
}

// burstEcho behaves like a real Windows Wi-Fi link: when TTL probes
// overlap, every reply in the burst comes back about 10 ms late.
type burstEcho struct {
	pathEcho
	cmu               sync.Mutex
	inFlight, maxSeen int
}

func (b *burstEcho) Echo(dst net.IP, o EchoOpts) (EchoReply, error) {
	if o.TTL == 0 {
		return b.pathEcho.Echo(dst, o)
	}
	b.cmu.Lock()
	b.inFlight++
	b.maxSeen = max(b.maxSeen, b.inFlight)
	b.cmu.Unlock()
	time.Sleep(2 * time.Millisecond)
	b.cmu.Lock()
	burst := b.maxSeen > 1
	b.inFlight--
	b.cmu.Unlock()
	r, err := b.pathEcho.Echo(dst, o)
	if burst && r.Kind != EchoTimeout {
		r.RTT += 10 * time.Millisecond
	}
	return r, err
}

func TestTraceRoundsDontBurstTTLProbes(t *testing.T) {
	// The path from a real Windows 11 trace to 1.1.1.1 (public hops replaced).
	e := &burstEcho{pathEcho: pathEcho{routers: []string{"192.168.0.1", "198.51.100.121", "198.51.100.241", "203.0.113.163", "203.0.113.5", "203.0.113.20", "203.0.113.12"}, dst: "127.0.0.1"}}
	withEchoer(t, e, nil)
	r := Trace(context.Background(), "127.0.0.1", RouteOpts{Rounds: 3, Interval: time.Millisecond})
	if len(r.Hops) != 8 || !r.Reached {
		t.Fatalf("got %+v", r)
	}
	if e.maxSeen > 1 {
		t.Errorf("%d TTL probes were in flight at once", e.maxSeen)
	}
	for _, h := range r.Hops {
		if want := float64(h.TTL * 3); h.AvgMs != want {
			t.Errorf("hop %d avg %.0f ms, want %.0f", h.TTL, h.AvgMs, want)
		}
	}
}
