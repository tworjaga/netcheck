package probe

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func freeTCP(t *testing.T) (port int, closeFn func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, func() { l.Close() }
}

func TestPingOpenPort(t *testing.T) {
	port, stop := freeTCP(t)
	defer stop()
	r := Ping(context.Background(), "127.0.0.1", port, 4, 5*time.Millisecond, nil)
	if r.Sent != 4 || r.Received != 4 || r.LossPct != 0 {
		t.Fatalf("got %+v", r)
	}
}

func TestPingRefusedCountsAsReply(t *testing.T) {
	port, stop := freeTCP(t)
	stop() // nothing listening now: the OS answers with a reset
	time.Sleep(20 * time.Millisecond)
	r := Ping(context.Background(), "127.0.0.1", port, 3, 5*time.Millisecond, nil)
	if r.Received != 3 {
		t.Fatalf("refused connections should count as replies, got %+v", r)
	}
}

func TestPingAutoPicksAnsweringPort(t *testing.T) {
	port, stop := freeTCP(t)
	defer stop()
	r := PingAuto(context.Background(), "127.0.0.1", []int{port}, 3, 5*time.Millisecond, nil)
	if r.Received != 3 {
		t.Fatalf("got %+v", r)
	}
}

func TestStats(t *testing.T) {
	r := PingResult{Sent: 4, Received: 3, SamplesMs: []float64{10, 20, -1, 30}}
	r.finish()
	if r.LossPct != 25 || r.MinMs != 10 || r.MaxMs != 30 || r.AvgMs != 20 || r.JitterMs != 10 {
		t.Fatalf("got %+v", r)
	}
}

// fakeDNS answers every A query with 1.2.3.4. Names starting with "nx" get
// NXDOMAIN, unless hijack is set, in which case they get an answer too.
func fakeDNS(t *testing.T, hijack bool) (port string, closeFn func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			if n < 13 {
				continue
			}
			i := 12
			var name strings.Builder
			for i < n && q[i] != 0 {
				l := int(q[i])
				name.Write(q[i+1 : min(i+1+l, n)])
				i += l + 1
			}
			end := i + 5 // zero byte + qtype + qclass
			if end > n {
				continue
			}
			nx := strings.HasPrefix(name.String(), "nx") && !hijack
			resp := append([]byte{}, q[:2]...) // ID
			if nx {
				resp = append(resp, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0)
			} else {
				resp = append(resp, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
			}
			resp = append(resp, q[12:end]...)
			if !nx {
				resp = append(resp, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4)
			}
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port), func() { pc.Close() }
}

func TestDNSHealthy(t *testing.T) {
	port, stop := fakeDNS(t, false)
	defer stop()
	r := CheckResolver(context.Background(), Resolver{Label: "fake", Addr: "127.0.0.1", Port: port}, DefaultNames)
	if r.Answered != len(DefaultNames) || r.RewritesNX || r.Error != "" {
		t.Fatalf("got %+v", r)
	}
}

func TestDNSDetectsNXDOMAINRewrite(t *testing.T) {
	port, stop := fakeDNS(t, true)
	defer stop()
	r := CheckResolver(context.Background(), Resolver{Label: "fake", Addr: "127.0.0.1", Port: port}, DefaultNames)
	if !r.RewritesNX {
		t.Fatalf("expected NXDOMAIN rewrite to be detected, got %+v", r)
	}
}

func TestDNSDeadResolver(t *testing.T) {
	port, stop := fakeDNS(t, false)
	stop() // nothing listening
	time.Sleep(20 * time.Millisecond)
	r := CheckResolver(context.Background(), Resolver{Label: "dead", Addr: "127.0.0.1", Port: port}, DefaultNames)
	if r.Answered != 0 || r.Error == "" {
		t.Fatalf("got %+v", r)
	}
}
