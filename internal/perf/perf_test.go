package perf

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func startServer(t *testing.T, once bool) (string, *[]Result, chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var logged []Result
	s := &Server{Log: func(_ string, r Result) { mu.Lock(); logged = append(logged, r); mu.Unlock() }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln, once) }()
	t.Cleanup(func() { cancel(); <-done })
	return ln.Addr().String(), &logged, done
}

func TestTCPBothWays(t *testing.T) {
	addr, logged, _ := startServer(t, false)
	ticks := 0
	down := Run(context.Background(), addr, Request{Test: TCPDown, Streams: 2, Duration: 700 * time.Millisecond}, func(float64) { ticks++ })
	if down.Error != "" || down.Bytes == 0 || down.Mbps <= 0 || down.Streams != 2 || ticks == 0 || len(down.Samples) == 0 {
		t.Fatalf("down: %+v ticks %d", down, ticks)
	}
	if down.Elapsed < 400*time.Millisecond || down.Elapsed > 3*time.Second {
		t.Errorf("down took %v", down.Elapsed)
	}
	up := Run(context.Background(), addr, Request{Test: TCPUp, Streams: 3, Duration: 700 * time.Millisecond}, nil)
	if up.Error != "" || up.Bytes == 0 || up.Mbps <= 0 || up.Streams != 3 {
		t.Fatalf("up: %+v", up)
	}
	time.Sleep(100 * time.Millisecond)
	if len(*logged) != 2 || (*logged)[0].Test != TCPDown || (*logged)[0].Bytes != down.Bytes {
		t.Errorf("server log: %+v", *logged)
	}
}

func TestUDP(t *testing.T) {
	addr, _, _ := startServer(t, false)
	r := Run(context.Background(), addr, Request{Test: UDP, Duration: 600 * time.Millisecond, Rate: 4_000_000, Size: 1000}, nil)
	if r.Error != "" || r.UDP == nil {
		t.Fatalf("%+v", r)
	}
	// 4 Mbit/s of 1000-byte packets is 500 a second: about 300 in 0.6 s.
	if r.UDP.Sent < 200 || r.UDP.Sent > 400 || r.UDP.Received == 0 || r.UDP.LossPct > 20 {
		t.Errorf("udp: %+v", r.UDP)
	}
	if r.Mbps < 1 || r.Mbps > 8 {
		t.Errorf("rate %v Mbit/s, asked for 4", r.Mbps)
	}
}

func TestOnceAndRefusals(t *testing.T) {
	addr, _, done := startServer(t, true)
	// Not the last test: the server keeps going.
	if r := Run(context.Background(), addr, Request{Test: TCPDown, Streams: 1, Duration: 300 * time.Millisecond}, nil); r.Error != "" {
		t.Fatal(r.Error)
	}
	select {
	case <-done:
		t.Fatal("--once stopped before the client's last test")
	case <-time.After(300 * time.Millisecond):
	}
	if r := Run(context.Background(), addr, Request{Test: TCPUp, Streams: 1, Duration: 300 * time.Millisecond, Last: true}, nil); r.Error != "" {
		t.Fatal(r.Error)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
		done <- nil // for the cleanup
	case <-time.After(3 * time.Second):
		t.Error("--once keeps serving")
	}
	r := Run(context.Background(), addr, Request{Test: TCPDown, Streams: 1, Duration: time.Second}, nil)
	if !strings.Contains(r.Error, "nothing listens") {
		t.Errorf("stopped server: %q", r.Error)
	}

	// Something else on the port: an HTTP server, say.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			c.Close()
		}
	}()
	if r := Run(context.Background(), ln.Addr().String(), Request{Test: TCPDown, Streams: 1, Duration: time.Second}, nil); !strings.Contains(r.Error, "isn't a netcheck perf server") {
		t.Errorf("not netcheck: %q", r.Error)
	}
	addr2, _, _ := startServer(t, false)
	if r := Run(context.Background(), addr2, Request{Test: "nope", Streams: 1, Duration: time.Second}, nil); !strings.Contains(r.Error, "unknown test") {
		t.Errorf("bad test: %q", r.Error)
	}
}

func TestServerIgnoresStrangers(t *testing.T) {
	addr, logged, _ := startServer(t, false)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := c.Read(make([]byte, 10)); n != 0 {
		t.Error("a stranger got an answer")
	}
	c.Close()
	// A data stream for a session that doesn't exist is dropped too.
	d, _ := net.Dial("tcp", addr)
	d.Write([]byte(magic + " DATA 0123456789abcdef 0\n"))
	d.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := d.Read(make([]byte, 10)); n != 0 {
		t.Error("unknown session served")
	}
	d.Close()
	if len(*logged) != 0 {
		t.Errorf("nothing to log: %+v", *logged)
	}
}

func TestUDPCounter(t *testing.T) {
	var c udpCounter
	pkt := func(seq uint64, sentNs int64) []byte {
		b := make([]byte, 100)
		binary.BigEndian.PutUint64(b, seq)
		binary.BigEndian.PutUint64(b[8:], uint64(sentNs))
		return b
	}
	base := time.Unix(1000, 0)
	// Transit 10 ms, 12 ms, then seq 1 arrives after 3 (reordered), 10 ms.
	c.packet(pkt(0, base.UnixNano()), base.Add(10*time.Millisecond))
	c.packet(pkt(2, base.Add(20*time.Millisecond).UnixNano()), base.Add(32*time.Millisecond))
	c.packet(pkt(1, base.Add(10*time.Millisecond).UnixNano()), base.Add(36*time.Millisecond))
	s := c.stats(4)
	if s.Received != 3 || s.Lost != 1 || s.LossPct != 25 || s.OutOfOrder != 1 || s.JitterMs <= 0 || s.JitterMs > 5 {
		t.Errorf("%+v", s)
	}
}
