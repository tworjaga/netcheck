package probe

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeEcho replies according to a script: positive = RTT in ms, negative = loss.
type fakeEcho struct {
	mu     sync.Mutex // the device sweep pings from many goroutines
	script []float64
	i      int
}

func (f *fakeEcho) Echo(dst net.IP, o EchoOpts) (EchoReply, error) {
	f.mu.Lock()
	v := f.script[f.i%len(f.script)]
	f.i++
	f.mu.Unlock()
	if v < 0 {
		return EchoReply{Kind: EchoTimeout}, nil
	}
	return EchoReply{Kind: EchoOK, From: dst, RTT: time.Duration(v * float64(time.Millisecond))}, nil
}

func withEchoer(t *testing.T, e Echoer, err error) {
	t.Helper()
	old := openEchoer
	openEchoer = func() (Echoer, error) { return e, err }
	t.Cleanup(func() { openEchoer = old })
}

func TestPingBestUsesICMP(t *testing.T) {
	withEchoer(t, &fakeEcho{script: []float64{10, 12, 11, 13}}, nil)
	r := PingBest(context.Background(), "127.0.0.1", []int{1}, 5, time.Millisecond, nil)
	if r.Method != "icmp" || r.Received != 5 || r.Note != "" {
		t.Fatalf("got %+v", r)
	}
}

func TestPingBestCountsLoss(t *testing.T) {
	withEchoer(t, &fakeEcho{script: []float64{5, 5, 5, -1, 5, -1, 5, -1}}, nil)
	r := PingBest(context.Background(), "127.0.0.1", []int{1}, 4, time.Millisecond, nil)
	if r.Method != "icmp" || r.Sent != 4 || r.Received == 4 || r.LossPct == 0 {
		t.Fatalf("expected some loss, got %+v", r)
	}
}

func TestPingBestFallsBackWhenICMPUnavailable(t *testing.T) {
	withEchoer(t, nil, ErrNoICMP)
	port, stop := freeTCP(t)
	defer stop()
	r := PingBest(context.Background(), "127.0.0.1", []int{port}, 3, time.Millisecond, nil)
	if r.Received != 3 || r.Note == "" || r.Method == "icmp" {
		t.Fatalf("expected TCP fallback with a note, got %+v", r)
	}
}

func TestPingBestFallsBackWhenICMPFiltered(t *testing.T) {
	withEchoer(t, &fakeEcho{script: []float64{-1}}, nil)
	port, stop := freeTCP(t)
	defer stop()
	r := PingBest(context.Background(), "127.0.0.1", []int{port}, 3, time.Millisecond, nil)
	if r.Received != 3 || r.Note == "" {
		t.Fatalf("expected TCP fallback when ICMP is filtered, got %+v", r)
	}
}

func TestPingBestStopsOnCancel(t *testing.T) {
	withEchoer(t, &fakeEcho{script: []float64{5}}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	done := make(chan PingResult, 1)
	go func() { done <- PingBest(ctx, "127.0.0.1", []int{1}, 0, 10*time.Millisecond, nil) }()
	select {
	case r := <-done:
		if r.Sent == 0 {
			t.Fatalf("expected some probes before cancel, got %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PingBest did not stop after cancel")
	}
}

func TestEchoPacketChecksum(t *testing.T) {
	p := echoPacket(1, 2, 32)
	if checksum(p) != 0 {
		t.Fatalf("a valid ICMP packet checksums to zero, got %#x", checksum(p))
	}
	if p[0] != 8 || p[7] != 2 {
		t.Fatalf("bad header %v", p[:8])
	}
}
