package cli

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/ui"
)

func TestWakeTarget(t *testing.T) {
	store := &deviceStore{Networks: map[string]*knownNetwork{"router aa": {Devices: map[string]*knownDevice{
		"00:11:22:33:44:55": {IP: "192.168.0.50", MAC: "00:11:22:33:44:55", Name: "Office-PC"},
		"00:11:22:33:44:66": {IP: "192.168.0.51", MAC: "00:11:22:33:44:66", Name: "Office-Laptop"},
		"00:11:22:33:44:77": {IP: "192.168.0.52", MAC: "00:11:22:33:44:77", Name: "nas"},
	}}}}
	if mac, name, ip, err := wakeTarget("NAS", store); err != nil || mac.String() != "00:11:22:33:44:77" || name != "nas" || ip != "192.168.0.52" {
		t.Errorf("by name: %v %q %q %v", mac, name, ip, err)
	}
	if mac, _, ip, err := wakeTarget("192.168.0.50", store); err != nil || mac.String() != "00:11:22:33:44:55" || ip != "192.168.0.50" {
		t.Errorf("by address: %v %q %v", mac, ip, err)
	}
	if _, _, ip, err := wakeTarget("00-11-22-33-44-66", store); err != nil || ip != "192.168.0.51" {
		t.Errorf("a MAC finds its address for --wait: %q %v", ip, err)
	}
	if _, _, _, err := wakeTarget("office", store); err == nil || !strings.Contains(err.Error(), "several devices") {
		t.Errorf("ambiguous: %v", err)
	}
	if _, _, _, err := wakeTarget("printer", store); err == nil {
		t.Error("unknown name")
	}
	if mac, _, _, err := wakeTarget("00:11:22:33:44:99", nil); err != nil || mac == nil {
		t.Errorf("a MAC needs no store: %v", err)
	}
}

func TestGreeting(t *testing.T) {
	if g := greeting("10.0.0.2", 8080, "hello\n"); !strings.HasPrefix(g, "netcheck: you reached 10.0.0.2 on port 8080") {
		t.Errorf("plain: %q", g)
	}
	if g := greeting("10.0.0.2", 8080, "GET / HTTP/1.1\r\n"); !strings.HasPrefix(g, "HTTP/1.1 200 OK\r\n") || !strings.Contains(g, "Content-Length:") {
		t.Errorf("http: %q", g)
	}
	if p := printable("a\x00b\x1bc\r\n"); p != "a.b.c" {
		t.Errorf("printable: %q", p)
	}
}

// TestOpenAndConnect runs open's server and connect's exchange against each
// other on loopback, over TCP and UDP.
func TestOpenAndConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var hits []openHit
	go serveOpen(ctx, ln, "127.0.0.1", 1234, func(h openHit) { mu.Lock(); hits = append(hits, h); mu.Unlock() })

	in := connectInfo{Target: ln.Addr().String(), Proto: "tcp"}
	c, err := openConn(context.Background(), &in, ln.Addr().String(), false, false, false, "")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	exchange(c, []byte("hello there\n"), time.Second, &out, &in)
	c.Close()
	if !strings.Contains(out.String(), "you reached 127.0.0.1 on port 1234") || in.Sent != 12 || in.Closed != "remote" {
		t.Errorf("tcp: %q %+v", out.String(), in)
	}
	st, msg, _ := connectVerdict(in)
	if st != ui.OK || !strings.Contains(msg, "it said: netcheck: you reached") {
		t.Errorf("verdict: %q", msg)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serveOpenUDP(ctx, pc, "127.0.0.1", 1234, func(h openHit) { mu.Lock(); hits = append(hits, h); mu.Unlock() })
	u := connectInfo{Target: pc.LocalAddr().String(), Proto: "udp"}
	uc, err := openConn(context.Background(), &u, pc.LocalAddr().String(), true, false, false, "")
	if err != nil {
		t.Fatal(err)
	}
	exchange(uc, []byte("ping\n"), 500*time.Millisecond, nil, &u)
	uc.Close()
	if !strings.Contains(u.Received, "you reached") {
		t.Errorf("udp: %+v", u)
	}
	cancel()
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(hits) != 2 || hits[0].First != "hello there" || hits[1].Proto != "udp" || hits[1].First != "ping" {
		t.Errorf("hits: %+v", hits)
	}
}

func TestConnectHelpers(t *testing.T) {
	if !isText([]byte("220 hello\r\n\tok")) || isText([]byte{0x16, 0x03, 0x01}) {
		t.Error("isText")
	}
	d := hexDump([]byte("ABCDEFGHIJKLMNOP\x00\x01"))
	if !strings.Contains(d, "0000  41 42 43 44 45 46 47 48  49 4a") || !strings.Contains(d, "|ABCDEFGHIJKLMNOP|") || !strings.Contains(d, "0010  00 01") {
		t.Errorf("hex dump:\n%s", d)
	}
	if !strings.Contains(hexDump(make([]byte, 600)), "... 88 more bytes") {
		t.Error("long dumps are cut at 512")
	}
	in := connectInfo{Target: "x:1", Proto: "tcp", Received: "\x16\x03\x01\x00"}
	if _, msg, _ := connectVerdict(in); !strings.Contains(msg, "4 bytes of binary data") {
		t.Errorf("binary: %q", msg)
	}
	if st, msg, notes := connectVerdict(connectInfo{Target: "x:53", Proto: "udp", Sent: 9}); st != ui.OK || !strings.Contains(msg, "no answer came back") || len(notes) != 1 {
		t.Errorf("udp silence: %q %v", msg, notes)
	}
	if st, msg, _ := connectVerdict(connectInfo{Error: "connection refused: nothing listens on x:1"}); st != ui.Bad || !strings.HasPrefix(msg, "Couldn't connect") {
		t.Errorf("error: %q", msg)
	}
	if _, msg, _ := connectVerdict(connectInfo{Target: "x:1", Proto: "tcp", Received: strings.Repeat("y", 200)}); strings.HasSuffix(msg, "….") {
		t.Errorf("no dot after the ellipsis: %q", msg)
	}
}
