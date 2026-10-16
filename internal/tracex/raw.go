package tracex

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// rawProber sends ordinary UDP datagrams or TCP connection attempts with a
// short TTL, and hears the routers' "time exceeded" replies on a raw ICMP
// socket (which needs administrator or root rights). Each probe has its own
// source port; an ICMP error quotes the start of the packet it's about, so
// the port matches the reply to the probe.
type rawProber struct {
	conn    net.PacketConn
	proto   string
	dst     net.IP
	port    int
	timeout time.Duration

	mu      sync.Mutex
	waiters map[int]chan icmpHit
}

type icmpHit struct {
	from      net.IP
	typ, code byte
	at        time.Time
}

// listenICMP opens the raw socket. Windows wants it bound to the address
// the packets go out from.
var listenICMP = func(dst net.IP) (net.PacketConn, error) {
	addr := "0.0.0.0"
	if runtime.GOOS == "windows" {
		c, err := net.Dial("udp4", net.JoinHostPort(dst.String(), "9"))
		if err != nil {
			return nil, err
		}
		addr = c.LocalAddr().(*net.UDPAddr).IP.String()
		c.Close()
	}
	return net.ListenPacket("ip4:icmp", addr)
}

func isPermission(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) ||
		strings.Contains(strings.ToLower(err.Error()), "access") || strings.Contains(err.Error(), "permission")
}

func newRawProber(proto string, dst net.IP, port int, timeout time.Duration) (*rawProber, error) {
	c, err := listenICMP(dst)
	if err != nil {
		if isPermission(err) {
			return nil, ErrPrivileged
		}
		return nil, err
	}
	p := &rawProber{conn: c, proto: proto, dst: dst.To4(), port: port, timeout: timeout, waiters: map[int]chan icmpHit{}}
	go p.read()
	return p, nil
}

func (p *rawProber) close() { p.conn.Close() }

// parseICMP reads an ICMP error about one of our probes: who sent it, its
// type and code, and the quoted packet's protocol, destination and source
// port. Some systems hand over the IPv4 header too; it's skipped.
func parseICMP(b []byte) (typ, code, proto byte, dst net.IP, sport int, ok bool) {
	if len(b) > 0 && b[0]>>4 == 4 {
		ihl := int(b[0]&0x0f) * 4
		if len(b) < ihl {
			return
		}
		b = b[ihl:]
	}
	if len(b) < 8+20+4 || (b[0] != 11 && b[0] != 3) {
		return
	}
	inner := b[8:]
	if inner[0]>>4 != 4 {
		return
	}
	ihl := int(inner[0]&0x0f) * 4
	if len(inner) < ihl+4 {
		return
	}
	return b[0], b[1], inner[9], net.IP(append([]byte(nil), inner[16:20]...)), int(binary.BigEndian.Uint16(inner[ihl:])), true
}

func (p *rawProber) read() {
	buf := make([]byte, 1500)
	want := map[string]byte{"udp": 17, "tcp": 6}[p.proto]
	for {
		n, from, err := p.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		at := time.Now()
		typ, code, proto, dst, sport, ok := parseICMP(buf[:n])
		if !ok || proto != want || !dst.Equal(p.dst) {
			continue
		}
		p.mu.Lock()
		ch := p.waiters[sport]
		p.mu.Unlock()
		if ch != nil {
			var ip net.IP
			if a, ok := from.(*net.IPAddr); ok {
				ip = a.IP
			}
			select {
			case ch <- icmpHit{ip, typ, code, at}:
			default:
			}
		}
	}
}

// register claims a free source port for one probe.
func (p *rawProber) register() (int, chan icmpHit) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		port := 33000 + rand.Intn(28000)
		if p.waiters[port] == nil {
			ch := make(chan icmpHit, 1)
			p.waiters[port] = ch
			return port, ch
		}
	}
}

func (p *rawProber) unregister(port int) {
	p.mu.Lock()
	delete(p.waiters, port)
	p.mu.Unlock()
}

func (p *rawProber) probe(ctx context.Context, ttl int) reply {
	for try := 0; try < 3; try++ {
		sport, hits := p.register()
		r, again := p.send(ctx, ttl, sport, hits)
		p.unregister(sport)
		if !again {
			return r
		}
	}
	return reply{}
}

// send makes one attempt; again means the source port was taken.
func (p *rawProber) send(ctx context.Context, ttl, sport int, hits chan icmpHit) (reply, bool) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	target := net.JoinHostPort(p.dst.String(), strconv.Itoa(p.port))
	start := time.Now()
	type outcome struct {
		err error
		at  time.Time
	}
	done := make(chan outcome, 1)
	switch p.proto {
	case "udp":
		d := net.Dialer{LocalAddr: &net.UDPAddr{Port: sport}, Control: ttlControl(ttl)}
		c, err := d.DialContext(ctx, "udp4", target)
		if err != nil {
			return reply{}, isAddrInUse(err)
		}
		defer c.Close()
		start = time.Now()
		if _, err := c.Write([]byte("netcheck trace")); err != nil {
			return reply{}, false
		}
		go func() {
			// A service that answers the datagram means we got there.
			c.SetReadDeadline(time.Now().Add(p.timeout))
			b := make([]byte, 512)
			if _, err := c.Read(b); err == nil {
				done <- outcome{nil, time.Now()}
			}
		}()
	case "tcp":
		d := net.Dialer{LocalAddr: &net.TCPAddr{Port: sport}, Control: ttlControl(ttl)}
		go func() {
			c, err := d.DialContext(ctx, "tcp4", target)
			if err == nil {
				c.Close()
			}
			done <- outcome{err, time.Now()}
		}()
	}
	select {
	case h := <-hits:
		r := reply{from: h.from, rtt: h.at.Sub(start), ok: true}
		switch {
		case h.typ == 3 && h.from.Equal(p.dst):
			r.reached = true
		case h.typ == 3:
			r.unreach = true
		}
		return r, false
	case o := <-done:
		switch {
		case o.err == nil && p.proto == "tcp":
			return reply{from: p.dst, rtt: o.at.Sub(start), reached: true, state: "open", ok: true}, false
		case o.err == nil:
			return reply{from: p.dst, rtt: o.at.Sub(start), reached: true, ok: true}, false
		case errors.Is(o.err, syscall.ECONNREFUSED) || strings.Contains(o.err.Error(), "refused"):
			return reply{from: p.dst, rtt: o.at.Sub(start), reached: true, state: "closed", ok: true}, false
		case isAddrInUse(o.err):
			return reply{}, true
		}
		// The connection attempt gave up; an ICMP reply may still be on its way.
		select {
		case h := <-hits:
			return reply{from: h.from, rtt: h.at.Sub(start), ok: true, unreach: h.typ == 3 && !h.from.Equal(p.dst), reached: h.typ == 3 && h.from.Equal(p.dst)}, false
		case <-ctx.Done():
		}
	case <-ctx.Done():
	}
	return reply{}, false
}

func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || strings.Contains(err.Error(), "address already in use") || strings.Contains(err.Error(), "Only one usage")
}
