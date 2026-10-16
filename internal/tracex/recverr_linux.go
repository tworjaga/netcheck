package tracex

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"
)

// platformProber: with root, the raw socket; without, UDP can still hear
// the routers through the socket's error queue (IP_RECVERR), the way
// tracepath does. TCP has no such way in.
func platformProber(proto string, dst net.IP, port int, timeout time.Duration) (prober, string, error) {
	p, err := newRawProber(proto, dst, port, timeout)
	switch {
	case err == nil:
		return p, "raw", nil
	case errors.Is(err, ErrPrivileged) && proto == "udp":
		return &recverrProber{dst: dst.To4(), port: port, timeout: timeout}, "recverr", nil
	}
	return nil, "", err
}

type recverrProber struct {
	dst     net.IP
	port    int
	timeout time.Duration
}

func (recverrProber) close() {}

// sock_extended_err (linux/errqueue.h): errno u32, origin u8, type u8,
// code u8, pad u8, info u32, data u32; then the offender's sockaddr_in.
const soEEOriginICMP = 2

func (p *recverrProber) probe(ctx context.Context, ttl int) reply {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return reply{}
	}
	defer syscall.Close(fd)
	if syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl) != nil ||
		syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_RECVERR, 1) != nil {
		return reply{}
	}
	sa := &syscall.SockaddrInet4{Port: p.port}
	copy(sa.Addr[:], p.dst)
	if syscall.Connect(fd, sa) != nil {
		return reply{}
	}
	start := time.Now()
	if _, err := syscall.Write(fd, []byte("netcheck trace")); err != nil {
		return reply{}
	}
	buf, oob := make([]byte, 512), make([]byte, 512)
	deadline := start.Add(p.timeout)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		_, oobn, _, _, err := syscall.Recvmsg(fd, buf, oob, syscall.MSG_ERRQUEUE|syscall.MSG_DONTWAIT)
		if err == nil {
			if r, ok := p.parse(oob[:oobn], start); ok {
				return r
			}
			continue
		}
		// A service that answers the datagram means we got there.
		if n, _, err := syscall.Recvfrom(fd, buf, syscall.MSG_DONTWAIT); err == nil && n >= 0 {
			return reply{from: p.dst, rtt: time.Since(start), reached: true, ok: true}
		}
		time.Sleep(5 * time.Millisecond)
	}
	return reply{}
}

func (p *recverrProber) parse(oob []byte, start time.Time) (reply, bool) {
	at := time.Now()
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return reply{}, false
	}
	for _, m := range msgs {
		if m.Header.Level != syscall.SOL_IP || m.Header.Type != syscall.IP_RECVERR || len(m.Data) < 16+8 {
			continue
		}
		if m.Data[4] != soEEOriginICMP {
			continue
		}
		typ := m.Data[5]
		from := net.IP(append([]byte(nil), m.Data[20:24]...))
		r := reply{from: from, rtt: at.Sub(start), ok: true}
		switch {
		case typ == 3 && from.Equal(p.dst):
			r.reached = true
		case typ == 3:
			r.unreach = true
		case typ != 11:
			continue
		}
		return r, true
	}
	return reply{}, false
}
