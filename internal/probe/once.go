package probe

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"
)

// Pinger probes one host, one sample per call. It settles on a method once
// (ICMP if the host answers it, else the first TCP port that answers) so a
// long-running monitor doesn't renegotiate on every tick.
type Pinger struct {
	Host   string
	Addr   string
	Method string // "icmp" or "tcp:<port>"
	echo   Echoer
	dst    net.IP
	tcp    string
}

// ErrNoReply means neither ICMP nor any of the TCP ports answered.
var ErrNoReply = errors.New("no reply to ICMP or TCP")

// NewPinger picks how to probe host. When nothing answers it still returns
// a usable Pinger (ICMP if available, else the first port) together with
// ErrNoReply, so callers can keep measuring a link that is down right now.
func NewPinger(ctx context.Context, host string, ports []int) (*Pinger, error) {
	ip, err := resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	p := &Pinger{Host: host, Addr: ip, dst: net.ParseIP(ip)}
	e, eerr := openEchoer()
	icmpOK := eerr == nil && p.dst.To4() != nil
	if icmpOK && icmpAnswers(ctx, p.dst) {
		p.echo, p.Method = e, "icmp"
		return p, nil
	}
	for _, port := range ports {
		addr := net.JoinHostPort(ip, strconv.Itoa(port))
		for try := 0; try < 2 && ctx.Err() == nil; try++ {
			if _, ok := probeTCP(ctx, addr, 700*time.Millisecond); ok {
				p.tcp, p.Method = addr, "tcp:"+strconv.Itoa(port)
				return p, nil
			}
		}
	}
	switch {
	case icmpOK:
		p.echo, p.Method = e, "icmp"
	case len(ports) > 0:
		p.tcp, p.Method = net.JoinHostPort(ip, strconv.Itoa(ports[0])), "tcp:"+strconv.Itoa(ports[0])
	default:
		return nil, ErrNoReply
	}
	return p, ErrNoReply
}

// Once sends a single probe and returns the round trip in ms, or -1 if it
// was lost. It never blocks longer than timeout.
func (p *Pinger) Once(ctx context.Context, timeout time.Duration) float64 {
	if p.echo != nil {
		r, err := p.echo.Echo(p.dst, EchoOpts{Timeout: timeout})
		if err != nil || r.Kind != EchoOK {
			return -1
		}
		return float64(r.RTT.Microseconds()) / 1000
	}
	rtt, ok := probeTCP(ctx, p.tcp, timeout)
	if !ok {
		return -1
	}
	return float64(rtt.Microseconds()) / 1000
}

// LookupOnce resolves one name against r and returns the time taken in ms,
// or -1 when the server didn't answer. A "no such host" answer counts as an
// answer: the server is up, it just has no record.
//
// When r has no address (the OS resolver, as on Windows, where the system's
// servers can't be read without extra dependencies), the OS cache would
// answer every repeat instantly and hide an outage, so a fresh random name
// is used each time instead of name.
func LookupOnce(ctx context.Context, r Resolver, name string, timeout time.Duration) float64 {
	if r.Addr == "" {
		name = randomName()
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	ips, err := r.resolver().LookupIP(c, "ip4", name)
	el := time.Since(start)
	var de *net.DNSError
	switch {
	case err == nil && len(ips) > 0:
	case errors.As(err, &de) && de.IsNotFound:
	default:
		return -1
	}
	return float64(el.Microseconds()) / 1000
}
