package adv

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Some tools send many requests to a target (port checks across a range,
// say). Those are free on your own networks; anything public needs
// --authorized, which states you're allowed to test it, and is paced.

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// Own reports whether ip is on a network that's normally your own:
// private, loopback, link-local or carrier-grade NAT space.
func Own(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip)
}

// resolve is a test seam for looking up a target's addresses.
var resolve = func(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	var out []net.IP
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, err
}

// CheckScope refuses targets outside your own networks unless authorized
// is set. A name is judged by every address it resolves to.
func CheckScope(ctx context.Context, targets []Target, authorized bool) error {
	if authorized {
		return nil
	}
	var public []string
	for _, t := range targets {
		ips := []net.IP{t.IP()}
		if ips[0] == nil {
			var err error
			if ips, err = resolve(ctx, t.Host); err != nil {
				return fmt.Errorf("couldn't look up %s: %w", t.Host, err)
			}
		}
		for _, ip := range ips {
			if !Own(ip) {
				public = append(public, t.Host)
				break
			}
		}
	}
	if len(public) == 0 {
		return nil
	}
	if len(public) > 3 {
		public = append(public[:3], fmt.Sprintf("and %d more", len(public)-3))
	}
	return fmt.Errorf("%s isn't on your own network. Only test machines you're allowed to; add --authorized to confirm you are", strings.Join(public, ", "))
}

// GentleRate is the default pace for public targets: requests per second.
const GentleRate = 10

// Pacer spaces requests evenly at a fixed rate.
type Pacer struct {
	mu    sync.Mutex
	every time.Duration
	next  time.Time
	now   func() time.Time
	sleep func(context.Context, time.Duration)
}

// NewPacer allows perSecond requests a second (0 or less: no limit).
func NewPacer(perSecond int) *Pacer {
	p := &Pacer{now: time.Now, sleep: sleepCtx}
	if perSecond > 0 {
		p.every = time.Second / time.Duration(perSecond)
	}
	return p
}

// Wait blocks until the next request may go, or ctx ends.
func (p *Pacer) Wait(ctx context.Context) error {
	if p.every == 0 {
		return ctx.Err()
	}
	p.mu.Lock()
	now := p.now()
	at := p.next
	if at.Before(now) {
		at = now
	}
	p.next = at.Add(p.every)
	p.mu.Unlock()
	p.sleep(ctx, at.Sub(now))
	return ctx.Err()
}

func sleepCtx(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
