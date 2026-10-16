package probe

import (
	"context"
	"net"
	"time"
)

// IPv6Result describes whether IPv6 works here and whether it's used.
type IPv6Result struct {
	Address   string  `json:"address,omitempty"` // a global IPv6 address on this machine
	Reachable bool    `json:"reachable"`         // an IPv6-only host answered
	V6Ms      float64 `json:"v6_ms,omitempty"`   // TCP connect time over IPv6
	V4Ms      float64 `json:"v4_ms,omitempty"`   // the same over IPv4, for comparison
	DNSAAAA   bool    `json:"dns_aaaa"`          // the resolver returns IPv6 addresses
	Preferred bool    `json:"preferred"`         // the OS lists IPv6 first for dual-stack names
	Target    string  `json:"target,omitempty"`  // which IPv6 host answered
	Error     string  `json:"error,omitempty"`
}

// Test seams.
var (
	tcpConnect = func(ctx context.Context, addr string, timeout time.Duration) (float64, bool) {
		rtt, ok := probeTCP(ctx, addr, timeout)
		return float64(rtt.Microseconds()) / 1000, ok
	}
	lookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return net.DefaultResolver.LookupIPAddr(ctx, host)
	}
	globalV6 = func() net.IP {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return nil
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() == nil && n.IP.IsGlobalUnicast() && !isULA(n.IP) {
				return n.IP
			}
		}
		return nil
	}
)

// isULA reports fc00::/7, which is private and can't reach the internet.
func isULA(ip net.IP) bool { return len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc }

// Well-known anycast DNS servers, reached on 443 because that port is
// almost never filtered.
var (
	v6Targets = []string{"[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443"}
	v4Target  = "1.1.1.1:443"
	dualStack = "www.cloudflare.com"
)

// medianConnect takes the median of three connects; ok if any succeeded.
func medianConnect(ctx context.Context, addr string) (float64, bool) {
	var ms []float64
	for i := 0; i < 3 && ctx.Err() == nil; i++ {
		if v, ok := tcpConnect(ctx, addr, 2*time.Second); ok {
			ms = append(ms, v)
		} else if i == 0 {
			return 0, false // don't wait out three timeouts on a dead path
		}
	}
	if len(ms) == 0 {
		return 0, false
	}
	return median(ms), true
}

// CheckIPv6 tests IPv6 connectivity, DNS, and whether the OS prefers it.
func CheckIPv6(ctx context.Context) IPv6Result {
	var r IPv6Result
	if ip := globalV6(); ip != nil {
		r.Address = ip.String()
	}
	for _, t := range v6Targets {
		if ms, ok := medianConnect(ctx, t); ok {
			r.Reachable, r.V6Ms, r.Target = true, ms, t
			break
		}
	}
	if ms, ok := medianConnect(ctx, v4Target); ok {
		r.V4Ms = ms
	}
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := lookupIPAddr(c, dualStack)
	if err != nil {
		r.Error = "DNS lookup failed"
		return r
	}
	for i, a := range addrs {
		if a.IP.To4() == nil {
			r.DNSAAAA = true
			r.Preferred = i == 0
			break
		}
	}
	return r
}
