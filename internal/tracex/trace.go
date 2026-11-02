// Package tracex traces the route to a host over ICMP, UDP or TCP, and
// names the network that owns each hop.
package tracex

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
)

// Hop is one router on the way, or the destination.
type Hop struct {
	TTL     int       `json:"ttl"`
	IP      string    `json:"ip,omitempty"` // empty: no answer at this distance
	Name    string    `json:"name,omitempty"`
	ASN     int       `json:"asn,omitempty"`
	Owner   string    `json:"owner,omitempty"`
	Prefix  string    `json:"prefix,omitempty"`
	RTTs    []float64 `json:"rtt_ms"` // one per probe; -1 = no answer
	Reached bool      `json:"reached,omitempty"`
	Note    string    `json:"note,omitempty"` // "unreachable" when a router refused to pass the probe on
}

// Answered is how many probes came back.
func (h Hop) Answered() int {
	n := 0
	for _, r := range h.RTTs {
		if r >= 0 {
			n++
		}
	}
	return n
}

// Best and Avg are over the probes that came back.
func (h Hop) Best() float64 {
	b := -1.0
	for _, r := range h.RTTs {
		if r >= 0 && (b < 0 || r < b) {
			b = r
		}
	}
	return b
}

func (h Hop) Avg() float64 {
	s, n := 0.0, 0
	for _, r := range h.RTTs {
		if r >= 0 {
			s += r
			n++
		}
	}
	if n == 0 {
		return -1
	}
	return s / float64(n)
}

// Result is a traced route.
type Result struct {
	Target    string `json:"target"`
	Addr      string `json:"addr,omitempty"`
	Proto     string `json:"proto"`
	Port      int    `json:"port,omitempty"`
	Method    string `json:"method,omitempty"` // how the hops were heard: "icmp", "raw", "recverr", "system"
	Hops      []Hop  `json:"hops"`
	Reached   bool   `json:"reached"`
	PortState string `json:"port_state,omitempty"` // TCP: "open" or "closed" when reached
	Note      string `json:"note,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Options shape a trace.
type Options struct {
	Proto   string // "icmp" (default), "udp", "tcp"
	Port    int    // UDP default 33434, TCP default 443
	MaxHops int    // default 30
	Probes  int    // per hop, default 3
	Timeout time.Duration
	NoNames bool // skip reverse names and owners
}

// ErrPrivileged: hearing routers' replies to UDP or TCP probes needs a raw
// socket here.
var ErrPrivileged = errors.New("needs a raw socket")

// prober sends one probe with a given TTL and says who answered.
type prober interface {
	probe(ctx context.Context, ttl int) reply
	close()
}

type reply struct {
	from    net.IP
	rtt     time.Duration
	reached bool   // the destination itself answered
	state   string // TCP: "open" or "closed"
	unreach bool   // a router said the destination can't be reached
	ok      bool   // anything came back
}

// Test seams.
var (
	resolveHost = func(ctx context.Context, host string) (net.IP, error) {
		if ip := net.ParseIP(host); ip != nil {
			return ip, nil
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if err != nil {
			return nil, err
		}
		return ips[0], nil
	}
	newProber  = platformProber
	icmpTrace  = probe.Trace
	silentStop = 6 // consecutive silent hops before giving up
)

// privilegeHint says how to get a raw socket on this system.
func privilegeHint(proto string) string {
	switch runtime.GOOS {
	case "windows":
		return strings.ToUpper(proto) + " traces need a terminal opened as administrator on Windows (to hear the routers' replies); the default ICMP trace works without"
	case "linux":
		return "TCP traces need root (sudo) on Linux; UDP and the default ICMP trace work without"
	}
	return strings.ToUpper(proto) + " traces need root (sudo) here; the default ICMP trace works without"
}

// Trace follows the route to host.
func Trace(ctx context.Context, host string, o Options) Result {
	if o.Proto == "" {
		o.Proto = "icmp"
	}
	if o.MaxHops <= 0 {
		o.MaxHops = 30
	}
	if o.Probes <= 0 {
		o.Probes = 3
	}
	if o.Timeout <= 0 {
		o.Timeout = 1500 * time.Millisecond
	}
	if o.Port == 0 {
		o.Port = map[string]int{"udp": 33434, "tcp": 443}[o.Proto]
	}
	r := Result{Target: host, Proto: o.Proto}
	if o.Proto != "icmp" {
		r.Port = o.Port
	}
	dst, err := resolveHost(ctx, host)
	if err != nil {
		var dns *net.DNSError
		if errors.As(err, &dns) && dns.IsNotFound {
			r.Error = host + " doesn't exist"
		} else {
			r.Error = "couldn't look up " + host
		}
		return r
	}
	if dst.To4() == nil {
		r.Error = "tracing supports IPv4 destinations only"
		return r
	}
	r.Addr = dst.String()

	if o.Proto == "icmp" {
		rr := icmpTrace(ctx, r.Addr, probe.RouteOpts{MaxHops: o.MaxHops, Rounds: o.Probes, Interval: 200 * time.Millisecond})
		r.Method, r.Reached, r.Note, r.Error = rr.Method, rr.Reached, rr.Note, rr.Error
		for _, h := range rr.Hops {
			x := Hop{TTL: h.TTL, IP: h.IP, RTTs: append([]float64(nil), h.SamplesMs...)}
			x.Reached = r.Reached && h.IP == r.Addr
			r.Hops = append(r.Hops, x)
		}
	} else {
		p, method, err := newProber(o.Proto, dst, o.Port, o.Timeout)
		if err != nil {
			if errors.Is(err, ErrPrivileged) {
				r.Error = privilegeHint(o.Proto)
			} else {
				r.Error = err.Error()
			}
			return r
		}
		defer p.close()
		r.Method = method
		walk(ctx, p, o, &r)
	}
	if !o.NoNames {
		enrich(ctx, r.Hops)
	}
	return r
}

// walk probes TTL 1, 2, 3... until the destination answers. The probes of
// one TTL go out together; TTLs go one after another, since a burst over
// many TTLs made every hop look slower on a real Wi-Fi link.
func walk(ctx context.Context, p prober, o Options, r *Result) {
	silent := 0
	for ttl := 1; ttl <= o.MaxHops && ctx.Err() == nil; ttl++ {
		h := Hop{TTL: ttl, RTTs: make([]float64, o.Probes)}
		replies := make([]reply, o.Probes)
		var wg sync.WaitGroup
		for i := 0; i < o.Probes; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Stagger slightly so the probes aren't one burst.
				time.Sleep(time.Duration(i) * 20 * time.Millisecond)
				replies[i] = p.probe(ctx, ttl)
			}()
		}
		wg.Wait()
		for i, rep := range replies {
			h.RTTs[i] = -1
			if !rep.ok {
				continue
			}
			h.RTTs[i] = float64(rep.rtt.Microseconds()) / 1000
			if h.IP == "" && rep.from != nil {
				h.IP = rep.from.String()
			}
			if rep.reached {
				h.Reached = true
				if rep.state != "" {
					r.PortState = rep.state
				}
			}
			if rep.unreach {
				h.Note = "unreachable"
			}
		}
		if h.Reached && h.IP == "" {
			h.IP = r.Addr
		}
		r.Hops = append(r.Hops, h)
		switch {
		case h.Reached:
			r.Reached = true
			return
		case h.Note == "unreachable":
			r.Note = fmt.Sprintf("%s said %s can't be reached", h.IP, r.Addr)
			return
		case h.IP == "":
			silent++
			if silent >= silentStop {
				r.Hops = r.Hops[:len(r.Hops)-silent+1]
				r.Note = fmt.Sprintf("no answer from hop %d on; stopped after %d silent hops", ttl-silent+1, silent)
				// The routers may just stay quiet; see whether the
				// destination answers at full distance.
				if rep := p.probe(ctx, 64); rep.ok && rep.reached {
					r.Hops = append(r.Hops, Hop{TTL: 0, IP: r.Addr, RTTs: []float64{float64(rep.rtt.Microseconds()) / 1000}, Reached: true})
					r.Reached, r.PortState = true, rep.state
					r.Note = fmt.Sprintf("the routers after hop %d didn't answer, but the destination did", ttl-silent)
				}
				return
			}
		default:
			silent = 0
		}
	}
}

// --- who owns each hop ---

var (
	lookupTXT  = net.DefaultResolver.LookupTXT
	lookupAddr = net.DefaultResolver.LookupAddr
)

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// Owner is who an address belongs to: its AS number, name and prefix.
type Owner struct {
	ASN    int    `json:"asn,omitempty"`
	Name   string `json:"name,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	CC     string `json:"country,omitempty"`
}

// localOwner names addresses that no AS announces.
func localOwner(ip net.IP) string {
	switch {
	case ip.IsPrivate():
		return "private network"
	case cgnat.Contains(ip):
		return "carrier-grade NAT (your ISP)"
	case ip.IsLoopback(), ip.IsLinkLocalUnicast():
		return "this machine's link"
	}
	return ""
}

// asNames caches AS number → name for one run.
var asNames sync.Map

// LookupOwner asks Team Cymru's IP-to-ASN service over DNS:
// 5.4.3.2.origin.asn.cymru.com TXT "13335 | 1.1.1.0/24 | US | apnic | 2011-08-11",
// then AS13335.asn.cymru.com TXT "13335 | US | apnic | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US".
func LookupOwner(ctx context.Context, ip net.IP) Owner {
	v4 := ip.To4()
	if v4 == nil {
		return Owner{}
	}
	txt, err := lookupTXT(ctx, fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0]))
	if err != nil || len(txt) == 0 {
		return Owner{}
	}
	f := strings.Split(txt[0], "|")
	if len(f) < 3 {
		return Owner{}
	}
	var o Owner
	fmt.Sscan(strings.Fields(strings.TrimSpace(f[0]) + " 0")[0], &o.ASN)
	o.Prefix, o.CC = strings.TrimSpace(f[1]), strings.TrimSpace(f[2])
	if o.ASN == 0 {
		return o
	}
	if n, ok := asNames.Load(o.ASN); ok {
		o.Name = n.(string)
		return o
	}
	if t, err := lookupTXT(ctx, fmt.Sprintf("AS%d.asn.cymru.com", o.ASN)); err == nil && len(t) > 0 {
		if g := strings.Split(t[0], "|"); len(g) >= 5 {
			o.Name = strings.TrimSpace(g[4])
		}
	}
	asNames.Store(o.ASN, o.Name)
	return o
}

// enrich adds reverse names and owners, all hops at once.
func enrich(ctx context.Context, hops []Hop) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := range hops {
		ip := net.ParseIP(hops[i].IP)
		if ip == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if names, err := lookupAddr(ctx, ip.String()); err == nil && len(names) > 0 {
				hops[i].Name = strings.TrimSuffix(names[0], ".")
			}
			if l := localOwner(ip); l != "" {
				hops[i].Owner = l
				return
			}
			o := LookupOwner(ctx, ip)
			hops[i].ASN, hops[i].Owner, hops[i].Prefix = o.ASN, ShortOwner(o.Name), o.Prefix
		}()
	}
	wg.Wait()
}

// ShortOwner trims Cymru's "CLOUDFLARENET - Cloudflare, Inc., US" to
// "Cloudflare, Inc.".
func ShortOwner(s string) string {
	if _, rest, ok := strings.Cut(s, " - "); ok {
		s = rest
	}
	if i := strings.LastIndex(s, ", "); i > 0 && len(s)-i == 4 {
		s = s[:i]
	}
	return s
}

// Jump is the biggest rise in delay between two answering hops.
type Jump struct {
	From, To int     // TTLs
	AddMs    float64 // how much slower the later hop is
}

// BiggestJump finds where along the route the delay grows most, comparing
// each hop's best time (the least disturbed by queues and slow replies).
func BiggestJump(hops []Hop) Jump {
	var j Jump
	prev := -1
	for i, h := range hops {
		if h.Best() < 0 {
			continue
		}
		if prev >= 0 {
			if d := h.Best() - hops[prev].Best(); d > j.AddMs {
				j = Jump{hops[prev].TTL, h.TTL, d}
			}
		}
		prev = i
	}
	return j
}

// Owners lists the networks along the route in order, each once.
func Owners(hops []Hop) []string {
	var out []string
	seen := map[string]bool{}
	for _, h := range hops {
		if h.Owner == "" || seen[h.Owner] {
			continue
		}
		seen[h.Owner] = true
		out = append(out, h.Owner)
	}
	return out
}
