package dnsx

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Trace resolves a name the way a resolver does, in the open: from the
// root servers down through each referral to an authoritative answer,
// recording who answered at every step and which servers failed.

// NS is one nameserver: its name and an address to ask.
type NS struct {
	Name string `json:"name"`
	Addr string `json:"addr"` // IP, no port
}

// RootServers are the 13 root nameservers' IPv4 addresses.
var RootServers = []NS{
	{"a.root-servers.net.", "198.41.0.4"}, {"b.root-servers.net.", "170.247.170.2"},
	{"c.root-servers.net.", "192.33.4.12"}, {"d.root-servers.net.", "199.7.91.13"},
	{"e.root-servers.net.", "192.203.230.10"}, {"f.root-servers.net.", "192.5.5.241"},
	{"g.root-servers.net.", "192.112.36.4"}, {"h.root-servers.net.", "198.97.190.53"},
	{"i.root-servers.net.", "192.36.148.17"}, {"j.root-servers.net.", "192.58.128.30"},
	{"k.root-servers.net.", "193.0.14.129"}, {"l.root-servers.net.", "199.7.83.42"},
	{"m.root-servers.net.", "202.12.27.33"},
}

// Lame is a nameserver that should have answered for a zone and didn't.
type Lame struct {
	Zone   string `json:"zone"`
	Server NS     `json:"server"`
	Why    string `json:"why"`
}

// TraceStep is one level of the walk: the zone asked, the server that
// answered, and where it pointed next (or the answer).
type TraceStep struct {
	Zone      string        `json:"zone"`
	Server    NS            `json:"server"`
	RTT       time.Duration `json:"rtt_ns"`
	Rcode     string        `json:"rcode"`
	Next      string        `json:"next_zone,omitempty"`    // the delegated zone
	NextNS    []NS          `json:"next_servers,omitempty"` // its nameservers
	NoGlue    bool          `json:"no_glue,omitempty"`      // their addresses had to be looked up
	Answer    []RR          `json:"answer,omitempty"`
	Authority bool          `json:"authoritative"`
	Disagree  []string      `json:"disagree,omitempty"` // with --all: servers whose answer differed
	Varies    []string      `json:"varies,omitempty"`   // with --all: servers that gave only different addresses
}

// TraceResult is the whole walk.
type TraceResult struct {
	Name   string        `json:"name"`
	Type   string        `json:"type"`
	Steps  []TraceStep   `json:"steps"`
	Lame   []Lame        `json:"lame,omitempty"`
	Final  string        `json:"final"` // "answer", "cname", "nxdomain", "nodata", "failed"
	Answer []RR          `json:"answer,omitempty"`
	Total  time.Duration `json:"total_ns"`
	Error  string        `json:"error,omitempty"`
}

// TraceOptions tune a trace.
type TraceOptions struct {
	All     bool          // ask every nameserver at each level, not just the first that works
	Timeout time.Duration // per query; 0 = 2.5 s
	Tries   int           // servers to try per level before giving up; 0 = 4
}

// Test seams: sending a query, and looking up a nameserver's address when
// the referral didn't include it (no glue).
var (
	traceExchange = Exchange
	lookupNS      = func(ctx context.Context, host string) ([]string, error) {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		var out []string
		for _, a := range addrs {
			if a.IP.To4() != nil {
				out = append(out, a.IP.String())
			}
		}
		if len(out) == 0 && err == nil {
			err = fmt.Errorf("%s has no IPv4 address", host)
		}
		return out, err
	}
)

// inZone reports whether name is zone or below it.
func inZone(name, zone string) bool {
	name, zone = strings.ToLower(Fqdn(name)), strings.ToLower(Fqdn(zone))
	return zone == "." || name == zone || strings.HasSuffix(name, "."+zone)
}

// answerKey is a comparable form of an answer, for --all. With loose set,
// A and AAAA addresses are left out: load-balanced and geo DNS hand out
// different ones by design. A referral's NS records count; the NS records
// some servers add beside an answer don't.
func answerKey(m *Msg, loose bool) string {
	seen := map[string]bool{}
	var parts []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			parts = append(parts, p)
		}
	}
	for _, rr := range m.Answer {
		if loose && (rr.Type == TypeA || rr.Type == TypeAAAA) {
			add(rr.TypeName() + " " + strings.ToLower(rr.Name))
			continue
		}
		add(rr.TypeName() + " " + strings.ToLower(rr.Name) + " " + strings.ToLower(rr.Data))
	}
	if len(m.Answer) == 0 {
		for _, rr := range m.Authority {
			if rr.Type == TypeNS {
				add("NS " + strings.ToLower(rr.Data))
			}
		}
	}
	sort.Strings(parts)
	return RcodeString(m.Rcode) + "|" + strings.Join(parts, ",")
}

type nsReply struct {
	ns  NS
	res *Result
	err error
}

// askLevel asks a zone's servers: in order until one answers usefully, or
// all of them at once with all set. Unusable replies are reported as lame.
func askLevel(ctx context.Context, zone string, servers []NS, q Query, o TraceOptions) (nsReply, []nsReply, []Lame) {
	usable := func(r nsReply) (bool, string) {
		switch {
		case r.err != nil:
			return false, r.err.Error()
		case r.res.Msg.Rcode == RcodeRefused:
			return false, "refused to answer for the zone"
		case r.res.Msg.Rcode == RcodeServFail:
			return false, "answered SERVFAIL"
		case r.res.Msg.Rcode == RcodeNotImp || r.res.Msg.Rcode == RcodeFormErr:
			return false, "answered " + RcodeString(r.res.Msg.Rcode)
		case zone != "." && !r.res.Msg.AA && len(r.res.Msg.Answer) > 0:
			return false, "answered without authority (lame)"
		}
		return true, ""
	}
	ask := func(ns NS) nsReply {
		res, err := traceExchange(ctx, Server{Addr: net.JoinHostPort(ns.Addr, "53"), Transport: UDP}, q, o.Timeout)
		return nsReply{ns, res, err}
	}
	var replies []nsReply
	if o.All {
		replies = make([]nsReply, len(servers))
		var wg sync.WaitGroup
		for i, ns := range servers {
			wg.Add(1)
			go func() { defer wg.Done(); replies[i] = ask(ns) }()
		}
		wg.Wait()
	} else {
		for i, ns := range servers {
			if i >= o.Tries || ctx.Err() != nil {
				break
			}
			r := ask(ns)
			replies = append(replies, r)
			if ok, _ := usable(r); ok {
				break
			}
		}
	}
	var best nsReply
	var good []nsReply
	var lame []Lame
	for _, r := range replies {
		if ok, why := usable(r); ok {
			if best.res == nil {
				best = r
			}
			good = append(good, r)
		} else {
			lame = append(lame, Lame{Zone: zone, Server: r.ns, Why: why})
		}
	}
	return best, good, lame
}

// Trace walks from the root to name's answer of type t.
func Trace(ctx context.Context, name string, t uint16, o TraceOptions) (res TraceResult) {
	if o.Timeout == 0 {
		o.Timeout = 2500 * time.Millisecond
	}
	if o.Tries == 0 {
		o.Tries = 4
	}
	name = Fqdn(name)
	res = TraceResult{Name: name, Type: TypeString(t)}
	start := time.Now()
	defer func() { res.Total = time.Since(start) }()
	zone, servers := ".", RootServers
	q := Query{Name: name, Type: t, NoEDNS: false}

	for depth := 0; depth < 32 && ctx.Err() == nil; depth++ {
		best, good, lame := askLevel(ctx, zone, servers, q, o)
		for _, l := range lame {
			// A root server that doesn't answer is a path problem near
			// the asker, not a broken delegation anyone could fix.
			if zone != "." || best.res == nil {
				res.Lame = append(res.Lame, l)
			}
		}
		if best.res == nil {
			res.Final, res.Error = "failed", fmt.Sprintf("none of the nameservers for %s answered", zone)
			return res
		}
		m := best.res.Msg
		step := TraceStep{Zone: zone, Server: best.ns, RTT: best.res.RTT, Rcode: RcodeString(m.Rcode), Authority: m.AA}
		if o.All && len(good) > 1 {
			for _, g := range good[1:] {
				switch {
				case answerKey(g.res.Msg, true) != answerKey(m, true):
					step.Disagree = append(step.Disagree, g.ns.Name)
				case answerKey(g.res.Msg, false) != answerKey(m, false):
					step.Varies = append(step.Varies, g.ns.Name)
				}
			}
		}
		switch {
		case m.Rcode == RcodeNXDomain:
			res.Steps, res.Final = append(res.Steps, step), "nxdomain"
			return res
		case len(m.Answer) > 0:
			step.Answer, res.Answer = m.Answer, m.Answer
			res.Final = "answer"
			if !hasType(m.Answer, t) && hasType(m.Answer, TypeCNAME) {
				res.Final = "cname"
			}
			res.Steps = append(res.Steps, step)
			return res
		}
		// A referral: NS records for a zone between this one and the name.
		next, nsNames := "", []string{}
		for _, rr := range m.Authority {
			if rr.Type == TypeNS {
				if next == "" {
					next = rr.Name
				}
				if strings.EqualFold(rr.Name, next) {
					nsNames = append(nsNames, rr.Data)
				}
			}
		}
		if next == "" {
			res.Steps, res.Final = append(res.Steps, step), "nodata"
			return res
		}
		if !inZone(next, zone) || !inZone(name, next) || strings.EqualFold(next, zone) {
			res.Steps = append(res.Steps, step)
			res.Final, res.Error = "failed", fmt.Sprintf("%s (%s) pointed to %s, which isn't on the way to %s", best.ns.Name, zone, next, name)
			return res
		}
		glue := map[string][]string{}
		for _, rr := range m.Additional {
			if rr.Type == TypeA {
				glue[strings.ToLower(rr.Name)] = append(glue[strings.ToLower(rr.Name)], rr.Data)
			}
		}
		var nextServers []NS
		for _, n := range nsNames {
			addrs := glue[strings.ToLower(n)]
			if len(addrs) == 0 {
				step.NoGlue = true
				looked, err := lookupNS(ctx, n)
				if err != nil {
					res.Lame = append(res.Lame, Lame{Zone: next, Server: NS{Name: n}, Why: "its address couldn't be found: " + err.Error()})
					continue
				}
				addrs = looked
			}
			for _, a := range addrs {
				nextServers = append(nextServers, NS{Name: n, Addr: a})
				break // one address per server keeps the walk quick
			}
		}
		step.Next, step.NextNS = next, nextServers
		res.Steps = append(res.Steps, step)
		if len(nextServers) == 0 {
			res.Final, res.Error = "failed", fmt.Sprintf("no usable nameserver address for %s", next)
			return res
		}
		zone, servers = next, nextServers
	}
	res.Final = "failed"
	if res.Error == "" {
		res.Error = "too many referrals"
		if ctx.Err() != nil {
			res.Error = "interrupted"
		}
	}
	return res
}

func hasType(rrs []RR, t uint16) bool {
	for _, rr := range rrs {
		if rr.Type == t {
			return true
		}
	}
	return false
}
