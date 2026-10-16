package dnsx

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Propagate compares what a name's own nameservers say with what public
// resolvers have cached, to show whether a change has spread.

// PublicResolver is a well-known open resolver.
type PublicResolver struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
}

// PublicResolvers are asked by Propagate. They're anycast: each answers from
// its site nearest the asker, so this shows what users near you see.
var PublicResolvers = []PublicResolver{
	{"Cloudflare", "1.1.1.1"}, {"Google", "8.8.8.8"}, {"Quad9", "9.9.9.9"},
	{"OpenDNS", "208.67.222.222"}, {"AdGuard", "94.140.14.14"}, {"CleanBrowsing", "185.228.168.9"},
	{"Control D", "76.76.2.0"}, {"DNS.SB", "185.222.222.222"}, {"Comodo", "8.26.56.26"},
	{"Yandex", "77.88.8.8"},
}

// PropState is how one source compares with the expected answer.
type PropState string

const (
	PropUpdated PropState = "updated" // has the expected answer
	PropStale   PropState = "stale"   // has something else cached
	PropMissing PropState = "missing" // says the name or record doesn't exist
	PropFailed  PropState = "failed"  // didn't answer
)

// PropAnswer is one source's answer.
type PropAnswer struct {
	Source string        `json:"source"`
	Addr   string        `json:"addr"`
	Values []string      `json:"values"`
	TTL    uint32        `json:"ttl"` // for a resolver: seconds until its cached copy expires
	Rcode  string        `json:"rcode,omitempty"`
	RTT    time.Duration `json:"rtt_ns"`
	State  PropState     `json:"state"`
	Error  string        `json:"error,omitempty"`
}

// PropResult is the comparison.
type PropResult struct {
	Name          string       `json:"name"`
	Type          string       `json:"type"`
	Zone          string       `json:"zone"`
	Expected      []string     `json:"expected"`
	ExpectedFrom  string       `json:"expected_from"` // "nameservers" or "you"
	AuthAgree     bool         `json:"nameservers_agree"`
	Authoritative []PropAnswer `json:"nameservers"`
	Public        []PropAnswer `json:"resolvers"`
	Error         string       `json:"error,omitempty"`
}

// Counts tallies the public resolvers by state, and the longest remaining
// cache time among the stale ones.
func (p PropResult) Counts() (updated, stale, missing, failed int, wait time.Duration) {
	for _, a := range p.Public {
		switch a.State {
		case PropUpdated:
			updated++
		case PropStale, PropMissing:
			if a.State == PropStale {
				stale++
			} else {
				missing++
			}
			wait = max(wait, time.Duration(a.TTL)*time.Second)
		default:
			failed++
		}
	}
	return
}

// values is the sorted, lower-cased data of the records of type t.
func values(m *Msg, t uint16) ([]string, uint32) {
	var out []string
	ttl := uint32(0)
	for _, rr := range m.Answer {
		if rr.Type == t {
			out = append(out, strings.ToLower(rr.Data))
			if ttl == 0 || rr.TTL < ttl {
				ttl = rr.TTL
			}
		}
	}
	sort.Strings(out)
	return out, ttl
}

// negativeTTL is how long a "doesn't exist" answer is cached: the SOA's
// TTL in the authority section, capped by its minimum field.
func negativeTTL(m *Msg) uint32 {
	for _, rr := range m.Authority {
		if rr.Type == TypeSOA {
			return rr.TTL
		}
	}
	return 0
}

func same(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// propExchange is a test seam.
var propExchange = Exchange

func askSource(ctx context.Context, source, addr string, q Query, t uint16) PropAnswer {
	a := PropAnswer{Source: source, Addr: addr}
	r, err := propExchange(ctx, Server{Addr: net.JoinHostPort(addr, "53"), Transport: UDP}, q, 3*time.Second)
	if err != nil {
		a.State, a.Error = PropFailed, err.Error()
		return a
	}
	a.RTT, a.Rcode = r.RTT, RcodeString(r.Msg.Rcode)
	switch r.Msg.Rcode {
	case RcodeSuccess:
		a.Values, a.TTL = values(r.Msg, t)
		if len(a.Values) == 0 {
			a.TTL = negativeTTL(r.Msg)
		}
	case RcodeNXDomain:
		a.TTL = negativeTTL(r.Msg)
	default:
		a.State, a.Error = PropFailed, "answered "+a.Rcode
	}
	return a
}

// Propagate asks the name's authoritative nameservers (found by a trace)
// and the public resolvers. expect, when given, is the answer to look for;
// otherwise it's what the nameservers say.
func Propagate(ctx context.Context, name string, t uint16, expect []string) PropResult {
	name = Fqdn(name)
	p := PropResult{Name: name, Type: TypeString(t)}
	tr := Trace(ctx, name, t, TraceOptions{})
	// The authoritative servers are those of the last zone delegated on the
	// way down.
	var auth []NS
	for _, s := range tr.Steps {
		if len(s.NextNS) > 0 {
			auth, p.Zone = s.NextNS, s.Next
		}
	}
	if len(auth) == 0 {
		p.Error = "couldn't find the nameservers for " + strings.TrimSuffix(name, ".")
		if tr.Final == "nxdomain" {
			p.Error = strings.TrimSuffix(name, ".") + " doesn't exist"
		} else if tr.Error != "" {
			p.Error += ": " + tr.Error
		}
		return p
	}

	var wg sync.WaitGroup
	p.Authoritative = make([]PropAnswer, len(auth))
	for i, ns := range auth {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Authoritative[i] = askSource(ctx, ns.Name, ns.Addr, Query{Name: name, Type: t}, t)
		}()
	}
	p.Public = make([]PropAnswer, len(PublicResolvers))
	for i, r := range PublicResolvers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Public[i] = askSource(ctx, r.Name, r.Addr, Query{Name: name, Type: t, Recursion: true}, t)
		}()
	}
	wg.Wait()

	// What counts as "updated": the given value, else the nameservers'.
	p.AuthAgree = true
	var ref []string
	refSet := false
	for _, a := range p.Authoritative {
		if a.State == PropFailed {
			continue
		}
		if !refSet {
			ref, refSet = a.Values, true
		} else if !same(ref, a.Values) {
			p.AuthAgree = false
		}
	}
	p.Expected, p.ExpectedFrom = ref, "nameservers"
	if len(expect) > 0 {
		for i := range expect {
			expect[i] = strings.ToLower(strings.TrimSpace(expect[i]))
		}
		sort.Strings(expect)
		p.Expected, p.ExpectedFrom = expect, "you"
	}
	judge := func(a *PropAnswer) {
		if a.State == PropFailed {
			return
		}
		switch {
		case same(a.Values, p.Expected):
			a.State = PropUpdated
		case len(a.Values) == 0:
			a.State = PropMissing
		default:
			a.State = PropStale
		}
	}
	for i := range p.Authoritative {
		judge(&p.Authoritative[i])
	}
	for i := range p.Public {
		judge(&p.Public[i])
	}
	return p
}
