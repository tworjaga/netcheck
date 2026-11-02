// Package domain audits a domain's public setup: its nameservers, SOA,
// DNSSEC chain, CAA, mail records, blocklist listings and web certificate.
// Every check ends in a status, a sentence and, when something's wrong, the
// fix. Nothing here changes anything; it only asks.
package domain

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tworjaga/netcheck/internal/dnsx"
)

// Status of one check.
type Status string

const (
	OK   Status = "ok"
	Warn Status = "warn"
	Bad  Status = "bad"
	Info Status = "info" // worth knowing, not a problem
)

// Areas, in the order they're shown.
const (
	AreaNS     = "Nameservers"
	AreaSOA    = "SOA"
	AreaDNSSEC = "DNSSEC"
	AreaCAA    = "CAA"
	AreaMail   = "Mail"
	AreaBL     = "Blocklists"
	AreaWeb    = "Web certificate"
)

// Areas lists every area in display order.
var Areas = []string{AreaNS, AreaSOA, AreaDNSSEC, AreaCAA, AreaMail, AreaBL, AreaWeb}

// Check is one finding.
type Check struct {
	Area   string `json:"area"`
	Status Status `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

// Nameserver is what one of the zone's nameservers said.
type Nameserver struct {
	Name   string        `json:"name"`
	Addr   string        `json:"addr"`
	Serial uint32        `json:"serial,omitempty"`
	RTT    time.Duration `json:"rtt_ns,omitempty"`
	Error  string        `json:"error,omitempty"`
}

// MXHost is one mail server.
type MXHost struct {
	Pref  int      `json:"preference"`
	Host  string   `json:"host"`
	Addrs []string `json:"addrs"`
}

// Report is the whole audit.
type Report struct {
	Domain      string        `json:"domain"`
	Asked       string        `json:"asked,omitempty"` // the name given, when it wasn't the zone itself
	Nameservers []Nameserver  `json:"nameservers"`
	MX          []MXHost      `json:"mx"`
	Checks      []Check       `json:"checks"`
	Score       int           `json:"score"`
	Grade       string        `json:"grade"`
	CertDays    int           `json:"cert_days"` // fewest days left on a web certificate; -1 = none checked
	Took        time.Duration `json:"took_ns"`
	Error       string        `json:"error,omitempty"`
}

// Count tallies the checks by status.
func (r Report) Count() (ok, warn, bad int) {
	for _, c := range r.Checks {
		switch c.Status {
		case OK:
			ok++
		case Warn:
			warn++
		case Bad:
			bad++
		}
	}
	return
}

// Test seams.
var (
	exchange = dnsx.Exchange
	trace    = dnsx.Trace
	// resolvers answer the ordinary lookups. Both validate DNSSEC, so their
	// AD bit says whether the chain holds.
	resolvers = []string{"1.1.1.1", "8.8.8.8"}
	now       = time.Now
)

const queryTimeout = 3 * time.Second

// ask sends a recursive query to the resolvers, the second if the first
// doesn't answer.
func ask(ctx context.Context, name string, t uint16, dnssec bool) (*dnsx.Msg, error) {
	var err error
	for _, r := range resolvers {
		var res *dnsx.Result
		res, err = exchange(ctx, dnsx.Server{Addr: net.JoinHostPort(r, "53"), Transport: dnsx.UDP}, dnsx.Query{Name: dnsx.Fqdn(name), Type: t, Recursion: true, DNSSEC: dnssec}, queryTimeout)
		if err == nil {
			return res.Msg, nil
		}
	}
	return nil, err
}

// askNS sends a non-recursive query to one nameserver.
func askNS(ctx context.Context, addr, name string, t uint16, dnssec bool) (*dnsx.Result, error) {
	return exchange(ctx, dnsx.Server{Addr: net.JoinHostPort(addr, "53"), Transport: dnsx.UDP}, dnsx.Query{Name: dnsx.Fqdn(name), Type: t, DNSSEC: dnssec}, queryTimeout)
}

func ofType(rrs []dnsx.RR, t uint16) []dnsx.RR {
	var out []dnsx.RR
	for _, rr := range rrs {
		if rr.Type == t {
			out = append(out, rr)
		}
	}
	return out
}

func trim(name string) string { return strings.TrimSuffix(name, ".") }

func names(ns []string) string {
	out := make([]string, len(ns))
	for i, n := range ns {
		out[i] = trim(n)
	}
	return strings.Join(out, ", ")
}

// Audit checks a domain. A name inside a zone (www.example.com) is audited
// as that zone.
func Audit(ctx context.Context, name string) Report {
	start := now()
	name = strings.ToLower(dnsx.Fqdn(strings.TrimSpace(name)))
	r := Report{Domain: trim(name), CertDays: -1}
	defer func() { r.Took = now().Sub(start) }()

	tr := trace(ctx, name, dnsx.TypeSOA, dnsx.TraceOptions{})
	var parent []dnsx.NS
	zone := ""
	for _, s := range tr.Steps {
		if len(s.NextNS) > 0 {
			parent, zone = s.NextNS, s.Next
		}
	}
	if tr.Final == "nxdomain" && (zone == "" || !strings.EqualFold(zone, name)) {
		r.Error = trim(name) + " doesn't exist"
		return r
	}
	if zone == "" {
		r.Error = "couldn't find the nameservers for " + trim(name)
		if tr.Error != "" {
			r.Error += ": " + tr.Error
		}
		return r
	}
	zone = strings.ToLower(zone)
	if zone != name {
		r.Asked, r.Domain = trim(name), trim(zone)
	}
	// Nameservers the delegation named but whose address couldn't be found.
	var noAddr []string
	for _, l := range tr.Lame {
		if strings.EqualFold(l.Zone, zone) && l.Server.Addr == "" {
			noAddr = append(noAddr, l.Server.Name)
		}
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	add := func(cs []Check) {
		mu.Lock()
		r.Checks = append(r.Checks, cs...)
		mu.Unlock()
	}
	run := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	run(func() {
		ns, cs := nameservers(ctx, zone, parent, noAddr)
		mu.Lock()
		r.Nameservers = ns
		mu.Unlock()
		add(cs)
	})
	run(func() { add(dnssec(ctx, zone, parent)) })
	run(func() { add(caa(ctx, zone)) })
	run(func() {
		mx, cs := mail(ctx, zone)
		mu.Lock()
		r.MX = mx
		mu.Unlock()
		add(cs)
		add(blocklists(ctx, zone, mx))
	})
	run(func() {
		days, cs := web(ctx, zone)
		mu.Lock()
		r.CertDays = days
		mu.Unlock()
		add(cs)
	})
	wg.Wait()

	order := map[string]int{}
	for i, a := range Areas {
		order[a] = i
	}
	sort.SliceStable(r.Checks, func(i, j int) bool { return order[r.Checks[i].Area] < order[r.Checks[j].Area] })
	signed := false
	for _, c := range r.Checks {
		signed = signed || c.Area == AreaDNSSEC && c.Status == OK && strings.HasPrefix(c.Title, "Signed")
	}
	r.Score, r.Grade = grade(r.Checks, signed)
	return r
}

// grade turns the checks into a score out of 100 and a letter. Any real
// problem caps the grade at C; A+ needs a clean sheet and best, the one
// thing beyond the basics each tool asks for (DNSSEC for a domain,
// enforced MTA-STS for mail).
// Grade scores checks the way the domain audit does, for the other
// graded audits (site).
func Grade(cs []Check, best bool) (int, string) { return grade(cs, best) }

func grade(cs []Check, best bool) (int, string) {
	score, bad, warn := 100, 0, 0
	for _, c := range cs {
		switch c.Status {
		case Bad:
			score -= 20
			bad++
		case Warn:
			score -= 7
			warn++
		}
	}
	score = max(score, 0)
	g := "F"
	for _, s := range []struct {
		min int
		g   string
	}{{90, "A"}, {85, "A-"}, {75, "B"}, {65, "C"}, {50, "D"}, {35, "E"}} {
		if score >= s.min {
			g = s.g
			break
		}
	}
	if bad == 0 && warn == 0 && best {
		g = "A+"
	}
	if bad > 0 && (g == "A" || g == "A-" || g == "B") {
		g = "C"
	}
	return score, g
}
