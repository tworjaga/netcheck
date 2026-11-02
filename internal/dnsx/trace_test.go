package dnsx

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// zoneFake is a pretend DNS hierarchy: root → com. → example.com., with
// ns1.example.com (glue) and ns2.other.net (no glue, looked up).
type zoneFake struct {
	ns1Down   bool   // ns1 times out
	ns2       string // "ok", "refused", "differ", "nx"
	final     string // "a", "nxdomain", "cname", "badreferral"
	resolvers map[string]func(q []byte) []byte
}

const (
	gtld = "192.0.2.10"
	ns1  = "192.0.2.20"
	ns2  = "192.0.2.21"
)

func (z *zoneFake) exchange(_ context.Context, srv Server, q Query, _ time.Duration) (*Result, error) {
	host, _, _ := net.SplitHostPort(srv.Addr)
	q.ID = 77
	query, _ := q.Pack()
	var raw []byte
	isRoot := false
	for _, r := range RootServers {
		isRoot = isRoot || r.Addr == host
	}
	switch {
	case isRoot:
		raw = answer(query, 0, [3]int{0, 1, 1}, func(w *wire) {
			w.rr("com", TypeNS, 172800, func(w *wire) { w.name("a.gtld-servers.net") })
			w.rr("a.gtld-servers.net", TypeA, 172800, func(w *wire) { w.b = append(w.b, 192, 0, 2, 10) })
		})
	case host == gtld && z.final == "badreferral":
		raw = answer(query, 0, [3]int{0, 1, 0}, func(w *wire) {
			w.rr("evil.org", TypeNS, 3600, func(w *wire) { w.name("ns.evil.org") })
		})
	case host == gtld:
		raw = answer(query, 0, [3]int{0, 2, 1}, func(w *wire) {
			w.rr("example.com", TypeNS, 172800, func(w *wire) { w.name("ns1.example.com") })
			w.rr("example.com", TypeNS, 172800, func(w *wire) { w.name("ns2.other.net") })
			w.rr("ns1.example.com", TypeA, 172800, func(w *wire) { w.b = append(w.b, 192, 0, 2, 20) })
		})
	case host == ns1 && z.ns1Down:
		return nil, errors.New("no answer (timed out)")
	case host == ns1 || (host == ns2 && z.ns2 != "refused"):
		ip := []byte{203, 0, 113, 5}
		if host == ns2 && z.ns2 == "differ" {
			ip = []byte{203, 0, 113, 99}
		}
		final := z.final
		if host == ns2 && z.ns2 == "nx" {
			final = "nxdomain"
		}
		switch final {
		case "nxdomain":
			raw = answer(query, 0x0400|RcodeNXDomain, [3]int{0, 1, 0}, func(w *wire) {
				w.rr("example.com", TypeSOA, 300, func(w *wire) {
					w.name("ns1.example.com")
					w.name("hostmaster.example.com")
					for i := 0; i < 5; i++ {
						w.u32(300)
					}
				})
			})
		case "cname":
			raw = answer(query, 0x0400, [3]int{1, 0, 0}, func(w *wire) {
				w.rr("www.example.com", TypeCNAME, 300, func(w *wire) { w.name("cdn.example.net") })
			})
		default:
			raw = answer(query, 0x0400, [3]int{1, 0, 0}, func(w *wire) {
				w.rr(q.Name, TypeA, 300, func(w *wire) { w.b = append(w.b, ip...) })
			})
		}
	case host == ns2:
		raw = answer(query, RcodeRefused, [3]int{0, 0, 0}, func(*wire) {})
	case z.resolvers[host] != nil:
		raw = z.resolvers[host](query)
	default:
		return nil, errors.New("no answer (timed out)")
	}
	m, err := Parse(raw)
	return &Result{Msg: m, RTT: 10 * time.Millisecond, Size: len(raw)}, err
}

func useFake(t *testing.T, z *zoneFake) {
	t.Helper()
	oldT, oldP, oldL := traceExchange, propExchange, lookupNS
	traceExchange, propExchange = z.exchange, z.exchange
	lookupNS = func(_ context.Context, host string) ([]string, error) {
		if host == "ns2.other.net." {
			return []string{ns2}, nil
		}
		return nil, errors.New("not found")
	}
	t.Cleanup(func() { traceExchange, propExchange, lookupNS = oldT, oldP, oldL })
}

func TestTraceWalksDelegations(t *testing.T) {
	useFake(t, &zoneFake{ns2: "ok"})
	r := Trace(context.Background(), "www.example.com", TypeA, TraceOptions{})
	if r.Final != "answer" || len(r.Steps) != 3 || len(r.Answer) != 1 || r.Answer[0].Data != "203.0.113.5" {
		t.Fatalf("got %+v", r)
	}
	zones := []string{r.Steps[0].Zone, r.Steps[1].Zone, r.Steps[2].Zone}
	if strings.Join(zones, " ") != ". com. example.com." || r.Steps[1].Next != "example.com." || !r.Steps[2].Authority {
		t.Errorf("steps: %+v", r.Steps)
	}
	if !r.Steps[1].NoGlue || len(r.Steps[1].NextNS) != 2 || r.Steps[1].NextNS[1].Addr != ns2 {
		t.Errorf("ns2 has no glue and is looked up: %+v", r.Steps[1])
	}
	if len(r.Lame) != 0 {
		t.Errorf("no lame servers: %+v", r.Lame)
	}
}

func TestTraceFallsBackAndFlagsLame(t *testing.T) {
	useFake(t, &zoneFake{ns1Down: true, ns2: "ok"})
	r := Trace(context.Background(), "www.example.com", TypeA, TraceOptions{})
	if r.Final != "answer" || r.Steps[2].Server.Addr != ns2 {
		t.Fatalf("ns2 answers when ns1 is down: %+v", r)
	}
	if len(r.Lame) != 1 || r.Lame[0].Server.Name != "ns1.example.com." || !strings.Contains(r.Lame[0].Why, "timed out") || r.Lame[0].Zone != "example.com." {
		t.Errorf("lame: %+v", r.Lame)
	}
	useFake(t, &zoneFake{ns1Down: true, ns2: "refused"})
	r = Trace(context.Background(), "www.example.com", TypeA, TraceOptions{})
	if r.Final != "failed" || len(r.Lame) != 2 || !strings.Contains(r.Error, "example.com.") {
		t.Errorf("both down: %+v", r)
	}
}

func TestTraceAllFindsDisagreement(t *testing.T) {
	useFake(t, &zoneFake{ns2: "differ"})
	r := Trace(context.Background(), "www.example.com", TypeA, TraceOptions{All: true})
	last := r.Steps[len(r.Steps)-1]
	if len(last.Disagree) != 0 || len(last.Varies) != 1 || last.Varies[0] != "ns2.other.net." {
		t.Errorf("ns2 gives a different address, which only varies: %+v", last)
	}
	useFake(t, &zoneFake{ns2: "nx"})
	r = Trace(context.Background(), "www.example.com", TypeA, TraceOptions{All: true})
	last = r.Steps[len(r.Steps)-1]
	if len(last.Disagree) != 1 || last.Disagree[0] != "ns2.other.net." {
		t.Errorf("ns2 says the name doesn't exist, a real disagreement: %+v", last)
	}
}

func TestTraceEndings(t *testing.T) {
	cases := map[string]string{"nxdomain": "nxdomain", "cname": "cname", "badreferral": "failed"}
	for final, want := range cases {
		useFake(t, &zoneFake{ns2: "ok", final: final})
		r := Trace(context.Background(), "www.example.com", TypeA, TraceOptions{})
		if r.Final != want {
			t.Errorf("%s: final %q, want %q (%+v)", final, r.Final, want, r)
		}
		if final == "badreferral" && !strings.Contains(r.Error, "evil.org") {
			t.Errorf("bad referral named: %s", r.Error)
		}
	}
}

func TestPropagate(t *testing.T) {
	resolver := func(ips []byte, ttl uint32, nx bool) func([]byte) []byte {
		return func(q []byte) []byte {
			if nx {
				return answer(q, RcodeNXDomain, [3]int{0, 1, 0}, func(w *wire) {
					w.rr("example.com", TypeSOA, ttl, func(w *wire) {
						w.name("ns1.example.com")
						w.name("hostmaster.example.com")
						for i := 0; i < 5; i++ {
							w.u32(300)
						}
					})
				})
			}
			return answer(q, 0x0080, [3]int{1, 0, 0}, func(w *wire) {
				w.rr("www.example.com", TypeA, ttl, func(w *wire) { w.b = append(w.b, ips...) })
			})
		}
	}
	z := &zoneFake{ns2: "ok", resolvers: map[string]func([]byte) []byte{
		"198.51.100.1": resolver([]byte{203, 0, 113, 5}, 280, false),  // updated
		"198.51.100.2": resolver([]byte{203, 0, 113, 1}, 1200, false), // old value, 20 min left
		"198.51.100.3": resolver(nil, 600, true),                      // cached "doesn't exist"
	}}
	useFake(t, z)
	old := PublicResolvers
	PublicResolvers = []PublicResolver{{"One", "198.51.100.1"}, {"Two", "198.51.100.2"}, {"Three", "198.51.100.3"}, {"Dead", "198.51.100.4"}}
	defer func() { PublicResolvers = old }()

	p := Propagate(context.Background(), "www.example.com", TypeA, nil)
	if p.Error != "" || p.Zone != "example.com." || !p.AuthAgree || len(p.Authoritative) != 2 || strings.Join(p.Expected, ",") != "203.0.113.5" {
		t.Fatalf("got %+v", p)
	}
	states := ""
	for _, a := range p.Public {
		states += string(a.State) + " "
	}
	if states != "updated stale missing failed " {
		t.Errorf("states: %s", states)
	}
	up, stale, missing, failed, wait := p.Counts()
	if up != 1 || stale != 1 || missing != 1 || failed != 1 || wait != 20*time.Minute {
		t.Errorf("counts %d %d %d %d, wait %v", up, stale, missing, failed, wait)
	}

	p = Propagate(context.Background(), "www.example.com", TypeA, []string{"203.0.113.1"})
	if p.ExpectedFrom != "you" || p.Public[1].State != PropUpdated || p.Public[0].State != PropStale || p.Authoritative[0].State != PropStale {
		t.Errorf("--expect compares against the given value: %+v", p.Public)
	}

	useFake(t, &zoneFake{ns2: "differ", resolvers: z.resolvers})
	if p := Propagate(context.Background(), "www.example.com", TypeA, nil); p.AuthAgree {
		t.Error("the nameservers disagree")
	}
}
