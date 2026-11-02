package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/dnsx"
	"github.com/tworjaga/netcheck/internal/ui"
)

func traceOf(final string) dnsx.TraceResult {
	ns := dnsx.NS{Name: "ns1.example.com.", Addr: "192.0.2.20"}
	return dnsx.TraceResult{Name: "www.example.com.", Type: "A", Final: final, Total: 90 * time.Millisecond,
		Steps: []dnsx.TraceStep{
			{Zone: ".", Server: dnsx.RootServers[0], Next: "com.", NextNS: []dnsx.NS{{Name: "a.gtld-servers.net."}}},
			{Zone: "com.", Server: dnsx.NS{Name: "a.gtld-servers.net."}, Next: "example.com.", NextNS: []dnsx.NS{ns}},
			{Zone: "example.com.", Server: ns, Rcode: "NOERROR"},
		}}
}

func TestTraceVerdict(t *testing.T) {
	r := traceOf("answer")
	r.Answer = []dnsx.RR{{Name: "www.example.com.", Type: dnsx.TypeA, Data: "192.0.2.1"}}
	if st, msg, _ := traceVerdict(r); st != ui.OK || !strings.Contains(msg, "3 steps") || !strings.Contains(msg, "90 ms") {
		t.Errorf("answer: %v %s", st, msg)
	}
	r.Lame = []dnsx.Lame{{Zone: "example.com.", Server: dnsx.NS{Name: "ns2.example.com."}, Why: "refused to answer for the zone"}}
	if st, msg, notes := traceVerdict(r); st != ui.Warn || !strings.Contains(msg, "1 nameserver") || !strings.Contains(strings.Join(notes, " "), "ns2.example.com (for example.com.) refused") {
		t.Errorf("lame: %v %s %v", st, msg, notes)
	}
	r.Lame = nil
	r.Steps[2].Varies = []string{"ns2.example.com."}
	if st, _, notes := traceVerdict(r); st != ui.OK || !strings.Contains(strings.Join(notes, " "), "load-balanced") {
		t.Errorf("only addresses vary: %v %v", st, notes)
	}
	r.Steps[2].Disagree = []string{"ns2.example.com."}
	if st, msg, _ := traceVerdict(r); st != ui.Warn || !strings.Contains(msg, "don't all agree") {
		t.Errorf("disagree: %v %s", st, msg)
	}

	r = traceOf("cname")
	r.Answer = []dnsx.RR{{Name: "www.example.com.", Type: dnsx.TypeCNAME, Data: "cdn.example.net."}}
	if _, msg, _ := traceVerdict(r); !strings.Contains(msg, "alias for cdn.example.net;") {
		t.Errorf("cname: %s", msg)
	}
	r = traceOf("nxdomain")
	if st, msg, _ := traceVerdict(r); st != ui.Warn || !strings.Contains(msg, "says ns1.example.com for example.com.") || strings.Contains(msg, "..") {
		t.Errorf("nxdomain: %v %s", st, msg)
	}
	r = traceOf("failed")
	r.Error = "none of the nameservers for example.com. answered"
	if st, msg, _ := traceVerdict(r); st != ui.Bad || !strings.Contains(msg, "none of the nameservers") {
		t.Errorf("failed: %v %s", st, msg)
	}
}

func TestTraceTableFitsNarrow(t *testing.T) {
	r := traceOf("answer")
	r.Answer = []dnsx.RR{{Type: dnsx.TypeA}}
	for _, l := range traceTable(r).Lines(78) {
		if strings.Contains(l, "…") {
			t.Errorf("cut off at 78 columns: %q", l)
		}
	}
}

func prop(states ...dnsx.PropState) dnsx.PropResult {
	p := dnsx.PropResult{Name: "www.example.com.", Type: "A", Zone: "example.com.", Expected: []string{"192.0.2.1"}, ExpectedFrom: "nameservers", AuthAgree: true,
		Authoritative: []dnsx.PropAnswer{{Source: "ns1.example.com.", Values: []string{"192.0.2.1"}, TTL: 300, State: dnsx.PropUpdated}}}
	for i, s := range states {
		a := dnsx.PropAnswer{Source: "R" + string(rune('A'+i)), State: s, TTL: uint32(600 * (i + 1))}
		switch s {
		case dnsx.PropUpdated:
			a.Values = []string{"192.0.2.1"}
		case dnsx.PropStale:
			a.Values = []string{"192.0.2.9"}
		case dnsx.PropFailed:
			a.Error = "no answer (timed out)"
		}
		p.Public = append(p.Public, a)
	}
	return p
}

func TestPropVerdict(t *testing.T) {
	if st, msg, _ := propVerdict(prop(dnsx.PropUpdated, dnsx.PropUpdated)); st != ui.OK || !strings.Contains(msg, "Every resolver") {
		t.Errorf("all updated: %v %s", st, msg)
	}
	st, msg, notes := propVerdict(prop(dnsx.PropUpdated, dnsx.PropStale, dnsx.PropMissing, dnsx.PropFailed))
	if st != ui.Warn || !strings.Contains(msg, "1 of 3 resolvers") || !strings.Contains(msg, "2 still have") || !strings.Contains(msg, "within 30 min") {
		t.Errorf("behind: %v %s", st, msg)
	}
	if !strings.Contains(strings.Join(notes, " "), "1 resolver didn't answer") || !strings.Contains(notes[0], "anycast") {
		t.Errorf("notes: %v", notes)
	}
	p := prop(dnsx.PropUpdated)
	p.AuthAgree = false
	p.Authoritative = append(p.Authoritative, dnsx.PropAnswer{Source: "ns2.example.com.", Values: []string{"192.0.2.9"}, State: dnsx.PropStale})
	if st, msg, _ := propVerdict(p); st != ui.Bad || !strings.Contains(msg, "ns2.example.com: 192.0.2.9") {
		t.Errorf("nameservers disagree: %v %s", st, msg)
	}
	p = prop()
	p.Error = "couldn't find the nameservers for nope.invalid."
	if st, _, _ := propVerdict(p); st != ui.Bad {
		t.Errorf("error is bad: %v", st)
	}
	if lines := strings.Join(propLines(prop(dnsx.PropStale)), "\n"); !strings.Contains(lines, "old value · 10 min left") || !strings.Contains(lines, "Nameservers for example.com.") {
		t.Errorf("lines:\n%s", lines)
	}
}
