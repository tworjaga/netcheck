package cli

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/dnsx"
	"github.com/tworjaga/netcheck/internal/ui"
)

func TestDigArgs(t *testing.T) {
	names, qt, srv, err := digArgs([]string{"@1.1.1.1", "example.com", "mx"})
	if err != nil || len(names) != 1 || names[0] != "example.com" || qt != dnsx.TypeMX || srv != "1.1.1.1" {
		t.Errorf("any order: %v %d %q %v", names, qt, srv, err)
	}
	if _, _, _, err := digArgs([]string{"example.com", "MAILX"}); err == nil || !strings.Contains(err.Error(), "isn't a record type") {
		t.Errorf("unknown type: %v", err)
	}
	if names, qt, _, _ := digArgs([]string{"example.com"}); qt != 0 || len(names) != 1 {
		t.Errorf("type is optional")
	}
}

func digResult(rcode int, ad bool, answers ...dnsx.RR) *dnsx.Result {
	return &dnsx.Result{Msg: &dnsx.Msg{Rcode: rcode, AD: ad, Answer: answers}, RTT: 18 * time.Millisecond, Size: 120}
}

func TestDigOutcome(t *testing.T) {
	a := dnsx.RR{Name: "example.com.", Type: dnsx.TypeA, TTL: 300, Data: "192.0.2.1"}
	cname := dnsx.RR{Name: "www.example.com.", Type: dnsx.TypeCNAME, TTL: 60, Data: "example.com."}
	sig := dnsx.RR{Name: "example.com.", Type: dnsx.TypeRRSIG, TTL: 300}
	cases := []struct {
		name string
		r    *dnsx.Result
		err  error
		st   ui.Status
		has  string
	}{
		{"answer", digResult(0, false, a, a), nil, ui.OK, "has 2 A records."},
		{"validated, with a signature that isn't an alias", digResult(0, true, a, sig), nil, ui.OK, "has 1 A record. The answer is DNSSEC-validated."},
		{"through an alias", digResult(0, false, cname, a), nil, ui.OK, "by way of an alias (CNAME)"},
		{"no data", digResult(0, false), nil, ui.Skip, "exists but has no A records"},
		{"nxdomain", digResult(dnsx.RcodeNXDomain, false), nil, ui.Warn, "doesn't exist (NXDOMAIN)"},
		{"servfail", digResult(dnsx.RcodeServFail, false), nil, ui.Bad, "--cd asks without validation"},
		{"refused", digResult(dnsx.RcodeRefused, false), nil, ui.Bad, "refused"},
		{"no answer", nil, errors.New("no answer (timed out)"), ui.Bad, "didn't answer"},
	}
	for _, c := range cases {
		st, msg, vals := digOutcome("example.com", dnsx.TypeA, c.r, c.err)
		if st != c.st || !strings.Contains(msg, c.has) {
			t.Errorf("%s: got %v %q", c.name, st, msg)
		}
		if c.err == nil && (vals["time"] != 18 || vals["answers"] != float64(len(c.r.Msg.Answer))) {
			t.Errorf("%s: measurements %v", c.name, vals)
		}
		if c.err != nil && vals != nil {
			t.Errorf("%s: a failed query has nothing for --fail-on to judge", c.name)
		}
	}
	_, _, vals := digOutcome("example.com", dnsx.TypeA, digResult(0, false, cname, a), nil)
	if vals["ttl"] != 60*1000 {
		t.Errorf("ttl is the lowest TTL, in ms: %v", vals["ttl"])
	}
}

func TestRecordLines(t *testing.T) {
	lines := recordLines([]dnsx.RR{
		{Name: "example.com.", Type: dnsx.TypeMX, TTL: 3600, Data: "10 mail.example.com."},
		{Name: "a-much-longer-name.example.com.", Type: dnsx.TypeA, TTL: 60, Data: "192.0.2.1"},
	}, false)
	// TTLs are right-aligned: "3600" and "60" end in the same column.
	end := func(l, ttl string) int { return ui.VisWidth(l[:strings.Index(l, " "+ttl+" ")+1+len(ttl)]) }
	if len(lines) != 2 || end(lines[0], "3600") != end(lines[1], "60") {
		t.Errorf("columns line up:\n%s", strings.Join(lines, "\n"))
	}
}
