package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/portx"
	"github.com/tworjaga/netcheck/internal/ui"
)

func layers(st ...portx.Status) portx.Report {
	names := []string{portx.LayerListen, portx.LayerFirewall, portx.LayerRouter, portx.LayerInternet, portx.LayerOutside}
	r := portx.Report{Port: 8080, Proto: "tcp"}
	for i, s := range st {
		r.Layers = append(r.Layers, portx.Layer{Name: names[i], Status: s, Title: names[i] + " title", Fix: names[i] + " fix"})
	}
	return r
}

func TestPortVerdict(t *testing.T) {
	r := layers(portx.OK, portx.Bad, portx.OK, portx.Bad, portx.Unknown)
	r.Layers[1].Title = "No Windows Firewall rule lets TCP 8080 in"
	st, msg, fixes := portVerdict(r)
	if st != ui.Bad || msg != "TCP 8080 can't be reached: no Windows Firewall rule lets TCP 8080 in." || fixes[0] != "Firewall fix" || !strings.HasPrefix(fixes[1], "Then: Internet title") {
		t.Errorf("%v %q %v", st, msg, fixes)
	}
	if st, msg, _ := portVerdict(layers(portx.OK, portx.OK, portx.OK, portx.OK, portx.OK)); st != ui.OK || !strings.Contains(msg, "reachable from the internet") {
		t.Errorf("all ok: %q", msg)
	}
	if st, msg, notes := portVerdict(layers(portx.OK, portx.OK, portx.Warn, portx.OK, portx.Unknown)); st != ui.Warn || !strings.Contains(msg, "need a look") || len(notes) != 2 {
		t.Errorf("warn: %v %q %v", st, msg, notes)
	}
	if st, msg, _ := portVerdict(layers(portx.OK, portx.OK, portx.OK, portx.OK, portx.Unknown)); st != ui.OK || !strings.Contains(msg, "test from outside is what's left") {
		t.Errorf("untested: %q", msg)
	}
	smb := layers(portx.OK, portx.Bad, portx.OK, portx.OK, portx.Unknown)
	smb.Port = 445
	if _, _, notes := portVerdict(smb); !strings.HasPrefix(notes[0], "Careful: SMB file sharing shouldn't be reachable") {
		t.Errorf("caution first: %v", notes)
	}
	redis := layers(portx.OK, portx.OK, portx.OK, portx.OK, portx.Unknown)
	redis.Port = 6379
	if _, _, notes := portVerdict(redis); !strings.Contains(notes[0], "Redis has no password") {
		t.Errorf("redis caution: %v", notes)
	}
	if lowerTitle("TCP 8080 is closed") != "TCP 8080 is closed" || lowerTitle("Nothing listens") != "nothing listens" {
		t.Error("lowerTitle")
	}
}

func TestReachVerdict(t *testing.T) {
	yes, no := true, false
	r := func(host string, port int, expect, result string, holds *bool) portx.ReachResult {
		return portx.ReachResult{Rule: portx.Rule{Host: host, Port: port, Expect: expect}, Result: result, Holds: holds, RTT: 5 * time.Millisecond}
	}
	rs := []portx.ReachResult{r("10.0.0.1", 80, "allow", portx.Open, &yes), r("10.0.0.1", 23, "deny", portx.Open, &no), r("10.0.0.1", 3306, "allow", portx.Filtered, &no)}
	st, msg, notes := reachVerdict(rs)
	all := strings.Join(notes, " ")
	if st != ui.Bad || msg != "2 of 3 rules don't hold." || !strings.Contains(all, "10.0.0.1:23 should be blocked") || !strings.Contains(all, "drops it on the way") {
		t.Errorf("%v %q %v", st, msg, notes)
	}
	if _, msg, _ := reachVerdict(rs[:2]); msg != "1 of 2 rules doesn't hold." {
		t.Errorf("singular: %q", msg)
	}
	if st, msg, _ := reachVerdict(rs[:1]); st != ui.OK || msg != "The rule holds." {
		t.Errorf("all hold: %q", msg)
	}
	plain := []portx.ReachResult{r("a", 1, "", portx.Open, nil), r("b", 2, "", portx.Refused, nil)}
	if st, msg, _ := reachVerdict(plain); st != ui.OK || msg != "1 of 2 targets open from here." {
		t.Errorf("no expectations: %q", msg)
	}
	f := r("nope.test", 1, "allow", portx.Failed, nil)
	f.Error = "the name doesn't resolve"
	if st, _, notes := reachVerdict([]portx.ReachResult{rs[0], f}); st != ui.Warn || !strings.Contains(notes[0], "couldn't be tried") {
		t.Errorf("failed: %v %v", st, notes)
	}
}
