package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
	"net"
	"os"
	"time"
)

func parseInterspersed(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		_ = fs.Parse(args)
		args = fs.Args()
		if len(args) == 0 {
			return pos
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func fmtMs(v float64) string {
	if v < 10 {
		return fmt.Sprintf("%.1f ms", v)
	}
	return fmt.Sprintf("%.0f ms", v)
}

func tail(v []float64, n int) []float64 {
	if len(v) > n {
		return v[len(v)-n:]
	}
	return v
}

func kv(k, v string) string { return ui.Dim(k) + " " + v }

type finding struct {
	St  ui.Status
	Msg string
}

func pingStatus(r probe.PingResult, slowMs float64, noReply ui.Status) ui.Status {
	switch {
	case r.Received == 0:
		return noReply
	case r.LossPct > 2, r.AvgMs > slowMs, r.JitterMs > 30:
		return ui.Warn
	}
	return ui.OK
}

func pingRow(label string, st ui.Status, r probe.PingResult, note string) string {
	target := r.Target
	if r.Received == 0 {
		why := "no reply"
		if r.Error != "" {
			why = r.Error
		} else if note != "" {
			why = note
		}
		return ui.Row(label, st, target, "–", ui.Dim(why))
	}
	extra := ui.Spark(tail(r.SamplesMs, 24))
	if r.LossPct > 0 {
		extra += "  " + ui.Dim(fmt.Sprintf("%.0f%% loss", r.LossPct))
	}
	return ui.Row(label, st, target, fmtMs(r.AvgMs), extra)
}

func startDNS(ctx context.Context, rs []probe.Resolver, names []string) []chan probe.DNSResult {
	chans := make([]chan probe.DNSResult, len(rs))
	for i, r := range rs {
		chans[i] = make(chan probe.DNSResult, 1)
		go func(r probe.Resolver, ch chan probe.DNSResult) {
			ch <- probe.CheckResolver(ctx, r, names)
		}(r, chans[i])
	}
	return chans
}

// dnsVerdict judges the system resolver (rs[0]) against the public ones.
// It returns a status, a plain-English sentence, and a short note for table rows.
func dnsVerdict(rs []probe.DNSResult) (ui.Status, string, string) {
	sys := rs[0]
	var best *probe.DNSResult
	for i := 1; i < len(rs); i++ {
		if r := &rs[i]; r.Answered > 0 && (best == nil || r.MedianMs < best.MedianMs) {
			best = r
		}
	}
	switch {
	case sys.Answered == 0 && best == nil:
		return ui.Bad, "No DNS server answered, so names can't be looked up.", "no answers"
	case sys.Answered == 0:
		return ui.Bad, fmt.Sprintf("Your DNS server isn't answering, but %s is. Try switching to %s.", best.Label, best.Addr), "not answering"
	case sys.RewritesNX:
		return ui.Warn, "Your DNS server redirects unknown names to another page, which is often ISP ads. A public resolver avoids that.", "rewrites unknown names"
	case sys.Answered < sys.Lookups:
		return ui.Warn, fmt.Sprintf("Your DNS server dropped %d of %d lookups.", sys.Lookups-sys.Answered, sys.Lookups), "dropped lookups"
	case best != nil && sys.MedianMs > 80 && sys.MedianMs-best.MedianMs > 40:
		return ui.Warn, fmt.Sprintf("DNS is slow (%s). %s answers in %s, so switching could speed up browsing.", fmtMs(sys.MedianMs), best.Label, fmtMs(best.MedianMs)),
			fmt.Sprintf("slower than %s (%s)", best.Label, fmtMs(best.MedianMs))
	case sys.MedianMs > 300 && (best == nil || best.MedianMs > 300):
		// Every server is slow alike: the delay is on the way to all of them.
		fastest := ""
		if best != nil {
			fastest = fmt.Sprintf(", fastest %s %s", best.Label, fmtMs(best.MedianMs))
		}
		return ui.Warn, fmt.Sprintf("Every DNS server answers slowly (yours %s%s), so it's the network that's slow, not your DNS. netcheck ping or doctor shows where.", fmtMs(sys.MedianMs), fastest),
			"all slow: the network"
	}
	return ui.OK, "DNS is healthy.", ""
}

// lead picks the headline: the first Bad finding, else the first Warn, else
// ok. The rest follow it in dim text.
func lead(findings []finding, ok string) (ui.Status, string) {
	for _, want := range []ui.Status{ui.Bad, ui.Warn} {
		for _, f := range findings {
			if f.St == want {
				return f.St, f.Msg
			}
		}
	}
	return ui.OK, ok
}

// printVerdict prints the headline with the other findings, then any extra
// notes, under it.
func printVerdict(st ui.Status, head string, findings []finding, extra ...string) {
	var notes []string
	for _, f := range findings {
		if f.Msg != head {
			notes = append(notes, f.Msg)
		}
	}
	ui.Verdict(st, head, append(notes, extra...)...)
}

// fmtDur renders a duration the way a person would say it.
func fmtDur(d time.Duration) string {
	s := int(d.Round(time.Second).Seconds())
	switch {
	case s < 60:
		return fmt.Sprintf("%d s", s)
	case s < 3600:
		if s%60 == 0 || s >= 600 {
			return fmt.Sprintf("%d min", (s+30)/60)
		}
		return fmt.Sprintf("%d min %d s", s/60, s%60)
	case s < 86400:
		h, m := s/3600, (s%3600+30)/60
		if m == 60 {
			h, m = h+1, 0
		}
		if h == 24 {
			return "1 d"
		}
		if m == 0 {
			return fmt.Sprintf("%d h", h)
		}
		return fmt.Sprintf("%d h %d min", h, m)
	}
	d2, h := s/86400, (s%86400+1800)/3600
	if h == 24 {
		d2, h = d2+1, 0
	}
	if h == 0 {
		return fmt.Sprintf("%d d", d2)
	}
	return fmt.Sprintf("%d d %d h", d2, h)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// exitFor is the exit code for a verdict: 1 on a hard failure.
func exitFor(st ui.Status) int {
	if st == ui.Bad {
		return 1
	}
	return 0
}

// okIf is OK when b holds, else a neutral dash.
func okIf(b bool) ui.Status {
	if b {
		return ui.OK
	}
	return ui.Skip
}

func hasMsg(fs []finding, msg string) bool {
	for _, f := range fs {
		if f.Msg == msg {
			return true
		}
	}
	return false
}

func parseIP(s string) net.IP { return net.ParseIP(s) }
