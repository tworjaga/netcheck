package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/dnsx"
	"github.com/tworjaga/netcheck/internal/ui"
)

// traceDefault: a bare --fail-on value is the total time.
var traceDefault = adv.Default{Metric: "time", Op: '>'}

// traceVerdict sums up a trace.
func traceVerdict(r dnsx.TraceResult) (ui.Status, string, []string) {
	var notes []string
	for _, l := range r.Lame {
		notes = append(notes, fmt.Sprintf("%s (for %s) %s.", strings.TrimSuffix(l.Server.Name, "."), l.Zone, l.Why))
	}
	var disagree []string
	for _, s := range r.Steps {
		if len(s.Disagree) > 0 {
			disagree = append(disagree, fmt.Sprintf("%s: %s gave a different answer than %s.", s.Zone, trimDots(s.Disagree), strings.TrimSuffix(s.Server.Name, ".")))
		}
		if len(s.Varies) > 0 {
			notes = append(notes, fmt.Sprintf("%s: %s gave different addresses than %s; that's normal for load-balanced or geo DNS.", s.Zone, trimDots(s.Varies), strings.TrimSuffix(s.Server.Name, ".")))
		}
	}
	steps := len(r.Steps)
	took := fmtMs(float64(r.Total.Microseconds()) / 1000)
	var st ui.Status
	var msg string
	switch r.Final {
	case "answer":
		st, msg = ui.OK, fmt.Sprintf("%s resolves from the root in %d steps (%s).", strings.TrimSuffix(r.Name, "."), steps, took)
	case "cname":
		target := ""
		for _, rr := range r.Answer {
			if rr.Type == dnsx.TypeCNAME {
				target = strings.TrimSuffix(rr.Data, ".")
			}
		}
		st, msg = ui.OK, fmt.Sprintf("%s is an alias for %s; trace that name to follow it.", strings.TrimSuffix(r.Name, "."), target)
	case "nxdomain":
		last := r.Steps[len(r.Steps)-1]
		st, msg = ui.Warn, fmt.Sprintf("%s doesn't exist, says %s for %s.", strings.TrimSuffix(r.Name, "."), strings.TrimSuffix(last.Server.Name, "."), strings.TrimSuffix(last.Zone, "."))
	case "nodata":
		st, msg = ui.Skip, fmt.Sprintf("%s exists but has no %s records.", strings.TrimSuffix(r.Name, "."), r.Type)
	default:
		return ui.Bad, "The trace failed: " + r.Error + ".", append(notes, disagree...)
	}
	switch {
	case len(disagree) > 0:
		st, msg = ui.Warn, msg+" But the nameservers don't all agree, so different resolvers get different answers."
	case len(r.Lame) > 0:
		st, msg = ui.Warn, msg+fmt.Sprintf(" %s didn't answer properly; resolvers lose time on them, so fix them or take them out of the delegation.", plural(len(r.Lame), "nameserver", "nameservers"))
	}
	return st, msg, append(disagree, notes...)
}

func trimDots(names []string) string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = strings.TrimSuffix(n, ".")
	}
	return strings.Join(out, ", ")
}

// traceTable is one row per step: zone, server, address, time, result.
func traceTable(r dnsx.TraceResult) ui.Table {
	// The address column only when there's room for it and the result.
	wide := ui.PanelWidth() >= 100
	tb := ui.Table{Headers: []string{"Zone", "Server", "Time", "Result"}}
	if wide {
		tb.Headers = []string{"Zone", "Server", "Address", "Time", "Result"}
	}
	for _, s := range r.Steps {
		st, result := ui.OK, ""
		switch {
		case s.Next != "":
			result = fmt.Sprintf("→ %s (%d NS)", s.Next, len(s.NextNS))
		case len(s.Answer) > 0:
			result = "answer"
		default:
			result = s.Rcode
		}
		if s.Rcode == "NXDOMAIN" {
			st = ui.Warn
		}
		if len(s.Disagree) > 0 {
			st, result = ui.Warn, result+ui.Dim(" · "+plural(len(s.Disagree), "server disagrees", "servers disagree"))
		}
		if len(s.Varies) > 0 {
			result += ui.Dim(" · addresses vary")
		}
		cells := []string{s.Zone, strings.TrimSuffix(s.Server.Name, "."), fmtMs(float64(s.RTT.Microseconds()) / 1000), result}
		if wide {
			cells = []string{s.Zone, strings.TrimSuffix(s.Server.Name, "."), s.Server.Addr, cells[2], result}
		}
		tb.Rows = append(tb.Rows, ui.TableRow{Status: st, Cells: cells})
	}
	return tb
}

func traceLines(r dnsx.TraceResult, raw bool) []string {
	var out []string
	out = append(out, traceTable(r).Lines(ui.PanelWidth())...)
	if len(r.Answer) > 0 {
		out = append(out, "")
		out = append(out, recordLines(r.Answer, raw)...)
	}
	return out
}

func cmdDNSTrace(args []string) int {
	fs := flag.NewFlagSet("dnstrace", flag.ExitOnError)
	common := adv.Register(fs)
	all := fs.Bool("all", false, "ask every nameserver at each step and compare their answers")
	pos := parseInterspersed(fs, args)
	ui.SetQuiet(common.JSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	usage := func(msg string) int {
		fmt.Fprintln(os.Stderr, "netcheck dnstrace: "+msg)
		fmt.Fprintln(os.Stderr, "usage: netcheck dnstrace <name> [type] [--all]")
		return 2
	}
	names, qtype, server, err := digArgs(pos)
	switch {
	case err != nil:
		return usage(err.Error())
	case server != "":
		return usage("a trace starts at the root servers, so it takes no @server")
	case len(names) != 1:
		return usage("name one domain to trace")
	}
	if qtype == 0 {
		qtype = dnsx.TypeA
	}
	rules, err := common.Rules()
	if err != nil {
		return usage(err.Error())
	}
	opts := dnsx.TraceOptions{All: *all}
	title := fmt.Sprintf("%s · %s · from the root", names[0], dnsx.TypeString(qtype))

	if common.Watch > 0 {
		ui.Title("dns trace")
		adv.Watch(ctx, common.Watch, func(ctx context.Context) []string {
			r := dnsx.Trace(ctx, names[0], qtype, opts)
			st, msg, _ := traceVerdict(r)
			return append(append([]string{"  " + ui.Bold(title), ""}, traceLines(r, common.Raw)...), "", "  "+st.Paint(msg))
		})
		return 0
	}

	ui.Title("dns trace")
	t := ui.Begin("Tracing")
	t.Progress("asking the root servers…")
	r := dnsx.Trace(ctx, names[0], qtype, opts)
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	st, msg, notes := traceVerdict(r)
	vals := map[string]float64{"time": float64(r.Total.Microseconds()) / 1000, "lame": float64(len(r.Lame)), "steps": float64(len(r.Steps))}
	broken := adv.Broken(rules, traceDefault, vals)

	ui.Open(title)
	for _, l := range traceTable(r).Lines(ui.PanelWidth()) {
		ui.Println(l)
	}
	ui.Close()
	if len(r.Answer) > 0 {
		ui.Println("")
		ui.Open("Answer")
		for _, l := range recordLines(r.Answer, common.Raw) {
			ui.Println(l)
		}
		ui.Close()
	}
	if !common.Raw {
		ui.Verdict(st, msg, append(notes, broken...)...)
	}
	ui.Println("")
	if common.JSON {
		adv.Envelope{Tool: "dnstrace", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Data: r, FailedOn: broken}.Write(os.Stdout)
	}
	return adv.ExitCode(st.String(), broken)
}
