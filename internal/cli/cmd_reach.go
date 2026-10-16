package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/portx"
	"github.com/tworjaga/netcheck/internal/ui"
)

func reachVerdict(rs []portx.ReachResult) (ui.Status, string, []string) {
	held, broke, open, failed := 0, 0, 0, 0
	var notes []string
	for _, r := range rs {
		if r.Result == portx.Open {
			open++
		}
		switch {
		case r.Result == portx.Failed:
			failed++
			notes = append(notes, fmt.Sprintf("%s couldn't be tried: %s.", r.Rule, r.Error))
		case r.Holds == nil:
		case *r.Holds:
			held++
		default:
			broke++
			if r.Expect == "allow" {
				notes = append(notes, fmt.Sprintf("%s should be allowed but is %s%s.", r.Rule, r.Result, map[string]string{
					portx.Refused: " (the host or a firewall said no)", portx.Filtered: " (no answer: something drops it on the way)"}[r.Result]))
			} else {
				notes = append(notes, fmt.Sprintf("%s should be blocked but the connection was accepted.", r.Rule))
			}
		}
	}
	switch {
	case held+broke == 0:
		return ui.OK, fmt.Sprintf("%d of %s open from here.", open, plural(len(rs), "target", "targets")), notes
	case broke > 0:
		verb := "don't hold"
		if broke == 1 {
			verb = "doesn't hold"
		}
		return ui.Bad, fmt.Sprintf("%d of %s %s.", broke, plural(held+broke, "rule", "rules"), verb), notes
	case failed > 0:
		return ui.Warn, fmt.Sprintf("The %s that could be tried %s; %d couldn't be tried.", plural(held, "rule", "rules"), map[bool]string{true: "holds", false: "hold"}[held == 1], failed), notes
	}
	if held == 1 {
		return ui.OK, "The rule holds.", notes
	}
	return ui.OK, fmt.Sprintf("All %d rules hold.", held), notes
}

func reachTable(rs []portx.ReachResult) ui.Table {
	tb := ui.Table{Headers: []string{"Target", "Expected", "Result", "Time"}}
	for _, r := range rs {
		st := ui.OK
		switch {
		case r.Result == portx.Failed:
			st = ui.Warn
		case r.Holds != nil && !*r.Holds:
			st = ui.Bad
		case r.Holds == nil:
			st = ui.Skip
		}
		took := ""
		if r.Result == portx.Open {
			took = fmtMs(float64(r.RTT.Microseconds()) / 1000)
		}
		exp := r.Expect
		if exp == "" {
			exp = ui.Dim("–")
		}
		res := r.Result
		if r.Error != "" && r.Result == portx.Failed {
			res += ui.Dim(" · " + r.Error)
		}
		tb.Rows = append(tb.Rows, ui.TableRow{Status: st, Cells: []string{ui.Cut(r.Rule.String(), 34), exp, res, took}})
	}
	return tb
}

func cmdReach(args []string) int {
	fs := flag.NewFlagSet("reach", flag.ExitOnError)
	common := adv.Register(fs)
	timeout := fs.Duration("timeout", 3*time.Second, "how long to wait for each connection")
	pos := parseInterspersed(fs, args)
	ui.SetQuiet(common.JSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	usage := func(msg string) int {
		fmt.Fprintln(os.Stderr, "netcheck reach: "+msg)
		fmt.Fprintln(os.Stderr, "usage: netcheck reach <host:port> [allow|deny] ... | -f rules.txt [--authorized]")
		return 2
	}
	var rules []portx.Rule
	// On the command line, "allow" or "deny" belongs to the target before it.
	for i := 0; i < len(pos); i++ {
		spec := pos[i]
		if i+1 < len(pos) && !strings.Contains(pos[i+1], ":") {
			spec += " " + pos[i+1]
			i++
		}
		r, err := portx.ParseRule(spec)
		if err != nil {
			return usage(err.Error())
		}
		rules = append(rules, r)
	}
	if common.File != "" {
		f, err := os.Open(common.File)
		if err != nil {
			return usage(err.Error())
		}
		sc := bufio.NewScanner(f)
		for line := 1; sc.Scan(); line++ {
			l := strings.TrimSpace(strings.SplitN(sc.Text(), "#", 2)[0])
			if l == "" {
				continue
			}
			r, err := portx.ParseRule(l)
			if err != nil {
				f.Close()
				return usage(fmt.Sprintf("%s line %d: %v", common.File, line, err))
			}
			r.Line = line
			rules = append(rules, r)
		}
		f.Close()
	}
	if len(rules) == 0 {
		return usage("give at least one host:port")
	}
	failRules, err := common.Rules()
	if err != nil {
		return usage(err.Error())
	}
	var targets []adv.Target
	for _, r := range rules {
		targets = append(targets, adv.Target{Host: r.Host, Port: r.Port})
	}
	if err := adv.CheckScope(ctx, targets, common.Authorized); err != nil {
		return usage(err.Error())
	}
	var wait func(context.Context) error
	if common.Authorized {
		p := adv.NewPacer(adv.GentleRate)
		wait = p.Wait
	}
	ui.Title("reach")
	if common.Watch > 0 {
		adv.Watch(ctx, common.Watch, func(ctx context.Context) []string {
			rs := portx.Reach(ctx, rules, *timeout, wait)
			st, msg, _ := reachVerdict(rs)
			return append(reachTable(rs).Lines(ui.PanelWidth()), "", "  "+st.Paint(msg))
		})
		return 0
	}
	t := ui.Begin("Connecting")
	t.Progress(fmt.Sprintf("to %s…", plural(len(rules), "target", "targets")))
	rs := portx.Reach(ctx, rules, *timeout, wait)
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	st, msg, notes := reachVerdict(rs)
	mismatch := 0
	for _, r := range rs {
		if r.Holds != nil && !*r.Holds {
			mismatch++
		}
	}
	broken := adv.Broken(failRules, adv.Default{Metric: "mismatches", Op: '>'}, map[string]float64{"mismatches": float64(mismatch)})
	ui.Open(fmt.Sprintf("From this machine · %s", plural(len(rules), "target", "targets")))
	for _, l := range reachTable(rs).Lines(ui.PanelWidth()) {
		ui.Println(l)
	}
	ui.Close()
	if !common.Raw {
		ui.Verdict(st, msg, append(notes, broken...)...)
	}
	ui.Println("")
	if common.JSON {
		adv.Envelope{Tool: "reach", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Data: rs, FailedOn: broken}.Write(os.Stdout)
	}
	return adv.ExitCode(st.String(), broken)
}
