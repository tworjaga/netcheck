package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/portx"
	"github.com/tworjaga/netcheck/internal/ui"
)

func layerStatus(s portx.Status) ui.Status {
	switch s {
	case portx.OK:
		return ui.OK
	case portx.Warn:
		return ui.Warn
	case portx.Bad:
		return ui.Bad
	}
	return ui.Skip
}

// neverPublic are services that shouldn't face the internet at all, on top
// of the risky ones listen knows.
var neverPublic = map[string]string{"tcp/135": "Windows RPC", "tcp/139": "NetBIOS", "tcp/445": "SMB file sharing", "udp/137": "NetBIOS", "udp/138": "NetBIOS"}

// caution warns before helping open a port that should stay private.
func caution(proto string, port int) string {
	key := fmt.Sprintf("%s/%d", proto, port)
	name, ok := neverPublic[key]
	why := "it's a favourite target for attacks from the internet"
	if r, risk := risky[key]; risk && r.st != ui.Skip {
		name, ok, why = firstNonEmpty(knownPorts[key], "This service"), true, r.why
	}
	if !ok {
		return ""
	}
	return fmt.Sprintf("Careful: %s shouldn't be reachable from the internet (%s). To use it from outside, connect through a VPN (WireGuard, Tailscale) instead of opening the port.", name, why)
}

// portVerdict names the first layer that stops connections, or says what
// still wasn't confirmed.
func portVerdict(r portx.Report) (ui.Status, string, []string) {
	P := fmt.Sprintf("%s %d", strings.ToUpper(r.Proto), r.Port)
	if c := caution(r.Proto, r.Port); c != "" {
		st, msg, notes := portVerdictPlain(r, P)
		return st, msg, append([]string{c}, notes...)
	}
	return portVerdictPlain(r, P)
}

func portVerdictPlain(r portx.Report, P string) (ui.Status, string, []string) {
	if b := r.Blocking(); b != nil {
		var fixes []string
		if b.Fix != "" {
			fixes = append(fixes, b.Fix)
		}
		for _, l := range r.Layers {
			if l.Name != b.Name && l.Status == portx.Bad && l.Fix != "" {
				fixes = append(fixes, "Then: "+l.Title+". "+l.Fix)
			}
		}
		return ui.Bad, fmt.Sprintf("%s can't be reached: %s.", P, lowerTitle(b.Title)), fixes
	}
	var notes []string
	warn := false
	for _, l := range r.Layers {
		if l.Status == portx.Warn {
			warn = true
		}
		if (l.Status == portx.Warn || l.Status == portx.Unknown) && l.Fix != "" {
			notes = append(notes, l.Title+": "+l.Fix)
		}
	}
	last := r.Layers[len(r.Layers)-1]
	switch {
	case last.Status == portx.OK:
		return ui.OK, fmt.Sprintf("%s is reachable from the internet; every layer lets it through.", P), notes
	case warn:
		return ui.Warn, fmt.Sprintf("Nothing here blocks %s, but some layers need a look.", P), notes
	}
	return ui.OK, fmt.Sprintf("Nothing on this side blocks %s; the test from outside is what's left.", P), notes
}

// lowerTitle lower-cases a title's first letter to sit mid-sentence, leaving
// acronyms (TCP, UDP) alone.
func lowerTitle(s string) string {
	if s == "" {
		return s
	}
	if len(s) > 1 && s[1] >= 'A' && s[1] <= 'Z' { // an acronym: UDP, TCP
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

func portLines(r portx.Report, width int) []string {
	var out []string
	for i, l := range r.Layers {
		st := layerStatus(l.Status)
		title := l.Title
		if l.Status == portx.Bad || l.Status == portx.Warn {
			title = st.Paint(title)
		}
		out = append(out, fmt.Sprintf("  %s  %s  %s", st.Sym(), ui.Pad(ui.Dim(fmt.Sprintf("%d %s", i+1, l.Name)), 15), title))
		if l.Detail != "" {
			for _, w := range ui.Wrap(l.Detail, max(20, width-22)) {
				out = append(out, strings.Repeat(" ", 22)+ui.Dim(w))
			}
		}
	}
	return out
}

func cmdPort(args []string) int {
	fs := flag.NewFlagSet("port", flag.ExitOnError)
	common := adv.Register(fs)
	udp := fs.Bool("udp", false, "the port is UDP")
	helper := fs.String("helper", os.Getenv("NETCHECK_PORT_HELPER"), "port-check helper URL, to test from outside (or NETCHECK_PORT_HELPER)")
	from := fs.String("from", "", "test from outside through this paired agent (netcheck agent add)")
	pos := parseInterspersed(fs, args)
	ui.SetQuiet(common.JSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	usage := func(msg string) int {
		fmt.Fprintln(os.Stderr, "netcheck port: "+msg)
		fmt.Fprintln(os.Stderr, "usage: netcheck port <port> [--udp] [--from agent | --helper URL]")
		return 2
	}
	if len(pos) != 1 {
		return usage("give the port your server uses")
	}
	port, err := strconv.Atoi(strings.TrimPrefix(strings.ToLower(pos[0]), "tcp/"))
	if strings.HasPrefix(strings.ToLower(pos[0]), "udp/") {
		*udp = true
		port, err = strconv.Atoi(pos[0][4:])
	}
	if err != nil || port < 1 || port > 65535 {
		return usage(fmt.Sprintf("%q isn't a port", pos[0]))
	}
	rules, err := common.Rules()
	if err != nil {
		return usage(err.Error())
	}
	proto := "tcp"
	if *udp {
		proto = "udp"
	}
	opts := portx.Options{Helper: *helper}
	if *from != "" {
		ext, err := agentExternal(*from)
		if err != nil {
			return usage(err.Error())
		}
		opts.External = ext
	}
	ui.Title("port")
	if common.Watch > 0 {
		adv.Watch(ctx, common.Watch, func(ctx context.Context) []string {
			r := portx.Diagnose(ctx, port, proto, opts)
			st, msg, _ := portVerdict(r)
			return append(portLines(r, ui.PanelWidth()), "", "  "+st.Paint(msg))
		})
		return 0
	}
	t := ui.Begin("Checking")
	t.Progress(fmt.Sprintf("the program, firewall, router and internet side of %s %d…", strings.ToUpper(proto), port))
	r := portx.Diagnose(ctx, port, proto, opts)
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	st, msg, notes := portVerdict(r)
	blocked := 0.0
	if r.Blocking() != nil {
		blocked = 1
	}
	broken := adv.Broken(rules, adv.Default{Metric: "blocked", Op: '>'}, map[string]float64{"blocked": blocked})
	ui.Open(fmt.Sprintf("%s %d, from the program out", strings.ToUpper(proto), port))
	for _, l := range portLines(r, ui.PanelWidth()) {
		ui.Println(l)
	}
	ui.Close()
	if !common.Raw {
		ui.Verdict(st, msg, append(notes, broken...)...)
	}
	ui.Println("")
	if common.JSON {
		adv.Envelope{Tool: "port", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Data: r, FailedOn: broken}.Write(os.Stdout)
	}
	return adv.ExitCode(st.String(), broken)
}
