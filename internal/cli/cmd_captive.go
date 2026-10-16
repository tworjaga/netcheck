package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

// captiveVerdict reads the check URLs: all intact means no portal; a
// redirect means a portal wants you to sign in.
func captiveVerdict(r probe.CaptiveResult) (ui.Status, string) {
	intact, altered, failed, redirect := 0, 0, 0, ""
	for _, p := range r.Probes {
		switch {
		case p.Error != "":
			failed++
		case p.Intact:
			intact++
		default:
			altered++
			if redirect == "" {
				redirect = p.Redirect
			}
		}
	}
	switch {
	case intact+altered == 0:
		return ui.Bad, "Couldn't reach any of the check servers: you're offline, or plain web traffic (port 80) is blocked."
	case altered > 0 && redirect != "":
		return ui.Bad, fmt.Sprintf("A captive portal is intercepting web traffic (it redirects to %s). Open any http:// page in a browser to sign in or accept the terms.", redirect)
	case altered > 0 && intact == 0:
		return ui.Bad, "A captive portal or filter is answering in place of the internet. Open a browser to see what it wants."
	case altered > 0:
		return ui.Warn, fmt.Sprintf("%d of %d check servers got a different answer than expected, so something on the way (a filter or proxy) is rewriting plain web pages.", altered, intact+altered)
	}
	return ui.OK, "No captive portal: plain web traffic reaches the internet untouched."
}

func cmdCaptive(args []string) int {
	fs := flag.NewFlagSet("captive", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	parseInterspersed(fs, args)
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ui.Title("captive")
	ui.Open("Connectivity checks")
	defer ui.Close()
	t := ui.Begin("Checking")
	t.Progress("asking the OS connectivity-check servers…")
	r := probe.CheckCaptive(ctx)
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	for _, p := range r.Probes {
		host := p.Name + "'s check"
		switch {
		case p.Error != "":
			ui.Println(ui.Row("No answer", ui.Skip, host, "–", ui.Dim(p.Error)))
		case p.Intact:
			ui.Println(ui.Row("Untouched", ui.OK, host, fmt.Sprint(p.Status), ""))
		case p.Redirect != "":
			ui.Println(ui.Row("Redirected", ui.Bad, host, fmt.Sprint(p.Status), ui.Dim("to "+p.Redirect)))
		default:
			ui.Println(ui.Row("Altered", ui.Warn, host, fmt.Sprint(p.Status), ui.Dim("unexpected content")))
		}
	}
	st, msg := captiveVerdict(r)
	ui.Verdict(st, msg)
	ui.Println("")
	if *asJSON {
		printJSON(struct {
			probe.CaptiveResult
			Verdict verdict `json:"verdict"`
		}{r, verdict{st.String(), msg}})
	}
	return exitFor(st)
}
