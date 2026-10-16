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

// ipv6Verdict says whether IPv6 works, is used, and whether it's a problem.
func ipv6Verdict(r probe.IPv6Result) (ui.Status, string) {
	switch {
	case !r.Reachable && r.V4Ms == 0:
		return ui.Bad, "Couldn't reach the internet over IPv4 or IPv6."
	case !r.Reachable && r.Address != "":
		return ui.Warn, "IPv6 is set up on this computer but can't reach the internet, so apps may wait for it to time out before falling back to IPv4. Restarting the router often fixes it."
	case !r.Reachable:
		return ui.Skip, "This network is IPv4-only. That's still common and nothing breaks; IPv6 mostly helps games and calls behind carrier-grade NAT."
	case !r.DNSAAAA:
		return ui.Warn, "IPv6 works, but your DNS server doesn't hand out IPv6 addresses, so it's hardly used."
	case r.V4Ms > 0 && r.V6Ms > r.V4Ms+50:
		return ui.Warn, fmt.Sprintf("IPv6 works but is much slower than IPv4 (%s against %s), and most apps try IPv6 first.", fmtMs(r.V6Ms), fmtMs(r.V4Ms))
	case !r.Preferred:
		return ui.OK, "IPv6 works, but this computer prefers IPv4 for sites that have both."
	}
	return ui.OK, "IPv6 works and is preferred."
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func cmdIPv6(args []string) int {
	fs := flag.NewFlagSet("ipv6", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	parseInterspersed(fs, args)
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ui.Title("ipv6")
	ui.Open("IPv6")
	defer ui.Close()
	t := ui.Begin("IPv6")
	t.Progress("connecting over IPv6 and IPv4…")
	r := probe.CheckIPv6(ctx)
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	addr := r.Address
	if addr == "" {
		addr = "none"
	}
	ui.Println(ui.Row("Address", okIf(r.Address != ""), addr, "", ""))
	if r.Reachable {
		ui.Println(ui.Row("Internet", ui.OK, "over IPv6", fmtMs(r.V6Ms), ui.Dim(fmt.Sprintf("IPv4 %s", fmtMs(r.V4Ms)))))
	} else {
		ui.Println(ui.Row("Internet", ui.Skip, "over IPv6", "–", ui.Dim("no route")))
	}
	ui.Println(ui.Row("DNS", okIf(r.DNSAAAA), "IPv6 answers", yesNo(r.DNSAAAA), ""))
	ui.Println(ui.Row("Preferred", okIf(r.Preferred && r.Reachable), "IPv6 first", yesNo(r.Preferred && r.Reachable), ""))

	st, msg := ipv6Verdict(r)
	ui.Verdict(st, msg)
	ui.Println("")
	if *asJSON {
		printJSON(struct {
			probe.IPv6Result
			Verdict verdict `json:"verdict"`
		}{r, verdict{st.String(), msg}})
	}
	return exitFor(st)
}
