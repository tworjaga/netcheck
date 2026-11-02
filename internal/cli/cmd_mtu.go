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

// mtuVerdict explains the path MTU in plain words.
func mtuVerdict(r probe.MTUResult) (ui.Status, string) {
	switch {
	case r.Error == probe.ErrNoICMP.Error():
		return ui.Skip, "Can't measure: ping (ICMP) isn't available here without elevation."
	case r.Error == probe.ErrICMPBlocked.Error():
		return ui.Skip, fmt.Sprintf("Can't measure: %s doesn't answer ping.", r.Target)
	case r.Error != "" || r.MTU == 0:
		return ui.Warn, "Couldn't measure the path MTU: " + r.Error + "."
	case r.MTU == 1500:
		return ui.OK, "Full-size 1500-byte packets get through, so there's no fragmentation trouble."
	case !r.Signalled:
		return ui.Warn, fmt.Sprintf("Packets over %d bytes vanish without the \"too big\" reply that should come back (a path-MTU black hole). Some sites hang after connecting; setting the router's MTU to %d fixes it.", r.MTU, r.MTU)
	case r.MTU == 1492:
		return ui.OK, "1492-byte packets: normal for a PPPoE connection (common on DSL and fibre)."
	case r.MTU >= 1400:
		return ui.OK, fmt.Sprintf("%d-byte packets: a little under 1500, typical with a VPN or tunnel.", r.MTU)
	}
	return ui.Warn, fmt.Sprintf("The path only carries %d-byte packets, which is unusually small. Check the router's MTU setting or the VPN.", r.MTU)
}

func cmdMTU(args []string) int {
	fs := flag.NewFlagSet("mtu", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	pos := parseInterspersed(fs, args)
	host := "1.1.1.1"
	if len(pos) > 0 {
		host = pos[0]
	}
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ui.Title("mtu")
	ui.Open("Path MTU")
	defer ui.Close()
	t := ui.Begin("MTU")
	t.Progress("sending don't-fragment pings to " + host + "…")
	r := probe.ProbeMTU(ctx, host)
	st, msg := mtuVerdict(r)
	switch {
	case r.MTU > 0:
		t.Finish(ui.Row("MTU", st, r.Addr, fmt.Sprintf("%d", r.MTU), ui.Dim(fmt.Sprintf("bytes · %d probes", r.Probes))))
	default:
		t.Finish(ui.Row("MTU", st, host, "–", ui.Dim(r.Error)))
	}
	if ctx.Err() != nil {
		return 130
	}
	ui.Verdict(st, msg)
	ui.Println("")
	if *asJSON {
		printJSON(struct {
			probe.MTUResult
			Verdict verdict `json:"verdict"`
		}{r, verdict{st.String(), msg}})
	}
	return exitFor(st)
}
