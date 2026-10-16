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

func validates(r probe.DNSSECResult) bool {
	return r.Answered && (r.Rejects || (r.AD && !r.RejectKnown))
}

// dnssecVerdict judges the system resolver, with Cloudflare as a control
// that shows whether DNSSEC data can cross this network at all.
func dnssecVerdict(sys, control probe.DNSSECResult) (ui.Status, string) {
	switch {
	case !sys.Answered && control.Answered:
		return ui.Warn, fmt.Sprintf("Your DNS server (%s) didn't answer direct queries, so its DNSSEC support is unknown.", sys.Server)
	case !sys.Answered:
		return ui.Bad, "No DNS server answered, so DNSSEC couldn't be tested."
	case validates(sys) && sys.RejectKnown:
		return ui.OK, "Your DNS server validates DNSSEC: forged answers for signed domains are refused."
	case validates(sys):
		return ui.OK, "Your DNS server marks signed answers as verified (DNSSEC)."
	case sys.AD && sys.RejectKnown && !sys.Rejects:
		return ui.Warn, "Your DNS server claims to check DNSSEC but let a deliberately broken signature through."
	case validates(control):
		return ui.Warn, fmt.Sprintf("Your DNS server (%s) doesn't check DNSSEC. Cloudflare (1.1.1.1) and Quad9 (9.9.9.9) do, if you want forged answers refused.", sys.Server)
	case control.Answered:
		return ui.Warn, "Neither your DNS server nor Cloudflare validated here, so something on the network is stripping DNSSEC data."
	}
	return ui.Warn, fmt.Sprintf("Your DNS server (%s) doesn't check DNSSEC.", sys.Server)
}

func dnssecRow(label string, r probe.DNSSECResult) string {
	switch {
	case !r.Answered:
		return ui.Row(label, ui.Skip, r.Server, "–", ui.Dim(r.Error))
	case validates(r):
		return ui.Row(label, ui.OK, r.Server, "valid", ui.Dim("rejects broken signatures: "+yesNo(r.Rejects)))
	}
	return ui.Row(label, ui.Warn, r.Server, "none", ui.Dim("doesn't validate"))
}

func cmdDNSSEC(args []string) int {
	fs := flag.NewFlagSet("dnssec", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	parseInterspersed(fs, args)
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ui.Title("dnssec")
	ui.Open("DNSSEC")
	defer ui.Close()
	var note string
	server := ""
	if ns := probe.DNSServers(ctx); len(ns) > 0 {
		server = ns[0]
	} else if gw, err := probe.DefaultGateway(); err == nil {
		server = gw.String()
		note = "Couldn't read this computer's DNS servers, so your router was tested instead."
	}
	t := ui.Begin("DNSSEC")
	t.Progress("querying signed and broken test names…")
	ctrlCh := make(chan probe.DNSSECResult, 1)
	go func() { ctrlCh <- probe.CheckDNSSEC(ctx, "1.1.1.1") }()
	var sys probe.DNSSECResult
	if server != "" {
		sys = probe.CheckDNSSEC(ctx, server)
	} else {
		sys = probe.DNSSECResult{Error: "no DNS server found"}
	}
	control := <-ctrlCh
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	ui.Println(dnssecRow("Your DNS", sys))
	ui.Println(dnssecRow("Cloudflare", control))
	st, msg := dnssecVerdict(sys, control)
	ui.Verdict(st, msg, note)
	ui.Println("")
	if *asJSON {
		printJSON(struct {
			System  probe.DNSSECResult `json:"system"`
			Control probe.DNSSECResult `json:"control"`
			Verdict verdict            `json:"verdict"`
		}{sys, control, verdict{st.String(), msg}})
	}
	return exitFor(st)
}
