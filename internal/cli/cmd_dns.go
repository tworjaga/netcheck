package cli

import (
	"context"
	"flag"
	"fmt"
	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
	"os"
	"os/signal"
	"strings"
)

type dnsReport struct {
	Resolvers []probe.DNSResult `json:"resolvers"`
	Verdict   verdict           `json:"verdict"`
}

type verdict struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func cmdDNS(args []string) int {
	fs := flag.NewFlagSet("dns", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	pos := parseInterspersed(fs, args)
	names := probe.DefaultNames
	if len(pos) > 0 {
		names = []string{strings.TrimSuffix(pos[0], ".") + "."}
	}
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ui.Title("dns")
	ui.Open("Resolvers")
	defer ui.Close()
	gw, _ := probe.DefaultGateway()
	rs := probe.BuildResolvers(gw)
	chans := startDNS(ctx, rs, names)

	results := make([]probe.DNSResult, len(rs))
	for i, ch := range chans {
		t := ui.Begin(rs[i].Label)
		t.Progress(rs[i].Addr)
		r := <-ch
		results[i] = r
		st, metric, extra := ui.OK, "–", ""
		switch {
		case r.Answered == 0:
			st, extra = ui.Bad, ui.Dim(r.Error)
		case r.RewritesNX:
			st, metric, extra = ui.Warn, fmtMs(r.MedianMs), ui.Dim("rewrites unknown names")
		case r.Answered < r.Lookups:
			st, metric, extra = ui.Warn, fmtMs(r.MedianMs), ui.Dim(fmt.Sprintf("%d of %d answered", r.Answered, r.Lookups))
		default:
			metric = fmtMs(r.MedianMs)
		}
		addr := r.Addr
		if addr == "" {
			addr = "default"
		}
		t.Finish(ui.Row(r.Label, st, addr, metric, extra))
	}
	st, msg, _ := dnsVerdict(results)
	ui.Verdict(st, msg)
	ui.Println("")
	if *asJSON {
		printJSON(dnsReport{results, verdict{st.String(), msg}})
	}
	if st == ui.Bad {
		return 1
	}
	return 0
}
