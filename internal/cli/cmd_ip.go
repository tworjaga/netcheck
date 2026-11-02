package cli

import (
	"context"
	"flag"
	"net"
	"os"
	"os/signal"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

type ipReport struct {
	probe.IPInfo
	NAT *probe.NATInfo `json:"nat,omitempty"`
}

// natStatus turns a NAT finding into a status glyph and a short label.
func natStatus(n probe.NATInfo) (ui.Status, string) {
	switch n.Kind {
	case "none":
		return ui.OK, "direct"
	case "double":
		return ui.Warn, "double NAT"
	case "cgnat":
		return ui.Warn, "CGNAT"
	}
	return ui.Skip, "unknown"
}

func cmdIP(args []string) int {
	fs := flag.NewFlagSet("ip", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	parseInterspersed(fs, args)
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ui.Title("ip")
	ui.Open("Connection")
	defer ui.Close()
	var rep ipReport

	t := ui.Begin("Public IP")
	pub, err := probe.PublicIP(ctx)
	if err != nil {
		rep.Error = err.Error()
		t.Finish(ui.Row("Public IP", ui.Bad, "not found", "–", ui.Dim("offline, or the lookup services are blocked")))
		ui.Println("")
		if *asJSON {
			printJSON(rep)
		}
		return 1
	}
	t.Finish(ui.Row("Public IP", ui.OK, pub.String(), "", ""))

	t = ui.Begin("ISP")
	rep.IPInfo = probe.LookupASN(ctx, pub)
	if rep.ASN == "" && rep.ISP == "" {
		t.Finish(ui.Row("ISP", ui.Skip, "unknown", "–", ui.Dim("lookup failed")))
	} else {
		name, extra := rep.ISP, ""
		if rep.ASN != "" {
			extra = ui.Dim(rep.ASN)
			if rep.Country != "" {
				extra += ui.Dim(" · " + rep.Country)
			}
		}
		if name == "" {
			name, extra = rep.ASN, ui.Dim(rep.Country)
		}
		t.Finish(ui.Row("ISP", ui.OK, name, "", extra))
	}

	t = ui.Begin("NAT")
	gw, gwErr := probe.DefaultGateway()
	if gwErr != nil {
		t.Finish(ui.Row("NAT", ui.Skip, "unknown", "–", ui.Dim("couldn't detect your router")))
	} else {
		t.Progress("asking " + gw.String() + "…")
		n := probe.DetectNAT(ctx, gw, pub, routeHops(gw))
		rep.NAT = &n
		st, label := natStatus(n)
		t.Finish(ui.Row("NAT", st, label, "", ui.Dim(natRowNote(n))))
		ui.Verdict(st, n.Detail)
	}
	ui.Close()
	ui.Println("")
	if *asJSON {
		printJSON(rep)
	}
	return 0
}

func natRowNote(n probe.NATInfo) string {
	switch {
	case n.Method == "upnp" && n.RouterIP != "":
		return "router WAN " + n.RouterIP
	case n.Method == "route":
		return "judged from the route"
	}
	return ""
}

// routeHops is the weaker NAT fallback: the first routers past the gateway.
func routeHops(gw net.IP) func(context.Context) []net.IP {
	return func(ctx context.Context) []net.IP { return probe.FirstHops(ctx, "1.1.1.1", 4) }
}
