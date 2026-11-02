package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

// Public DNS services by ASN: answers from these aren't your ISP's, and
// aren't a leak to your ISP either.
var publicDNS = map[string]string{
	"AS15169": "Google Public DNS",
	"AS13335": "Cloudflare",
	"AS19281": "Quad9",
	"AS42":    "Quad9",
	"AS36692": "Cisco OpenDNS",
	"AS34939": "NextDNS",
}

func egressName(e probe.Egress) string {
	if n, ok := publicDNS[e.ASN]; ok {
		return n
	}
	if e.Org != "" {
		return e.Org
	}
	if e.ASN != "" {
		return e.ASN
	}
	return e.IP
}

// leakVerdict compares who answers DNS with who the internet sees you as.
// With a VPN up, DNS answered by anyone but the VPN or a public resolver
// is a leak: that party sees every site you look up.
func leakVerdict(r probe.LeakResult) (ui.Status, string) {
	if len(r.Resolvers) == 0 {
		return ui.Skip, "Couldn't see which DNS servers answer for you; the lookup services may be blocked."
	}
	var foreign []probe.Egress
	public := ""
	for _, e := range r.Resolvers {
		switch {
		case e.ASN != "" && e.ASN == r.Public.ASN:
		case publicDNS[e.ASN] != "":
			public = publicDNS[e.ASN]
		default:
			foreign = append(foreign, e)
		}
	}
	vpnOn := len(r.VPN) > 0
	exit := r.Public.ISP
	if exit == "" {
		exit = r.Public.ASN
	}
	switch {
	case vpnOn && len(foreign) > 0 && r.Public.ASN != "":
		return ui.Bad, fmt.Sprintf("DNS leak: with the VPN on, your lookups are answered by %s, not through the VPN (%s). %s can see every site you visit.", egressName(foreign[0]), exit, egressName(foreign[0]))
	case vpnOn && len(foreign) > 0:
		return ui.Warn, fmt.Sprintf("Your lookups are answered by %s while a VPN is up. Couldn't confirm who the VPN exit belongs to, so check this is your VPN's DNS.", egressName(foreign[0]))
	case vpnOn && public != "":
		return ui.OK, fmt.Sprintf("No leak: with the VPN on, DNS goes to %s rather than your ISP.", public)
	case vpnOn:
		return ui.OK, fmt.Sprintf("No leak: DNS goes through the VPN (%s).", exit)
	case len(foreign) > 0:
		return ui.OK, fmt.Sprintf("No VPN detected. Your DNS is answered by %s, which isn't your ISP; fine if you chose it.", egressName(foreign[0]))
	case public != "":
		return ui.OK, fmt.Sprintf("No VPN detected. Your DNS is answered by %s.", public)
	}
	return ui.OK, fmt.Sprintf("No VPN detected. Your DNS is your ISP's (%s), as expected.", exit)
}

func cmdLeak(args []string) int {
	fs := flag.NewFlagSet("leak", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	parseInterspersed(fs, args)
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ui.Title("leak")
	ui.Open("Who answers your DNS")
	defer ui.Close()
	t := ui.Begin("DNS")
	t.Progress("asking who answers your lookups…")
	r := probe.CheckLeak(ctx)
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	if len(r.VPN) > 0 {
		ui.Println(ui.Row("VPN", ui.OK, strings.Join(r.VPN, ", "), "", ui.Dim("tunnel interface up")))
	} else {
		ui.Println(ui.Row("VPN", ui.Skip, "none detected", "", ""))
	}
	pub := r.Public.IP
	if pub == "" {
		pub = "unknown"
	}
	ui.Println(ui.Row("Public IP", ui.Skip, pub, "", ui.Dim(strings.TrimSpace(r.Public.ASN+" "+r.Public.ISP))))
	for _, e := range r.Resolvers {
		ui.Println(ui.Row("DNS", ui.Skip, e.IP, "", ui.Dim(strings.TrimSpace(e.ASN+" "+egressName(e)))))
	}
	st, msg := leakVerdict(r)
	var notes []string
	if len(r.VPN) == 0 {
		notes = append(notes, "VPNs are spotted by their adapter names; one with an unusual name may be missed.")
	}
	ui.Verdict(st, msg, notes...)
	ui.Println("")
	if *asJSON {
		printJSON(struct {
			probe.LeakResult
			Verdict verdict `json:"verdict"`
		}{r, verdict{st.String(), msg}})
	}
	return exitFor(st)
}
