package cli

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

// dhcpVerdict: exactly one DHCP server is healthy; two or more means a
// rogue one (a spare router, a repeater in router mode) handing out wrong
// settings. viaAP means the one server is the Wi-Fi access point we're on.
func dhcpVerdict(r probe.DHCPResult, gw string, viaAP bool) (ui.Status, string) {
	switch n := len(r.Servers); {
	case r.Unavailable != "":
		return ui.Skip, "Can't listen for DHCP answers without administrator rights. Run it as administrator (or with sudo) to check for a second DHCP server."
	case r.Error != "":
		return ui.Warn, "The DHCP check failed: " + r.Error + "."
	case n == 0:
		return ui.Warn, "No DHCP server answered. That's fine if addresses here are set by hand; otherwise new devices can't get online."
	case n == 1 && gw != "" && r.Servers[0].ServerID != gw && viaAP && r.Servers[0].Router == gw:
		return ui.OK, fmt.Sprintf("One DHCP server (%s): the Wi-Fi access point you're connected to, handing out your router's (%s) settings. That's normal for a Wi-Fi extender or mesh point.", r.Servers[0].ServerID, gw)
	case n == 1 && gw != "" && r.Servers[0].ServerID != gw:
		return ui.OK, fmt.Sprintf("One DHCP server (%s). It isn't your router (%s), which is fine if you set it up that way, a Pi-hole for example.", r.Servers[0].ServerID, gw)
	case n == 1:
		return ui.OK, fmt.Sprintf("One DHCP server (%s), as it should be.", r.Servers[0].ServerID)
	}
	var ids []string
	for _, s := range r.Servers {
		ids = append(ids, s.ServerID)
	}
	return ui.Bad, fmt.Sprintf("%d DHCP servers answered (%s). The extra one, often a spare router or a repeater still in router mode, hands out wrong addresses and devices drop off at random. Find it by the address it offers.",
		len(r.Servers), strings.Join(ids, ", "))
}

// sameDevice reports whether a LAN MAC and a Wi-Fi BSSID belong to one box.
// Access points often number their radios on from the LAN MAC, so only the
// last octet may differ.
func sameDevice(mac, bssid string) bool {
	if len(mac) != 17 || len(bssid) != 17 {
		return false
	}
	return strings.EqualFold(mac[:14], bssid[:14])
}

func cmdDHCP(args []string) int {
	fs := flag.NewFlagSet("dhcp", flag.ExitOnError)
	wait := fs.Duration("w", 3*time.Second, "how long to wait for offers")
	asJSON := fs.Bool("json", false, "machine-readable output")
	parseInterspersed(fs, args)
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ui.Title("dhcp")
	ui.Open("DHCP servers")
	defer ui.Close()
	gw := ""
	if ip, err := probe.DefaultGateway(); err == nil {
		gw = ip.String()
	}
	t := ui.Begin("DHCP")
	t.Progress("broadcasting a discover and listening for offers…")
	r := probe.FindDHCPServers(ctx, *wait)
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	for _, s := range r.Servers {
		st := ui.OK
		if len(r.Servers) > 1 && s.ServerID != gw {
			st = ui.Bad
		}
		extra := "offers " + s.Offered
		if s.Router != "" {
			extra += " · router " + s.Router
		}
		if len(s.DNS) > 0 {
			extra += " · DNS " + strings.Join(s.DNS, ", ")
		}
		ui.Println(ui.Row("Server", st, s.ServerID, "", ui.Dim(extra)))
	}
	viaAP := false
	if len(r.Servers) == 1 && gw != "" && r.Servers[0].ServerID != gw {
		w := probe.ReadWifi(ctx)
		viaAP = w.Connected && sameDevice(probe.MACOf(ctx, net.ParseIP(r.Servers[0].ServerID)), w.BSSID)
	}
	st, msg := dhcpVerdict(r, gw, viaAP)
	if len(r.Servers) == 0 && r.Unavailable == "" {
		ui.Println(ui.Row("Server", st, "none answered", "", ""))
	}
	if r.Unavailable != "" {
		ui.Println(ui.Row("DHCP", ui.Skip, "not checked", "", ui.Dim(r.Unavailable)))
	}
	var notes []string
	if r.Unavailable == "" {
		notes = append(notes, "Only a discover was sent; no address was taken.")
	}
	ui.Verdict(st, msg, notes...)
	ui.Println("")
	if *asJSON {
		printJSON(struct {
			probe.DHCPResult
			Verdict verdict `json:"verdict"`
		}{r, verdict{st.String(), msg}})
	}
	return exitFor(st)
}
