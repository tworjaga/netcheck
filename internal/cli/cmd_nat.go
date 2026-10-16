package cli

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

// natType turns the STUN mapping and what the router said over UPnP into
// the Open / Moderate / Strict that consoles show. wan is the router's WAN
// address, nil when the router doesn't answer UPnP.
func natType(m probe.NATMapping, wan net.IP) (label string, st ui.Status, msg string) {
	switch m.Behaviour {
	case "udp-blocked":
		return "Strict", ui.Warn, "No STUN server answered over UDP, so UDP looks blocked here. Online games and voice chat need it; they'll fall back to slower relays, or not connect."
	case "none":
		return "Open", ui.OK, "This computer has a public address of its own, with no NAT in between: Open. Games can be reached directly (if the firewall lets them)."
	case "address-dependent":
		return "Strict", ui.Warn, "Your NAT gives every destination a different port (symmetric NAT), which consoles call Strict. Peer-to-peer games and voice chat may fail to connect or fall back to relays. The usual causes are carrier-grade NAT or a second router; forwarding the game's ports or a DMZ for the console can help."
	case "endpoint-independent":
		switch {
		case wan != nil && m.Public != "" && wan.String() == m.Public:
			return "Open", ui.OK, "Your NAT keeps one port per connection, and your router offers UPnP with its own public address, so games can open the ports they need: Open."
		case wan != nil:
			return "Moderate", ui.Warn, fmt.Sprintf("Your NAT keeps one port per connection, but your router's internet address (%s) isn't your public one (%s): there's another NAT in front of it (carrier-grade, or a second router), and ports can't be opened through that: Moderate. Most games still work; hosting and some voice chats may not.", wan, m.Public)
		}
		return "Moderate", ui.Warn, "Your NAT keeps one port per connection, but your router doesn't offer UPnP, so games can't open ports themselves: Moderate. Most games still work; turning UPnP on, or forwarding the game's ports, would make it Open."
	}
	return "unknown", ui.Skip, "Only one STUN server answered, so how your NAT maps ports can't be told. Try again in a moment."
}

// mappingLabel describes the STUN result for the Mapping row.
func mappingLabel(m probe.NATMapping) string {
	switch m.Behaviour {
	case "none":
		return "no NAT"
	case "endpoint-independent":
		return "same port for every destination"
	case "address-dependent":
		return "new port per destination"
	case "udp-blocked":
		return "UDP blocked"
	}
	return "unknown"
}

func cmdNAT(args []string) int {
	fs := flag.NewFlagSet("nat", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	parseInterspersed(fs, args)
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ui.Title("nat")
	ui.Open("NAT")
	defer ui.Close()
	t := ui.Begin("STUN")
	t.Progress("asking STUN servers where your packets come from…")
	m := probe.DetectNATMapping(ctx)
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	for _, a := range m.Answers {
		if a.Error != "" {
			ui.Println(ui.Row("STUN", ui.Skip, a.Server, "–", ui.Dim(a.Error)))
			continue
		}
		ui.Println(ui.Row("STUN", ui.OK, a.Server, "", ui.Dim("sees "+a.Mapped)))
	}
	mst := ui.OK
	if m.Behaviour == "address-dependent" || m.Behaviour == "udp-blocked" {
		mst = ui.Warn
	}
	note := ""
	if m.PortPreserved {
		note = "port kept"
	}
	ui.Println(ui.Row("Mapping", mst, mappingLabel(m), "", ui.Dim(note)))

	// Open vs Moderate depends on whether games can open ports: UPnP on a
	// router that has the public address itself.
	var wan net.IP
	if m.Behaviour == "endpoint-independent" {
		t = ui.Begin("UPnP")
		if gw, err := probe.DefaultGateway(); err == nil {
			t.Progress("asking " + gw.String() + "…")
			wan, _ = probe.RouterWANIP(ctx, gw)
		}
		t.Clear()
		if ctx.Err() != nil {
			return 130
		}
		if wan != nil {
			ui.Println(ui.Row("UPnP", ui.OK, "available", "", ui.Dim("router WAN "+wan.String())))
		} else {
			ui.Println(ui.Row("UPnP", ui.Skip, "not offered", "–", ui.Dim("the router doesn't answer UPnP")))
		}
	}
	label, st, msg := natType(m, wan)
	ui.Println(ui.Row("NAT type", st, label, "", ""))
	ui.Verdict(st, msg)
	ui.Println("")
	if *asJSON {
		rep := struct {
			probe.NATMapping
			RouterWAN string  `json:"router_wan_ip,omitempty"`
			Type      string  `json:"nat_type"`
			Verdict   verdict `json:"verdict"`
		}{m, "", label, verdict{st.String(), msg}}
		if wan != nil {
			rep.RouterWAN = wan.String()
		}
		printJSON(rep)
	}
	return exitFor(st)
}
