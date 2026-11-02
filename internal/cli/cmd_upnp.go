package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

// upnpVerdict explains the router's UPnP port mappings. Open ports aren't a
// fault in themselves, so a list is OK; the point is that people see them.
func upnpVerdict(ms []probe.PortMapping, err error) (ui.Status, string) {
	switch {
	case errors.Is(err, probe.ErrNoUPnP):
		return ui.OK, "Your router doesn't answer UPnP (it's off, or not offered), so apps can't open ports on it by themselves. That's the safer setting; games and calls may need ports forwarded by hand."
	case err != nil && len(ms) == 0:
		return ui.Warn, "Couldn't read the router's port mappings: " + err.Error() + "."
	case err != nil:
		return ui.Warn, fmt.Sprintf("The router stopped answering after %d port mappings, so the list may be incomplete.", len(ms))
	case len(ms) == 0:
		return ui.OK, "UPnP is on, but no device has opened a port on your router right now."
	case len(ms) == 1:
		return ui.OK, fmt.Sprintf("1 port is open to the internet through UPnP, to %s. If you don't recognise it, find the device with netcheck devices, or turn UPnP off in your router.", ms[0].Client)
	}
	clients := map[string]bool{}
	for _, m := range ms {
		clients[m.Client] = true
	}
	return ui.OK, fmt.Sprintf("%d ports are open to the internet through UPnP, to %d devices. Each lets the internet reach that device directly. If you don't recognise one, find the device with netcheck devices, or turn UPnP off in your router.", len(ms), len(clients))
}

// mappingNote is the dim tail of a mapping row.
func mappingNote(m probe.PortMapping) string {
	note := m.Description
	switch {
	case m.LeaseSeconds > 0:
		note = joinDot(note, leaseLeft(m.LeaseSeconds))
	default:
		note = joinDot(note, "permanent")
	}
	if m.RemoteHost != "" {
		note = joinDot(note, "only from "+m.RemoteHost)
	}
	if !m.Enabled {
		note = joinDot(note, "disabled")
	}
	return note
}

func cmdUPnP(args []string) int {
	fs := flag.NewFlagSet("upnp", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	parseInterspersed(fs, args)
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ui.Title("upnp")
	ui.Open("Port mappings")
	defer ui.Close()
	gw, gwErr := probe.DefaultGateway()
	if gwErr != nil {
		ui.Println(ui.Row("UPnP", ui.Skip, "unknown", "–", ui.Dim("couldn't detect your router")))
		ui.Println("")
		if *asJSON {
			printJSON(struct {
				Error string `json:"error"`
			}{"couldn't detect your router"})
		}
		return 0
	}
	t := ui.Begin("UPnP")
	t.Progress("asking " + gw.String() + " for its port mappings…")
	ms, err := probe.PortMappings(ctx, gw)
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	if len(ms) == 0 {
		label := "no ports open"
		if errors.Is(err, probe.ErrNoUPnP) {
			label = "not available"
		}
		ui.Println(ui.Row("UPnP", ui.OK, label, "", ui.Dim("router "+gw.String())))
	}
	for _, m := range ms {
		st := ui.OK
		if !m.Enabled {
			st = ui.Skip
		}
		ui.Println(ui.Row(m.Protocol, st, fmt.Sprintf("%d → %s:%d", m.ExternalPort, m.Client, m.InternalPort), "", ui.Dim(mappingNote(m))))
	}
	st, msg := upnpVerdict(ms, err)
	ui.Verdict(st, msg)
	ui.Println("")
	if *asJSON {
		rep := struct {
			Router    string              `json:"router"`
			Available bool                `json:"upnp_available"`
			Mappings  []probe.PortMapping `json:"mappings"`
			Verdict   verdict             `json:"verdict"`
		}{gw.String(), !errors.Is(err, probe.ErrNoUPnP), ms, verdict{st.String(), msg}}
		if rep.Mappings == nil {
			rep.Mappings = []probe.PortMapping{}
		}
		printJSON(rep)
	}
	return 0
}

// leaseLeft is a short "time left" for a mapping that expires.
func leaseLeft(s int) string {
	d := time.Duration(s) * time.Second
	if d >= time.Hour {
		return fmt.Sprintf("%d h left", int(d.Round(time.Hour)/time.Hour))
	}
	return fmt.Sprintf("%d min left", max(1, int(d.Round(time.Minute)/time.Minute)))
}
