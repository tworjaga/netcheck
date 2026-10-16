package cli

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

type hostPorts struct {
	IP   string           `json:"ip"`
	Name string           `json:"name,omitempty"`
	Open []probe.PortInfo `json:"open"`
}

type portsReport struct {
	Subnet   string                `json:"subnet,omitempty"`
	Hosts    []hostPorts           `json:"hosts,omitempty"`
	External *probe.ExternalResult `json:"external,omitempty"`
	Verdict  verdict               `json:"verdict"`
}

// legacyPorts are unencrypted remote-access protocols worth switching off.
var legacyPorts = map[int]string{23: "Telnet", 21: "FTP"}

// exposedRisky are services that are fine at home but dangerous if the
// router forwards them to the internet.
var exposedRisky = map[int]bool{21: true, 23: true, 139: true, 445: true, 3389: true, 5900: true}

// portsVerdict judges a local scan.
func portsVerdict(hosts []hostPorts) (ui.Status, string) {
	for _, h := range hosts {
		for _, p := range h.Open {
			if name, bad := legacyPorts[p.Port]; bad {
				return ui.Warn, fmt.Sprintf("%s (port %d) is open on %s. It sends passwords unencrypted, so switch it off if you can.", name, p.Port, h.IP)
			}
		}
	}
	return ui.OK, "Nothing alarming: no unencrypted remote-access ports are open on your devices."
}

// externalVerdict judges an internet-side check of one port.
func externalVerdict(r probe.ExternalResult) (ui.Status, string) {
	switch {
	case r.Error != "":
		return ui.Skip, "Couldn't check: " + r.Error + "."
	case r.Open && exposedRisky[r.Port]:
		return ui.Warn, fmt.Sprintf("Port %d is open to the whole internet on %s. That service isn't meant to be exposed; close the forwarding rule unless you set it up on purpose.", r.Port, r.IP)
	case r.Open:
		return ui.OK, fmt.Sprintf("Port %d is reachable from the internet on %s.", r.Port, r.IP)
	}
	return ui.OK, fmt.Sprintf("Port %d is closed from the internet on %s. If you expected it open, check the router's port forwarding, the device's firewall, and `netcheck ip` for carrier-grade NAT, which blocks all incoming connections.", r.Port, r.IP)
}

func portsLine(h hostPorts) string {
	var ps []string
	st := ui.OK
	for _, p := range h.Open {
		ps = append(ps, fmt.Sprintf("%d %s", p.Port, p.Service))
		if _, bad := legacyPorts[p.Port]; bad {
			st = ui.Warn
		}
	}
	name := h.Name
	if name == "" {
		name = "–"
	} else if len(name) > 22 {
		name = name[:21] + "…"
	}
	return "  " + st.Sym() + "  " + ui.Pad(h.IP, 16) + ui.Pad(name, 24) + ui.Dim(strings.Join(ps, " · "))
}

func scanHosts(ctx context.Context, targets []hostPorts, onDone func(done int)) []hostPorts {
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	sem := make(chan struct{}, 8)
	for i := range targets {
		sem <- struct{}{}
		wg.Add(1)
		go func(h *hostPorts) {
			defer wg.Done()
			defer func() { <-sem }()
			h.Open = probe.ScanPorts(ctx, h.IP, probe.CommonPorts, 700*time.Millisecond)
			mu.Lock()
			done++
			if onDone != nil {
				onDone(done)
			}
			mu.Unlock()
		}(&targets[i])
	}
	wg.Wait()
	return targets
}

func cmdPorts(args []string) int {
	fs := flag.NewFlagSet("ports", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	ext := fs.Int("x", 0, "check from the internet whether this `port` is reachable (needs a helper)")
	helper := fs.String("helper", os.Getenv("NETCHECK_PORT_HELPER"), "port-check helper URL (or set NETCHECK_PORT_HELPER)")
	pos := parseInterspersed(fs, args)
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ui.Title("ports")

	if *ext != 0 {
		return portsExternal(ctx, *ext, *helper, *asJSON)
	}

	var targets []hostPorts
	rep := portsReport{}
	if len(pos) > 0 {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, pos[0])
		if err != nil || len(ips) == 0 {
			ui.Println("  " + ui.Alert("Couldn't find "+pos[0]+".") + "\n")
			return 1
		}
		ip := ips[0].IP
		if !probe.IsLocalAddr(ip) {
			ui.Println("  " + ui.Alert("netcheck only scans devices on your own network.") + ui.Dim(" "+ip.String()+" is on the internet.") + "\n")
			return 2
		}
		targets = []hostPorts{{IP: ip.String(), Name: pos[0]}}
		if pos[0] == ip.String() {
			targets[0].Name = ""
		}
	} else {
		local := probe.LocalIP()
		subnet, err := probe.LocalSubnet(local)
		if err != nil {
			ui.Println("  " + ui.Alert("Couldn't find your local network.") + "\n")
			return 1
		}
		gw, _ := probe.DefaultGateway()
		t := ui.Begin("Finding devices")
		found := probe.DiscoverDevices(ctx, local, gw, subnet, probe.ScanOptions{MDNSWait: time.Second, SSDPWait: time.Second,
			OnFound: func(n int) { t.Progress(fmt.Sprintf("%d found", n)) }})
		t.Clear()
		rep.Subnet = found.Subnet
		for _, d := range found.Devices {
			targets = append(targets, hostPorts{IP: d.IP, Name: d.Name})
		}
	}
	if ctx.Err() != nil {
		ui.Println("  " + ui.Dim("Interrupted.") + "\n")
		return 130
	}

	ui.Open("Open ports")
	defer ui.Close()
	t := ui.Begin("Scanning")
	t.Progress(fmt.Sprintf("0 of %d devices", len(targets)))
	targets = scanHosts(ctx, targets, func(n int) { t.Progress(fmt.Sprintf("%d of %d devices", n, len(targets))) })
	t.Clear()
	if ctx.Err() != nil {
		ui.Println("  " + ui.Dim("Interrupted.") + "\n")
		return 130
	}

	quietHosts := 0
	for _, h := range targets {
		if len(h.Open) == 0 {
			quietHosts++
			continue
		}
		ui.Println(portsLine(h))
		rep.Hosts = append(rep.Hosts, h)
	}
	var notes []string
	if len(rep.Hosts) == 0 {
		ui.Println("  " + ui.Dim("No common ports are open on the devices checked."))
	} else if quietHosts > 0 {
		notes = append(notes, fmt.Sprintf("%d other devices have none of the %d common ports open.", quietHosts, len(probe.CommonPorts)))
	}
	st, msg := portsVerdict(rep.Hosts)
	ui.Verdict(st, msg, notes...)
	ui.Println("")
	rep.Verdict = verdict{st.String(), msg}
	if *asJSON {
		printJSON(rep)
	}
	return 0
}

func portsExternal(ctx context.Context, port int, helper string, asJSON bool) int {
	if port < 1 || port > 65535 {
		ui.Println("  " + ui.Alert("Port must be between 1 and 65535.") + "\n")
		return 2
	}
	if helper == "" {
		ui.Println("  " + ui.Dim("Checking from the internet needs a helper outside your network."))
		ui.Println("  " + ui.Dim("Set one with --helper URL or NETCHECK_PORT_HELPER. See the README (\"Port helper\")") + "\n")
		return 2
	}
	t := ui.Begin("Internet")
	t.Progress(fmt.Sprintf("asking the helper about port %d…", port))
	r := probe.ExternalCheck(ctx, helper, port)
	st, msg := externalVerdict(r)
	switch {
	case r.Error != "":
		t.Finish(ui.Row("Port "+fmt.Sprint(port), ui.Skip, "unknown", "–", ui.Dim("no result")))
	case r.Open:
		t.Finish(ui.Row("Port "+fmt.Sprint(port), st, "open", "", ui.Dim(r.IP)))
	default:
		t.Finish(ui.Row("Port "+fmt.Sprint(port), st, "closed", "", ui.Dim(r.IP)))
	}
	var notes []string
	if r.Error == "" {
		notes = append(notes, "The helper at "+helper+" saw your public address and this port.")
	}
	ui.Verdict(st, msg, notes...)
	ui.Println("")
	if asJSON {
		printJSON(portsReport{External: &r, Verdict: verdict{st.String(), msg}})
	}
	if r.Error != "" {
		return 1
	}
	return 0
}
