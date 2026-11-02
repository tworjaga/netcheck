// Package portx answers "why can't anyone reach my server on this port?"
// by walking the layers in between, and checks firewall expectations
// ("this host:port should be allowed / blocked") from this machine.
package portx

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/sockets"
)

// Status of one layer.
type Status string

const (
	OK      Status = "ok"
	Warn    Status = "warn"
	Bad     Status = "bad"
	Unknown Status = "unknown" // couldn't be checked from here
)

// Layer is one step between a client on the internet and the program.
type Layer struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

// Layer names, in order from the program out.
const (
	LayerListen   = "Program"
	LayerFirewall = "Firewall"
	LayerRouter   = "Router"
	LayerInternet = "Internet"
	LayerOutside  = "From outside"
)

// Report is the walk for one port.
type Report struct {
	Port     int                   `json:"port"`
	Proto    string                `json:"proto"`
	Program  string                `json:"program,omitempty"`
	Layers   []Layer               `json:"layers"`
	External *probe.ExternalResult `json:"external,omitempty"`
}

// Blocking is the first layer that stops connections, or nil.
func (r Report) Blocking() *Layer {
	for i := range r.Layers {
		if r.Layers[i].Status == Bad {
			return &r.Layers[i]
		}
	}
	return nil
}

// Options for a diagnosis.
type Options struct {
	Helper string // port-check helper URL, for the test from outside
	// External, when set, tests from outside instead of the helper (a
	// netcheck agent, say).
	External func(ctx context.Context, port int) probe.ExternalResult
}

// FirewallVerdict is what a platform's firewall check concludes.
type FirewallVerdict struct {
	Status Status
	Title  string
	Detail string
	Fix    string
}

// Test seams.
var (
	listSockets = sockets.List
	firewall    = platformFirewall
	gateway     = probe.DefaultGateway
	localIP     = probe.LocalIP
	mappings    = probe.PortMappings
	routerWAN   = probe.RouterWANIP
	publicIP    = probe.PublicIP
	external    = probe.ExternalCheck
	ipv6Global  = func() []string {
		var out []string
		addrs, _ := net.InterfaceAddrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() == nil && n.IP.IsGlobalUnicast() && !n.IP.IsPrivate() {
				out = append(out, n.IP.String())
			}
		}
		return out
	}
)

// listenLayer: is anything listening, and on which addresses?
func listenLayer(port int, proto string) (Layer, string) {
	l := Layer{Name: LayerListen}
	snap, err := listSockets()
	if err != nil {
		l.Status, l.Title, l.Detail = Unknown, "Couldn't list the sockets", err.Error()
		return l, ""
	}
	var mine []sockets.Socket
	for _, s := range sockets.Listeners(snap.Sockets) {
		if s.Proto == proto && s.LocalPort == port {
			mine = append(mine, s)
		}
	}
	P := strings.ToUpper(proto)
	if len(mine) == 0 {
		l.Status, l.Title = Bad, fmt.Sprintf("Nothing listens on %s %d", P, port)
		l.Fix = "Start the server, and check which port its settings name; `netcheck listen` shows what does listen."
		return l, ""
	}
	prog := mine[0].Process
	who := prog
	if who == "" {
		who = "a program"
	}
	local, all := true, false
	var addrs []string
	for _, s := range mine {
		addrs = append(addrs, s.LocalIP)
		switch s.Scope() {
		case "all":
			all, local = true, false
		case "interface":
			local = false
		}
	}
	switch {
	case local:
		l.Status, l.Title = Bad, fmt.Sprintf("%s listens on %s %d, but only for this machine", who, P, port)
		l.Detail = "bound to " + strings.Join(addrs, ", ")
		l.Fix = "Make the server listen on all addresses (0.0.0.0, or :: for IPv6 too) instead of 127.0.0.1 / localhost; the setting is usually called bind, host or listen."
	case all:
		l.Status, l.Title = OK, fmt.Sprintf("%s listens on %s %d on every address", who, P, port)
	default:
		l.Status, l.Title = OK, fmt.Sprintf("%s listens on %s %d", who, P, port)
		l.Detail = "only on " + strings.Join(addrs, ", ") + "; connections to other addresses of this machine won't reach it"
	}
	return l, prog
}

// routerLayer: does the router forward the port to this machine?
func routerLayer(ctx context.Context, port int, proto string) Layer {
	l := Layer{Name: LayerRouter}
	me := localIP()
	if me != nil && !me.IsPrivate() && !me.IsLoopback() {
		l.Status, l.Title = OK, "This machine has a public address of its own; no forwarding needed"
		l.Detail = me.String()
		return l
	}
	gw, err := gateway()
	if err != nil {
		l.Status, l.Title = Unknown, "No router found"
		return l
	}
	ms, err := mappings(ctx, gw)
	if err != nil {
		l.Status, l.Title = Unknown, "The router doesn't show its port forwarding (no UPnP)"
		l.Fix = fmt.Sprintf("Open the router's settings (http://%s) and check that port %d (%s) is forwarded to %s.", gw, port, strings.ToUpper(proto), me)
		return l
	}
	var other []string
	for _, m := range ms {
		if !strings.EqualFold(m.Protocol, proto) || (m.ExternalPort != port && m.InternalPort != port) {
			continue
		}
		if m.Client == me.String() {
			if !m.Enabled {
				l.Status, l.Title = Bad, fmt.Sprintf("The router's forwarding for port %d is switched off", m.ExternalPort)
				l.Fix = "Enable the rule in the router, or restart the program that asked for it."
				return l
			}
			l.Status = OK
			l.Title = fmt.Sprintf("The router forwards port %d to this machine", m.ExternalPort)
			if m.InternalPort != m.ExternalPort {
				l.Title = fmt.Sprintf("The router forwards its port %d to this machine's port %d", m.ExternalPort, m.InternalPort)
				if m.InternalPort != port {
					l.Status = Bad
					l.Fix = fmt.Sprintf("The rule ends at port %d, not %d: change one or the other.", m.InternalPort, port)
				}
			}
			if m.Description != "" {
				l.Detail = "set up by " + m.Description
			}
			return l
		}
		other = append(other, fmt.Sprintf("%s:%d", m.Client, m.InternalPort))
	}
	if len(other) > 0 {
		l.Status, l.Title = Bad, fmt.Sprintf("The router forwards port %d to another device", port)
		l.Detail = "to " + strings.Join(other, ", ") + "; this machine is " + me.String()
		l.Fix = fmt.Sprintf("Point the forwarding rule at %s, or give this machine the address it names.", me)
		return l
	}
	l.Status, l.Title = Warn, fmt.Sprintf("No forwarding for port %d shows over UPnP", port)
	l.Detail = "rules added by hand in the router's settings don't show here"
	l.Fix = fmt.Sprintf("In the router's settings (http://%s), forward %s port %d to %s, unless you already have.", gw, strings.ToUpper(proto), port, me)
	return l
}

// internetLayer: can connections from the internet reach this network at
// all (carrier-grade or double NAT), and is there IPv6?
func internetLayer(ctx context.Context) Layer {
	l := Layer{Name: LayerInternet}
	pub, _ := publicIP(ctx)
	var wan net.IP
	if gw, err := gateway(); err == nil {
		wan, _ = routerWAN(ctx, gw)
	}
	v6 := ipv6Global()
	v6note := ""
	if len(v6) > 0 {
		v6note = fmt.Sprintf("This machine also has a public IPv6 address (%s): clients with IPv6 can reach it directly, no forwarding needed, if the firewall lets them.", v6[0])
	}
	switch {
	case wan == nil && pub == nil:
		l.Status, l.Title = Unknown, "Couldn't learn the public address"
		l.Detail = v6note
		return l
	case wan == nil:
		l.Status, l.Title, l.Detail = Unknown, "Public address "+pub.String(), "the router didn't say its own internet address, so carrier-grade NAT can't be ruled out"
		if v6note != "" {
			l.Detail += ". " + v6note
		}
		return l
	}
	n := probe.ClassifyNAT(wan, pub)
	switch n.Kind {
	case "cgnat":
		l.Status, l.Title = Bad, "Your ISP shares one public address between customers (carrier-grade NAT)"
		l.Detail = "the router's internet address is " + wan.String()
		l.Fix = "Incoming connections can't reach you over IPv4. Ask the ISP for a public IPv4 address, use IPv6, or a tunnel (Cloudflare Tunnel, Tailscale, a VPS)."
		if v6note != "" {
			l.Fix += " " + v6note
		}
	case "double":
		l.Status, l.Title = Warn, "There's a second router in front of yours (double NAT)"
		l.Detail = "your router's internet address is " + wan.String() + ", a private one"
		l.Fix = "Forward the port on the outer router too, or put it in bridge mode."
	default:
		l.Status, l.Title = OK, "Your router has the public address "+wan.String()
		l.Detail = v6note
	}
	return l
}

// Diagnose walks the layers for one port.
func Diagnose(ctx context.Context, port int, proto string, o Options) Report {
	r := Report{Port: port, Proto: proto}
	listen, prog := listenLayer(port, proto)
	r.Program = prog
	var fw FirewallVerdict
	var router, inet Layer
	var ext *probe.ExternalResult
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); fw = firewall(ctx, port, proto, prog) }()
	go func() { defer wg.Done(); router = routerLayer(ctx, port, proto) }()
	go func() { defer wg.Done(); inet = internetLayer(ctx) }()
	if (o.Helper != "" || o.External != nil) && proto == "tcp" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var e probe.ExternalResult
			if o.External != nil {
				e = o.External(ctx, port)
			} else {
				e = external(ctx, o.Helper, port)
			}
			ext = &e
		}()
	}
	wg.Wait()
	out := Layer{Name: LayerOutside, Status: Unknown, Title: "Not tested from outside",
		Fix: "Test the last step for real from a machine outside your network: a paired agent (--from NAME; see netcheck agent) or the port-check helper (--helper URL)."}
	switch {
	case proto != "tcp":
		out.Title, out.Fix = "UDP can't be tested from outside: an open UDP port usually stays silent", ""
	case ext != nil && ext.Error != "":
		out.Title, out.Detail = "The test from outside failed", ext.Error
		out.Fix = ""
	case ext != nil && ext.Open:
		out.Status, out.Title = OK, fmt.Sprintf("Reachable from the internet at %s:%d", ext.IP, port)
		out.Fix = ""
	case ext != nil:
		out.Status, out.Title = Bad, fmt.Sprintf("Not reachable from the internet at %s:%d", ext.IP, port)
		out.Fix = ""
	}
	r.External = ext
	r.Layers = []Layer{listen, {Name: LayerFirewall, Status: fw.Status, Title: fw.Title, Detail: fw.Detail, Fix: fw.Fix}, router, inet, out}
	return r
}
