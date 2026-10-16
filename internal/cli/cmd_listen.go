package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/sockets"
	"github.com/tworjaga/netcheck/internal/ui"
)

// listSockets is a test seam.
var listSockets = sockets.List

// knownPorts names the usual service on a port.
var knownPorts = map[string]string{
	"tcp/21": "FTP", "tcp/22": "SSH", "tcp/23": "Telnet", "tcp/25": "SMTP", "udp/53": "DNS", "tcp/53": "DNS",
	"udp/67": "DHCP server", "udp/68": "DHCP client", "tcp/80": "web (HTTP)", "tcp/110": "POP3", "udp/123": "NTP",
	"tcp/135": "Windows RPC", "udp/137": "NetBIOS names", "udp/138": "NetBIOS datagrams", "tcp/139": "NetBIOS sessions",
	"tcp/143": "IMAP", "udp/161": "SNMP", "tcp/443": "web (HTTPS)", "udp/443": "HTTP/3", "tcp/445": "SMB file sharing",
	"udp/500": "IPsec", "tcp/587": "mail submission", "tcp/631": "printing (IPP)", "tcp/993": "IMAPS", "tcp/995": "POP3S",
	"tcp/1433": "SQL Server", "udp/1900": "SSDP / UPnP", "tcp/2375": "Docker API", "tcp/2376": "Docker API (TLS)",
	"tcp/3000": "dev server", "tcp/3306": "MySQL", "tcp/3389": "Remote Desktop", "udp/3389": "Remote Desktop",
	"udp/3702": "WS-Discovery", "tcp/5000": "dev server", "tcp/5040": "Windows device connections", "udp/5050": "Windows device connections",
	"udp/5353": "mDNS", "udp/5355": "LLMNR", "tcp/5357": "WS-Discovery", "tcp/5432": "PostgreSQL", "tcp/5173": "dev server",
	"tcp/5900": "VNC", "tcp/5985": "WinRM", "tcp/5986": "WinRM (TLS)", "tcp/6379": "Redis", "tcp/7680": "Windows Delivery Optimization",
	"tcp/8000": "dev server", "tcp/8080": "web (alternate)", "tcp/8443": "web (alternate)", "tcp/8888": "dev server",
	"tcp/9200": "Elasticsearch", "tcp/11211": "memcached", "udp/11211": "memcached", "tcp/27017": "MongoDB",
}

// rpcHosts are the Windows processes that take dynamic RPC ports.
var rpcHosts = map[string]bool{"lsass.exe": true, "wininit.exe": true, "svchost.exe": true, "spoolsv.exe": true, "services.exe": true}

func portName(proto string, port int, process string) string {
	if n, ok := knownPorts[fmt.Sprintf("%s/%d", proto, port)]; ok {
		return n
	}
	if proto == "tcp" && port >= 49664 && rpcHosts[strings.ToLower(process)] {
		return "Windows RPC"
	}
	return ""
}

// risk is what an open service on a port means when the network can reach
// it: the status and why.
type risk struct {
	st  ui.Status
	why string
}

var risky = map[string]risk{
	"tcp/23":    {ui.Bad, "Telnet sends passwords in the clear"},
	"tcp/2375":  {ui.Bad, "an unencrypted Docker API gives whoever reaches it full control of the machine"},
	"tcp/6379":  {ui.Bad, "Redis has no password by default"},
	"tcp/27017": {ui.Bad, "MongoDB is a classic target for data theft"},
	"tcp/9200":  {ui.Bad, "Elasticsearch has no login by default"},
	"tcp/11211": {ui.Bad, "memcached is used for DDoS amplification"},
	"udp/11211": {ui.Bad, "memcached is used for DDoS amplification"},
	"tcp/3306":  {ui.Warn, "databases are better kept to this machine or a private network"},
	"tcp/5432":  {ui.Warn, "databases are better kept to this machine or a private network"},
	"tcp/1433":  {ui.Warn, "databases are better kept to this machine or a private network"},
	"tcp/3389":  {ui.Warn, "Remote Desktop is a favourite target for password guessing"},
	"tcp/5900":  {ui.Warn, "VNC often has weak or no passwords"},
	"tcp/5985":  {ui.Warn, "WinRM gives remote command access"},
	"tcp/21":    {ui.Warn, "FTP sends passwords in the clear"},
	"udp/161":   {ui.Warn, "SNMP with the default community string gives away the configuration"},
	"tcp/3000":  {ui.Skip, "a development server"}, "tcp/5000": {ui.Skip, "a development server"}, "tcp/5173": {ui.Skip, "a development server"},
	"tcp/8000": {ui.Skip, "a development server"}, "tcp/8888": {ui.Skip, "a development server"},
}

// listener is one service: a program on a port, on one or more addresses.
type listener struct {
	Proto   string   `json:"proto"`
	Port    int      `json:"port"`
	PID     int      `json:"pid,omitempty"`
	Process string   `json:"process,omitempty"`
	Service string   `json:"service,omitempty"`
	Scope   string   `json:"scope"` // "local", "network", "interface"
	Addrs   []string `json:"addrs"`
}

// group folds sockets of one program on one port (IPv4 and IPv6, several
// interfaces) into one listener.
func group(ss []sockets.Socket, all bool) []listener {
	idx := map[string]int{}
	var out []listener
	for _, s := range sockets.Listeners(ss) {
		if s.Proto == "udp" && s.LocalPort >= 49152 && !all {
			continue // the ephemeral range: programs' own outgoing traffic
		}
		key := fmt.Sprintf("%s/%d/%d", s.Proto, s.LocalPort, s.PID)
		i, ok := idx[key]
		if !ok {
			i = len(out)
			idx[key] = i
			out = append(out, listener{Proto: s.Proto, Port: s.LocalPort, PID: s.PID, Process: s.Process, Service: portName(s.Proto, s.LocalPort, s.Process), Scope: "local"})
		}
		l := &out[i]
		l.Addrs = append(l.Addrs, s.LocalIP)
		switch s.Scope() {
		case "all":
			l.Scope = "network"
		case "interface":
			if l.Scope == "local" {
				l.Scope = "interface"
			}
		}
	}
	// Open to the network first, then by port.
	rank := map[string]int{"network": 0, "interface": 1, "local": 2}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Scope] != rank[out[j].Scope] {
			return rank[out[i].Scope] < rank[out[j].Scope]
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func reach(l listener) string {
	switch l.Scope {
	case "network":
		return "the network"
	case "local":
		return ui.Dim("this machine only")
	}
	var v []string
	for _, a := range l.Addrs {
		if !strings.HasPrefix(a, "fe80:") {
			v = append(v, a)
		}
	}
	if len(v) == 0 {
		v = l.Addrs
	}
	if len(v) > 2 {
		return fmt.Sprintf("%s and %d more", strings.Join(v[:2], ", "), len(v)-2)
	}
	return strings.Join(v, ", ")
}

// listenFindings judges what's open to the network.
func listenFindings(ls []listener) []struct {
	st  ui.Status
	msg string
} {
	var out []struct {
		st  ui.Status
		msg string
	}
	for _, l := range ls {
		if l.Scope == "local" {
			continue
		}
		r, ok := risky[fmt.Sprintf("%s/%d", l.Proto, l.Port)]
		if !ok {
			continue
		}
		who := l.Process
		if who == "" {
			who = "a program"
		}
		msg := fmt.Sprintf("%s (%s %d, %s) accepts connections from the network: %s.", firstNonEmpty(l.Service, "port"), strings.ToUpper(l.Proto), l.Port, who, r.why)
		switch r.st {
		case ui.Skip:
			msg = fmt.Sprintf("%s on %s %d is reachable from the network; bind it to 127.0.0.1 unless others should see it.", strings.ToUpper(r.why[:1])+r.why[1:]+" ("+who+")", strings.ToUpper(l.Proto), l.Port)
		default:
			msg += " Bind it to 127.0.0.1, or limit it in the firewall."
		}
		out = append(out, struct {
			st  ui.Status
			msg string
		}{r.st, msg})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].st == ui.Bad && out[j].st != ui.Bad })
	return out
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

func listenVerdict(ls []listener, partial bool) (ui.Status, string, []string) {
	open, unknown, programs := 0, 0, map[string]bool{}
	for _, l := range ls {
		if l.Process == "" {
			unknown++
		} else {
			programs[l.Process] = true
		}
		if l.Scope != "local" {
			open++
		}
	}
	st := ui.OK
	verb := "listen"
	if len(programs) == 1 {
		verb = "listens"
	}
	msg := fmt.Sprintf("%s %s on %s; %d open to the network, the rest to this machine only.", plural(len(programs), "program", "programs"), verb, plural(len(ls), "port", "ports"), open)
	if len(programs) == 0 {
		msg = fmt.Sprintf("%s listening; %d open to the network, the rest to this machine only.", plural(len(ls), "port", "ports"), open)
	}
	if len(ls) == 0 {
		msg = "Nothing listens for connections."
	}
	var notes []string
	for _, f := range listenFindings(ls) {
		if f.st == ui.Bad || f.st == ui.Warn && st != ui.Bad {
			st = max(st, f.st)
		}
		notes = append(notes, f.msg)
	}
	if open > 0 {
		notes = append(notes, "Open to the network means other machines can connect unless a firewall stops them.")
	}
	if unknown > 0 && !partial {
		notes = append(notes, fmt.Sprintf("%s belong to no process visible here: the system itself, or another container or namespace.", plural(unknown, "port", "ports")))
	}
	if partial {
		hint := "run it with sudo"
		if runtime.GOOS == "windows" {
			hint = "run it as administrator"
		}
		notes = append(notes, "Some programs belong to other users and show without a name; "+hint+" to see them all.")
	}
	return st, msg, notes
}

func listenTable(ls []listener) ui.Table {
	tb := ui.Table{Headers: []string{"Port", "Program", "Service", "Reachable from"}}
	risks := map[int]ui.Status{}
	for _, l := range ls {
		if r, ok := risky[fmt.Sprintf("%s/%d", l.Proto, l.Port)]; ok && l.Scope != "local" {
			risks[l.Port] = r.st
		}
	}
	for _, l := range ls {
		st := ui.OK
		if l.Scope != "local" {
			st = ui.Skip
			if r, ok := risks[l.Port]; ok && r != ui.Skip {
				st = r
			}
		}
		prog := ui.Cut(strings.TrimSuffix(l.Process, ".exe"), 22)
		if prog == "" {
			prog = ui.Dim("unknown")
		}
		tb.Rows = append(tb.Rows, ui.TableRow{Status: st, Cells: []string{fmt.Sprintf("%s %d", strings.ToUpper(l.Proto), l.Port), prog, ui.Cut(l.Service, 18), reach(l)}})
	}
	return tb
}

func cmdListen(args []string) int {
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	common := adv.Register(fs)
	all := fs.Bool("all", false, "include UDP ports in the ephemeral range (49152 and up)")
	tcpOnly := fs.Bool("tcp", false, "TCP only")
	pos := parseInterspersed(fs, args)
	ui.SetQuiet(common.JSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if len(pos) > 0 {
		fmt.Fprintln(os.Stderr, "netcheck listen: takes no arguments")
		fmt.Fprintln(os.Stderr, "usage: netcheck listen [--tcp] [--all]")
		return 2
	}
	rules, err := common.Rules()
	if err != nil {
		fmt.Fprintln(os.Stderr, "netcheck listen: "+err.Error())
		return 2
	}
	look := func() ([]listener, sockets.Snapshot, error) {
		snap, err := listSockets()
		if err != nil {
			return nil, snap, err
		}
		ls := group(snap.Sockets, *all)
		if *tcpOnly {
			var t []listener
			for _, l := range ls {
				if l.Proto == "tcp" {
					t = append(t, l)
				}
			}
			ls = t
		}
		return ls, snap, nil
	}
	ui.Title("listen")
	if common.Watch > 0 {
		adv.Watch(ctx, common.Watch, func(context.Context) []string {
			ls, snap, err := look()
			if err != nil {
				return []string{"  " + ui.Bad.Paint(err.Error())}
			}
			st, msg, _ := listenVerdict(ls, snap.Partial)
			return append(listenTable(ls).Lines(ui.PanelWidth()), "", "  "+st.Paint(msg))
		})
		return 0
	}
	ls, snap, err := look()
	if err != nil {
		ui.Verdict(ui.Bad, "Couldn't list the sockets: "+err.Error()+".")
		ui.Println("")
		return 1
	}
	st, msg, notes := listenVerdict(ls, snap.Partial)
	open := 0
	for _, l := range ls {
		if l.Scope != "local" {
			open++
		}
	}
	broken := adv.Broken(rules, adv.Default{Metric: "open", Op: '>'}, map[string]float64{"open": float64(open), "ports": float64(len(ls))})
	ui.Open(fmt.Sprintf("Listening on this machine · %s", plural(len(ls), "port", "ports")))
	for _, l := range listenTable(ls).Lines(ui.PanelWidth()) {
		ui.Println(l)
	}
	ui.Close()
	if !common.Raw {
		ui.Verdict(st, msg, append(notes, broken...)...)
	}
	ui.Println("")
	if common.JSON {
		adv.Envelope{Tool: "listen", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg},
			Data: map[string]any{"listeners": ls, "partial": snap.Partial, "method": snap.Method}, FailedOn: broken}.Write(os.Stdout)
	}
	return adv.ExitCode(st.String(), broken)
}
