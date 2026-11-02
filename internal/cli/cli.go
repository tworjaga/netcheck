// netcheck: a quiet, good-looking diagnostic tool for home networks.
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/tworjaga/netcheck/internal/ui"
)

// version is set by Main from the root main.go, where releases bump it.
var version = "dev"

// command is one runnable feature. Every command works as a direct
// invocation (netcheck <name>) and from the menu.
type command struct {
	name string // direct command name
	menu string // label in the menu
	desc string // one-line description
	args string // usage hint
	run  func(args []string) int
}

// commands is the single source of truth for dispatch, help and the menu.
var commands = []command{
	{"doctor", "Doctor", "full check with a plain-English verdict", "[--fast]", cmdDoctor},
	{"speed", "Speed", "throughput and bufferbloat", "[-t 8s]", cmdSpeed},
	{"wifi", "Wi-Fi", "signal, channel, congestion", "[-n samples] [--walk]", cmdWifi},
	{"devices", "Devices", "who is on your network, and who's new", "[--no-save]", cmdDevices},
	{"route", "Route", "traceroute / mtr", "[host] [-c N] [-m hops]", cmdRoute},
	{"ports", "Ports", "local and external reachability", "[host] [-x port --helper URL]", cmdPorts},
	{"ping", "Ping", "latency, jitter, packet loss", "[host] [-c N] [--tcp] [-p port] [-i 250ms]", cmdPing},
	{"dns", "DNS", "resolver comparison and sanity", "[name]", cmdDNS},
	{"watch", "Watch", "live monitor, saved to history", "[-i 5s] [-d 1h] [--no-log] [--simple]", cmdWatch},
	{"history", "History", "trends from what watch recorded", "[--days 7]", cmdHistory},
	{"ip", "IP info", "public IP, ISP, CGNAT / double NAT", "", cmdIP},
	{"upnp", "UPnP ports", "ports apps opened on your router", "", cmdUPnP},
	{"nat", "NAT type", "Open / Moderate / Strict, for games and calls", "", cmdNAT},
	{"report", "Report", "a summary to send your ISP", "[--format md|json] [-o file] [--fast] [--compare last|file]", cmdReport},
	{"ipv6", "IPv6", "does it work, and is it preferred", "", cmdIPv6},
	{"dhcp", "DHCP", "rogue second DHCP server", "[-w 3s]", cmdDHCP},
	{"captive", "Captive portal", "is a login page intercepting the web", "", cmdCaptive},
	{"tls", "TLS / clock", "HTTPS interception and clock skew", "", cmdTLS},
	{"leak", "DNS leak", "who answers your DNS, VPN check", "", cmdLeak},
	{"dnssec", "DNSSEC", "does your DNS validate signatures", "", cmdDNSSEC},
	{"mtu", "MTU", "largest packet that gets through", "[host]", cmdMTU},
	{"dig", "DNS lookup", "any record from any server", "<name> [type] [@server] [--tcp|--dot|--doh] [--dnssec] [-x addr]", cmdDig},
	{"dnstrace", "DNS trace", "follow a name down from the root servers", "<name> [type] [--all]", cmdDNSTrace},
	{"propagate", "Propagation", "has a DNS change reached the resolvers yet", "<name> [type] [--expect value] [--watch 30s]", cmdPropagate},
	{"domain", "Domain audit", "nameservers, DNSSEC, mail records, blocklists, certificates", "<domain> [-f domains.txt] [--fail-on B]", cmdDomain},
	{"mail", "Mail check", "mail servers, STARTTLS, SPF lookups, MTA-STS", "<domain> [-f domains.txt] [--fail-on B]", cmdMail},
	{"http", "HTTP request", "timing waterfall, redirects, headers", "<url> [-X method] [-H 'Name: value'] [-d body] [-n 10] [--headers]", cmdHTTP},
	{"cert", "Certificates", "chain, names, expiry, TLS versions", "<host[:port]> [--starttls smtp|imap|pop3|ftp] [--sni name] [--fail-on 14d]", cmdCert},
	{"trace", "Trace by protocol", "route over ICMP, TCP or UDP, with each hop's network", "<host> [--tcp|--udp] [-p port] [-m 30] [-q 3] [-n]", cmdTrace},
	{"whois", "Whois", "who holds a domain, IP address or AS", "<domain | IP | AS number> [--raw] [--fail-on 30d]", cmdWhois},
	{"site", "Site audit", "HTTPS, HSTS, security headers, cookies, mixed content", "<url or host> [-f sites.txt] [--fail-on B]", cmdSite},
	{"listen", "Listening ports", "what listens here, which program, who can reach it", "[--tcp] [--all]", cmdListen},
	{"conns", "Connections", "open connections, by program, with who's at the other end", "[-p program] [--all] [--local] [-n]", cmdConns},
	{"port", "Port doctor", "why can't anyone reach my server on this port", "<port> [--udp] [--helper URL]", cmdPort},
	{"reach", "Reachability", "does the firewall allow what it should, block what it shouldn't", "<host:port> [allow|deny] ... | -f rules.txt", cmdReach},
	{"perf", "Throughput", "speed, loss and jitter between two machines", "--server | <host> [-t 5s] [-P 4] [--down|--up] [--udp 50M]", cmdPerf},
	{"wake", "Wake-on-LAN", "switch on a sleeping machine over the network", "<MAC | device name> [--wait 2m] [--ip broadcast]", cmdWake},
	{"open", "Open a port", "listen on a port and see who connects", "<port> [--udp] [-t 10m] [--bind address]", cmdOpen},
	{"connect", "Connect", "talk to any port: TCP, UDP or TLS (netcat)", "<host:port> [--udp] [--tls] [-s text] [-w 3s] [--crlf]", cmdConnect},
	{"uptime", "Uptime monitor", "your servers on one screen, with history", "<https://... | tcp://host:port | ping://host | dns://name> ... | -f servers.txt [--once] [--report]", cmdUptime},
	{"lanaudit", "LAN audit", "what's risky on my network, graded", "[--fail-on B]", cmdLanaudit},
	{"lanwatch", "LAN watch", "new devices, ARP spoofing, DHCP and DNS changes, live", "[-i 2m] [--notify] [--webhook URL] [--email ...]", cmdLanwatch},
	{"agent", "Agent", "run checks from another machine, through a Cloudflare Tunnel", "[--tunnel] [--uptime file] | install | status [name] | add <name> <url> <token> | list | remove <name>", cmdAgent},
	{"install", "Install", "put netcheck on your PATH", "[--yes]", cmdInstall},
	{"uninstall", "Uninstall", "remove it again", "[--yes]", cmdUninstall},
	{"update", "Update", "get the latest release", "[--check]", cmdUpdate},
}

// menuOrder is the home menu; extras live under "More…".
var menuOrder = []string{"doctor", "speed", "ping", "watch", "dns", "devices", "route", "wifi", "ports"}
var extras = []string{"report", "history", "ip", "upnp", "nat", "ipv6", "dhcp", "captive", "tls", "leak", "dnssec", "mtu"}

// setup commands run from the command line only, not the menu.
var setup = []string{"install", "uninstall", "update"}

func find(name string) *command {
	for i := range commands {
		if commands[i].name == name {
			return &commands[i]
		}
	}
	return nil
}

// Main runs netcheck with os.Args; v is the release version.
func Main(v string) {
	version = v
	args := os.Args[1:]
	if len(args) == 0 {
		os.Exit(home())
	}
	switch args[0] {
	case "help", "-h", "--help":
		usage()
		return
	case "version", "-v", "--version":
		fmt.Println("netcheck", version)
		return
	}
	if c := find(args[0]); c != nil {
		// --from NAME runs the check on a paired agent instead (port
		// handles it itself: the outside test is what moves there).
		if from, rest := splitFrom(args[1:]); from != "" && c.name != "port" && os.Getenv("NETCHECK_AGENT_CHILD") == "" {
			os.Exit(runRemote(c.name, from, rest))
		}
		os.Exit(c.run(args[1:]))
	}
	fmt.Fprintf(os.Stderr, "netcheck: unknown command %q\n\n", args[0])
	usage()
	os.Exit(2)
}

func usage() {
	ui.Title("v" + version)
	fmt.Println("  " + ui.Dim("usage") + "  netcheck [command] [options]")
	section := func(title string, names []string) {
		fmt.Println("\n  " + ui.Bold(title))
		// The description column fits the longest description here.
		w := 40
		for _, n := range names {
			if c := find(n); c != nil {
				w = max(w, ui.VisWidth(c.desc)+2)
			}
		}
		for _, n := range names {
			c := find(n)
			if c == nil {
				continue
			}
			line := "  " + ui.Accent(fmt.Sprintf("%-10s", c.name)) + ui.Pad(c.desc, w)
			if c.args != "" {
				line += ui.Dim(c.args)
			}
			fmt.Println(strings.TrimRight(line, " "))
		}
	}
	section("Normal", append(append([]string{}, menuOrder...), extras...))
	var built []string
	for _, t := range advancedTools {
		if find(t.cmd) != nil {
			built = append(built, t.cmd)
		}
	}
	if len(built) > 0 {
		section("Advanced", built)
	} else {
		fmt.Println("\n  " + ui.Bold("Advanced"))
		fmt.Println("  " + ui.Dim("Tools for sysadmins, arriving step by step; the menu lists what's planned (Tab)."))
	}
	section("Setup", setup)
	fmt.Println()
	fmt.Println("  " + ui.Dim("Run with no command for the interactive menu; Tab switches Normal and Advanced."))
	fmt.Println("  " + ui.Dim("Add --json to any command for machine-readable output."))
	fmt.Println()
}

// ---------------------------------------------------------------- home

func items(names []string, more bool) []ui.Item {
	var out []ui.Item
	for _, n := range names {
		if c := find(n); c != nil {
			out = append(out, ui.Item{Name: c.menu, Desc: c.desc, Ready: true, Usage: strings.TrimSpace("netcheck " + c.name + " " + c.args), About: about[c.name]})
		}
	}
	if more {
		out = append(out, ui.Item{Name: "More…", Desc: "report, history, IP, UPnP, IPv6, DHCP, TLS/clock, …", Ready: true, About: "More checks: the report for your ISP, history, IP and NAT, UPnP ports, NAT type, IPv6, DHCP, captive portals, TLS and your clock, DNS leaks, DNSSEC and MTU."})
	}
	return out
}

func home() int {
	if !ui.StdinTTY() || !ui.Interactive() {
		usage()
		return 0
	}
	sum := startSummary()
	cfg := loadConfig()
	mode := 0
	if cfg.MenuMode == "advanced" {
		mode = 1
	}
	normal, adv := items(menuOrder, true), advancedItems()
	sel := 0
	for {
		got, i := ui.MenuModes("", sum.String, []string{"Normal", "Advanced"}, [][]ui.Item{normal, adv}, mode, sel)
		if got != mode {
			mode, sel = got, 0
			cfg.MenuMode = map[int]string{0: "normal", 1: "advanced"}[mode]
			_ = saveConfig(cfg) // remembered for next time; losing it costs nothing
		}
		if i < 0 {
			return 0
		}
		sel = i
		var c *command
		switch {
		case mode == 0 && i >= len(menuOrder): // "More…"
			menuLoop("more", sum.String, extras, false)
			continue
		case mode == 0:
			c = find(menuOrder[i])
		default:
			c = find(advancedTools[i].cmd)
		}
		if c == nil {
			continue
		}
		c.run(nil)
		if !ui.WaitKey("⏎ back to menu · q quit") {
			return 0
		}
	}
}

// menuLoop runs a menu until the user quits it. With more set, the last row
// opens the extras submenu.
func menuLoop(title string, summary func() string, names []string, more bool) int {
	list := items(names, more)
	sel := 0
	for {
		i := ui.Menu(title, summary, list, sel)
		if i < 0 {
			return 0
		}
		sel = i
		if i >= len(names) { // "More…"
			menuLoop("more", summary, extras, false)
			continue
		}
		find(names[i]).run(nil)
		if !ui.WaitKey("⏎ back to menu · q quit") {
			return 0
		}
	}
}
