package cli

import (
	"strings"

	"github.com/tworjaga/netcheck/internal/ui"
)

// plannedTool is one entry of the Advanced menu. It is listed from the
// start, greyed out as "soon", and becomes runnable as soon as a command
// named cmd exists, so later steps only add the command.
type plannedTool struct {
	cmd, label, desc, about string
}

// advancedTools follows docs/TODO.md, in build order.
var advancedTools = []plannedTool{
	{"dig", "DNS lookup", "any record, any server", "Any DNS record from any server, with TTLs, flags and timing, over UDP, TCP, DNS over TLS or DNS over HTTPS."},
	{"dnstrace", "DNS trace", "resolve from the root down", "Follows a name from the root servers down, showing each delegation and flagging broken ones."},
	{"propagate", "Propagation", "who has the new record yet", "Asks public resolvers around the world and the domain's own nameservers whether a change has arrived."},
	{"domain", "Domain audit", "is my domain set up right", "Nameservers, DNSSEC, CAA, mail setup, blocklists and certificates, with a verdict and fix per area."},
	{"mail", "Mail audit", "SPF, DMARC, DKIM, MX", "The mail part of the domain audit: MX and STARTTLS, SPF, DMARC, DKIM, MTA-STS and reverse DNS."},
	{"http", "HTTP request", "timing waterfall, headers", "One request broken into DNS, connect, TLS, first byte and download, with redirects and headers."},
	{"cert", "Certificates", "chain, names, expiry", "The certificate chain, names and expiry for any host and port, including STARTTLS services."},
	{"trace", "Trace by protocol", "route over TCP or UDP", "The route to a host over TCP, UDP or ICMP, with the network owner of each hop."},
	{"whois", "Whois", "who owns an IP or domain", "Owner, registrar, dates and abuse contact for an IP address or domain, via RDAP."},
	{"site", "Site audit", "TLS grade, security headers", "How well a web server is configured: TLS, redirects and HSTS, security headers, graded A to F."},
	{"listen", "Listening ports", "what's open on this machine", "Every listening port on this computer, with the program that owns it and where it's reachable from."},
	{"conns", "Connections", "live connections by program", "Live connections from this computer, by program and remote network."},
	{"port", "Port doctor", "why can't anyone reach my server", "Follows a port from the program through the firewall and router to the internet and names the first thing in the way."},
	{"reach", "Reachability", "check firewall rules", "Checks a list of hosts and ports from here and compares the result with what you expect."},
	{"perf", "Throughput", "speed between two machines", "Measures throughput, jitter and loss between two machines that both run netcheck."},
	{"open", "Open a port", "listen and see who connects", "Listens on a port for a while and shows every connection, so you can test a port before the real server exists."},
	{"connect", "Connect", "talk to any port (netcat)", "Opens a TCP, UDP or TLS connection to any port, shows the greeting and lets you type to it."},
	{"wake", "Wake-on-LAN", "switch on a sleeping machine", "Sends a Wake-on-LAN packet to a machine by its MAC address or its name from the devices list, and waits for it to come up."},
	{"uptime", "Uptime monitor", "your servers on one screen", "A live dashboard for a list of servers, with uptime, response times, events and alerts."},
	{"lanaudit", "LAN audit", "what's risky on my network", "Looks for risky services and settings on your own network and explains each one."},
	{"lanwatch", "LAN watch", "who joins, ARP spoofing, changes", "Watches the network live: devices joining and leaving, ARP spoofing, a second DHCP server, gateway, DNS and public address changes, new UPnP forwards; with alerts."},
	{"agent", "Agent", "run checks from a server", "A small service on a server, so checks can run from there."},
}

// advancedItems is the Advanced menu: tools whose command exists are ready.
func advancedItems() []ui.Item {
	var out []ui.Item
	for _, t := range advancedTools {
		it := ui.Item{Name: t.label, Desc: t.desc, About: t.about}
		if c := find(t.cmd); c != nil {
			it.Ready = true
			it.Usage = strings.TrimSpace("netcheck " + c.name + " " + c.args)
		}
		out = append(out, it)
	}
	return out
}
