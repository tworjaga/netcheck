package cli

// about explains each command in the full-screen menu's side panel: what it
// checks and how, in a sentence or two.
var about = map[string]string{
	"doctor":  "Runs the checks that matter in parallel: your router, Wi-Fi, the internet, DNS, IPv6, NAT and a speed test. Then one verdict, the most serious problem first, with what it's good for.",
	"speed":   "Downloads and uploads against Cloudflare in parallel streams, and measures latency while the line is busy. The rise is graded A to F (bufferbloat), with SQM settings to fix it.",
	"wifi":    "Signal, band, channel and how crowded it is, read from the system. --walk measures room by room and ranks the spots.",
	"devices": "Finds who is on your network with a ping sweep, the ARP table, mDNS and SSDP, and marks devices that weren't there last time.",
	"route":   "Traces the path to a host and keeps measuring every hop, like mtr, so you can see where latency or loss starts.",
	"ports":   "Scans your own devices for common open ports. -x asks a helper outside your network whether a port is reachable from the internet.",
	"ping":    "Latency, jitter and loss to a host, drawn as a live chart. Uses real ICMP without admin rights, or TCP connects where ICMP is blocked.",
	"dns":     "Compares your DNS with Cloudflare, Google and Quad9, and checks whether yours rewrites unknown names into ad pages.",
	"watch":   "A live dashboard of your router, the internet and DNS every few seconds, saved to history. Leave it running to catch drops.",
	"history": "Trends from what watch recorded: outages with times, whether your router was answering during them, and the worst hours of the day.",
	"ip":      "Your public address and ISP, and whether there's carrier-grade or double NAT between you and the internet.",
	"upnp":    "Lists the ports apps and devices opened on your router themselves. Each one lets the internet reach that device.",
	"nat":     "Your NAT type as consoles show it: Open, Moderate or Strict, from two STUN servers and whether your router allows UPnP.",
	"report":  "A plain-English summary for your ISP with the numbers behind it. --compare last shows before and after a change.",
	"ipv6":    "Whether IPv6 works, how it compares with IPv4, and whether your system prefers it.",
	"dhcp":    "Broadcasts one DHCP discover, without taking an address, and counts the servers that answer. Two or more means a rogue one.",
	"captive": "Checks whether a login page is intercepting plain web traffic, as on hotel and café Wi-Fi.",
	"tls":     "Checks HTTPS against three large sites and names the problem, flags HTTPS inspection by antivirus or proxies, and checks your clock.",
	"leak":    "Finds out who really answers your DNS lookups. With a VPN on, DNS from your ISP is a leak.",
	"dnssec":  "Checks whether your DNS validates signatures and refuses forged answers, with Cloudflare as a control.",
	"mtu":     "Finds the largest packet that gets through without fragmenting, and spots path-MTU black holes.",
}
