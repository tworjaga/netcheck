<div align="center">

# netcheck

**A quiet diagnostic tool for home networks.**

It runs the checks a patient network engineer would, then tells you in plain
English what's wrong and what to do about it, with the most serious problem first.

[![CI](https://github.com/tworjaga/netcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/tworjaga/netcheck/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white)
![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-555)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Telemetry](https://img.shields.io/badge/telemetry-none-brightgreen)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

One small binary · no installer · no admin rights for almost everything · no telemetry · Go standard library only

<img src="docs/demo.gif" alt="netcheck: the menu, ping, an HTTP timing waterfall and a website audit" width="800">

</div>

```
  netcheck  doctor

  ╭─ Connection ───────────────────────────────────────────────────────────────────────╮
  │ Gateway     ✓  192.168.1.1          2.1 ms  ▁▂▁▁▃▁▁▂▁▁                      │
  │ Wi-Fi       ✓  HomeNet             -58 dBm  good · 5 GHz · ch 44 · quiet channel   │
  │ Internet    ✓  1.1.1.1               14 ms  ▁▂▁▁▃▁▁▂▁▁                      │
  │ DNS         !  Router 192.168.1.1   180 ms  slower than Cloudflare (11 ms)         │
  │ IPv6        ✓  works                 15 ms  preferred                              │
  │ NAT         !  CGNAT                        203.0.113.7                            │
  │ Speed       ✓  312 / 41 Mbps                down / up · bufferbloat A (+9 ms)      │
  ╰────────────────────────────────────────────────────────────────────────────────────╯

  ╭─ Good for ─────────────────────────────────────────────────────────────────────────╮
  │ Calls       ✓  good     steady, low latency                                        │
  │ Gaming      ✓  good     low latency and steady timing                              │
  │ 4K video    ✓  good     plenty of bandwidth                                        │
  ╰────────────────────────────────────────────────────────────────────────────────────╯

  ╭────────────────────────────────────────────────────────────────────────────────────╮
  │ ! DNS is slow (180 ms). Cloudflare answers in 11 ms, so switching could speed up   │
  │   browsing.                                                                        │
  │   · Your ISP shares one public address between many customers (carrier-grade NAT). │
  │     Hosting games or servers from home won't work without a public IPv4 address;   │
  │     ask your ISP for one, or use IPv6.                                             │
  ╰────────────────────────────────────────────────────────────────────────────────────╯
```
<div align="center">
<a href="https://deepwiki.com/tworjaga/netcheck"><img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a>

## What it finds

|   |   |
|---|---|
| **Wi-Fi** | Signal in dBm, band and channel, crowded channels and a better one to switch to |
| **Speed** | Download, upload and bufferbloat (A–F), with the SQM settings to fix it |
| **Internet** | Latency, jitter and loss to your router and beyond, hop by hop like `mtr` |
| **DNS** | Your resolver against Cloudflare, Google and Quad9; ad-page hijacking; DNSSEC; leaks |
| **Your network** | Who's on it, rogue DHCP servers, ports apps opened on your router via UPnP |
| **Your ISP** | Public IP and ISP, carrier-grade and double NAT, IPv6, MTU black holes |
| **Interference** | Captive portals, HTTPS interception by antivirus or proxies, clock skew |
| **Over time** | A live monitor with history, outages with timestamps, and a report to send your ISP |

## Quick start

One command downloads the latest release for your system, checks it
against the release's `SHA256SUMS` and puts it on your PATH.

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/tworjaga/netcheck/main/scripts/install.ps1 | iex
```

macOS and Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/tworjaga/netcheck/main/scripts/install.sh | sh
```

Both scripts are short; read them first if you like:
[install.ps1](scripts/install.ps1), [install.sh](scripts/install.sh).
`NETCHECK_VERSION=v0.9.0` picks a release, and on macOS and Linux
`NETCHECK_INSTALL_DIR` picks the folder.

Or download the binary from
[Releases](https://github.com/tworjaga/netcheck/releases) (or
[build it](#build)) and put it on your PATH yourself:

```
netcheck install      # asks first; netcheck uninstall removes it
```

Later, `netcheck update` gets the newest release the same way (checked
against `SHA256SUMS`), and `netcheck update --check` only says whether
there is one.

Then:

```
netcheck              # a menu of every check
netcheck doctor       # everything that matters, one verdict
```

On Windows `install` copies netcheck to `%LOCALAPPDATA%\Programs\netcheck`
and adds that folder to your user PATH (no admin rights; open a new terminal
afterwards). On macOS and Linux it copies to `~/.local/bin` and shows the
line to add to your shell profile if that folder isn't on PATH yet.

In a large enough window the menu fills the screen, with what each command checks beside the list. Use the arrow keys or j/k, `/` to search, Enter to run, q or Esc to quit.

**Normal and Advanced.** The menu has two modes; Tab switches them and the
choice is remembered. Normal holds everything above, for home networks.
Advanced is for sysadmins, with the same interface: its tools are being
added step by step (see `docs/TODO.md`), and the menu already lists what's
planned.

## Advanced tools

Every Advanced tool ends in a verdict and takes the same options: `--json`
(one shape for all tools), `--raw` (data only), `--fail-on` (exit 1 when a
rule breaks, for scripts and monitoring: `200ms`, `14d`, `loss>1%`,
`grade<B`), `--watch 5s` (rerun in place) and `-f file` (one target per
line, `#` comments). Targets outside your own networks need `--authorized`
where a tool sends many requests.

| Command | What it does |
|---|---|
| `netcheck dig <name> [type] [@server]` | any DNS record from any server |
| `netcheck dnstrace <name> [type]` | follow a name down from the root servers |
| `netcheck propagate <name> [type]` | has a DNS change reached the resolvers yet |
| `netcheck domain <domain>` | a domain's whole public setup, graded, with fixes |
| `netcheck mail <domain>` | how a domain receives mail: servers, TLS, SPF, MTA-STS |
| `netcheck http <url>` | one request, timed phase by phase, with redirects |
| `netcheck cert <host[:port]>` | any server's certificate chain, names, expiry, TLS versions |
| `netcheck trace <host> [--tcp\|--udp]` | the route, with the network that owns each hop |
| `netcheck whois <domain\|IP\|AS>` | who holds a domain, address or network |
| `netcheck site <url>` | a website's HTTPS, HSTS, headers and cookies, graded |
| `netcheck listen` | what listens on this machine, which program, who can reach it |
| `netcheck conns` | open connections by program, with who's at the other end |
| `netcheck port <port>` | why can't anyone reach my server on this port |
| `netcheck reach <host:port> [allow\|deny]` | does the firewall allow and block what it should |
| `netcheck perf --server` / `netcheck perf <host>` | speed, loss and jitter between two machines |
| `netcheck open <port>` | listen on a port and see who connects |
| `netcheck connect <host:port>` | talk to any port over TCP, UDP or TLS |
| `netcheck wake <MAC or name>` | switch on a sleeping machine (Wake-on-LAN) |
| `netcheck uptime <targets> \| -f servers.txt` | your servers on one screen, with history |
| `netcheck lanaudit` | what's risky on my network, graded |
| `netcheck lanwatch` | new devices, ARP spoofing, DHCP and DNS changes, live |
| `netcheck agent` | run checks from another machine, through a Cloudflare Tunnel; watch servers from there |
| `netcheck uptime <targets> \| -f servers.txt` | your servers on one screen, with history |

**dig** asks any record type (A, AAAA, CNAME, MX, TXT, NS, SOA, CAA, SRV,
PTR, DS, DNSKEY, RRSIG, NSEC, TLSA, SSHFP, HTTPS and any `TYPEnnn`) over UDP
(retried over TCP when the answer is too big), `--tcp`, `--dot` (DNS over
TLS, certificate checked) or `--doh` (DNS over HTTPS). The server is an
address, a `https://…/dns-query` URL or `cloudflare`, `google`, `quad9`;
without one it asks this computer's DNS server. An address as the name does
a reverse lookup (or `-x`). `--dnssec` asks for signatures, `--cd` turns
validation off (to tell a DNSSEC failure from a dead server), `--norec`
asks an authoritative server directly, `--all` shows every section and
`--short` prints the data only. With `-f names.txt` (a name and an optional
type per line) the results come as one table. `--fail-on` knows `time`,
`answers` and `ttl`; a bare value means time (`--fail-on 200ms`).

**dnstrace** resolves a name the way a resolver does, in the open: from a
root server through each referral to the answer, showing who answered at
every step. Nameservers that time out, refuse or answer without authority
are listed as lame, and a referral that points away from the name stops the
trace. `--all` asks every nameserver at each step and flags the ones that
disagree (different addresses alone are left as a note: load-balanced and
geo DNS do that on purpose). `--fail-on` knows `time`, `lame` and `steps`.

**propagate** asks a name's own nameservers and ten public resolvers
(Cloudflare, Google, Quad9, OpenDNS and others) and shows which already have
the current answer and how long the rest keep their old copy. The current
answer is what the nameservers say, or `--expect 203.0.113.5`. Nameservers
that disagree with each other are called out first. The public resolvers are
anycast, so this is what their sites nearest you have cached. `--watch 30s`
follows it until everything has caught up; `--fail-on` knows `behind`
(the default: `--fail-on 0`), `updated` and `wait`.

**domain** audits a domain and grades it A+ to F, with the fix for each
problem. Nameservers: how many, whether each answers with authority, one
network or several, the same zone version on all of them, the registry and
the zone listing the same ones, and none open to recursive queries for
anyone. SOA timers. DNSSEC: the registry's DS matches a key, resolvers
validate the chain, current algorithms, signatures not about to run out.
CAA. Mail: MX hosts that resolve, SPF, DMARC and DKIM under the common
selectors. The mail servers and the domain on Spamhaus, SpamCop, Barracuda
and PSBL. The certificates on the domain and `www`. A name inside a zone
(`www.example.com`) audits the zone. `-f domains.txt` gives one row per
domain. `--fail-on` knows `grade` (the default: `--fail-on B` fails at C or
worse), `score`, `problems`, `bad` and `cert` (`--fail-on cert<14d`). It
only asks; it changes nothing and sends no mail.

**mail** goes deeper on mail. Each mail server (up to four, lowest
preference first) gets a visit on port 25: the greeting, EHLO, STARTTLS,
the TLS version and the certificate, then QUIT; it never starts a message.
It checks that each server's address has reverse DNS that resolves back,
counts the DNS lookups SPF needs against the limit of 10 (following every
`include:` and `redirect=`), and fetches the MTA-STS policy to see that it
covers every MX, plus TLS-RPT, the records and the blocklists from
`domain`. Many home and mobile ISPs block outgoing port 25; when no server
answers, it says so instead of blaming the servers. `--fail-on` knows
`grade` (the default), `score`, `problems`, `bad` and `lookups`.

**http** sends one request on a fresh connection and times each phase: DNS,
connect, TLS, the server preparing the answer, and the download, drawn as a
waterfall. Redirects are followed one at a time, each with its own timing.
It shows the status, protocol (HTTP/2 or 1.1), address, size as sent and
the main headers (`--headers` for all). `-X`, `-H 'Name: value'` and `-d`
shape the request, `-k` skips the certificate check, `--no-follow`,
`--http1`, `-4` and `-6` do what they say, and `-n 10` repeats it and shows
the fastest, median and slowest of each phase. `--fail-on` knows `time`
(the default), `ttfb`, `dns`, `connect`, `tls`, `wait`, `status`, `size`
and `redirects`.

**cert** shows the certificate chain a server presents, from its own
certificate up to the root, and checks it: trusted, the right name, not
expired or about to, a complete chain (a missing intermediate is caught even
where this computer would fetch it), key and signature strength, which TLS
versions it accepts, and Certificate Transparency. It works on any port, and
speaks STARTTLS first on mail and FTP ports (25, 587, 143, 110, 21; or
`--starttls smtp|imap|pop3|ftp|none`). `--sni` asks for another name, `-f`
checks a list. `--fail-on 14d` fails when fewer days are left; it also knows
`problems`.

**trace** follows the route hop by hop and names the network that owns each
one (its AS, from Team Cymru's IP-to-ASN data) and its reverse name. It
points out where the delay grows most and which networks the route crosses.
The default is ICMP, like `route`, and needs no special rights. `--tcp` (port
443 unless `-p`) looks like an ordinary connection, so it gets through
firewalls that drop pings, and says whether the port is open or closed.
`--udp` uses the classic traceroute ports. Hearing the routers' replies to
TCP and UDP takes a raw socket: a terminal opened as administrator on
Windows, root elsewhere, except UDP on Linux, which works without (the way
`tracepath` does). When the routers stay quiet it still checks whether the
destination answers. `-m` hops, `-q` probes per hop, `-n` skips the names.
`--fail-on` knows `rtt` (the default), `hops` and `loss`.

**whois** asks the registry who holds a domain, an IP address or an AS
number, over RDAP, and over classic whois for the endings without RDAP (.at,
.de, .eu, .ch, .io and others). For a domain: registrar, holder where it's
public, dates, status, nameservers and DNSSEC, with a warning when it runs
out within 30 days and a note when the transfer lock is off. For an address:
its range, holder, abuse contact and the network announcing it. `--raw`
prints the whois text as sent; `--fail-on 30d` fails when fewer days are
left before it expires.

**site** audits a website the way a browser meets it and grades it A+ to F.
HTTPS: the certificate (as `cert` checks it), TLS versions, and whether
http:// sends visitors to https:// with a permanent redirect. HSTS: present,
long enough, covering subdomains, ready for the browsers' preload list.
Security headers: Content-Security-Policy (and inline scripts it still
allows), X-Content-Type-Options, framing (frame-ancestors or
X-Frame-Options), Referrer-Policy, Permissions-Policy, and headers that name
the server software's version. Cookies: Secure, HttpOnly, SameSite. Content:
scripts, styles and images the page loads over plain http://. Extras:
HTTP/2, compression, security.txt. A certificate browsers refuse means F,
whatever else is right. A+ needs a clean sheet and HSTS ready for preload.
`-f` checks a list; `--fail-on` knows `grade` (the default), `score`,
`problems`, `bad` and `cert`.

**listen** lists every port this machine listens on, with the program behind
it, the usual service and who can reach it: this machine only, or the
network (every interface, or a named address). IPv4 and IPv6 and the same
port on several interfaces fold into one row. Databases, Redis, MongoDB,
Elasticsearch, memcached, an unencrypted Docker API, Telnet, FTP, Remote
Desktop, VNC and WinRM open to the network are called out, as are
development servers. UDP ports from 49152 up (programs' own outgoing
traffic) are left out unless `--all`; `--tcp` shows TCP only. `--fail-on`
knows `open` (the default) and `ports`.

**conns** lists the open connections by program, with the other end's
name and the network that owns it. Identical connections fold into one row
(`open ×4`), and connections between programs on this machine are left out
unless `--local`. It points out programs with connections piling up
unclosed (CLOSE_WAIT) and attempts nobody answers. `-p` picks one program,
`--all` adds closing connections, `-n` skips the names; `--watch 2s`
follows it live. `--fail-on` knows `conns` (the default) and `closewait`.

Both read the system's own tables: iphlpapi on Windows, /proc on Linux,
lsof on macOS. On Linux and macOS, other users' programs show only with
sudo; it says so when that's the case.

**port** walks the layers between the internet and a server on this machine
and names the first one that stops connections, with the fix: (1) does a
program listen on the port, and on every address or only 127.0.0.1; (2) does
the firewall let it in: Windows Firewall's rules for the network profile in
use (Public or Private), read without admin rights, or ufw / nftables /
iptables on Linux (with sudo) and the macOS firewall; (3) does the router
forward the port to this machine (over UPnP; rules added by hand don't show);
(4) can the internet reach your network at all, or does the ISP use
carrier-grade NAT, and is there public IPv6; (5) with `--helper`, the
port-check helper tries it from outside. For services that shouldn't face
the internet (SMB, RDP, databases and the like) it suggests a VPN instead.
`--udp` for UDP ports.

**reach** checks firewall expectations from this machine: give it
`host:port allow` or `host:port deny` (on the command line, or one per line
with `-f rules.txt`), and it tries each connection and reports the ones that
don't hold, telling refused (something said no) from filtered (no answer).
Without allow or deny it just reports what's open. Targets outside your own
networks need `--authorized` and are paced. `--fail-on` knows `mismatches`
(the default).

**perf** measures between two machines, like iperf: run `netcheck perf
--server` on one (it prints the command for the other) and `netcheck perf
<host>` on the other. TCP runs each direction in turn over 4 parallel
streams (`-P`), 5 seconds each (`-t`), with the speed shown live; the side
that receives does the measuring. `--down` or `--up` runs one direction.
`--udp 50M` sends UDP at that rate instead and reports what arrived: loss,
reordering and jitter (RFC 3550), the numbers that decide call and game
quality. The verdict points out one direction being much slower, speed
swinging from moment to moment, loss, and a sender that couldn't reach the
rate asked for. The server listens on port 5205 (`-p`), answers only
netcheck clients, caps tests at 60 seconds and 16 streams, and with
`--once` stops after one client. On Windows, allow it on Private networks
when the firewall asks. `--fail-on` knows `down` (the default, in Mbit/s),
`up`, `loss` and `jitter`.

**open** listens on a port (`--udp` for UDP) and shows every connection
that arrives: when, from where, and the first line it sent. Visitors get a
short "you reached ..." reply, as a web page when they speak HTTP, so a
browser, `connect` or `http` can test it. It's for testing a port, the
firewall and port forwarding before the real server exists. `-t 10m` stops
it after a while; `--bind` listens on one address only.

**connect** opens a connection to any port, like netcat: TCP, UDP or
`--tls`. At a terminal you type and see the answers (`--crlf` for SMTP,
HTTP, POP3 and IMAP); piped input is sent as it is; `-s 'text'` sends
that and shows the answer. Binary answers come as a hex dump. With
`--tls` it checks the certificate (`-k` to go on anyway) and shows the
TLS version and cipher.

**wake** sends a Wake-on-LAN packet to a MAC address, or to a device by its
name or address from `netcheck devices`, on every local network's
broadcast address. `--wait 2m` then waits for the machine to answer.
`--ip` sends to one address instead (a directed broadcast, or a host
across a VPN).

**uptime** watches a list of servers: `https://` and `http://` pages
(status, response time, days left on the certificate), `tcp://host:port`,
`ping://host` and `dns://name`; a bare `host:port` is TCP and a bare name
HTTPS. On the command line or in a file (`-f servers.txt`), one per line,
with options: `name=Shop_API`, `expect=204` (the status, or for DNS the
address it should resolve to) and `timeout=5s`. It checks every 30 seconds
(`-i`) on a full-screen dashboard: status, response time, recent checks,
uptime and certificate days per target, and an event log. A target counts as
down after 3 failed checks in a row (`--down-after`), so a single blip
doesn't; certificates under 14 days (`--cert`) are an event too. Piped, it
prints one line per change. Results are saved (to `uptime.jsonl` beside the
other netcheck files, or `NETCHECK_UPTIME_LOG`; `--no-log` to skip), and
`--report --days 30` sums them up: uptime, outages, the longest, average
response time. `--once` checks everything once and exits 1 if anything
fails, for scripts. It checks only while it runs; for around-the-clock
watching, run it on a server.

Alerts tell you about each down, back up and certificate event; switch on
the ones you want:

- `--notify`: a desktop notification (Windows notification, notify-send on
  Linux, macOS Notification Center).
- `--webhook URL` (more than once is fine): Discord, Slack and Teams webhooks
  and ntfy topics (`https://ntfy.sh/your-topic`, for alerts on your phone)
  get their own format; any other URL gets JSON with a `text` field and the
  event.
- `--alert-cmd '...'`: runs your command through the shell, with
  `NETCHECK_EVENT` (down, up, cert), `NETCHECK_NAME`, `NETCHECK_TARGET`,
  `NETCHECK_TEXT`, `NETCHECK_DETAIL`, `NETCHECK_DOWN_FOR` (seconds),
  `NETCHECK_TIME` and `NETCHECK_HOST`.
- `--email to@example.com --smtp smtp.example.com:587 --smtp-user
  you@example.com`: mail over STARTTLS (587) or TLS (465). The password comes
  from the `NETCHECK_SMTP_PASSWORD` environment variable, never a file or the
  command line; for Gmail, use an app password. netcheck refuses to log in
  without TLS.

The same settings fit in the servers file as lines like `alert desktop`,
`alert webhook https://...`, `alert command ...` or `alert email to@x
smtp=host:587 user=you@x`. `--test-alert` sends a test through each channel
and says which worked. A channel that fails shows up in the event log.

**lanaudit** looks for what's risky on the network this machine is on and
grades it A+ to F, with the fix for each finding. The Wi-Fi: open, WEP,
the first WPA and WPA2 with TKIP are called out; WPA3 is best. The router:
its admin page on plain HTTP, Telnet, UPnP and the ports devices opened
through it, and more than one DHCP server (or addresses handed out by
something other than the router). Every device: a short list of ports that
matter (Telnet, FTP, the Docker API, Redis, MongoDB, MQTT, VNC, databases,
Remote Desktop, file sharing, camera streams), with the device named where
it can be. Devices `netcheck devices` hasn't seen before are listed. It
only looks at what answers: no passwords, no exploits, private networks
only. `--fail-on` knows `grade` (the default), `score`, `problems` and
`bad`.

**lanwatch** keeps an eye on the network and says when something changes:
a device joins (called new when `netcheck devices` has never seen it) or
leaves (after 15 minutes missing, `--leave`, since phones sleep); the
router's hardware address changes, or another address answers with it,
the classic signs of ARP spoofing; a second DHCP server appears; the default
gateway, DNS servers or public address change; a device opens or closes a
port to the internet over UPnP. It looks every 2 minutes (`-i`), and for
DHCP servers every fifth round. On a terminal it's a dashboard (the
network, its devices and the events); piped, one line per change. Events
are saved to `lanwatch.jsonl` (`--no-log` to skip). Alerts work as for
`uptime` (`--notify`, `--webhook`, `--alert-cmd`, `--email`, `--test-alert`);
by default only warnings and alarms raise one, `--alert-all` for every
change. Private networks only.

**agent** runs checks from another machine: a VPS, a NAS, a Raspberry Pi
somewhere else. On that machine, `netcheck agent` listens on 127.0.0.1 only,
and [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
carries requests to it through a Cloudflare Tunnel: the server opens no
port, and Cloudflare provides HTTPS. `netcheck agent --tunnel` starts a
quick tunnel (no account needed; its `https://....trycloudflare.com`
address changes on every start); for a lasting address, point a named
tunnel on your own domain at `http://127.0.0.1:5299`. The agent prints the
line to pair with, holding its token:

    netcheck agent add vps https://agent.example.com TOKEN

Then add `--from vps` to a check to run it there and see the result here:
`netcheck http example.com --from vps`, `netcheck trace 1.1.1.1 --from vps`,
`dig`, `cert`, `whois`, `ping` and the other read-only checks.
`netcheck port 8080 --from vps` tests your port from the agent, the real
outside test that `port` otherwise needs a helper for. Every request needs
the token (`--rotate-token` makes a new one); the agent refuses anything but
its list of checks, and flags that would read files, run for ever or send
alerts from it; it slows down after 30 requests a minute. Behind
Cloudflare Access, add the service token with `--access-id` and
`--access-secret`. `netcheck agent list` shows the paired agents and whether
they answer.

The agent can also watch servers around the clock, from where it stands:
`netcheck agent --uptime servers.txt` checks the targets in the file every
minute (`--every`), in the `uptime -f` format, alert lines included, and
saves the history there for `netcheck uptime --report`.
`netcheck agent status vps` shows what it watches, what's down and the
latest changes; `netcheck agent status` on the server itself also shows the
service.

`netcheck agent install` (with the same flags) makes the agent a service, so
it starts by itself and comes back if it stops: a systemd unit on Linux (a
user unit, or a system one as root), a launchd job on macOS (a LaunchDaemon
as root), and a Task Scheduler task on Windows that starts at sign-in.
`netcheck agent uninstall` removes it. The service doesn't see your shell's
variables, so if `NETCHECK_SMTP_PASSWORD` is set when you install, it's
saved to `agent.env` (readable by you only) for email alerts. For a lasting
address, create a named tunnel in the Cloudflare dashboard (Zero Trust,
Networks, Tunnels) with a public hostname pointing at
`http://127.0.0.1:5299`, and run the `cloudflared service install` command
it shows; cloudflared then runs as its own service too.

## Commands

Every command also runs directly, and every command takes `--json`.

| Command | What it does |
|---|---|
| `netcheck doctor [--fast]` | everything below that matters, one verdict |
| `netcheck speed [-t 8s]` | download, upload, bufferbloat, what it's good for |
| `netcheck ping [host] [-c 20] [-i 250ms] [--tcp] [-p 443]` | latency, jitter, packet loss |
| `netcheck watch [-i 5s] [-d 1h] [--no-log] [--log file] [--simple]` | live dashboard, saved to history |
| `netcheck dns [name]` | your DNS against Cloudflare, Google and Quad9 |
| `netcheck devices [--no-save]` | who is on your network, and who's new |
| `netcheck route [host] [-c 10] [-m 30]` | live traceroute (mtr-style) |
| `netcheck wifi [-n 15] [--walk]` | signal, channel crowding, live signal view, room-by-room walk test |
| `netcheck ports [host] [-x port --helper URL]` | local and external reachability |

<details>
<summary><b>More…</b> (in the menu under “More…”, or directly)</summary>

| Command | What it does |
|---|---|
| `netcheck report [--format md\|json] [-o file] [--fast] [--days 7] [--compare last\|file]` | a summary to send your ISP; before and after a change |
| `netcheck history [--days 7] [--log file]` | trends from what `watch` recorded |
| `netcheck ip` | public IP, ISP, CGNAT / double NAT |
| `netcheck upnp` | ports apps opened on your router |
| `netcheck nat` | NAT type for games and calls: Open, Moderate or Strict |
| `netcheck ipv6` | does IPv6 work, and is it preferred |
| `netcheck dhcp [-w 3s]` | rogue second DHCP server (may need admin) |
| `netcheck captive` | is a login page intercepting the web |
| `netcheck tls` | HTTPS interception, clock skew |
| `netcheck leak` | who answers your DNS; leaks with a VPN |
| `netcheck dnssec` | does your DNS validate signatures |
| `netcheck mtu [host]` | largest packet that gets through |

</details>

**Output.** `--json` on any command gives machine-readable output (`watch
--json` streams one line per sample, then a summary line; `report --json`
equals `--format json`). Colours turn off with `NO_COLOR=1` or when the
output isn't a terminal; `NETCHECK_ASCII=1` swaps the Unicode glyphs for
plain ASCII. `NETCHECK_HIDE_IP=1` leaves your public IP address and ISP out of
the menu's top line, for screenshots and screen sharing.

**Exit codes.** 1 when a check finds a hard failure (no internet, DNS
dead, a captive portal, a rogue DHCP server…), 2 for bad usage, 130 when
Ctrl-C cuts a check short, otherwise 0. `watch` and `ping -c 0`, which run
until Ctrl-C, end normally. `report` returns 0 unless it can't write its
file.

**Time limits.** Every probe has a timeout, nothing waits on a dead network,
and Ctrl-C always stops cleanly. Checks interrupted halfway are dropped, not
shown as failures.

## A report for your ISP

```
netcheck watch                 # leave it running for a few days (or evenings)
netcheck report -o report.md   # then send them this
```

The report leads with plain-English findings, then the numbers behind them:
your public IP and ISP, NAT, latency and loss to your router and to the
internet, DNS, speed and bufferbloat, IPv6, the route to 1.1.1.1 hop by hop,
and, if `watch` has been running, outages with timestamps and whether your
router was still answering during each one (if it was, the problem is past
your home). It says how each number was measured.

> [!NOTE]
> The report contains your public IP address, and no Wi-Fi names, passwords or device lists.

**Before and after.** Every report keeps its numbers in
`<config dir>/netcheck/last-report.json` (override with
`NETCHECK_LAST_REPORT`). Make a change, such as turning on SQM, moving
the router or switching DNS, and compare:

```
netcheck report                  # before
netcheck report --compare last   # after: adds a "Compared with …" table
```

The table lists latency, jitter and loss to the router and the internet,
your DNS, Wi-Fi signal, download, upload and bufferbloat, each marked
better, worse or about the same (changes under 10%, or under a few ms or
dB, count as the same), followed by both verdicts. `--compare` also takes
any file saved with `--format json`.

## How each check measures

<details>
<summary><b>Ping, doctor, DNS, speed, readiness</b></summary>

- **Ping** uses real ICMP without admin rights: `IcmpSendEcho` on Windows,
  unprivileged ping sockets on macOS and Linux. If ICMP is unavailable or
  filtered it falls back to timing TCP connects (a refused connection still
  counts as a reply) and says so in one line.
- **Doctor** runs the router, Wi-Fi, internet, IPv6 and NAT checks in
  parallel, DNS once the internet is known to work, and the speed test last
  and alone so its load doesn't distort the rest. The verdict is one
  ordered list: no connection, then DNS, then the link from the Wi-Fi
  outward (weak signal and loss to the router are reported as one cause),
  loss past the router, speed, what the connection is good for, and last
  broken IPv6, a crowded channel and CGNAT.
- **DNS** queries your resolver and three public ones directly, compares
  median lookup times, and checks whether yours rewrites non-existent names
  (often ISP ad pages).
- **Speed** downloads and uploads in parallel streams against
  `speed.cloudflare.com`, skips TCP warm-up, and measures latency while the
  line is busy. The added latency is graded A–F (bufferbloat). At C or worse
  it suggests SQM limits at 90% of what was measured.
- **Good for calls / gaming / 4K** rates what was measured against common
  guidance (calls: under 150 ms, jitter under 30 ms, under 1% loss, 3 Mbps
  each way; fast games: under 60 ms and jitter under 10 ms; 4K: 25 Mbps
  down). Anything not measured is named instead of guessed.

</details>

<details>
<summary><b>Watch and history</b></summary>

- **Watch** probes router, internet and DNS every 5 s in parallel. In a
  window of at least 70×20 it's a full-screen dashboard: a large internet
  chart, the current numbers, router and DNS panels, and an event log
  (drops with how long they lasted, latency spikes, missed probes, and
  devices that join while it runs, checked once a minute against the list
  `netcheck devices` remembered); q, Esc
  or Ctrl-C leave it and print the summary. `--simple`, a smaller window
  or piped output give a live panel instead. Each sample is appended to
  `<config dir>/netcheck/history.jsonl` (`%AppData%\netcheck` on Windows;
  override with `NETCHECK_HISTORY` or `--log`). The log rotates at 8 MB and
  keeps one older file: about four weeks at the default interval. Each line
  is `{"v":1,"t":"…","gw":2.1,"net":14.2,"dns":11}`: `v` is the format
  version, values are milliseconds, `-1` is a lost probe, and a missing
  field wasn't measured. On Windows the DNS probe looks up a fresh random
  name each time, because the system cache would otherwise hide an outage.
- **History** finds outages (two or more lost internet probes in a row;
  time when `watch` wasn't running never counts), whether the router
  answered during them, the worst hours of the day, and a per-day strip of
  hourly latency. Time-of-day claims need at least four hours with enough
  samples.

</details>

<details>
<summary><b>Wi-Fi, devices, route</b></summary>

- **Wi-Fi** reads `netsh wlan` (Windows), `nmcli` or `iw` (Linux) or
  `system_profiler` (macOS). netsh is parsed in any display language: keys
  are matched with accents as wildcards, because netsh writes the console's
  OEM code page, and signal and band also fall back on the shape of the
  values. Crowding counts strong networks overlapping your channel. Windows
  hides Wi-Fi details until Location is on; netcheck says so. `-n` is the
  number of 1-second signal samples in the live view (15 on a terminal,
  none for pipes or `--json`); `-n 0` runs until Ctrl-C, even with
  `--json`, which then prints when you stop it. `--walk` is a walk test:
  type a spot's name, five readings a second apart are taken there (the
  median counts), and at the end the spots are ranked strongest first,
  naming the access point each was on when there was more than one, with
  the weak spots called out.
- **Devices** combines a ping sweep of your subnet, the ARP table, mDNS and
  SSDP, with reverse DNS names and vendors from the MAC prefix. Each scan
  is remembered per network (told apart by the router's MAC address) in
  `<config dir>/netcheck/devices.json` (override with `NETCHECK_DEVICES`),
  so the next scan marks devices that weren't there before. The file stays
  on this computer; devices unseen for 90 days are forgotten, and
  `--no-save` skips both the comparison and the saving.
- **Route** sends ICMP with rising TTL and keeps measuring each hop, like
  mtr. Where TTL replies can't be read it runs `tracert -d` / `traceroute
  -n` once and then pings the hops it found.

</details>

<details>
<summary><b>IP / NAT, UPnP, IPv6, DHCP</b></summary>

- **IP / NAT** finds your public address (several services raced), your ISP
  (Team Cymru's DNS service, with a web API fallback), and compares your
  router's WAN address (UPnP) with the public one: a 100.64.0.0/10 or
  different address means carrier-grade NAT, a private one double NAT.
- **UPnP** asks your router (and only your router) for the ports apps
  and devices have opened on it themselves, one entry at a time until it
  says there are no more: protocol, port, which device, the app's
  description and how long is left. Each lets the internet reach that
  device. A router with UPnP off simply doesn't answer.
- **NAT type** asks two STUN servers run by different operators (Cloudflare
  and Google) from one UDP socket which public address and port they see.
  The same port for both means the NAT keeps one port per connection;
  a different port per destination is symmetric NAT, which consoles call
  Strict, and no answer at all means UDP is blocked. Open versus Moderate
  then depends on whether games can open ports: the router answering UPnP
  with its own public address. Telling every console category apart would
  need STUN servers with a second address (RFC 5780), which public ones
  rarely offer, so netcheck says how it decided.
- **IPv6** checks for a global address, connects to IPv6-only hosts,
  compares with IPv4, and checks whether DNS returns IPv6 and the system
  lists it first. IPv6 that's configured but broken is a warning (apps
  stall before falling back); IPv4-only is not a problem.
- **DHCP** broadcasts one DHCPDISCOVER (no address is taken) and counts the
  distinct servers that offer one; two or more means a rogue server. A
  single server that is the Wi-Fi access point you're on, handing out your
  router's settings, is recognised as an extender. Listening needs port 68.
  On Linux and macOS that takes root (or the system's DHCP client holds
  it); on Windows an ordinary user can usually open it. Without it
  netcheck says so and stops.

</details>

<details>
<summary><b>Captive portals, TLS, DNS leaks, DNSSEC, MTU</b></summary>

- **Captive** fetches Google's, Apple's and Microsoft's connectivity URLs
  over plain HTTP without following redirects, and names the portal.
- **TLS** handshakes with three large sites using the system's trust store,
  and names the problem: untrusted certificate, wrong name, out of date. It
  also flags HTTPS inspection, by known product names or by a trusted chain
  whose issuer and root are both outside the public CAs (typical of
  antivirus web shields and company proxies). Clock skew is the median
  difference from three web servers' `Date` headers.
- **Leak** asks `whoami.akamai.net` and `o-o.myaddr.l.google.com` which
  resolver reaches the internet for you, looks up who owns it, and
  compares that with your public address. With a VPN up, DNS answered by
  your ISP rather than the VPN or a public resolver is a leak.
- **DNSSEC** sends queries with the DNSSEC-OK bit for a signed name (the
  answer should be marked authenticated) and for deliberately broken test
  domains (a validating resolver refuses them), with Cloudflare as a
  control. On Windows the DNS servers come from `netsh`.
- **MTU** binary-searches don't-fragment pings between 576 and 1500 bytes,
  two tries per size so loss isn't mistaken for "too big", and detects
  path-MTU black holes (big packets vanishing without an error).

</details>

## Platform notes

| Platform | Notes |
|---|---|
| **Windows** | ICMP, the menu's arrow keys (console raw mode) and Wi-Fi need no admin rights. `dhcp` usually does too, since the system's DHCP client doesn't hold port 68; if netcheck says it can't open the port, use an administrator terminal. Wi-Fi details need Location turned on. |
| **macOS** | Works unprivileged throughout except `dhcp` (port 68 belongs to the system). |
| **Linux** | ICMP uses ping sockets, which most distributions allow (`net.ipv4.ping_group_range`); otherwise TCP is used. Unprivileged ping sockets can't read "time exceeded", so `route` uses the system `traceroute` there. `dhcp` needs root. |

**Known limits.** The MAC vendor table is a compact subset of the IEEE list,
not all of it. VPNs are recognised by adapter name, so one with an unusual
name can be missed. The list of public CAs used to spot HTTPS inspection
covers the large ones; a smaller CA could be flagged by mistake.

## Port helper

`netcheck ports` has two halves. The local half scans your own devices for
common open TCP ports; it refuses any address that isn't private, loopback or
link-local. The internet half, `netcheck ports -x 25565`, asks whether a port
is reachable *from outside*, which only a machine outside your network can
tell you.

netcheck doesn't ship with a built-in third-party service for this, because
no free public port-check API with documented terms could be verified.
Instead it speaks a tiny protocol you can host yourself:

```
GET <helper>/check?port=N   ->   {"ip":"203.0.113.7","port":N,"open":true}
```

The helper connects back to the address the request came from, never to one
the caller names, so it can't be used to scan other people. It rate-limits to
10 checks a minute per caller. A reference implementation using only the
standard library is in `contrib/portcheck-helper`:

```
go run ./contrib/portcheck-helper -addr :8080     # on a small server outside your home network
netcheck ports -x 25565 --helper http://your-server:8080
```

Set `NETCHECK_PORT_HELPER` to avoid typing `--helper`. The helper sees your
public address and the port you asked about, so run it yourself or trust its
operator.

> [!TIP]
> A closed port can also mean carrier-grade NAT (see `netcheck ip`), which
> blocks all incoming connections whatever the router does.

## Build

Go 1.24 or later. With Go installed, this fetches and builds the latest
release in one step:

```
go install github.com/tworjaga/netcheck@latest
```

No CGO, so every target cross-compiles from any machine:

```
go test ./...
go build -o netcheck .                                          # this machine
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dist/netcheck-windows-amd64.exe .
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -o dist/netcheck-macos-arm64 .
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -o dist/netcheck-linux-amd64 .
```

The code: `main.go` holds the version and starts `internal/cli`, which has
one file per command; the measurements live in the other `internal/`
packages (`probe`, `dnsx`, `webx`, `agent` and so on).

Tests use fakes (scripted pings, local DNS and HTTP servers, a fake clock)
and never touch the real network. CI runs vet and the tests on Windows,
macOS and Linux for every pull request.

**Releasing.** Set `version` in `main.go`, merge, then push a matching tag
(`git tag v0.4.1 && git push origin v0.4.1`). GitHub Actions builds
Windows, macOS and Linux binaries (amd64 and arm64) with a `SHA256SUMS`
file and publishes them as a GitHub release.

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 Alexey.
