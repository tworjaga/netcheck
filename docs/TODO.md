# netcheck TODO: Advanced mode

Normal mode (home users) is done. Advanced mode adds defensive tools for
sysadmins with the same terminal UI. One pull request per step, tested with
fakes in CI and checked on a real machine before merging. Each step is
planned in detail when it's reached.

Rules for every step: answer first (verdict and fix; `--raw` for data
only), `--json` and `--fail-on` exit codes, target lists with `-f file`,
`--watch` live mode, Go standard library only, defensive only (public
targets need `--authorized` and a gentle rate), no emoji. The repo stays
private.

## Step 0: foundation
- [x] `netcheck install` / `uninstall` to the user PATH (asks first)
- [x] Normal / Advanced switch in the menu (Tab, remembered)
- [x] command groups; `help` in sections (Normal, Advanced, Setup)
- [x] shared parts: target parsing, `--fail-on`, `--watch`, `--raw`,
      JSON envelope, `--authorized` helper, results table

## Step 1: DNS toolbox
- [x] `dig`: all record types; UDP, TCP, DNS over TLS, DNS over HTTPS
- [x] `dns trace` (`netcheck dnstrace`)
- [x] `propagate`

## Step 2: domain audit
- [x] `domain`: nameservers, DNSSEC, CAA, mail setup, blocklists, certificates
- [x] `mail`
- [x] release v0.5.0

## Step 3: web toolbox
- [x] `http` with a timing waterfall
- [x] `cert`
- [x] `trace --tcp` / `--udp`
- [x] `whois` (RDAP)

## Step 4: site audit
- [x] `site`: TLS grade, HTTP and HSTS, security headers

## Step 5: this machine
- [x] `listen`
- [x] `conns`

## Step 6: reachability
- [x] `port`: why can't anyone reach my server
- [x] `reach`: check firewall rules from a list
- [x] release v0.6.0

## Step 7: between machines
- [x] `perf`
- [x] connection utilities: `open`, `connect`, `wake`

## Step 8: monitoring
- [x] `uptime` dashboard with alerts
- [x] release v0.7.0

## Step 9: LAN security
- [x] LAN security audit (`lanaudit`)
- [x] network monitoring (`lanwatch`)
- [x] release v0.8.0

## Step 10: agent
- [x] `agent` on a server, so checks can run from there
- [x] the agent as a service, watching servers around the clock
- [x] release v0.9.0

## After Step 10
- [x] install scripts and `netcheck update`
- [x] release v0.10.0
