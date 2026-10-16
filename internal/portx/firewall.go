package portx

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// WinRule is one Windows Firewall rule, as the HNetCfg.FwPolicy2 COM
// interface reports it: numbers, not localized words.
type WinRule struct {
	Name     string  `json:"n"`
	Protocol int     `json:"p"`  // 6 TCP, 17 UDP, 256 any
	Ports    *string `json:"l"`  // "*", "80", "80,443", "5000-5010", or keywords like "RPC"
	App      *string `json:"a"`  // program path, or empty for any program
	Profiles int     `json:"pr"` // bits: 1 domain, 2 private, 4 public
	Action   int     `json:"ac"` // 1 allow, 0 block
	Remote   *string `json:"r"`  // "*", "LocalSubnet", addresses
	Package  *string `json:"k"`  // a Store app's package ID: the rule is for that app only
	Owner    *string `json:"o"`  // set on Store apps' rules (the user who installed the app): for that app only
	Service  *string `json:"s"`  // a Windows service name: the rule is for that service only
}

// WinFirewall is the firewall's state: the profiles in use, which are on
// and what they do by default, and the enabled inbound rules.
type WinFirewall struct {
	Current  int `json:"current"` // profile bits in use now
	Profiles []struct {
		Type    int  `json:"t"`
		Enabled bool `json:"e"`
		Inbound int  `json:"i"` // default inbound action: 0 block, 1 allow
	} `json:"profiles"`
	Rules []WinRule `json:"rules"`
}

// winScript reads the firewall through COM and prints it as JSON.
const winScript = `$ErrorActionPreference='Stop'
$fw = New-Object -ComObject HNetCfg.FwPolicy2
$rules = @($fw.Rules | Where-Object { $_.Direction -eq 1 -and $_.Enabled } | ForEach-Object {
  [pscustomobject]@{n=$_.Name;p=$_.Protocol;l=$_.LocalPorts;a=$_.ApplicationName;pr=$_.Profiles;ac=$_.Action;r=$_.RemoteAddresses;k=$_.LocalAppPackageId;s=$_.serviceName;o=$_.LocalUserOwner} })
$profiles = @(1,2,4 | ForEach-Object { [pscustomobject]@{t=$_;e=[bool]$fw.FirewallEnabled($_);i=[int]$fw.DefaultInboundAction($_)} })
[pscustomobject]@{current=$fw.CurrentProfileTypes;profiles=$profiles;rules=$rules} | ConvertTo-Json -Compress -Depth 4`

// ParseWinFirewall reads winScript's output.
func ParseWinFirewall(b []byte) (WinFirewall, error) {
	var f WinFirewall
	err := json.Unmarshal(b, &f)
	return f, err
}

var profileNames = map[int]string{1: "Domain", 2: "Private", 4: "Public"}

func profileList(bits int) string {
	var out []string
	for _, b := range []int{1, 2, 4} {
		if bits&b != 0 {
			out = append(out, profileNames[b])
		}
	}
	return strings.Join(out, " and ")
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// portMatch reports whether a rule's LocalPorts covers port.
func portMatch(spec string, port int) bool {
	if spec == "" || spec == "*" {
		return true
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			l, e1 := strconv.Atoi(lo)
			h, e2 := strconv.Atoi(hi)
			if e1 == nil && e2 == nil && port >= l && port <= h {
				return true
			}
			continue
		}
		if n, err := strconv.Atoi(part); err == nil && n == port {
			return true
		}
	}
	return false
}

// ruleMatch reports whether a rule applies to this port, protocol and
// program, and how specifically (a port rule names the port; a program
// rule names the program and allows any port).
func ruleMatch(r WinRule, port int, proto, program string) bool {
	want := map[string]int{"tcp": 6, "udp": 17}[proto]
	if r.Protocol != 256 && r.Protocol != want {
		return false
	}
	if !portMatch(str(r.Ports), port) {
		return false
	}
	if str(r.Package) != "" || str(r.Owner) != "" {
		return false // a Store app's rule; servers aren't Store apps
	}
	if svc := str(r.Service); svc != "" && svc != "*" && !strings.EqualFold(program, "svchost.exe") && !strings.EqualFold(program, "System") {
		return false // only for one Windows service
	}
	if app := str(r.App); app != "" {
		// Kernel services (SMB, http.sys) run as "System".
		base := app[strings.LastIndexAny(app, `\/`)+1:] // Windows paths, on any platform
		if strings.EqualFold(app, "System") && strings.EqualFold(program, "System") {
			// Windows narrows its own any-port System rules (Wi-Fi Direct,
			// Teredo) by conditions COM doesn't show; only a rule naming
			// the port counts.
			p := str(r.Ports)
			return p != "" && p != "*"
		}
		if program == "" || !strings.EqualFold(base, program) {
			return false
		}
	}
	return true
}

// EvalWindows decides whether inbound connections to port reach program
// on the profiles in use. A block rule wins over any allow rule; with no
// rule, the profile's default applies.
func EvalWindows(f WinFirewall, port int, proto, program string) FirewallVerdict {
	P := strings.ToUpper(proto)
	cur := f.Current
	if cur == 0 {
		cur = 4 // unknown: assume the strictest
	}
	enabled, defaultAllow := false, false
	for _, p := range f.Profiles {
		if cur&p.Type != 0 {
			enabled = enabled || p.Enabled
			defaultAllow = defaultAllow || p.Inbound == 1
		}
	}
	where := fmt.Sprintf("this network uses the %s profile", profileList(cur))
	if !enabled {
		return FirewallVerdict{Status: OK, Title: "Windows Firewall is off for this network", Detail: where,
			Fix: "Nothing blocks the port here, but the firewall protects everything else too; turn it back on and allow just this port."}
	}
	var allowHere, allowElsewhere, blockHere []WinRule
	for _, r := range f.Rules {
		if !ruleMatch(r, port, proto, program) {
			continue
		}
		here := r.Profiles&cur != 0
		switch {
		case r.Action == 0 && here:
			blockHere = append(blockHere, r)
		case r.Action == 1 && here:
			allowHere = append(allowHere, r)
		case r.Action == 1:
			allowElsewhere = append(allowElsewhere, r)
		}
	}
	names := func(rs []WinRule) string {
		var n []string
		for i, r := range rs {
			if i == 3 {
				n = append(n, fmt.Sprintf("and %d more", len(rs)-3))
				break
			}
			n = append(n, r.Name)
		}
		return strings.Join(n, "; ")
	}
	switch {
	case len(blockHere) > 0:
		return FirewallVerdict{Status: Bad, Title: fmt.Sprintf("Windows Firewall blocks %s %d", P, port), Detail: "block rule: " + names(blockHere),
			Fix: "Block rules win over allow rules: disable or delete that rule in Windows Defender Firewall (wf.msc), Inbound Rules."}
	case len(allowHere) > 0:
		subnet := true
		for _, r := range allowHere {
			subnet = subnet && strings.EqualFold(str(r.Remote), "LocalSubnet")
		}
		if subnet {
			return FirewallVerdict{Status: Warn, Title: fmt.Sprintf("Windows Firewall allows %s %d from your local network only", P, port), Detail: "rule: " + names(allowHere),
				Fix: "To let the internet in, widen the rule's remote addresses (Scope tab) from Local subnet to Any."}
		}
		return FirewallVerdict{Status: OK, Title: fmt.Sprintf("Windows Firewall allows %s %d", P, port), Detail: "rule: " + names(allowHere) + "; " + where}
	case defaultAllow:
		return FirewallVerdict{Status: OK, Title: "Windows Firewall lets everything in on this network", Detail: where}
	case len(allowElsewhere) > 0:
		return FirewallVerdict{Status: Bad, Title: fmt.Sprintf("Windows Firewall allows %s %d only on %s networks", P, port, profileList(allowElsewhere[0].Profiles&^cur)),
			Detail: where + "; rule: " + names(allowElsewhere),
			Fix:    "Set this network to Private (Settings > Network & internet > its properties) if you trust it, or add the rule for the " + profileList(cur) + " profile too."}
	}
	fix := fmt.Sprintf("Allow it, in a terminal opened as administrator: netsh advfirewall firewall add rule name=\"%s %d\" dir=in action=allow protocol=%s localport=%d", P, port, P, port)
	if program != "" && !strings.EqualFold(program, "System") {
		fix += fmt.Sprintf(" (or allow %s in Windows Security > Firewall & network protection > Allow an app).", program)
	}
	return FirewallVerdict{Status: Bad, Title: fmt.Sprintf("No Windows Firewall rule lets %s %d in", P, port), Detail: where + "; with no rule, Windows blocks it", Fix: fix}
}
