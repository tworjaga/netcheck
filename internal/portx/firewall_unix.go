//go:build !windows

package portx

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// run is a test seam for the firewall tools.
var run = func(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

var geteuid = os.Geteuid

func platformFirewall(ctx context.Context, port int, proto, program string) FirewallVerdict {
	if runtime.GOOS == "darwin" {
		return macFirewall(ctx)
	}
	return linuxFirewall(ctx, port, proto)
}

// macFirewall: macOS's application firewall asks per program, not per port.
func macFirewall(ctx context.Context) FirewallVerdict {
	out, err := run(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
	switch {
	case err != nil:
		return FirewallVerdict{Status: Unknown, Title: "Couldn't read the macOS firewall"}
	case strings.Contains(out, "disabled"):
		return FirewallVerdict{Status: OK, Title: "The macOS firewall is off"}
	}
	if b, _ := run(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getblockall"); strings.Contains(b, "enabled") || strings.Contains(b, "ENABLED") {
		return FirewallVerdict{Status: Bad, Title: "The macOS firewall blocks all incoming connections",
			Fix: "Turn off \"Block all incoming connections\" in System Settings > Network > Firewall > Options."}
	}
	return FirewallVerdict{Status: Unknown, Title: "The macOS firewall is on and decides per program",
		Fix: "Check System Settings > Network > Firewall > Options: the server program should be set to allow incoming connections."}
}

// dportRe matches a port in nft or iptables rule text.
func dportRe(port int) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(`dports? (\{[^}]*\b%d\b[^}]*\}|%d\b)|--dports? (\S*,)?%d\b`, port, port, port))
}

// EvalLinux judges what ufw, nft or iptables printed (any may be empty).
func EvalLinux(ufw, nft, ipt string, port int, proto string) FirewallVerdict {
	P := strings.ToUpper(proto)
	if strings.Contains(ufw, "Status: active") {
		re := regexp.MustCompile(fmt.Sprintf(`(?m)^%d(/%s)?\s+(ALLOW|DENY|REJECT|LIMIT)`, port, proto))
		if m := re.FindStringSubmatch(ufw); m != nil {
			if m[2] == "ALLOW" || m[2] == "LIMIT" {
				return FirewallVerdict{Status: OK, Title: fmt.Sprintf("ufw allows %s %d", P, port)}
			}
			return FirewallVerdict{Status: Bad, Title: fmt.Sprintf("ufw denies %s %d", P, port), Fix: fmt.Sprintf("sudo ufw allow %d/%s", port, proto)}
		}
		return FirewallVerdict{Status: Bad, Title: fmt.Sprintf("ufw is on and has no rule for %s %d", P, port), Fix: fmt.Sprintf("sudo ufw allow %d/%s", port, proto)}
	}
	text := nft + "\n" + ipt
	drop := regexp.MustCompile(`hook input[^\n]*policy drop|-P INPUT (DROP|REJECT)`).MatchString(text)
	mention := dportRe(port).FindString(text)
	switch {
	case strings.TrimSpace(text) == "":
		return FirewallVerdict{Status: OK, Title: "No firewall rules are loaded"}
	case !drop:
		return FirewallVerdict{Status: OK, Title: "The firewall lets connections in by default"}
	case mention != "":
		return FirewallVerdict{Status: OK, Title: fmt.Sprintf("A firewall rule mentions %s %d", P, port), Detail: strings.TrimSpace(mention)}
	}
	return FirewallVerdict{Status: Bad, Title: fmt.Sprintf("The firewall drops incoming connections and no rule opens %s %d", P, port),
		Fix: fmt.Sprintf("Allow it, e.g. sudo iptables -I INPUT -p %s --dport %d -j ACCEPT (and save it), or the equivalent for your firewall.", proto, port)}
}

func linuxFirewall(ctx context.Context, port int, proto string) FirewallVerdict {
	if geteuid() != 0 {
		return FirewallVerdict{Status: Unknown, Title: "The firewall can only be read with root", Fix: "Run it with sudo to check the firewall too."}
	}
	ufw, _ := run(ctx, "ufw", "status")
	nft, _ := run(ctx, "nft", "list", "ruleset")
	ipt, _ := run(ctx, "iptables", "-S")
	if strings.Contains(nft, "not found") || strings.Contains(nft, "executable file") {
		nft = ""
	}
	if strings.Contains(ipt, "not found") || strings.Contains(ipt, "executable file") {
		ipt = ""
	}
	if strings.Contains(ufw, "not found") || strings.Contains(ufw, "executable file") {
		ufw = ""
	}
	return EvalLinux(ufw, nft, ipt, port, proto)
}
