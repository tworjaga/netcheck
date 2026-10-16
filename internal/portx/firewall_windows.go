package portx

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// platformFirewall reads Windows Firewall through PowerShell and COM
// (HNetCfg.FwPolicy2), which works without admin rights and answers in
// numbers rather than the system's language.
func platformFirewall(ctx context.Context, port int, proto, program string) FirewallVerdict {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", winScript).Output()
	if err != nil {
		return FirewallVerdict{Status: Unknown, Title: "Couldn't read Windows Firewall", Detail: strings.TrimSpace(err.Error())}
	}
	f, err := ParseWinFirewall(out)
	if err != nil {
		return FirewallVerdict{Status: Unknown, Title: "Couldn't read Windows Firewall", Detail: "unexpected answer: " + err.Error()}
	}
	return EvalWindows(f, port, proto, program)
}
