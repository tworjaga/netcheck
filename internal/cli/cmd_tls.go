package cli

import (
	"context"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

// skewText says how far off the clock is, in words.
func skewText(s float64) string {
	dir := "ahead"
	if s < 0 {
		dir = "behind"
	}
	return fmtDur(time.Duration(math.Abs(s)*float64(time.Second))) + " " + dir
}

// tlsVerdict judges the handshakes and the clock. Findings are ordered by
// seriousness; the first one leads.
func tlsVerdict(r probe.TLSResult) (ui.Status, string, []finding) {
	var fs []finding
	abs := math.Abs(r.SkewSeconds)
	switch {
	case r.ClockChecked && abs >= 300:
		fs = append(fs, finding{ui.Bad, fmt.Sprintf("Your clock is %s. Secure sites, sign-ins and two-factor codes fail when it's this far out; turn on automatic time.", skewText(r.SkewSeconds))})
	case r.ClockChecked && abs >= 60:
		fs = append(fs, finding{ui.Warn, fmt.Sprintf("Your clock is %s. That's enough to break two-factor codes; turn on automatic time.", skewText(r.SkewSeconds))})
	}
	ok, network, v12 := 0, 0, 0
	inspector := ""
	for _, p := range r.Probes {
		switch p.Problem {
		case "":
			ok++
			if p.Version == "TLS 1.2" {
				v12++
			}
			if p.Inspector != "" {
				inspector = p.Inspector
			}
		case "network":
			network++
		case "untrusted":
			who := p.Issuer
			if who == "" {
				who = "an unknown issuer"
			}
			fs = append(fs, finding{ui.Bad, fmt.Sprintf("Secure connections are being intercepted: the certificate for %s comes from %q, which this computer doesn't trust. That's a filter, a proxy or a hostile network.", p.Host, who)})
		case "name":
			fs = append(fs, finding{ui.Bad, fmt.Sprintf("Something answers HTTPS for %s with another site's certificate, usually a captive portal or a filter.", p.Host)})
		case "expired", "not_yet_valid":
			if !r.ClockChecked || abs < 300 {
				fs = append(fs, finding{ui.Bad, fmt.Sprintf("The certificate for %s looks out of date. If your clock is right, something is intercepting the connection.", p.Host)})
			}
		}
	}
	if ok+len(fs) == 0 && network == len(r.Probes) {
		return ui.Bad, "Couldn't make any HTTPS connection; check your internet connection first.", nil
	}
	if inspector != "" {
		fs = append(fs, finding{ui.Warn, fmt.Sprintf("Encrypted connections are inspected by %q. That's expected from antivirus or on a work device; otherwise, find out why.", inspector)})
	}
	if ok > 0 && v12 == ok {
		fs = append(fs, finding{ui.Warn, "Connections settle for TLS 1.2 where the sites offer 1.3, so something in between (often a filter or an older proxy) is handling them."})
	}
	good := "HTTPS works: certificates check out"
	if r.ClockChecked {
		good += fmt.Sprintf(" and your clock is right (within %s)", fmtDur(time.Duration(math.Max(1, math.Round(abs))*float64(time.Second))))
	}
	st, head := lead(fs, good+".")
	return st, head, fs
}

func cmdTLS(args []string) int {
	fs := flag.NewFlagSet("tls", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	parseInterspersed(fs, args)
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ui.Title("tls")
	ui.Open("HTTPS and clock")
	defer ui.Close()
	t := ui.Begin("TLS")
	t.Progress("handshaking and comparing clocks…")
	r := probe.CheckTLS(ctx)
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	for _, p := range r.Probes {
		switch {
		case p.OK:
			extra := p.Version
			if p.Issuer != "" {
				extra += " · " + p.Issuer
			}
			st := ui.OK
			if p.Inspector != "" {
				st = ui.Warn
			}
			ui.Println(ui.Row("HTTPS", st, p.Host, fmtMs(p.Ms), ui.Dim(extra)))
		case p.Problem == "network":
			ui.Println(ui.Row("HTTPS", ui.Skip, p.Host, "–", ui.Dim(p.Error)))
		default:
			ui.Println(ui.Row("HTTPS", ui.Bad, p.Host, "–", ui.Dim(p.Problem+" · "+p.Issuer)))
		}
	}
	if r.ClockChecked {
		st := ui.OK
		switch abs := math.Abs(r.SkewSeconds); {
		case abs >= 300:
			st = ui.Bad
		case abs >= 60:
			st = ui.Warn
		}
		label := "in sync"
		if math.Abs(r.SkewSeconds) >= 2 {
			label = skewText(r.SkewSeconds)
		}
		metric := fmt.Sprintf("%+.0f s", r.SkewSeconds)
		if math.Abs(r.SkewSeconds) < 0.5 {
			metric = "0 s"
		}
		ui.Println(ui.Row("Clock", st, label, metric, ui.Dim("against web servers' clocks")))
	} else {
		ui.Println(ui.Row("Clock", ui.Skip, "not checked", "–", ui.Dim("no server answered")))
	}

	st, head, findings := tlsVerdict(r)
	printVerdict(st, head, findings)
	ui.Println("")
	if *asJSON {
		printJSON(struct {
			probe.TLSResult
			Verdict verdict `json:"verdict"`
		}{r, verdict{st.String(), head}})
	}
	return exitFor(st)
}
