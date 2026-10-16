package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/domain"
	"github.com/tworjaga/netcheck/internal/ui"
	"github.com/tworjaga/netcheck/internal/webx"
)

// certDefault: a bare --fail-on value is the fewest days the certificate
// may have left ("--fail-on 14d").
var certDefault = adv.Default{Metric: "days", Op: '<'}

// certTarget reads "host", "host:port", "[v6]:port" or a URL into a host
// and port (0 = not given).
func certTarget(s string) (string, int, error) {
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return "", 0, fmt.Errorf("%q isn't a URL", s)
		}
		port := map[string]int{"https": 443, "ldaps": 636, "imaps": 993, "smtps": 465, "pop3s": 995}[u.Scheme]
		if p, err := strconv.Atoi(u.Port()); err == nil {
			port = p
		}
		return u.Hostname(), port, nil
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", 0, fmt.Errorf("%q isn't a port", p)
		}
		return h, n, nil
	}
	return strings.Trim(s, "[]"), 0, nil
}

// certVerdict sums up an inspection.
func certVerdict(r webx.CertReport) (ui.Status, string, []string) {
	who := r.Host
	if r.Port != 443 {
		who = net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
	}
	if r.Error != "" {
		return ui.Bad, "Couldn't get the certificate from " + who + ": " + r.Error + ".", nil
	}
	st, _, fixes := auditVerdict(who, "", 0, r.Checks, "")
	var msg string
	switch {
	case r.Problem != "":
		msg = fmt.Sprintf("Clients refuse %s's certificate: %s.", who, firstBad(r.Checks))
	case st == ui.Bad:
		msg = fmt.Sprintf("%s's certificate is trusted, but: %s.", who, firstBad(r.Checks))
	case st == ui.Warn:
		msg = fmt.Sprintf("%s's certificate is trusted, with %s to look at.", who, plural(countIssues(r.Checks), "thing", "things"))
	default:
		msg = fmt.Sprintf("%s's certificate is trusted and valid for %d more days.", who, r.Chain[0].Days)
	}
	return st, msg, fixes
}

// firstBad is the first real problem's title, lower-cased to sit in a
// sentence.
func firstBad(cs []domain.Check) string {
	for _, c := range cs {
		if c.Status == domain.Bad {
			return strings.ToLower(c.Title[:1]) + c.Title[1:]
		}
	}
	return ""
}

func countIssues(cs []domain.Check) int {
	_, w, b := domain.Report{Checks: cs}.Count()
	return w + b
}

// chainLines draws the chain from the server's certificate up to the root.
func chainLines(r webx.CertReport, width int) []string {
	var out []string
	for i, c := range r.Chain {
		lead := "  "
		if i > 0 {
			lead = "  " + strings.Repeat("  ", i-1) + ui.Pick("└ ", "\\ ")
		}
		role := "server"
		switch {
		case c.FromStore:
			role = "root, from the trust store"
		case c.SelfSigned && c.CA:
			role = "root"
		case c.CA:
			role = "intermediate"
		}
		st := ui.OK
		switch {
		case c.Days < 0:
			st = ui.Bad
		case c.Days < 21 && i == 0:
			st = ui.Warn
		}
		out = append(out, lead+st.Sym()+" "+ui.Bold(c.Subject)+"  "+ui.Dim(role))
		pad := strings.Repeat(" ", ui.VisWidth(lead)+2)
		detail := fmt.Sprintf("%s · %s · until %s (%d days)", c.Key, c.SigAlg, c.NotAfter.UTC().Format("2006-01-02"), c.Days)
		if !c.FromStore && !(c.SelfSigned && c.CA) {
			detail += " · by " + c.Issuer
		}
		for _, l := range ui.Wrap(detail, max(20, width-len(pad)-2)) {
			out = append(out, pad+ui.Dim(l))
		}
		if i == 0 && len(c.Names) > 0 {
			names := c.Names
			more := ""
			if len(names) > 8 {
				names, more = names[:8], fmt.Sprintf(" and %d more", len(c.Names)-8)
			}
			for _, l := range ui.Wrap("names: "+strings.Join(names, ", ")+more, max(20, width-len(pad)-2)) {
				out = append(out, pad+ui.Dim(l))
			}
		}
	}
	return out
}

func certLines(r webx.CertReport, width int) []string {
	out := chainLines(r, width)
	out = append(out, "")
	var vs []string
	for _, v := range []string{"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"} {
		mark := ui.Dim("no")
		if r.Versions[v] {
			mark = "yes"
			if v == "TLS 1.0" || v == "TLS 1.1" {
				mark = ui.Caution("yes")
			}
		}
		vs = append(vs, strings.TrimPrefix(v, "TLS ")+" "+mark)
	}
	facts := [][2]string{
		{"Connection", strings.TrimSpace(r.Version + " · " + r.Cipher + " " + ui.Dim(r.ALPN))},
		{"Versions", "TLS " + strings.Join(vs, " · ")},
		{"Address", r.Addr},
		{"OCSP stapled", map[bool]string{true: "yes", false: ui.Dim("no")}[r.OCSP]},
	}
	if r.StartTLS != "" {
		facts = append(facts, [2]string{"STARTTLS", r.StartTLS})
	}
	for _, kv := range facts {
		out = append(out, "  "+ui.Pad(ui.Dim(kv[0]), 14)+kv[1])
	}
	out = append(out, "")
	return append(out, areaLines(r.Checks, width)...)
}

func certValues(r webx.CertReport) map[string]float64 {
	if r.Error != "" || len(r.Chain) == 0 {
		return nil
	}
	return map[string]float64{"days": float64(r.Chain[0].Days) * 24 * 3600 * 1000, "problems": float64(countIssues(r.Checks))}
}

func cmdCert(args []string) int {
	fs := flag.NewFlagSet("cert", flag.ExitOnError)
	common := adv.Register(fs)
	port := fs.Int("p", 0, "port (default 443, or from the URL)")
	starttls := fs.String("starttls", "", "speak smtp, imap, pop3 or ftp before TLS (default: from the port; none to turn off)")
	sni := fs.String("sni", "", "the name to ask for (default: the host)")
	pos := parseInterspersed(fs, args)
	ui.SetQuiet(common.JSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	usage := func(msg string) int {
		fmt.Fprintln(os.Stderr, "netcheck cert: "+msg)
		fmt.Fprintln(os.Stderr, "usage: netcheck cert <host[:port]> [-p port] [--starttls smtp|imap|pop3|ftp] [--sni name] [--fail-on 14d]")
		return 2
	}
	if common.File != "" {
		f, err := os.Open(common.File)
		if err != nil {
			return usage(err.Error())
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if l := strings.TrimSpace(strings.SplitN(sc.Text(), "#", 2)[0]); l != "" {
				pos = append(pos, strings.Fields(l)[0])
			}
		}
		f.Close()
	}
	if len(pos) == 0 {
		return usage("name a host")
	}
	type target struct {
		host        string
		port        int
		proto, show string
	}
	var targets []target
	for _, a := range pos {
		h, p, err := certTarget(a)
		if err != nil {
			return usage(err.Error())
		}
		if *port != 0 {
			p = *port
		}
		if p == 0 {
			p = 443
		}
		proto := webx.StartTLSFor(p)
		switch *starttls {
		case "":
		case "none":
			proto = ""
		case "smtp", "imap", "pop3", "ftp":
			proto = *starttls
		default:
			return usage(fmt.Sprintf("%q: STARTTLS works with smtp, imap, pop3 or ftp", *starttls))
		}
		show := h
		if p != 443 {
			show = net.JoinHostPort(h, strconv.Itoa(p))
		}
		targets = append(targets, target{h, p, proto, show})
	}
	rules, err := common.Rules()
	if err != nil {
		return usage(err.Error())
	}
	ui.Title("cert")

	if common.Watch > 0 {
		if len(targets) > 1 {
			return usage("--watch takes one host")
		}
		x := targets[0]
		adv.Watch(ctx, common.Watch, func(ctx context.Context) []string {
			r := webx.Inspect(ctx, x.host, x.port, *sni, x.proto)
			st, msg, _ := certVerdict(r)
			lines := []string{"  " + ui.Bold(x.show), ""}
			if r.Error == "" {
				lines = append(lines, certLines(r, ui.PanelWidth())...)
			}
			return append(lines, "", "  "+st.Paint(msg))
		})
		return 0
	}

	if len(targets) > 1 {
		tb := ui.Table{Headers: []string{"Host", "Days", "Issuer", "Problem"}}
		var reports []webx.CertReport
		var broken []string
		worst := ui.OK
		t := ui.Begin("Checking")
		for i, x := range targets {
			t.Progress(fmt.Sprintf("%s (%d of %d)…", x.show, i+1, len(targets)))
			r := webx.Inspect(ctx, x.host, x.port, *sni, x.proto)
			if ctx.Err() != nil {
				t.Clear()
				return 130
			}
			st, _, _ := certVerdict(r)
			worst = worstStatus(worst, st)
			for _, b := range adv.Broken(rules, certDefault, certValues(r)) {
				broken = append(broken, x.show+": "+b)
			}
			days, iss, prob := "–", "", worstCheck(x.show, r.Checks, r.Error)
			if len(r.Chain) > 0 {
				days, iss = fmt.Sprint(r.Chain[0].Days), r.Chain[0].Issuer
			}
			tb.Rows = append(tb.Rows, ui.TableRow{Status: st, Cells: []string{x.show, days, iss, prob}})
			reports = append(reports, r)
		}
		t.Clear()
		ui.Open(plural(len(targets), "host", "hosts"))
		for _, l := range tb.Lines(ui.PanelWidth()) {
			ui.Println(l)
		}
		ui.Close()
		msg := fmt.Sprintf("%d of %d certificates have nothing to fix.", countStatus(tb.Rows, ui.OK), len(targets))
		if !common.Raw {
			ui.Verdict(worst, msg, broken...)
		}
		ui.Println("")
		if common.JSON {
			adv.Envelope{Tool: "cert", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: worst.String(), Message: msg}, Data: reports, FailedOn: broken}.Write(os.Stdout)
		}
		return adv.ExitCode(worst.String(), broken)
	}

	x := targets[0]
	t := ui.Begin("Connecting")
	t.Progress(x.show + "…")
	r := webx.Inspect(ctx, x.host, x.port, *sni, x.proto)
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	st, msg, fixes := certVerdict(r)
	var broken []string
	if vals := certValues(r); vals != nil {
		broken = adv.Broken(rules, certDefault, vals)
	}
	if r.Error == "" {
		ui.Open(x.show)
		for _, l := range certLines(r, ui.PanelWidth()) {
			ui.Println(l)
		}
		ui.Close()
	}
	if !common.Raw {
		ui.Verdict(st, msg, append(fixes, broken...)...)
	}
	ui.Println("")
	if common.JSON {
		var findings []adv.Finding
		for _, c := range r.Checks {
			findings = append(findings, adv.Finding{Status: checkStatus(c.Status).String(), Message: c.Title})
		}
		adv.Envelope{Tool: "cert", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Findings: findings, Data: r, FailedOn: broken}.Write(os.Stdout)
	}
	return adv.ExitCode(st.String(), broken)
}
