package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/domain"
	"github.com/tworjaga/netcheck/internal/ui"
)

// domainDefault: a bare --fail-on value is the lowest acceptable grade
// ("--fail-on B" fails at C or worse).
var domainDefault = adv.Default{Metric: "grade", Op: '<'}

func checkStatus(s domain.Status) ui.Status {
	switch s {
	case domain.OK:
		return ui.OK
	case domain.Warn:
		return ui.Warn
	case domain.Bad:
		return ui.Bad
	}
	return ui.Skip
}

// auditVerdict sums up a graded audit (domain or mail): the status, a
// headline and the fixes, the real problems first.
func auditVerdict(name, grade string, score int, cs []domain.Check, failed string) (ui.Status, string, []string) {
	if failed != "" {
		return ui.Bad, "Couldn't audit: " + failed + ".", nil
	}
	_, warn, bad := domain.Report{Checks: cs}.Count()
	st := ui.OK
	var issues string
	switch {
	case bad > 0:
		st, issues = ui.Bad, plural(bad, "problem", "problems")
		if warn > 0 {
			issues += " and " + plural(warn, "warning", "warnings")
		}
	case warn > 0:
		st, issues = ui.Warn, plural(warn, "warning", "warnings")
	default:
		issues = "nothing to fix"
	}
	msg := fmt.Sprintf("%s gets %s (%d/100): %s.", name, grade, score, issues)
	var fixes []string
	for _, want := range []domain.Status{domain.Bad, domain.Warn, domain.Info} {
		for _, c := range cs {
			if c.Status == want && c.Fix != "" {
				fixes = append(fixes, c.Title+": "+c.Fix)
			}
		}
	}
	return st, msg, fixes
}

func domainVerdict(r domain.Report) (ui.Status, string, []string) {
	st, msg, fixes := auditVerdict(r.Domain, r.Grade, r.Score, r.Checks, r.Error)
	if r.Asked != "" && r.Error == "" {
		fixes = append([]string{r.Asked + " is part of the zone " + r.Domain + ", so this is the audit of " + r.Domain + "."}, fixes...)
	}
	return st, msg, fixes
}

// areaLines is one area's checks: a status line each, details dim below.
func areaLines(cs []domain.Check, width int) []string {
	var out []string
	for _, c := range cs {
		st := checkStatus(c.Status)
		title := c.Title
		if c.Status == domain.Warn || c.Status == domain.Bad {
			title = st.Paint(title)
		}
		out = append(out, "  "+st.Sym()+"  "+title)
		if c.Detail != "" {
			for _, l := range ui.Wrap(c.Detail, max(20, width-7)) {
				out = append(out, "     "+ui.Dim(l))
			}
		}
	}
	return out
}

// checkLines shows the checks area by area, leaving out empty areas.
func checkLines(areas []string, checks []domain.Check, width int) []string {
	var out []string
	for _, a := range areas {
		var cs []domain.Check
		for _, c := range checks {
			if c.Area == a {
				cs = append(cs, c)
			}
		}
		if len(cs) == 0 {
			continue
		}
		if len(out) > 0 {
			out = append(out, "")
		}
		out = append(out, "  "+ui.Bold(a))
		out = append(out, areaLines(cs, width)...)
	}
	return out
}

func domainLines(r domain.Report, width int) []string {
	return checkLines(domain.Areas, r.Checks, width)
}

// domainValues are the --fail-on measurements.
func domainValues(r domain.Report) map[string]float64 {
	if r.Error != "" {
		return nil
	}
	_, warn, bad := r.Count()
	g, _ := adv.GradeValue(r.Grade)
	v := map[string]float64{"grade": g, "score": float64(r.Score), "problems": float64(bad + warn), "bad": float64(bad)}
	if r.CertDays >= 0 {
		v["cert"] = float64(r.CertDays) * 24 * 3600 * 1000
	}
	return v
}

// worstCheck is the most serious finding, for the table.
func worstCheck(name string, cs []domain.Check, failed string) string {
	if failed != "" {
		return strings.TrimPrefix(failed, name+" ")
	}
	for _, want := range []domain.Status{domain.Bad, domain.Warn} {
		for _, c := range cs {
			if c.Status == want {
				return c.Area + ": " + c.Title
			}
		}
	}
	return ui.Dim("none")
}

func cmdDomain(args []string) int {
	fs := flag.NewFlagSet("domain", flag.ExitOnError)
	common := adv.Register(fs)
	names := parseInterspersed(fs, args)
	ui.SetQuiet(common.JSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	usage := func(msg string) int {
		fmt.Fprintln(os.Stderr, "netcheck domain: "+msg)
		fmt.Fprintln(os.Stderr, "usage: netcheck domain <domain> [-f domains.txt] [--fail-on B]")
		return 2
	}
	if common.File != "" {
		f, err := os.Open(common.File)
		if err != nil {
			return usage(err.Error())
		}
		sc := bufio.NewScanner(f)
		for line := 1; sc.Scan(); line++ {
			fields := strings.Fields(strings.SplitN(sc.Text(), "#", 2)[0])
			switch len(fields) {
			case 0:
				continue
			case 1:
				names = append(names, fields[0])
			default:
				f.Close()
				return usage(fmt.Sprintf("%s line %d: one domain per line", common.File, line))
			}
		}
		f.Close()
	}
	if len(names) == 0 {
		return usage("name a domain to audit")
	}
	rules, err := common.Rules()
	if err != nil {
		return usage(err.Error())
	}
	ui.Title("domain")

	if common.Watch > 0 {
		if len(names) > 1 {
			return usage("--watch takes one domain")
		}
		adv.Watch(ctx, common.Watch, func(ctx context.Context) []string {
			r := domain.Audit(ctx, names[0])
			st, msg, _ := domainVerdict(r)
			return append(append([]string{"  " + ui.Bold(r.Domain), ""}, domainLines(r, ui.PanelWidth())...), "", "  "+st.Paint(msg))
		})
		return 0
	}

	// Several domains: one row each.
	if len(names) > 1 {
		tb := ui.Table{Headers: []string{"Domain", "Grade", "Issues", "Most serious"}}
		var reports []domain.Report
		var broken []string
		worst := ui.OK
		t := ui.Begin("Auditing")
		for i, n := range names {
			t.Progress(fmt.Sprintf("%s (%d of %d)…", n, i+1, len(names)))
			r := domain.Audit(ctx, n)
			if ctx.Err() != nil {
				t.Clear()
				return 130
			}
			st, _, _ := domainVerdict(r)
			worst = worstStatus(worst, st)
			if vals := domainValues(r); vals != nil {
				for _, b := range adv.Broken(rules, domainDefault, vals) {
					broken = append(broken, r.Domain+": "+b)
				}
			}
			_, warn, bad := r.Count()
			grade := r.Grade
			if r.Error != "" {
				grade = "–"
			}
			tb.Rows = append(tb.Rows, ui.TableRow{Status: st, Cells: []string{r.Domain, grade, fmt.Sprint(bad + warn), worstCheck(r.Domain, r.Checks, r.Error)}})
			reports = append(reports, r)
		}
		t.Clear()
		ui.Open(plural(len(names), "domain", "domains"))
		for _, l := range tb.Lines(ui.PanelWidth()) {
			ui.Println(l)
		}
		ui.Close()
		msg := fmt.Sprintf("%d of %d domains have nothing to fix.", countStatus(tb.Rows, ui.OK), len(names))
		if !common.Raw {
			ui.Verdict(worst, msg, broken...)
		}
		ui.Println("")
		if common.JSON {
			adv.Envelope{Tool: "domain", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: worst.String(), Message: msg}, Data: reports, FailedOn: broken}.Write(os.Stdout)
		}
		return adv.ExitCode(worst.String(), broken)
	}

	t := ui.Begin("Auditing")
	t.Progress("nameservers, DNSSEC, mail records, blocklists and certificates for " + names[0] + "…")
	r := domain.Audit(ctx, names[0])
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	st, msg, fixes := domainVerdict(r)
	var broken []string
	if vals := domainValues(r); vals != nil {
		broken = adv.Broken(rules, domainDefault, vals)
	}
	if r.Error == "" {
		ui.Open(fmt.Sprintf("%s · grade %s", r.Domain, r.Grade))
		for _, l := range domainLines(r, ui.PanelWidth()) {
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
			findings = append(findings, adv.Finding{Status: checkStatus(c.Status).String(), Message: c.Area + ": " + c.Title})
		}
		adv.Envelope{Tool: "domain", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Findings: findings, Data: r, FailedOn: broken}.Write(os.Stdout)
	}
	return adv.ExitCode(st.String(), broken)
}
