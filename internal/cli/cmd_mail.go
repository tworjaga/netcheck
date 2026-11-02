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

// mailDefault: a bare --fail-on value is the lowest acceptable grade.
var mailDefault = adv.Default{Metric: "grade", Op: '<'}

// mailValues are the --fail-on measurements.
func mailValues(r domain.MailReport) map[string]float64 {
	if r.Error != "" {
		return nil
	}
	_, warn, bad := r.Count()
	g, _ := adv.GradeValue(r.Grade)
	v := map[string]float64{"grade": g, "score": float64(r.Score), "problems": float64(bad + warn), "bad": float64(bad)}
	if r.SPF != nil {
		v["lookups"] = float64(r.SPF.Lookups)
	}
	return v
}

func mailLines(r domain.MailReport, width int) []string {
	return checkLines(domain.MailAreas, r.Checks, width)
}

func cmdMail(args []string) int {
	fs := flag.NewFlagSet("mail", flag.ExitOnError)
	common := adv.Register(fs)
	names := parseInterspersed(fs, args)
	ui.SetQuiet(common.JSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	usage := func(msg string) int {
		fmt.Fprintln(os.Stderr, "netcheck mail: "+msg)
		fmt.Fprintln(os.Stderr, "usage: netcheck mail <domain> [-f domains.txt] [--fail-on B]")
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
		return usage("name a mail domain")
	}
	rules, err := common.Rules()
	if err != nil {
		return usage(err.Error())
	}
	ui.Title("mail")

	if common.Watch > 0 {
		if len(names) > 1 {
			return usage("--watch takes one domain")
		}
		adv.Watch(ctx, common.Watch, func(ctx context.Context) []string {
			r := domain.MailAudit(ctx, names[0])
			st, msg, _ := auditVerdict(r.Domain, r.Grade, r.Score, r.Checks, r.Error)
			return append(append([]string{"  " + ui.Bold(r.Domain), ""}, mailLines(r, ui.PanelWidth())...), "", "  "+st.Paint(msg))
		})
		return 0
	}

	if len(names) > 1 {
		tb := ui.Table{Headers: []string{"Domain", "Grade", "Issues", "Most serious"}}
		var reports []domain.MailReport
		var broken []string
		worst := ui.OK
		t := ui.Begin("Checking")
		for i, n := range names {
			t.Progress(fmt.Sprintf("%s (%d of %d)…", n, i+1, len(names)))
			r := domain.MailAudit(ctx, n)
			if ctx.Err() != nil {
				t.Clear()
				return 130
			}
			st, _, _ := auditVerdict(r.Domain, r.Grade, r.Score, r.Checks, r.Error)
			worst = worstStatus(worst, st)
			if vals := mailValues(r); vals != nil {
				for _, b := range adv.Broken(rules, mailDefault, vals) {
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
			adv.Envelope{Tool: "mail", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: worst.String(), Message: msg}, Data: reports, FailedOn: broken}.Write(os.Stdout)
		}
		return adv.ExitCode(worst.String(), broken)
	}

	t := ui.Begin("Checking")
	t.Progress("mail records, SPF lookups, MTA-STS, blocklists, and the mail servers on port 25 for " + names[0] + "…")
	r := domain.MailAudit(ctx, names[0])
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	st, msg, fixes := auditVerdict(r.Domain, r.Grade, r.Score, r.Checks, r.Error)
	var broken []string
	if vals := mailValues(r); vals != nil {
		broken = adv.Broken(rules, mailDefault, vals)
	}
	if r.Error == "" {
		ui.Open(fmt.Sprintf("%s · grade %s", r.Domain, r.Grade))
		for _, l := range mailLines(r, ui.PanelWidth()) {
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
		adv.Envelope{Tool: "mail", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Findings: findings, Data: r, FailedOn: broken}.Write(os.Stdout)
	}
	return adv.ExitCode(st.String(), broken)
}
