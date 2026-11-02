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
	"github.com/tworjaga/netcheck/internal/ui"
	"github.com/tworjaga/netcheck/internal/webx"
)

// siteDefault: a bare --fail-on value is the lowest acceptable grade.
var siteDefault = adv.Default{Metric: "grade", Op: '<'}

func siteName(r webx.SiteReport) string {
	if r.URL != "" {
		return strings.TrimSuffix(strings.TrimPrefix(r.URL, "https://"), "/")
	}
	return r.Target
}

func siteValues(r webx.SiteReport) map[string]float64 {
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

func siteVerdict(r webx.SiteReport) (ui.Status, string, []string) {
	st, msg, fixes := auditVerdict(siteName(r), r.Grade, r.Score, r.Checks, r.Error)
	if r.Error == "" && len(r.Hops) > 1 && r.URL != "" {
		fixes = append([]string{"Checked " + r.URL + ", where " + r.Target + " leads."}, fixes...)
	}
	return st, msg, fixes
}

func cmdSite(args []string) int {
	fs := flag.NewFlagSet("site", flag.ExitOnError)
	common := adv.Register(fs)
	targets := parseInterspersed(fs, args)
	ui.SetQuiet(common.JSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	usage := func(msg string) int {
		fmt.Fprintln(os.Stderr, "netcheck site: "+msg)
		fmt.Fprintln(os.Stderr, "usage: netcheck site <url or host> [-f sites.txt] [--fail-on B]")
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
				targets = append(targets, strings.Fields(l)[0])
			}
		}
		f.Close()
	}
	if len(targets) == 0 {
		return usage("name a site")
	}
	for _, t := range targets {
		if _, err := webx.NormalizeURL(t); err != nil {
			return usage(err.Error())
		}
	}
	rules, err := common.Rules()
	if err != nil {
		return usage(err.Error())
	}
	ua := "netcheck/" + version
	ui.Title("site")

	if common.Watch > 0 {
		if len(targets) > 1 {
			return usage("--watch takes one site")
		}
		adv.Watch(ctx, common.Watch, func(ctx context.Context) []string {
			r := webx.SiteAudit(ctx, targets[0], ua)
			st, msg, _ := siteVerdict(r)
			return append(append([]string{"  " + ui.Bold(siteName(r)), ""}, checkLines(webx.SiteAreas, r.Checks, ui.PanelWidth())...), "", "  "+st.Paint(msg))
		})
		return 0
	}

	if len(targets) > 1 {
		tb := ui.Table{Headers: []string{"Site", "Grade", "Issues", "Most serious"}}
		var reports []webx.SiteReport
		var broken []string
		worst := ui.OK
		t := ui.Begin("Checking")
		for i, x := range targets {
			t.Progress(fmt.Sprintf("%s (%d of %d)…", x, i+1, len(targets)))
			r := webx.SiteAudit(ctx, x, ua)
			if ctx.Err() != nil {
				t.Clear()
				return 130
			}
			st, _, _ := siteVerdict(r)
			worst = worstStatus(worst, st)
			for _, b := range adv.Broken(rules, siteDefault, siteValues(r)) {
				broken = append(broken, siteName(r)+": "+b)
			}
			_, warn, bad := r.Count()
			grade := r.Grade
			if r.Error != "" {
				grade = "–"
			}
			tb.Rows = append(tb.Rows, ui.TableRow{Status: st, Cells: []string{siteName(r), grade, fmt.Sprint(bad + warn), worstCheck(siteName(r), r.Checks, r.Error)}})
			reports = append(reports, r)
		}
		t.Clear()
		ui.Open(plural(len(targets), "site", "sites"))
		for _, l := range tb.Lines(ui.PanelWidth()) {
			ui.Println(l)
		}
		ui.Close()
		msg := fmt.Sprintf("%d of %d sites have nothing to fix.", countStatus(tb.Rows, ui.OK), len(targets))
		if !common.Raw {
			ui.Verdict(worst, msg, broken...)
		}
		ui.Println("")
		if common.JSON {
			adv.Envelope{Tool: "site", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: worst.String(), Message: msg}, Data: reports, FailedOn: broken}.Write(os.Stdout)
		}
		return adv.ExitCode(worst.String(), broken)
	}

	t := ui.Begin("Checking")
	t.Progress("HTTPS, certificate, HSTS, headers, cookies and content of " + targets[0] + "…")
	r := webx.SiteAudit(ctx, targets[0], ua)
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	st, msg, fixes := siteVerdict(r)
	var broken []string
	if vals := siteValues(r); vals != nil {
		broken = adv.Broken(rules, siteDefault, vals)
	}
	if r.Error == "" {
		ui.Open(fmt.Sprintf("%s · grade %s", siteName(r), r.Grade))
		for _, l := range checkLines(webx.SiteAreas, r.Checks, ui.PanelWidth()) {
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
		adv.Envelope{Tool: "site", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Findings: findings, Data: r, FailedOn: broken}.Write(os.Stdout)
	}
	return adv.ExitCode(st.String(), broken)
}
