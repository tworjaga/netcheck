package cli

import (
	"strings"
	"testing"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/domain"
	"github.com/tworjaga/netcheck/internal/ui"
	"github.com/tworjaga/netcheck/internal/webx"
)

func report(cs ...domain.Check) domain.Report {
	return domain.Report{Domain: "example.com", Grade: "C", Score: 66, CertDays: 30, Checks: cs}
}

func TestDomainVerdict(t *testing.T) {
	r := report(
		domain.Check{Area: domain.AreaMail, Status: domain.Warn, Title: "No DMARC policy", Fix: "Publish one."},
		domain.Check{Area: domain.AreaDNSSEC, Status: domain.Bad, Title: "Signatures don't validate", Fix: "Re-sign."},
		domain.Check{Area: domain.AreaCAA, Status: domain.Info, Title: "No CAA records", Fix: "Add CAA."},
		domain.Check{Area: domain.AreaNS, Status: domain.OK, Title: "2 nameservers"},
	)
	st, msg, fixes := domainVerdict(r)
	if st != ui.Bad || msg != "example.com gets C (66/100): 1 problem and 1 warning." {
		t.Errorf("%v %q", st, msg)
	}
	if len(fixes) != 3 || !strings.HasPrefix(fixes[0], "Signatures don't validate") || !strings.HasPrefix(fixes[2], "No CAA") {
		t.Errorf("fixes, worst first: %v", fixes)
	}
	r.Asked = "www.example.com"
	if _, _, fixes := domainVerdict(r); !strings.Contains(fixes[0], "part of the zone example.com") {
		t.Errorf("subdomain note first: %v", fixes)
	}
	if st, msg, _ := domainVerdict(report()); st != ui.OK || !strings.Contains(msg, "nothing to fix") {
		t.Errorf("clean: %v %s", st, msg)
	}
	if st, _, _ := domainVerdict(domain.Report{Error: "nope.com doesn't exist"}); st != ui.Bad {
		t.Error("an error is bad")
	}
}

func TestDomainFailOn(t *testing.T) {
	r := report(domain.Check{Status: domain.Warn}, domain.Check{Status: domain.Bad})
	vals := domainValues(r)
	for spec, wantBroken := range map[string]bool{"B": true, "C": false, "problems>1": true, "cert<14d": false, "cert<60d": true, "bad>0": true} {
		rules, err := adv.ParseRules(spec)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(adv.Broken(rules, domainDefault, vals)) > 0; got != wantBroken {
			t.Errorf("--fail-on %s: broken %v, want %v", spec, got, wantBroken)
		}
	}
	r.CertDays = -1
	if _, ok := domainValues(r)["cert"]; ok {
		t.Error("no certificate, no cert value")
	}
	if domainValues(domain.Report{Error: "x"}) != nil {
		t.Error("a failed audit has no values")
	}
}

func TestDomainLines(t *testing.T) {
	r := report(
		domain.Check{Area: domain.AreaWeb, Status: domain.OK, Title: "example.com: valid for 30 more days", Detail: strings.Repeat("long detail ", 20)},
		domain.Check{Area: domain.AreaNS, Status: domain.OK, Title: "2 nameservers"},
	)
	lines := domainLines(r, 60)
	text := strings.Join(lines, "\n")
	if strings.Index(text, "Nameservers") > strings.Index(text, "Web certificate") {
		t.Error("areas in order")
	}
	for _, l := range lines {
		if ui.VisWidth(l) > 60 {
			t.Errorf("too wide: %q", l)
		}
	}
	if strings.Contains(text, "SOA") {
		t.Error("empty areas are left out")
	}
}

func TestMailFailOn(t *testing.T) {
	r := domain.MailReport{Domain: "example.com", Grade: "A", Score: 93, SPF: &domain.SPFCount{Lookups: 9},
		Checks: []domain.Check{{Area: domain.AreaSPF, Status: domain.Warn, Title: "SPF needs 9 of 10 DNS lookups"}}}
	vals := mailValues(r)
	for spec, wantBroken := range map[string]bool{"B": false, "A+": true, "lookups>8": true, "lookups>9": false, "problems>0": true} {
		rules, err := adv.ParseRules(spec)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(adv.Broken(rules, mailDefault, vals)) > 0; got != wantBroken {
			t.Errorf("--fail-on %s: broken %v, want %v", spec, got, wantBroken)
		}
	}
	if st, msg, _ := auditVerdict(r.Domain, r.Grade, r.Score, r.Checks, r.Error); st != ui.Warn || msg != "example.com gets A (93/100): 1 warning." {
		t.Errorf("%v %q", st, msg)
	}
}

func TestSiteVerdict(t *testing.T) {
	r := webx.SiteReport{Target: "example.com", URL: "https://www.example.com/", Grade: "B", Score: 79, CertDays: 40,
		Hops:   []webx.Hop{{Status: 301}, {Status: 200}},
		Checks: []domain.Check{{Area: webx.AreaHSTS, Status: domain.Warn, Title: "No HSTS", Fix: "Send it."}}}
	st, msg, fixes := siteVerdict(r)
	if st != ui.Warn || msg != "www.example.com gets B (79/100): 1 warning." || !strings.Contains(fixes[0], "where example.com leads") {
		t.Errorf("%v %q %v", st, msg, fixes)
	}
	if v := siteValues(r); v["cert"] != 40*24*3600*1000 || v["problems"] != 1 {
		t.Errorf("values %v", v)
	}
	if st, msg, _ := siteVerdict(webx.SiteReport{Target: "x.test", Error: "neither https:// nor http:// answered"}); st != ui.Bad || !strings.HasPrefix(msg, "Couldn't audit") {
		t.Errorf("error: %q", msg)
	}
}
