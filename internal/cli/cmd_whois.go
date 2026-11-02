package cli

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/rdap"
	"github.com/tworjaga/netcheck/internal/tracex"
	"github.com/tworjaga/netcheck/internal/ui"
)

// whoisDefault: a bare --fail-on value is the fewest days a domain may have
// before it expires ("--fail-on 30d").
var whoisDefault = adv.Default{Metric: "expires", Op: '<'}

// whoisResult is a lookup plus, for an address, who announces it.
type whoisResult struct {
	rdap.Info
	Origin *tracex.Owner `json:"origin,omitempty"`
}

func day(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format("2006-01-02")
}

func daysUntil(t time.Time) int { return int(time.Until(t).Hours() / 24) }

func hasStatus(st []string, words ...string) bool {
	for _, s := range st {
		l := strings.ToLower(strings.ReplaceAll(s, " ", ""))
		for _, w := range words {
			if strings.Contains(l, w) {
				return true
			}
		}
	}
	return false
}

// whoisVerdict sums up a lookup.
func whoisVerdict(r whoisResult) (ui.Status, string, []string) {
	in := r.Info
	if in.Error != "" {
		return ui.Bad, "Couldn't look it up: " + in.Error + ".", nil
	}
	if !in.Found {
		src := in.Source
		if i := strings.Index(src, "://"); i >= 0 {
			src, _, _ = strings.Cut(src[i+3:], "/")
		}
		return ui.Skip, fmt.Sprintf("%s isn't registered, according to %s.", in.Query, src), nil
	}
	var notes []string
	if in.Abuse != "" {
		notes = append(notes, "Abuse reports go to "+in.Abuse+".")
	}
	switch in.Kind {
	case "ip":
		msg := in.Query + " is in " + firstOf(in.CIDR, in.Range)
		if in.Name != "" {
			msg += " (" + in.Name + ")"
		}
		if in.Holder != "" {
			msg += ", held by " + in.Holder
		}
		if r.Origin != nil && r.Origin.ASN != 0 {
			msg += fmt.Sprintf("; announced by AS%d", r.Origin.ASN)
			if r.Origin.Name != "" {
				msg += " " + tracex.ShortOwner(r.Origin.Name)
			}
		}
		return ui.OK, strings.TrimSuffix(msg, ".") + ".", notes
	case "asn":
		msg := "AS" + strings.TrimPrefix(strings.ToUpper(in.Query), "AS") + " is " + firstOf(in.Name, in.Handle)
		if in.Holder != "" {
			msg += " (" + in.Holder + ")"
		}
		if in.Registered != nil {
			msg += ", registered " + day(in.Registered)
		}
		return ui.OK, msg + ".", notes
	}

	st := ui.OK
	msg := in.Name + " is registered"
	if in.Registrar != "" {
		msg += " with " + in.Registrar
	}
	if in.Registered != nil {
		msg += " since " + day(in.Registered)
	}
	if in.Expires != nil {
		d := daysUntil(*in.Expires)
		switch {
		case d < 0:
			st = ui.Bad
			msg += fmt.Sprintf("; it expired on %s", day(in.Expires))
		case d < 30:
			st = ui.Warn
			msg += fmt.Sprintf("; it expires in %s, on %s", plural(d, "day", "days"), day(in.Expires))
		default:
			msg += fmt.Sprintf("; it runs until %s (%d days)", day(in.Expires), d)
		}
	}
	msg += "."
	switch {
	case hasStatus(in.Status, "redemptionperiod", "pendingdelete"):
		st = ui.Bad
		notes = append([]string{"The registry is about to delete it (" + strings.Join(in.Status, ", ") + "); renew or restore it at the registrar now."}, notes...)
	case st == ui.Warn:
		notes = append([]string{"Renew it at the registrar, or turn on automatic renewal."}, notes...)
	}
	if in.Protocol == "rdap" && len(in.Status) > 0 && !hasStatus(in.Status, "transferprohibited") {
		notes = append(notes, "Transfer lock is off: whoever has the transfer code can move the domain away. Turn it on at the registrar unless a move is planned.")
	}
	if in.DNSSEC != nil && *in.DNSSEC {
		notes = append(notes, "The registry has a DNSSEC key for it.")
	}
	return st, msg, notes
}

func firstOf(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

func whoisLines(r whoisResult, width int) []string {
	in := r.Info
	var facts [][2]string
	add := func(k, v string) {
		if v != "" {
			facts = append(facts, [2]string{k, v})
		}
	}
	switch in.Kind {
	case "domain":
		add("Domain", in.Name)
		add("Registrar", in.Registrar)
		add("Holder", in.Holder)
		add("Registered", day(in.Registered))
		add("Updated", day(in.Updated))
		if in.Expires != nil {
			add("Expires", fmt.Sprintf("%s (%d days)", day(in.Expires), daysUntil(*in.Expires)))
		}
		add("Status", strings.Join(in.Status, ", "))
		add("Nameservers", strings.Join(in.Nameservers, ", "))
		if in.DNSSEC != nil {
			add("DNSSEC", map[bool]string{true: "signed", false: "not signed"}[*in.DNSSEC])
		}
	case "ip":
		add("Range", in.Range)
		add("Prefix", in.CIDR)
		add("Network", in.Name)
		add("Holder", in.Holder)
		add("Type", in.Type)
		add("Country", in.Country)
		if r.Origin != nil && r.Origin.ASN != 0 {
			add("Announced by", strings.TrimSpace(fmt.Sprintf("AS%d %s", r.Origin.ASN, tracex.ShortOwner(r.Origin.Name))))
			add("BGP prefix", r.Origin.Prefix)
		}
		add("Registered", day(in.Registered))
		add("Updated", day(in.Updated))
	case "asn":
		add("Name", in.Name)
		add("Handle", in.Handle)
		add("Holder", in.Holder)
		add("Country", in.Country)
		add("Registered", day(in.Registered))
		add("Updated", day(in.Updated))
	}
	add("Abuse", in.Abuse)
	add("Source", strings.TrimSpace(in.Source+" "+ui.Dim(strings.ToUpper(in.Protocol))))
	var out []string
	for _, kv := range facts {
		for i, l := range ui.Wrap(kv[1], max(20, width-17)) {
			k := ""
			if i == 0 {
				k = kv[0]
			}
			out = append(out, "  "+ui.Pad(ui.Dim(k), 15)+l)
		}
	}
	return out
}

func whoisValues(r whoisResult) map[string]float64 {
	if r.Error != "" || !r.Found || r.Expires == nil {
		return nil
	}
	return map[string]float64{"expires": float64(daysUntil(*r.Expires)) * 24 * 3600 * 1000}
}

func lookupWhois(ctx context.Context, q string) whoisResult {
	r := whoisResult{Info: rdap.Lookup(ctx, q)}
	if ip := net.ParseIP(strings.TrimSpace(q)); ip != nil && r.Error == "" {
		o := tracex.LookupOwner(ctx, ip)
		r.Origin = &o
	}
	return r
}

func cmdWhois(args []string) int {
	fs := flag.NewFlagSet("whois", flag.ExitOnError)
	common := adv.Register(fs)
	pos := parseInterspersed(fs, args)
	ui.SetQuiet(common.JSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	usage := func(msg string) int {
		fmt.Fprintln(os.Stderr, "netcheck whois: "+msg)
		fmt.Fprintln(os.Stderr, "usage: netcheck whois <domain | IP address | AS number> [--raw] [--fail-on 30d]")
		return 2
	}
	if len(pos) != 1 {
		return usage("give one domain, IP address or AS number")
	}
	rules, err := common.Rules()
	if err != nil {
		return usage(err.Error())
	}
	ui.Title("whois")
	t := ui.Begin("Asking")
	t.Progress("the registry about " + pos[0] + "…")
	r := lookupWhois(ctx, pos[0])
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	st, msg, notes := whoisVerdict(r)
	var broken []string
	if vals := whoisValues(r); vals != nil {
		broken = adv.Broken(rules, whoisDefault, vals)
	}
	if r.Error == "" && r.Found {
		ui.Open(pos[0])
		for _, l := range whoisLines(r, ui.PanelWidth()) {
			ui.Println(l)
		}
		ui.Close()
	}
	if common.Raw && r.Raw != "" && !common.JSON {
		fmt.Println(strings.TrimRight(r.Raw, "\r\n"))
	}
	if !common.Raw {
		ui.Verdict(st, msg, append(notes, broken...)...)
	}
	ui.Println("")
	if common.JSON {
		adv.Envelope{Tool: "whois", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Data: r, FailedOn: broken}.Write(os.Stdout)
	}
	return adv.ExitCode(st.String(), broken)
}
