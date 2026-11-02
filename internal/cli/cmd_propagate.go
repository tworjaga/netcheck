package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/dnsx"
	"github.com/tworjaga/netcheck/internal/ui"
)

// propDefault: a bare --fail-on value is how many resolvers may still be
// behind ("--fail-on 0" fails until every one has the new answer).
var propDefault = adv.Default{Metric: "behind", Op: '>'}

func valuesText(v []string) string {
	if len(v) == 0 {
		return ui.Dim("none")
	}
	return strings.Join(v, ", ")
}

func cacheLeft(ttl uint32) string {
	return fmtDur(time.Duration(ttl) * time.Second)
}

// propVerdict sums up a propagation check.
func propVerdict(p dnsx.PropResult) (ui.Status, string, []string) {
	name := strings.TrimSuffix(p.Name, ".")
	if p.Error != "" {
		return ui.Bad, "Couldn't check: " + p.Error + ".", nil
	}
	notes := []string{"Public resolvers are anycast: this shows what their sites nearest you have cached."}
	up, stale, missing, failed, wait := p.Counts()
	total := up + stale + missing + failed
	if failed > 0 {
		notes = append(notes, plural(failed, "resolver didn't answer", "resolvers didn't answer")+".")
	}
	switch {
	case !p.AuthAgree:
		var parts []string
		for _, a := range p.Authoritative {
			if a.State != dnsx.PropFailed {
				parts = append(parts, strings.TrimSuffix(a.Source, ".")+": "+strings.Join(a.Values, ", "))
			}
		}
		return ui.Bad, fmt.Sprintf("Your nameservers for %s disagree (%s), so resolvers get different answers depending on which one they ask. Make sure every nameserver has the same version of the zone (compare their SOA serials).", p.Zone, strings.Join(parts, "; ")), notes
	case up == total-failed && len(p.Expected) == 0:
		return ui.OK, fmt.Sprintf("%s has no %s records, and every resolver agrees.", name, p.Type), notes
	case up == total-failed:
		return ui.OK, fmt.Sprintf("Every resolver that answered has the %s value for %s %s.", map[string]string{"nameservers": "nameservers'", "you": "expected"}[p.ExpectedFrom], name, p.Type), notes
	}
	behind := stale + missing
	msg := fmt.Sprintf("%d of %d resolvers have the %s value; %d still %s the old answer cached.", up, total-failed,
		map[string]string{"nameservers": "nameservers'", "you": "expected"}[p.ExpectedFrom], behind, map[bool]string{true: "has", false: "have"}[behind == 1])
	if wait > 0 {
		msg += " The last should update within " + fmtDur(wait) + ", when its cached copy expires."
	}
	return ui.Warn, msg, notes
}

func propState(a dnsx.PropAnswer) (ui.Status, string) {
	switch a.State {
	case dnsx.PropUpdated:
		return ui.OK, "updated"
	case dnsx.PropStale:
		return ui.Warn, "old value · " + cacheLeft(a.TTL) + " left"
	case dnsx.PropMissing:
		return ui.Warn, "says none · " + cacheLeft(a.TTL) + " left"
	}
	return ui.Bad, "no answer"
}

func propLines(p dnsx.PropResult) []string {
	var out []string
	auth := ui.Table{Headers: []string{"Nameserver", "Answer", "TTL"}}
	for _, a := range p.Authoritative {
		st, _ := propState(a)
		if a.State == dnsx.PropFailed {
			auth.Rows = append(auth.Rows, ui.TableRow{Status: ui.Bad, Cells: []string{strings.TrimSuffix(a.Source, "."), ui.Dim(a.Error), ""}})
			continue
		}
		if p.ExpectedFrom == "nameservers" {
			st = ui.OK
			if !p.AuthAgree {
				st = ui.Warn
			}
		}
		auth.Rows = append(auth.Rows, ui.TableRow{Status: st, Cells: []string{strings.TrimSuffix(a.Source, "."), valuesText(a.Values), cacheLeft(a.TTL)}})
	}
	out = append(out, "  "+ui.Bold("Nameservers for "+p.Zone))
	out = append(out, auth.Lines(ui.PanelWidth())...)
	pub := ui.Table{Headers: []string{"Resolver", "Answer", "State"}}
	for _, a := range p.Public {
		st, word := propState(a)
		answer := valuesText(a.Values)
		if a.State == dnsx.PropFailed {
			answer = ui.Dim(a.Error)
		}
		pub.Rows = append(pub.Rows, ui.TableRow{Status: st, Cells: []string{a.Source, answer, word}})
	}
	out = append(out, "", "  "+ui.Bold("Public resolvers"))
	return append(out, pub.Lines(ui.PanelWidth())...)
}

func cmdPropagate(args []string) int {
	fs := flag.NewFlagSet("propagate", flag.ExitOnError)
	common := adv.Register(fs)
	expect := fs.String("expect", "", "the answer to look for, comma-separated (default: what the nameservers say)")
	pos := parseInterspersed(fs, args)
	ui.SetQuiet(common.JSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	usage := func(msg string) int {
		fmt.Fprintln(os.Stderr, "netcheck propagate: "+msg)
		fmt.Fprintln(os.Stderr, "usage: netcheck propagate <name> [type] [--expect value] [--watch 30s]")
		return 2
	}
	names, qtype, server, err := digArgs(pos)
	switch {
	case err != nil:
		return usage(err.Error())
	case server != "":
		return usage("propagate asks the domain's nameservers and the public resolvers itself, so it takes no @server")
	case len(names) != 1:
		return usage("name one domain")
	}
	if qtype == 0 {
		qtype = dnsx.TypeA
	}
	rules, err := common.Rules()
	if err != nil {
		return usage(err.Error())
	}
	var want []string
	if *expect != "" {
		want = strings.Split(*expect, ",")
	}
	title := fmt.Sprintf("%s · %s", names[0], dnsx.TypeString(qtype))

	if common.Watch > 0 {
		ui.Title("propagate")
		adv.Watch(ctx, common.Watch, func(ctx context.Context) []string {
			p := dnsx.Propagate(ctx, names[0], qtype, append([]string(nil), want...))
			st, msg, _ := propVerdict(p)
			lines := []string{"  " + ui.Bold(title), ""}
			if p.Error == "" {
				lines = append(lines, propLines(p)...)
			}
			return append(lines, "", "  "+st.Paint(msg))
		})
		return 0
	}

	ui.Title("propagate")
	t := ui.Begin("Asking")
	t.Progress("finding the nameservers, then asking them and " + plural(len(dnsx.PublicResolvers), "resolver", "resolvers") + "…")
	p := dnsx.Propagate(ctx, names[0], qtype, want)
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	st, msg, notes := propVerdict(p)
	up, stale, missing, _, wait := p.Counts()
	vals := map[string]float64{"behind": float64(stale + missing), "updated": float64(up), "wait": float64(wait.Milliseconds())}
	var broken []string
	if p.Error == "" {
		broken = adv.Broken(rules, propDefault, vals)
	}
	if p.Error == "" {
		ui.Open(title)
		for _, l := range propLines(p) {
			ui.Println(l)
		}
		ui.Close()
	}
	if !common.Raw {
		ui.Verdict(st, msg, append(notes, broken...)...)
	}
	ui.Println("")
	if common.JSON {
		adv.Envelope{Tool: "propagate", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Data: p, FailedOn: broken}.Write(os.Stdout)
	}
	return adv.ExitCode(st.String(), broken)
}
