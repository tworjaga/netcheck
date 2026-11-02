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
	"github.com/tworjaga/netcheck/internal/tracex"
	"github.com/tworjaga/netcheck/internal/ui"
)

// traceRouteDefault: a bare --fail-on value is the time to the destination.
var traceRouteDefault = adv.Default{Metric: "rtt", Op: '>'}

func protoName(r tracex.Result) string {
	if r.Proto == "icmp" {
		return "ICMP"
	}
	return fmt.Sprintf("%s port %d", strings.ToUpper(r.Proto), r.Port)
}

func hopTime(h tracex.Hop) string {
	if h.Answered() == 0 {
		return ui.Dim("no answer")
	}
	s := fmtMs(h.Avg())
	if lost := len(h.RTTs) - h.Answered(); lost > 0 {
		s += ui.Dim(fmt.Sprintf(" · %d/%d lost", lost, len(h.RTTs)))
	}
	return s
}

func hopOwner(h tracex.Hop) string {
	switch {
	case h.ASN != 0 && h.Owner != "":
		return fmt.Sprintf("AS%d %s", h.ASN, h.Owner)
	case h.ASN != 0:
		return fmt.Sprintf("AS%d", h.ASN)
	}
	return h.Owner
}

// routeTable is one row per hop. The address gets its own column only when
// there's room; otherwise the name stands in for it.
func routeTable(r tracex.Result, width int) ui.Table {
	wide := width >= 110
	tb := ui.Table{Headers: []string{"#", "Host", "Owner", "Time"}}
	if wide {
		tb.Headers = []string{"#", "Address", "Name", "Owner", "Time"}
	}
	for _, h := range r.Hops {
		st := ui.OK
		switch {
		case h.Answered() == 0:
			st = ui.Skip
		case h.Answered() < len(h.RTTs) && h.Reached:
			st = ui.Warn
		case h.Note == "unreachable":
			st = ui.Bad
		}
		host := h.Name
		if host == "" {
			host = h.IP
		}
		if host == "" {
			host = ui.Dim("*")
		}
		if h.Reached {
			host = ui.Bold(host)
		}
		ttl := fmt.Sprint(h.TTL)
		if h.TTL == 0 {
			ttl = "?"
		}
		cells := []string{ttl, ui.Cut(host, 30), ui.Cut(hopOwner(h), 26), hopTime(h)}
		if wide {
			cells = []string{ttl, h.IP, ui.Cut(h.Name, 40), ui.Cut(hopOwner(h), 36), hopTime(h)}
		}
		tb.Rows = append(tb.Rows, ui.TableRow{Status: st, Cells: cells})
	}
	return tb
}

// routeVerdictAdv sums up a trace.
func routeVerdictAdv(r tracex.Result) (ui.Status, string, []string) {
	if r.Error != "" {
		return ui.Bad, "Couldn't trace: " + r.Error + ".", nil
	}
	var notes []string
	if owners := tracex.Owners(r.Hops); len(owners) > 1 {
		notes = append(notes, "Networks on the way: "+strings.TrimSuffix(strings.Join(owners, ui.Pick(" → ", " -> ")), ".")+".")
	}
	if j := tracex.BiggestJump(r.Hops); j.AddMs >= 20 {
		n := fmt.Sprintf("The delay grows most from hop %d to %d (+%s)", j.From, j.To, fmtMs(j.AddMs))
		for _, h := range r.Hops {
			if h.TTL == j.To && h.Owner != "" {
				n += ", at " + h.Owner
			}
		}
		notes = append(notes, strings.TrimSuffix(n, ".")+".")
	}
	last := r.Hops[len(r.Hops)-1]
	switch {
	case r.Reached:
		hops := plural(last.TTL, "hop", "hops")
		if last.TTL == 0 {
			hops = "an unknown number of hops"
			notes = append(notes, "The last routers before it didn't answer, so how many hops it takes isn't known.")
		}
		msg := fmt.Sprintf("Reached %s in %s over %s, %s.", r.Target, hops, protoName(r), fmtMs(last.Avg()))
		st := ui.OK
		switch r.PortState {
		case "open":
			msg = fmt.Sprintf("Reached %s in %s; port %d is open (%s).", r.Target, hops, r.Port, fmtMs(last.Avg()))
		case "closed":
			msg = fmt.Sprintf("Reached %s in %s, but port %d is closed: the host refused the connection.", r.Target, hops, r.Port)
			st = ui.Warn
		}
		if lost := len(last.RTTs) - last.Answered(); lost > 0 {
			st = ui.Warn
			notes = append([]string{fmt.Sprintf("%d of %d probes to the destination got no answer.", lost, len(last.RTTs))}, notes...)
		}
		return st, msg, notes
	case r.Note != "" && last.Note == "unreachable":
		return ui.Bad, fmt.Sprintf("%s can't be reached over %s: hop %d (%s) refused to pass it on.", r.Target, protoName(r), last.TTL, last.IP), notes
	}
	lastSeen := tracex.Hop{}
	for _, h := range r.Hops {
		if h.IP != "" {
			lastSeen = h
		}
	}
	where := "any router"
	if lastSeen.IP != "" {
		where = fmt.Sprintf("hop %d (%s)", lastSeen.TTL, strings.TrimSpace(lastSeen.IP+" "+ui.Dim(hopOwner(lastSeen))))
	}
	msg := fmt.Sprintf("No answer from %s over %s; the last answer came from %s.", r.Target, protoName(r), where)
	if r.Proto == "icmp" {
		notes = append(notes, "Many servers don't answer pings at all; try --tcp, which looks like an ordinary connection.")
	} else if r.Proto == "udp" && r.Port != 33434 {
		notes = append(notes, fmt.Sprintf("UDP to a port where a service listens often gets no answer at all: the service ignores a probe it doesn't understand. The default port, 33434, avoids that; or a firewall may drop %s.", protoName(r)))
	} else {
		notes = append(notes, fmt.Sprintf("A firewall at or after that hop may drop %s; try another --port, or the other protocol.", protoName(r)))
	}
	return ui.Warn, msg, notes
}

func routeValues(r tracex.Result) map[string]float64 {
	if r.Error != "" || len(r.Hops) == 0 {
		return nil
	}
	last := r.Hops[len(r.Hops)-1]
	v := map[string]float64{"hops": float64(last.TTL)}
	if r.Reached {
		v["rtt"] = last.Avg()
		v["loss"] = float64(len(last.RTTs)-last.Answered()) / float64(len(last.RTTs)) * 100
	}
	return v
}

func cmdTrace(args []string) int {
	fs := flag.NewFlagSet("trace", flag.ExitOnError)
	common := adv.Register(fs)
	tcp := fs.Bool("tcp", false, "trace with TCP connection attempts (needs admin/root)")
	udp := fs.Bool("udp", false, "trace with UDP datagrams")
	port := fs.Int("p", 0, "destination port (TCP default 443, UDP default 33434)")
	maxHops := fs.Int("m", 30, "most hops to try")
	probes := fs.Int("q", 3, "probes per hop")
	noNames := fs.Bool("n", false, "skip names and network owners")
	pos := parseInterspersed(fs, args)
	ui.SetQuiet(common.JSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	usage := func(msg string) int {
		fmt.Fprintln(os.Stderr, "netcheck trace: "+msg)
		fmt.Fprintln(os.Stderr, "usage: netcheck trace <host> [--tcp|--udp] [-p port] [-m 30] [-q 3] [-n]")
		return 2
	}
	switch {
	case len(pos) != 1:
		return usage("name one host")
	case *tcp && *udp:
		return usage("--tcp or --udp, not both")
	case *maxHops < 1 || *maxHops > 64:
		return usage("-m is 1 to 64")
	case *probes < 1 || *probes > 10:
		return usage("-q is 1 to 10")
	case *port < 0 || *port > 65535:
		return usage("-p is a port, 1 to 65535")
	}
	rules, err := common.Rules()
	if err != nil {
		return usage(err.Error())
	}
	o := tracex.Options{Proto: "icmp", Port: *port, MaxHops: *maxHops, Probes: *probes, NoNames: *noNames}
	switch {
	case *tcp:
		o.Proto = "tcp"
	case *udp:
		o.Proto = "udp"
	}
	ui.Title("trace")

	if common.Watch > 0 {
		adv.Watch(ctx, common.Watch, func(ctx context.Context) []string {
			r := tracex.Trace(ctx, pos[0], o)
			st, msg, _ := routeVerdictAdv(r)
			lines := []string{"  " + ui.Bold(pos[0]), ""}
			if r.Error == "" {
				lines = append(lines, routeTable(r, ui.PanelWidth()).Lines(ui.PanelWidth())...)
			}
			return append(lines, "", "  "+st.Paint(msg))
		})
		return 0
	}

	t := ui.Begin("Tracing")
	t.Progress(fmt.Sprintf("the route to %s over %s…", pos[0], strings.ToUpper(o.Proto)))
	r := tracex.Trace(ctx, pos[0], o)
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	st, msg, notes := routeVerdictAdv(r)
	var broken []string
	if vals := routeValues(r); vals != nil {
		broken = adv.Broken(rules, traceRouteDefault, vals)
	}
	if r.Error == "" {
		title := fmt.Sprintf("%s · %s", pos[0], protoName(r))
		if r.Addr != pos[0] {
			title = fmt.Sprintf("%s (%s) · %s", pos[0], r.Addr, protoName(r))
		}
		ui.Open(title)
		for _, l := range routeTable(r, ui.PanelWidth()).Lines(ui.PanelWidth()) {
			ui.Println(l)
		}
		ui.Close()
	}
	if !common.Raw {
		ui.Verdict(st, msg, append(notes, broken...)...)
	}
	ui.Println("")
	if common.JSON {
		adv.Envelope{Tool: "trace", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Data: r, FailedOn: broken}.Write(os.Stdout)
	}
	return adv.ExitCode(st.String(), broken)
}
