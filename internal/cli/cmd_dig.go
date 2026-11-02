package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/dnsx"
	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

// digTimeout is how long one query may take.
const digTimeout = 5 * time.Second

// digDefault is the --fail-on metric a bare value applies to: the time
// the answer took (fail when it's longer).
var digDefault = adv.Default{Metric: "time", Op: '>'}

// digArgs splits dig's arguments into names, a record type and a server,
// in any order: "example.com MX @1.1.1.1".
func digArgs(args []string) (names []string, qtype uint16, server string, err error) {
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "@"):
			server = a[1:]
		case qtype == 0 && len(names) > 0:
			t, ok := dnsx.ParseType(a)
			if !ok {
				return nil, 0, "", fmt.Errorf("%q isn't a record type (try A, AAAA, MX, TXT, NS, SOA, CAA, SRV, PTR, DS, DNSKEY)", a)
			}
			qtype = t
		default:
			names = append(names, a)
		}
	}
	return names, qtype, server, nil
}

// systemServer is the first DNS server this computer uses, else Cloudflare.
func systemServer(ctx context.Context, transport string) (dnsx.Server, error) {
	if transport == "" || transport == dnsx.UDP || transport == dnsx.TCP {
		if ns := probe.DNSServers(ctx); len(ns) > 0 {
			s, err := dnsx.ParseServer(ns[0], transport)
			s.Label = "system " + ns[0]
			return s, err
		}
	}
	return dnsx.ParseServer("cloudflare", transport)
}

// digOutcome judges an answer: the status, a sentence, and the measurements
// for --fail-on.
func digOutcome(name string, qtype uint16, r *dnsx.Result, err error) (ui.Status, string, map[string]float64) {
	if err != nil {
		return ui.Bad, "The server didn't answer: " + err.Error() + ".", nil
	}
	m := r.Msg
	vals := map[string]float64{"time": float64(r.RTT.Microseconds()) / 1000, "answers": float64(len(m.Answer))}
	if len(m.Answer) > 0 {
		minTTL := m.Answer[0].TTL
		for _, rr := range m.Answer {
			minTTL = min(minTTL, rr.TTL)
		}
		vals["ttl"] = float64(minTTL) * 1000
	}
	t := dnsx.TypeString(qtype)
	switch m.Rcode {
	case dnsx.RcodeSuccess:
		if len(m.Answer) == 0 {
			return ui.Skip, fmt.Sprintf("%s exists but has no %s records.", name, t), vals
		}
		n, alias := 0, false
		for _, rr := range m.Answer {
			if rr.Type == qtype || qtype == dnsx.TypeANY {
				n++
			}
			alias = alias || (rr.Type == dnsx.TypeCNAME && qtype != dnsx.TypeCNAME)
		}
		msg := fmt.Sprintf("%s has %s.", name, plural(n, t+" record", t+" records"))
		if alias {
			msg = fmt.Sprintf("%s has %s, by way of an alias (CNAME).", name, plural(n, t+" record", t+" records"))
		}
		if m.AD {
			msg += " The answer is DNSSEC-validated."
		}
		return ui.OK, msg, vals
	case dnsx.RcodeNXDomain:
		return ui.Warn, fmt.Sprintf("%s doesn't exist (NXDOMAIN).", name), vals
	case dnsx.RcodeServFail:
		return ui.Bad, "The server couldn't answer (SERVFAIL). Usually the domain's own nameservers are broken or unreachable, or its DNSSEC signatures don't validate; --cd asks without validation to tell which.", vals
	case dnsx.RcodeRefused:
		return ui.Bad, "The server refused to answer (REFUSED): it doesn't resolve names for you, or doesn't serve this zone.", vals
	}
	return ui.Bad, "The server answered " + dnsx.RcodeString(m.Rcode) + ".", vals
}

// recordLines lines records up as name, TTL, type, data. Long keys and
// signatures are summarised unless raw is set.
func recordLines(rrs []dnsx.RR, raw bool) []string {
	nw, tw := 0, 0
	for _, rr := range rrs {
		nw, tw = max(nw, len(rr.Name)), max(tw, len(rr.TypeName()))
	}
	var out []string
	for _, rr := range rrs {
		data := rr.Summary()
		if raw {
			data = rr.Data
		}
		out = append(out, "  "+ui.Pad(rr.Name, nw)+"  "+ui.Dim(fmt.Sprintf("%6d", rr.TTL))+"  "+ui.Accent(ui.Pad(rr.TypeName(), tw))+"  "+data)
	}
	return out
}

type digData struct {
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Server    string    `json:"server"`
	Transport string    `json:"transport"`
	RTTMs     float64   `json:"rtt_ms,omitempty"`
	Size      int       `json:"size,omitempty"`
	Rcode     string    `json:"rcode,omitempty"`
	Flags     string    `json:"flags,omitempty"`
	Retried   bool      `json:"retried_over_tcp,omitempty"`
	Msg       *dnsx.Msg `json:"message,omitempty"`
	Error     string    `json:"error,omitempty"`
}

func cmdDig(args []string) int {
	fs := flag.NewFlagSet("dig", flag.ExitOnError)
	common := adv.Register(fs)
	reverse := fs.String("x", "", "reverse lookup of an address")
	tcp := fs.Bool("tcp", false, "ask over TCP")
	dot := fs.Bool("dot", false, "ask over DNS over TLS (port 853)")
	doh := fs.Bool("doh", false, "ask over DNS over HTTPS")
	dnssec := fs.Bool("dnssec", false, "ask for DNSSEC signatures (DO bit)")
	cd := fs.Bool("cd", false, "checking disabled: don't validate DNSSEC")
	norec := fs.Bool("norec", false, "don't ask for recursion (query an authoritative server)")
	short := fs.Bool("short", false, "print the record data only")
	all := fs.Bool("all", false, "show the authority and additional sections too")
	pos := parseInterspersed(fs, args)
	ui.SetQuiet(common.JSON || *short)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	usage := func(msg string) int {
		fmt.Fprintln(os.Stderr, "netcheck dig: "+msg)
		fmt.Fprintln(os.Stderr, "usage: netcheck dig <name> [type] [@server] [--tcp|--dot|--doh] [--dnssec] [-x address] [-f names.txt]")
		return 2
	}
	names, qtype, server, err := digArgs(pos)
	if err != nil {
		return usage(err.Error())
	}
	lineTypes := map[int]uint16{} // per-name types from a -f file
	if *reverse != "" {
		names = append(names, *reverse)
	}
	if common.File != "" {
		f, err := os.Open(common.File)
		if err != nil {
			return usage(err.Error())
		}
		// One name per line, optionally followed by a record type: "example.com MX".
		sc := bufio.NewScanner(f)
		for line := 1; sc.Scan(); line++ {
			fields := strings.Fields(strings.SplitN(sc.Text(), "#", 2)[0])
			if len(fields) == 0 {
				continue
			}
			if len(fields) > 2 {
				f.Close()
				return usage(fmt.Sprintf("%s line %d: one name and an optional type per line", common.File, line))
			}
			names = append(names, fields[0])
			if len(fields) == 2 {
				t, ok := dnsx.ParseType(fields[1])
				if !ok {
					f.Close()
					return usage(fmt.Sprintf("%s line %d: %q isn't a record type", common.File, line, fields[1]))
				}
				lineTypes[len(names)-1] = t
			}
		}
		f.Close()
	}
	if len(names) == 0 {
		return usage("name what to look up")
	}
	rules, err := common.Rules()
	if err != nil {
		return usage(err.Error())
	}
	transport := ""
	switch {
	case *dot:
		transport = dnsx.DoT
	case *doh:
		transport = dnsx.DoH
	case *tcp:
		transport = dnsx.TCP
	}
	var srv dnsx.Server
	if server != "" {
		srv, err = dnsx.ParseServer(server, transport)
	} else {
		srv, err = systemServer(ctx, transport)
	}
	if err != nil {
		return usage(err.Error())
	}

	// One question per name; an address becomes its reverse (PTR) name.
	type question struct {
		shown, ask string
		qtype      uint16
	}
	var qs []question
	for i, n := range names {
		q := question{shown: n, ask: dnsx.Fqdn(n), qtype: qtype}
		if t, ok := lineTypes[i]; ok {
			q.qtype = t
		}
		if ip := net.ParseIP(n); ip != nil {
			q.ask, q.qtype = dnsx.ReverseName(ip), dnsx.TypePTR
		}
		if q.qtype == 0 {
			q.qtype = dnsx.TypeA
		}
		qs = append(qs, q)
	}
	ask := func(ctx context.Context, q question) (*dnsx.Result, error) {
		return dnsx.Exchange(ctx, srv, dnsx.Query{Name: q.ask, Type: q.qtype, Recursion: !*norec, DNSSEC: *dnssec, CD: *cd}, digTimeout)
	}
	transportLabel := strings.ToUpper(srv.Transport)
	if srv.Transport == dnsx.DoT || srv.Transport == dnsx.DoH {
		transportLabel = map[string]string{dnsx.DoT: "DNS over TLS", dnsx.DoH: "DNS over HTTPS"}[srv.Transport]
	}

	// Several names: one table, one row per name.
	if len(qs) > 1 {
		ui.Title("dig")
		tb := ui.Table{Headers: []string{"Name", "Type", "Answer", "Time"}}
		var data []digData
		var broken []string
		worst := ui.OK
		for _, q := range qs {
			r, err := ask(ctx, q)
			if ctx.Err() != nil {
				return 130
			}
			st, _, vals := digOutcome(q.shown, q.qtype, r, err)
			worst = worstStatus(worst, st)
			d := digData{Name: q.shown, Type: dnsx.TypeString(q.qtype), Server: srv.Name(), Transport: srv.Transport}
			answerText, timeText := "", "–"
			if err != nil {
				answerText, d.Error = err.Error(), err.Error()
			} else {
				var parts []string
				for _, rr := range r.Msg.Answer {
					if rr.Type == q.qtype {
						parts = append(parts, rr.Summary())
					}
				}
				answerText = strings.Join(parts, ", ")
				if answerText == "" {
					answerText = ui.Dim(dnsx.RcodeString(r.Msg.Rcode))
				}
				timeText = fmtMs(float64(r.RTT.Microseconds()) / 1000)
				d.RTTMs, d.Size, d.Rcode, d.Flags, d.Msg = float64(r.RTT.Microseconds())/1000, r.Size, dnsx.RcodeString(r.Msg.Rcode), r.Msg.Flags(), r.Msg
			}
			if vals != nil { // a failed query is already a bad row
				for _, b := range adv.Broken(rules, digDefault, vals) {
					broken = append(broken, q.shown+": "+b)
				}
			}
			tb.Rows = append(tb.Rows, ui.TableRow{Status: st, Cells: []string{q.shown, dnsx.TypeString(q.qtype), answerText, timeText}})
			data = append(data, d)
		}
		ui.Open(fmt.Sprintf("%d names · @%s · %s", len(qs), srv.Name(), transportLabel))
		for _, l := range tb.Lines(ui.PanelWidth()) {
			ui.Println(l)
		}
		ui.Close()
		head := fmt.Sprintf("%d of %d names answered cleanly.", countStatus(tb.Rows, ui.OK), len(qs))
		ui.Verdict(worst, head, broken...)
		ui.Println("")
		if common.JSON {
			adv.Envelope{Tool: "dig", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: worst.String(), Message: head}, Data: data, FailedOn: broken}.Write(os.Stdout)
		}
		return adv.ExitCode(worst.String(), broken)
	}

	q := qs[0]
	title := fmt.Sprintf("%s · %s · @%s · %s", q.shown, dnsx.TypeString(q.qtype), srv.Name(), transportLabel)
	if common.Watch > 0 {
		ui.Title("dig")
		adv.Watch(ctx, common.Watch, func(ctx context.Context) []string {
			r, err := ask(ctx, q)
			st, msg, _ := digOutcome(q.shown, q.qtype, r, err)
			lines := []string{"  " + ui.Bold(title), ""}
			if err == nil {
				lines = append(lines, recordLines(r.Msg.Answer, common.Raw)...)
				lines = append(lines, "", "  "+ui.Dim(fmt.Sprintf("%s · %s · %d bytes", dnsx.RcodeString(r.Msg.Rcode), fmtMs(float64(r.RTT.Microseconds())/1000), r.Size)))
			}
			return append(lines, "", "  "+st.Paint(msg))
		})
		return 0
	}

	r, err := ask(ctx, q)
	if ctx.Err() != nil {
		return 130
	}
	st, msg, vals := digOutcome(q.shown, q.qtype, r, err)
	var broken []string
	if vals != nil { // no answer: the verdict already fails, rules have nothing to judge
		broken = adv.Broken(rules, digDefault, vals)
	}
	d := digData{Name: q.shown, Type: dnsx.TypeString(q.qtype), Server: srv.Name(), Transport: srv.Transport}
	if err != nil {
		d.Error = err.Error()
	} else {
		d.RTTMs, d.Size, d.Rcode, d.Flags, d.Retried, d.Msg = float64(r.RTT.Microseconds())/1000, r.Size, dnsx.RcodeString(r.Msg.Rcode), r.Msg.Flags(), r.Retried, r.Msg
	}

	switch {
	case *short:
		if err == nil {
			for _, rr := range r.Msg.Answer {
				fmt.Println(rr.Data)
			}
		}
	case !common.JSON:
		ui.Title("dig")
		ui.Open(title)
		switch {
		case err != nil:
			ui.Println("  " + ui.Dim("no answer"))
		case len(r.Msg.Answer) == 0:
			ui.Println("  " + ui.Dim("no records"))
		default:
			for _, l := range recordLines(r.Msg.Answer, common.Raw) {
				ui.Println(l)
			}
		}
		ui.Close()
		if err == nil && (*all || len(r.Msg.Answer) == 0) && len(r.Msg.Authority) > 0 {
			ui.Println("")
			ui.Open("Authority")
			for _, l := range recordLines(r.Msg.Authority, common.Raw) {
				ui.Println(l)
			}
			ui.Close()
		}
		if err == nil && *all && len(r.Msg.Additional) > 0 {
			ui.Println("")
			ui.Open("Additional")
			for _, l := range recordLines(r.Msg.Additional, common.Raw) {
				ui.Println(l)
			}
			ui.Close()
		}
		if err == nil {
			ui.Println("")
			ui.Open("Response")
			rst := ui.OK
			if r.Msg.Rcode != dnsx.RcodeSuccess {
				rst = st
			}
			ui.Println(ui.Row("Status", rst, dnsx.RcodeString(r.Msg.Rcode), "", ui.Dim(r.Msg.Flags())))
			via := map[string]string{dnsx.UDP: "UDP", dnsx.TCP: "TCP", dnsx.DoT: "DNS over TLS", dnsx.DoH: "DNS over HTTPS"}[r.Transport]
			if r.Retried {
				via = "TCP (the UDP answer was too big)"
			}
			ui.Println(ui.Row("Time", ui.OK, fmtMs(float64(r.RTT.Microseconds())/1000), "", ui.Dim(fmt.Sprintf("%d bytes · %s", r.Size, via))))
			ui.Println(ui.Row("Server", ui.OK, srv.Name(), "", ""))
			if e := r.Msg.EDNS; e != nil {
				note := fmt.Sprintf("UDP size %d", e.UDPSize)
				if e.DO {
					note += " · DNSSEC requested"
				}
				ui.Println(ui.Row("EDNS", ui.OK, fmt.Sprintf("version %d", e.Version), "", ui.Dim(note)))
			}
			ui.Close()
		}
		if !common.Raw {
			ui.Verdict(st, msg, broken...)
		}
		ui.Println("")
	}
	if common.JSON {
		adv.Envelope{Tool: "dig", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Data: d, FailedOn: broken}.Write(os.Stdout)
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return 130
	}
	return adv.ExitCode(st.String(), broken)
}

// worstStatus is the more serious of two statuses.
func worstStatus(a, b ui.Status) ui.Status {
	rank := map[ui.Status]int{ui.OK: 0, ui.Skip: 1, ui.Warn: 2, ui.Bad: 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func countStatus(rows []ui.TableRow, st ui.Status) int {
	n := 0
	for _, r := range rows {
		if r.Status == st {
			n++
		}
	}
	return n
}
