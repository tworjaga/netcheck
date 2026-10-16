package cli

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/ui"
	"github.com/tworjaga/netcheck/internal/webx"
)

// httpDefault: a bare --fail-on value is the total time.
var httpDefault = adv.Default{Metric: "time", Op: '>'}

// headerFlag collects repeated -H "Name: value" options.
type headerFlag struct{ h http.Header }

func (f *headerFlag) String() string { return "" }
func (f *headerFlag) Set(s string) error {
	k, v, ok := strings.Cut(s, ":")
	if !ok || strings.TrimSpace(k) == "" {
		return fmt.Errorf("%q: a header is \"Name: value\"", s)
	}
	f.h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	return nil
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func fmtBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f kB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// phaseRows are the named phases of a request, in order.
func phaseRows(p webx.Phases) []struct {
	name string
	d    time.Duration
} {
	return []struct {
		name string
		d    time.Duration
	}{{"DNS", p.DNS}, {"Connect", p.Connect}, {"TLS", p.TLS}, {"Server", p.Wait}, {"Download", p.Download}}
}

// waterfall draws each phase as a bar starting where the last one ended.
func waterfall(p webx.Phases, width int) []string {
	barW := max(10, width-26)
	total := p.Total
	if total <= 0 {
		total = 1
	}
	var out []string
	var at time.Duration
	block := ui.Pick("█", "#")
	for _, r := range phaseRows(p) {
		if r.d == 0 && r.name != "Server" {
			continue
		}
		start := int(float64(barW) * float64(at) / float64(total))
		n := max(1, int(float64(barW)*float64(r.d)/float64(total)+0.5))
		if start+n > barW {
			n = max(1, barW-start)
			start = barW - n
		}
		bar := strings.Repeat(" ", start) + ui.Accent(strings.Repeat(block, n)) + strings.Repeat(" ", barW-start-n)
		out = append(out, "  "+ui.Pad(r.name, 10)+bar+" "+fmt.Sprintf("%8s", fmtMs(ms(r.d))))
		at += r.d
	}
	out = append(out, "  "+ui.Pad(ui.Bold("Total"), 10)+strings.Repeat(" ", barW)+" "+ui.PadL(ui.Bold(fmtMs(ms(p.Total))), 8))
	return out
}

// slowest is the phase that took longest.
func slowest(p webx.Phases) (string, time.Duration) {
	name, d := "", time.Duration(0)
	words := map[string]string{"DNS": "the DNS lookup", "Connect": "connecting", "TLS": "the TLS handshake", "Server": "the server preparing the answer", "Download": "the download"}
	for _, r := range phaseRows(p) {
		if r.d > d {
			name, d = words[r.name], r.d
		}
	}
	return name, d
}

// httpVerdict sums up a request.
func httpVerdict(r webx.Result) (ui.Status, string, []string) {
	f := r.Final()
	if r.Error != "" {
		msg := "The request failed: " + r.Error + "."
		if len(r.Hops) > 1 {
			msg = fmt.Sprintf("The request failed after %s: %s.", plural(len(r.Hops)-1, "redirect", "redirects"), r.Error)
		}
		return ui.Bad, msg, nil
	}
	st := ui.OK
	switch {
	case f.Status >= 500:
		st = ui.Bad
	case f.Status >= 400:
		st = ui.Warn
	}
	msg := fmt.Sprintf("%d %s in %s", f.Status, f.StatusText, fmtMs(ms(r.Total)))
	if len(r.Hops) > 1 {
		var redir time.Duration
		for _, h := range r.Hops[:len(r.Hops)-1] {
			redir += h.Phases.Total
		}
		msg += fmt.Sprintf(", %s of it on %s", fmtMs(ms(redir)), plural(len(r.Hops)-1, "redirect", "redirects"))
	}
	var notes []string
	name, d := slowest(f.Phases)
	if f.Phases.Total > 0 && name != "" {
		msg += fmt.Sprintf("; the most time went to %s (%s).", name, fmtMs(ms(d)))
	} else {
		msg += "."
	}
	if f.Phases.Wait > time.Second {
		st = max(st, ui.Warn)
		notes = append(notes, fmt.Sprintf("The server took %s to start answering; that's the application or database, not the network.", fmtMs(ms(f.Phases.Wait))))
	}
	if len(r.Hops) > 3 {
		notes = append(notes, fmt.Sprintf("%d redirects in a row: link to the final address directly to save the round trips.", len(r.Hops)-1))
	}
	if strings.HasPrefix(f.URL, "http://") {
		notes = append(notes, "The final page isn't served over HTTPS.")
	}
	if f.TLSVersion != "" && !strings.HasPrefix(f.Proto, "HTTP/2") && !strings.HasPrefix(f.Proto, "HTTP/3") {
		notes = append(notes, "The server speaks only HTTP/1.1 over HTTPS; HTTP/2 would load pages with many files faster.")
	}
	return st, msg, notes
}

func statusOf(code int) ui.Status {
	switch {
	case code >= 500:
		return ui.Bad
	case code >= 400:
		return ui.Warn
	}
	return ui.OK
}

// httpLines is the full view of one exchange.
func httpLines(r webx.Result, allHeaders bool, width int) []string {
	var out []string
	if len(r.Hops) > 1 {
		tb := ui.Table{Headers: []string{"Status", "URL", "Time"}}
		for _, h := range r.Hops {
			code := fmt.Sprint(h.Status)
			if h.Error != "" {
				code = "–"
			}
			tb.Rows = append(tb.Rows, ui.TableRow{Status: statusOf(h.Status), Cells: []string{code, h.URL, fmtMs(ms(h.Phases.Total))}})
		}
		out = append(out, "  "+ui.Bold("Redirects"))
		out = append(out, tb.Lines(width)...)
		out = append(out, "")
	}
	f := r.Final()
	out = append(out, waterfall(f.Phases, width)...)
	if f.Error != "" {
		return out
	}
	out = append(out, "")
	facts := [][2]string{{"Status", fmt.Sprintf("%d %s", f.Status, f.StatusText)}, {"Protocol", strings.TrimSpace(f.Proto + " " + ui.Dim(f.TLSVersion))}, {"Address", f.Remote}}
	size := fmtBytes(f.Size)
	if f.Encoding != "" {
		size += ui.Dim(" · " + f.Encoding)
	}
	facts = append(facts, [2]string{"Size", size})
	for _, k := range []string{"Server", "Content-Type", "Cache-Control", "Location"} {
		if v := f.Header.Get(k); v != "" {
			facts = append(facts, [2]string{k, v})
		}
	}
	for _, kv := range facts {
		out = append(out, "  "+ui.Pad(ui.Dim(kv[0]), 15)+ui.Cut(kv[1], max(20, width-17)))
	}
	if allHeaders {
		out = append(out, "", "  "+ui.Bold("Headers"))
		var keys []string
		for k := range f.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, v := range f.Header[k] {
				for i, l := range ui.Wrap(v, max(20, width-len(k)-6)) {
					lead := ui.Dim(k + ":")
					if i > 0 {
						lead = strings.Repeat(" ", len(k)+1)
					}
					out = append(out, "  "+lead+" "+l)
				}
			}
		}
	}
	return out
}

// median and maximum of n samples of a phase.
func spread(rs []webx.Result, pick func(webx.Phases) time.Duration) (time.Duration, time.Duration, time.Duration) {
	var v []time.Duration
	for _, r := range rs {
		if r.Error == "" {
			v = append(v, pick(r.Final().Phases))
		}
	}
	if len(v) == 0 {
		return 0, 0, 0
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v[0], v[len(v)/2], v[len(v)-1]
}

func httpValues(r webx.Result) map[string]float64 {
	if r.Error != "" {
		return nil
	}
	f := r.Final()
	return map[string]float64{
		"time": ms(r.Total), "ttfb": ms(f.Phases.TTFB()), "dns": ms(f.Phases.DNS), "connect": ms(f.Phases.Connect),
		"tls": ms(f.Phases.TLS), "wait": ms(f.Phases.Wait), "status": float64(f.Status), "size": float64(f.Size),
		"redirects": float64(len(r.Hops) - 1),
	}
}

func cmdHTTP(args []string) int {
	fs := flag.NewFlagSet("http", flag.ExitOnError)
	common := adv.Register(fs)
	hdr := &headerFlag{h: http.Header{}}
	method := fs.String("X", "", "request method (default GET, or POST with -d)")
	fs.Var(hdr, "H", "add a header, \"Name: value\" (repeatable)")
	data := fs.String("d", "", "send this as the request body")
	insecure := fs.Bool("k", false, "don't check the certificate")
	noFollow := fs.Bool("no-follow", false, "don't follow redirects")
	http1 := fs.Bool("http1", false, "use HTTP/1.1 only")
	v4 := fs.Bool("4", false, "IPv4 only")
	v6 := fs.Bool("6", false, "IPv6 only")
	count := fs.Int("n", 1, "send the request this many times and show the spread")
	headers := fs.Bool("headers", false, "show every response header")
	pos := parseInterspersed(fs, args)
	ui.SetQuiet(common.JSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	usage := func(msg string) int {
		fmt.Fprintln(os.Stderr, "netcheck http: "+msg)
		fmt.Fprintln(os.Stderr, "usage: netcheck http <url> [-X method] [-H 'Name: value'] [-d body] [-n 10] [--headers]")
		return 2
	}
	if len(pos) != 1 {
		return usage("give one URL")
	}
	if *count < 1 || *count > 100 {
		return usage("-n is 1 to 100")
	}
	if _, err := webx.NormalizeURL(pos[0]); err != nil {
		return usage(err.Error())
	}
	rules, err := common.Rules()
	if err != nil {
		return usage(err.Error())
	}
	o := webx.Options{Method: strings.ToUpper(*method), Header: hdr.h, Body: *data, Insecure: *insecure, NoFollow: *noFollow, HTTP1: *http1, UserAgent: "netcheck/" + version}
	switch {
	case *v4 && *v6:
		return usage("-4 or -6, not both")
	case *v4:
		o.Family = "4"
	case *v6:
		o.Family = "6"
	}
	method0 := o.Method
	if method0 == "" {
		method0 = map[bool]string{true: "POST", false: "GET"}[*data != ""]
	}
	u, _ := webx.NormalizeURL(pos[0])
	title := method0 + " " + u.String()
	ui.Title("http")

	if common.Watch > 0 {
		adv.Watch(ctx, common.Watch, func(ctx context.Context) []string {
			r := webx.Fetch(ctx, pos[0], o)
			st, msg, _ := httpVerdict(r)
			return append(append([]string{"  " + ui.Bold(title), ""}, httpLines(r, false, ui.PanelWidth())...), "", "  "+st.Paint(msg))
		})
		return 0
	}

	t := ui.Begin("Requesting")
	var runs []webx.Result
	for i := 0; i < *count; i++ {
		if *count > 1 {
			t.Progress(fmt.Sprintf("%s (%d of %d)…", u.Host, i+1, *count))
		} else {
			t.Progress(u.Host + "…")
		}
		runs = append(runs, webx.Fetch(ctx, pos[0], o))
		if ctx.Err() != nil {
			t.Clear()
			return 130
		}
	}
	t.Clear()
	r := runs[len(runs)-1]
	st, msg, notes := httpVerdict(r)
	if *count > 1 {
		failed := 0
		for _, x := range runs {
			if x.Error != "" {
				failed++
			}
		}
		// The median run stands for the rest.
		_, mid, _ := spread(runs, func(p webx.Phases) time.Duration { return p.Total })
		for _, x := range runs {
			if x.Error == "" && x.Final().Phases.Total == mid {
				r = x
			}
		}
		st, msg, notes = httpVerdict(r)
		if failed > 0 {
			st = max(st, ui.Warn)
			notes = append([]string{fmt.Sprintf("%d of %d requests failed.", failed, len(runs))}, notes...)
		}
		msg = "Median run: " + msg
	}
	var broken []string
	if vals := httpValues(r); vals != nil {
		broken = adv.Broken(rules, httpDefault, vals)
	}

	ui.Open(title)
	for _, l := range httpLines(r, *headers, ui.PanelWidth()) {
		ui.Println(l)
	}
	ui.Close()
	if *count > 1 {
		tb := ui.Table{Headers: []string{"Phase", "Fastest", "Median", "Slowest"}}
		for _, ph := range []struct {
			name string
			pick func(webx.Phases) time.Duration
		}{
			{"DNS", func(p webx.Phases) time.Duration { return p.DNS }},
			{"Connect", func(p webx.Phases) time.Duration { return p.Connect }},
			{"TLS", func(p webx.Phases) time.Duration { return p.TLS }},
			{"Server", func(p webx.Phases) time.Duration { return p.Wait }},
			{"Download", func(p webx.Phases) time.Duration { return p.Download }},
			{"Total", func(p webx.Phases) time.Duration { return p.Total }},
		} {
			lo, mid, hi := spread(runs, ph.pick)
			if hi == 0 {
				continue
			}
			tb.Rows = append(tb.Rows, ui.TableRow{Status: ui.Skip, Cells: []string{ph.name, fmtMs(ms(lo)), fmtMs(ms(mid)), fmtMs(ms(hi))}})
		}
		ui.Println("")
		ui.Open(fmt.Sprintf("%d requests", len(runs)))
		for _, l := range tb.Lines(ui.PanelWidth()) {
			ui.Println(l)
		}
		ui.Close()
	}
	if !common.Raw {
		ui.Verdict(st, msg, append(notes, broken...)...)
	}
	ui.Println("")
	if common.JSON {
		var data any = r
		if *count > 1 {
			data = runs
		}
		adv.Envelope{Tool: "http", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Data: data, FailedOn: broken}.Write(os.Stdout)
	}
	return adv.ExitCode(st.String(), broken)
}
